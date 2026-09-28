/* admin-device-detail-charts.js — v0.10.205 redesign.
 *
 * Owns the three "above the fold" charts on the device-detail page:
 *   - Overview (CPU %, Memory %, Disk %)
 *   - Network throughput (In/Out kbps)
 *   - CPU breakdown (user/system/iowait/...)
 *
 * Replaces the previous Chart.js implementations (loadStatusHistoryChart,
 * loadNetworkThroughputChart, loadCPUBreakdownChart) with uPlot. Key wins:
 *   - Brush-to-zoom + double-click reset, native to uPlot.
 *   - Synchronized cursor + zoom across all three charts via uPlot.sync('fwmon-device-detail').
 *   - Stepped + straight-line rendering (no spline overshoot inventing fake
 *     spikes on telemetry — splines are a lie for sampled data).
 *   - Server-side bucketing via GET /api/devices/:id/status-history?range=...
 *     so longer ranges return cleanly aggregated buckets, not raw poll-cadence
 *     noise. The range pill bar fetches once for all three charts.
 *   - Tabular numerals in the legend; JetBrains Mono in the axes.
 *
 * Public API (called from admin-device-detail.js):
 *   FwmonDeviceCharts.init(deviceId)        // mount + initial fetch
 *   FwmonDeviceCharts.setRange(range)       // change range + refetch
 *   FwmonDeviceCharts.destroy()             // teardown (e.g. on navigation)
 */
(function() {
    'use strict';

    var SYNC_KEY = 'fwmon-device-detail';
    var DEFAULT_RANGE = '24h';

    // Range pill definitions. label → human, value → backend range param.
    var RANGES = [
        { value: '1h',   label: '1h' },
        { value: '6h',   label: '6h' },
        { value: '12h',  label: '12h' },
        { value: '24h',  label: '24h' },
        { value: '7d',   label: '7d' },
        { value: '30d',  label: '30d' },
        { value: '90d',  label: '90d' }
    ];

    // Centralized palette — keep in sync with CSS variables in admin-device-detail.css.
    var P = {
        cpu:     '#7DD3FC', // sky
        memory:  '#C4B5FD', // violet
        disk:    '#86EFAC', // green
        netIn:   '#7DD3FC',
        netOut:  '#FCD34D',
        user:    '#7DD3FC',
        system:  '#FCA5A5',
        nice:    '#FCD34D',
        iowait:  '#C4B5FD',
        irq:     '#F0ABFC',
        softirq: '#5EEAD4',
        idle:    '#6B7280'
    };

    // Console design token reader (falls back to the shared helper / a manual
    // getComputedStyle). uPlot draws axes on canvas from these JS values, so
    // they're read fresh at every (re)build — including on theme toggle.
    function cssVar(name, fallback) {
        try {
            if (window.AdminCommon && AdminCommon.cssVar) return AdminCommon.cssVar(name, fallback);
            var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (e) { return fallback; }
    }
    function axisCfg() {
        return {
            stroke: cssVar('--fwmon-axis-stroke', '#6b7280'),
            font:  '11px "JetBrains Mono", ui-monospace, monospace',
            size:   24,
            grid:   { stroke: cssVar('--fwmon-grid-stroke', 'rgba(255, 255, 255, 0.06)'), width: 1 },
            ticks:  { stroke: cssVar('--fwmon-tick-stroke', 'rgba(255, 255, 255, 0.15)'), width: 1, size: 4 }
        };
    }

    // Shortest zoom window a drag selects (a smaller one widens around its middle).
    var MIN_ZOOM_MS = 5 * 60 * 1000;
    var LOAD_KEY = 'fwmon-device-charts';
    var HOST_IDS = ['fwmon-chart-overview', 'fwmon-chart-network', 'fwmon-chart-cpu'];

    var state = {
        deviceId: null,
        range: DEFAULT_RANGE,
        // Drag-to-zoom window {from, to} in epoch ms (bucket_ms), or null for
        // the preset range. Set when the user selects a range on a chart; the
        // charts are then re-queried for that window.
        window: null,
        charts: { overview: null, network: null, cpu: null },
        lastBuckets: null,
        resizeObserver: null,
        // Synced uPlot cursor key — must match across all instances.
        syncObj: (typeof uPlot !== 'undefined' && uPlot.sync) ? uPlot.sync(SYNC_KEY) : null
    };

    function init(deviceId) {
        if (typeof uPlot === 'undefined') {
            console.error('uPlot not loaded; charts cannot render.');
            return;
        }
        state.deviceId = deviceId;
        renderShell();
        wireRangePills();
        load(state.range);
        wireResize();
        wireThemeChange();
    }

    // Rebuild every uPlot from the cached buckets on Day/Night toggle so the
    // canvas-drawn axes pick up the new theme colors. We destroy first (the
    // overview chart has an in-place setData reuse path that would otherwise
    // keep the old axis stroke), then re-render — no data refetch.
    function wireThemeChange() {
        if (state.themeWired) return;
        state.themeWired = true;
        window.addEventListener('fwmon:themechange', function() {
            if (!state.lastBuckets || !state.lastBuckets.length) return;
            for (var k in state.charts) {
                if (state.charts[k]) {
                    try { state.charts[k].destroy(); } catch (e) { /* swallow */ }
                    state.charts[k] = null;
                }
            }
            renderOverview(state.lastBuckets);
            renderNetwork(state.lastBuckets);
            renderCPUBreakdown(state.lastBuckets);
        });
    }

    function destroy() {
        for (var k in state.charts) {
            if (state.charts[k]) {
                try { state.charts[k].destroy(); } catch (e) { /* swallow */ }
                state.charts[k] = null;
            }
        }
        if (state.resizeObserver) {
            try { state.resizeObserver.disconnect(); } catch (e) { /* swallow */ }
            state.resizeObserver = null;
        }
    }

    function setRange(range) {
        // The active pill still reloads when nothing is drawn (a cancelled first load).
        if (range === state.range && !state.window && hasCharts()) return;
        state.range = range;
        state.window = null;
        updateRangePillState();
        updateZoomChip();
        load(range);
    }

    // ----------------------------------------------------------------------
    // DOM scaffold — rebuild the three chart cards as uPlot hosts. Replaces
    // the original <canvas> elements with <div> hosts since uPlot mounts a
    // div container (not canvas-direct like Chart.js).
    // ----------------------------------------------------------------------
    function renderShell() {
        var overview = document.getElementById('status-history-section');
        var network  = document.getElementById('network-throughput-section');
        var cpu      = document.getElementById('cpu-breakdown-section');

        if (overview) {
            overview.classList.add('chart-card');
            overview.innerHTML = renderHeader('System Overview', 'CPU / Memory / Disk', /*withRangePills*/ true) +
                hostWrap('fwmon-chart-overview');
        }
        if (network) {
            network.classList.add('chart-card');
            // No legacy range select — the shared range pill row in the
            // overview card drives all three.
            network.innerHTML = renderHeader('Network Throughput', 'In / Out kbps', /*withRangePills*/ false) +
                hostWrap('fwmon-chart-network');
        }
        if (cpu) {
            cpu.classList.add('chart-card');
            cpu.innerHTML = renderHeader('CPU Breakdown', 'user / system / iowait / irq', /*withRangePills*/ false) +
                hostWrap('fwmon-chart-cpu');
        }
    }

    // hostWrap puts each uPlot host in a positioned wrapper. The loading
    // overlay mounts on the wrapper, not the host (whose content a redraw
    // replaces) and not the card (whose header holds the range pills).
    function hostWrap(id) {
        return '<div class="chart-host-wrap" id="' + id + '-wrap"><div class="chart-host" id="' + id + '"></div></div>';
    }

    function hostWraps() {
        return HOST_IDS.map(function(id) { return document.getElementById(id + '-wrap'); }).filter(Boolean);
    }

    function hasCharts() {
        return !!(state.charts.overview || state.charts.network || state.charts.cpu);
    }

    function destroyCharts() {
        for (var k in state.charts) {
            if (state.charts[k]) {
                try { state.charts[k].destroy(); } catch (e) { /* swallow */ }
                state.charts[k] = null;
            }
        }
    }

    function renderHeader(title, subtitle, withRangePills) {
        var pills = '';
        if (withRangePills) {
            pills = '<div class="chart-range-pills" id="fwmon-range-pills">';
            for (var i = 0; i < RANGES.length; i++) {
                var r = RANGES[i];
                var active = r.value === state.range ? ' active' : '';
                pills += '<button type="button" class="chart-range-pill' + active +
                    '" data-range="' + escapeAttr(r.value) + '">' + escapeHtml(r.label) + '</button>';
            }
            pills += '</div>';
            pills += '<span class="chart-zoom-hint"><span class="chart-zoom-chip" id="fwmon-zoom-chip" hidden></span>' +
                '<span id="fwmon-zoom-help">drag to zoom · dbl-click to reset</span>' +
                '<button type="button" class="chart-reset-btn" id="fwmon-reset-zoom" title="Reset zoom">reset</button></span>';
        }
        return '<div class="chart-card-header">' +
            '<div>' +
            '<h3 class="chart-card-title">' + escapeHtml(title) + '</h3>' +
            (subtitle ? '<div class="chart-card-subtitle">' + escapeHtml(subtitle) + '</div>' : '') +
            '</div>' +
            pills +
            '</div>';
    }

    function wireRangePills() {
        var bar = document.getElementById('fwmon-range-pills');
        if (!bar) return;
        bar.addEventListener('click', function(ev) {
            var btn = ev.target && ev.target.closest && ev.target.closest('.chart-range-pill');
            if (!btn) return;
            var r = btn.getAttribute('data-range');
            if (r) setRange(r);
        });
        var resetBtn = document.getElementById('fwmon-reset-zoom');
        if (resetBtn) {
            resetBtn.addEventListener('click', resetZoom);
        }
    }

    function updateRangePillState() {
        var bar = document.getElementById('fwmon-range-pills');
        if (!bar) return;
        var pills = bar.querySelectorAll('.chart-range-pill');
        for (var i = 0; i < pills.length; i++) {
            var p = pills[i];
            // A zoom window is not one of the presets: no pill is active.
            if (!state.window && p.getAttribute('data-range') === state.range) {
                p.classList.add('active');
            } else {
                p.classList.remove('active');
            }
        }
    }

    // smartPercentRange — uPlot range function for "this is a percentage"
    // y-axes (Overview CPU/Mem/Disk, CPU Breakdown). Behavior:
    //
    //   - Min is ALWAYS 0. Percentages floating on a non-zero baseline are
    //     misleading; readers don't expect "0%" to mean "85%".
    //   - Max auto-fits the visible-data max with a 15% headroom. uPlot's
    //     auto-fit considers ONLY series that aren't toggled off via the
    //     legend, so clicking a high-value series to hide it makes the
    //     remaining low-value series pop. That's the user's feature request.
    //   - The top is snapped UP to a "nice" round number (5/10/20/25/50/100)
    //     so axis ticks land on whole numbers, not 17.3 / 34.6 / 51.9.
    //   - A floor of 5% on the top means even a flat-at-zero chart still
    //     renders a readable axis (otherwise uPlot collapses to a hairline).
    //   - When utilization is near saturation (data max > 85%), we snap to
    //     100 — operators expect a "full" axis at high load.
    //
    // dataMin/dataMax come pre-computed by uPlot from visible series. When
    // every series is toggled off they arrive as Infinity/-Infinity; the
    // fallback is the historical hardcoded [0, 100].
    function smartPercentRange(u, dataMin, dataMax) {
        if (dataMax == null || !isFinite(dataMax)) return [0, 100];
        if (dataMax > 85) return [0, 100];
        var raw = Math.max(5, dataMax * 1.15);
        // Snap to a nice round number.
        var steps = [5, 10, 15, 20, 25, 30, 40, 50, 60, 70, 80, 90, 100];
        for (var i = 0; i < steps.length; i++) {
            if (raw <= steps[i]) return [0, steps[i]];
        }
        return [0, 100];
    }

    // resetZoom leaves a zoom window: the charts go back to the preset range,
    // re-queried. With no window (a plain drag preview) it only rescales.
    function resetZoom() {
        if (state.window) {
            state.window = null;
            updateRangePillState();
            updateZoomChip();
            load(state.range);
            return;
        }
        rescaleToData();
    }

    function rescaleToData() {
        // setScale('x', {min: null, max: null}) is a NO-OP in uPlot — null
        // means "keep the current value," not "auto-fit." To actually clear
        // a brush-zoom we have to set the scale back to the data's full
        // x-range. Each chart owns its own data array so we read from there
        // (rather than re-fetching). state.charts is sparse if a chart was
        // hidden (e.g. CPU breakdown when no breakdown data exists).
        for (var k in state.charts) {
            var c = state.charts[k];
            if (!c || !c.data || !c.data[0] || !c.setScale) continue;
            var xs = c.data[0];
            if (xs.length === 0) continue;
            c.setScale('x', { min: xs[0], max: xs[xs.length - 1] });
        }
    }

    // ----------------------------------------------------------------------
    // Drag-to-zoom (v0.11.270): a selection re-queries the window at a finer
    // bucket instead of only stretching the points already loaded. uPlot's own
    // drag rescale stays as the instant preview while the data loads.
    // ----------------------------------------------------------------------
    function onSelect(u) {
        // Only the chart the user dragged on: synced charts receive the same
        // selection with cursor.event == null.
        var ev = u.cursor && u.cursor.event;
        if (!ev || ev.type !== 'mouseup') return;
        var sel = u.select;
        if (!sel || sel.width < 2) return;
        var a = u.posToVal(sel.left, 'x'), b = u.posToVal(sel.left + sel.width, 'x');
        var from = Math.floor(Math.min(a, b) * 1000), to = Math.ceil(Math.max(a, b) * 1000);
        if (!isFinite(from) || !isFinite(to)) return;
        if (to - from < MIN_ZOOM_MS) {
            var mid = (from + to) / 2;
            from = Math.round(mid - MIN_ZOOM_MS / 2);
            to = from + MIN_ZOOM_MS;
        }
        zoomTo({ from: from, to: to });
    }

    function zoomTo(win) {
        state.window = win;
        updateRangePillState();
        updateZoomChip();
        load(state.range);
    }

    // The chip shows the zoom window (bucket_ms is the server's wall clock
    // encoded as UTC, as on the interface charts). "preview" marks a window
    // whose finer data was cancelled: the chart is the old data, stretched.
    function updateZoomChip(preview) {
        var chip = document.getElementById('fwmon-zoom-chip');
        var help = document.getElementById('fwmon-zoom-help');
        if (!chip) return;
        if (!state.window) {
            chip.hidden = true;
            chip.textContent = '';
            if (help) help.hidden = false;
            return;
        }
        chip.textContent = (preview ? 'preview — cancelled · ' : 'zoomed · ') + winLabel(state.window);
        chip.hidden = false;
        if (help) help.hidden = true;
    }

    function winLabel(w) {
        var pad = function(n) { return (n < 10 ? '0' : '') + n; };
        var fmt = function(ms) {
            var d = new Date(ms);
            return pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
        };
        return fmt(w.from) + ' → ' + fmt(w.to);
    }

    // ----------------------------------------------------------------------
    // Data fetch — one round trip feeds all three charts. The charts on screen
    // are kept (dimmed under the loading overlay) until the new data arrives;
    // only the very first paint shows a placeholder.
    // ----------------------------------------------------------------------
    function load(range) {
        var AC = window.AdminCommon;
        var firstPaint = !hasCharts();
        if (firstPaint) {
            HOST_IDS.forEach(function(id) {
                var h = document.getElementById(id);
                if (h) h.innerHTML = '<div class="chart-loading">loading ' + escapeHtml(range) + ' …</div>';
            });
        }
        var win = state.window;
        var url = '/admin/api/devices/' + encodeURIComponent(state.deviceId) + '/status-history?' +
            (win ? 'from=' + encodeURIComponent(win.from) + '&to=' + encodeURIComponent(win.to)
                 : 'range=' + encodeURIComponent(range));

        AC.chartLoad(hostWraps(), function(signal) {
            return AC.apiFetch(url, { signal: signal });
        }, { key: LOAD_KEY, label: win ? 'Loading higher-resolution data…' : 'Loading ' + range + ' …' })
            .then(function(r) {
                if (r.cancelled) {
                    // A newer load replaced this one: nothing to undo. A user
                    // Cancel keeps the stretched preview and says so; a
                    // cancelled first load says how to start again.
                    if (r.superseded) return;
                    if (firstPaint) showEmpty('Load cancelled — pick a range');
                    else if (win) updateZoomChip(true);
                    return;
                }
                var result = r.data;
                if (r.error || !result || !result.success) {
                    if (window.fwmonLog && r.error) window.fwmonLog.error('Failed to load device status history:', r.error);
                    failLoad(firstPaint, 'Could not load this range', function() { load(range); });
                    return;
                }
                var buckets = (result.data && result.data.buckets) || [];
                if (buckets.length === 0) {
                    // The chart on screen is the old data, stretched: say so.
                    if (win) updateZoomChip(true);
                    failLoad(firstPaint, 'No data in this range', function() { load(range); });
                    return;
                }
                state.lastBuckets = buckets;
                destroyCharts();
                renderOverview(buckets);
                renderNetwork(buckets);
                renderCPUBreakdown(buckets);
            });
    }

    // failLoad reports an empty or failed load. With charts on screen they are
    // kept and the notice sits over them; only a first paint has nothing to keep.
    function failLoad(firstPaint, msg, onRetry) {
        if (firstPaint) {
            destroyCharts();
            showEmpty(msg);
            return;
        }
        window.AdminCommon.chartNotice(hostWraps(), msg, { onRetry: onRetry });
    }

    function showEmpty(msg) {
        ['fwmon-chart-overview', 'fwmon-chart-network', 'fwmon-chart-cpu'].forEach(function(id) {
            var h = document.getElementById(id);
            if (h) h.innerHTML = '<div class="chart-empty">' + escapeHtml(msg) + '</div>';
        });
    }

    // ----------------------------------------------------------------------
    // uPlot common opts factory. Used by every chart to keep visual rules
    // exactly aligned: same axis fonts, same grid color, same sync key.
    // ----------------------------------------------------------------------
    function commonOpts(host, title, seriesDefs, yScaleOpts) {
        var width = host.clientWidth || 600;
        return {
            width: width,
            height: 240,
            title: title,
            cursor: {
                sync: { key: SYNC_KEY, setSeries: true },
                // dist 2: a 1-px drag neither previews nor fetches.
                drag: { x: true, y: false, setScale: true, dist: 2 },
                // uPlot's own double-click only rescales to the data on screen,
                // which after a zoom is the zoomed window; reset properly.
                bind: {
                    dblclick: function() { return function() { resetZoom(); return null; }; }
                },
                points: { size: 6, fill: function(u, sIdx) { return u.series[sIdx].stroke; } }
            },
            legend: { live: true, isolate: true },
            hooks: { setSelect: [onSelect] },
            scales: {
                x: { time: true },
                y: yScaleOpts || { auto: true }
            },
            axes: (function() {
                var AX = axisCfg();
                return [
                    {
                        stroke: AX.stroke,
                        font:   AX.font,
                        size:   AX.size,
                        grid:   AX.grid,
                        ticks:  AX.ticks,
                        space:  60
                    },
                    {
                        stroke: AX.stroke,
                        font:   AX.font,
                        size:   48,
                        grid:   AX.grid,
                        ticks:  AX.ticks
                    }
                ];
            })(),
            series: seriesDefs
        };
    }

    // ----------------------------------------------------------------------
    // Chart 1: System Overview — CPU/Memory/Disk %.
    //
    // In-place update path (v0.10.214, bundle C4): the series count and
    // formatter are stable across range changes (always CPU+Memory+Disk
    // at the same %-format), so we can reuse the existing uPlot instance
    // and just call setData(). Saves the ~30-50ms construction + GC on
    // every range-pill click; range-pill spam in particular feels snappy
    // now instead of stuttering.
    // ----------------------------------------------------------------------
    function renderOverview(buckets) {
        var host = document.getElementById('fwmon-chart-overview');
        if (!host) return;

        var x   = buckets.map(function(b) { return Math.floor(b.bucket_ms / 1000); });
        var cpu = buckets.map(function(b) { return numOrNull(b.cpu_usage); });
        var mem = buckets.map(function(b) { return numOrNull(b.memory_usage); });
        var dsk = buckets.map(function(b) { return numOrNull(b.disk_usage); });
        var data = [x, cpu, mem, dsk];

        if (state.charts.overview) {
            state.charts.overview.setData(data);
            return;
        }

        host.innerHTML = '';
        var seriesDefs = [
            {},
            seriesLine('CPU',     P.cpu,    valuePct),
            seriesLine('Memory',  P.memory, valuePct),
            seriesLine('Disk',    P.disk,   valuePct)
        ];

        var opts = commonOpts(host, '', seriesDefs, {
            range: smartPercentRange
        });
        opts.axes[1].values = function(u, vals) {
            return vals.map(function(v) { return v + '%'; });
        };
        state.charts.overview = new uPlot(opts, data, host);
    }

    // ----------------------------------------------------------------------
    // Chart 2: Network Throughput — In/Out kbps. Adaptive unit (kbps/Mbps).
    // ----------------------------------------------------------------------
    function renderNetwork(buckets) {
        var host = document.getElementById('fwmon-chart-network');
        if (!host) return;
        host.innerHTML = '';

        var hasAny = buckets.some(function(b) {
            return (b.network_in_kbps || 0) > 0 || (b.network_out_kbps || 0) > 0;
        });
        if (!hasAny) {
            host.innerHTML = '<div class="chart-empty">No network throughput data</div>';
            return;
        }

        var x      = buckets.map(function(b) { return Math.floor(b.bucket_ms / 1000); });
        var inSer  = buckets.map(function(b) { return numOrNull(b.network_in_kbps); });
        var outSer = buckets.map(function(b) { return numOrNull(b.network_out_kbps); });

        // Decide whether to label axis in kbps or Mbps based on data magnitude.
        var maxKbps = 0;
        for (var i = 0; i < inSer.length; i++) {
            if (inSer[i] != null && inSer[i] > maxKbps) maxKbps = inSer[i];
            if (outSer[i] != null && outSer[i] > maxKbps) maxKbps = outSer[i];
        }
        var useMbps = maxKbps >= 5000;
        var unitLabel = useMbps ? 'Mbps' : 'kbps';
        var unitScale = useMbps ? 0.001 : 1;

        var fmtBw = function(v) {
            if (v == null) return '--';
            var scaled = v * unitScale;
            return scaled.toFixed(scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2) + ' ' + unitLabel;
        };

        var seriesDefs = [
            {},
            seriesArea('In',  P.netIn,  fmtBw),
            seriesArea('Out', P.netOut, fmtBw)
        ];

        var opts = commonOpts(host, '', seriesDefs, { auto: true });
        opts.axes[1].values = function(u, vals) {
            return vals.map(function(v) {
                if (v >= 1000 * 1000) return (v / 1000 / 1000).toFixed(1) + 'G';
                if (v >= 1000)        return (v / 1000).toFixed(useMbps ? 1 : 0) + (useMbps ? 'M' : 'M');
                return v + (useMbps ? 'k' : '');
            });
        };
        opts.axes[1].size = 56;

        var chart = new uPlot(opts, [x, inSer, outSer], host);
        if (state.charts.network) state.charts.network.destroy();
        state.charts.network = chart;
    }

    // ----------------------------------------------------------------------
    // Chart 3: CPU Breakdown — stacked components. Hidden if all zero.
    // ----------------------------------------------------------------------
    // In-place update path (v0.10.214, bundle C4): 7 fixed series, fixed
    // %-formatter, no axis-unit switching — same setData()-reuse pattern
    // as renderOverview.
    function renderCPUBreakdown(buckets) {
        var host = document.getElementById('fwmon-chart-cpu');
        var section = document.getElementById('cpu-breakdown-section');
        if (!host) return;

        var hasBreakdown = buckets.some(function(b) {
            return (b.cpu_user || 0) > 0 || (b.cpu_system || 0) > 0 || (b.cpu_idle || 0) > 0;
        });
        if (!hasBreakdown) {
            if (section) section.style.display = 'none';
            return;
        }
        if (section) section.style.display = '';

        var x = buckets.map(function(b) { return Math.floor(b.bucket_ms / 1000); });
        var data = [
            x,
            buckets.map(function(b) { return numOrNull(b.cpu_user); }),
            buckets.map(function(b) { return numOrNull(b.cpu_system); }),
            buckets.map(function(b) { return numOrNull(b.cpu_nice); }),
            buckets.map(function(b) { return numOrNull(b.cpu_iowait); }),
            buckets.map(function(b) { return numOrNull(b.cpu_irq); }),
            buckets.map(function(b) { return numOrNull(b.cpu_softirq); }),
            buckets.map(function(b) { return numOrNull(b.cpu_idle); })
        ];

        if (state.charts.cpu) {
            state.charts.cpu.setData(data);
            return;
        }

        host.innerHTML = '';
        var seriesDefs = [
            {},
            seriesLine('user',    P.user,    valuePct),
            seriesLine('system',  P.system,  valuePct),
            seriesLine('nice',    P.nice,    valuePct),
            seriesLine('iowait',  P.iowait,  valuePct),
            seriesLine('irq',     P.irq,     valuePct),
            seriesLine('softirq', P.softirq, valuePct),
            seriesLine('idle',    P.idle,    valuePct)
        ];

        var opts = commonOpts(host, '', seriesDefs, {
            range: smartPercentRange
        });
        opts.axes[1].values = function(u, vals) {
            return vals.map(function(v) { return v + '%'; });
        };
        state.charts.cpu = new uPlot(opts, data, host);
    }

    // ----------------------------------------------------------------------
    // uPlot series helpers.
    //
    // We deliberately do NOT use spline interpolation (paths.spline). Splines
    // overshoot extrema and INVENT values between samples — fine for stock
    // prices, dishonest for sampled telemetry. Straight line segments tell
    // the truth: "here's the bucket value, and we don't know what happened
    // between these two sample points."
    // ----------------------------------------------------------------------
    function seriesLine(label, color, valueFmt) {
        return {
            label: label,
            stroke: color,
            width: 1.6,
            value: function(u, v) { return valueFmt ? valueFmt(v) : (v == null ? '--' : v); },
            points: { show: false },
            spanGaps: false
        };
    }

    function seriesArea(label, color, valueFmt) {
        return {
            label: label,
            stroke: color,
            width: 1.6,
            fill: hexToRgba(color, 0.10),
            value: function(u, v) { return valueFmt ? valueFmt(v) : (v == null ? '--' : v); },
            points: { show: false },
            spanGaps: false
        };
    }

    // ----------------------------------------------------------------------
    // Resize handling — uPlot.setSize() must be called when the container
    // resizes (tab switch, sidebar collapse, browser zoom). We watch each
    // host's bounding rect via ResizeObserver and forward to the chart.
    // ----------------------------------------------------------------------
    function wireResize() {
        if (typeof ResizeObserver === 'undefined') return;
        var hosts = ['fwmon-chart-overview', 'fwmon-chart-network', 'fwmon-chart-cpu'];
        var ro = new ResizeObserver(function(entries) {
            entries.forEach(function(entry) {
                var id = entry.target.id;
                var key = id === 'fwmon-chart-overview' ? 'overview'
                        : id === 'fwmon-chart-network'  ? 'network'
                        : id === 'fwmon-chart-cpu'      ? 'cpu'
                        : null;
                if (!key) return;
                var chart = state.charts[key];
                if (chart && chart.setSize) {
                    chart.setSize({
                        width: Math.max(280, entry.contentRect.width),
                        height: 240
                    });
                }
            });
        });
        for (var i = 0; i < hosts.length; i++) {
            var el = document.getElementById(hosts[i]);
            if (el) ro.observe(el);
        }
        state.resizeObserver = ro;
    }

    // ----------------------------------------------------------------------
    // Utilities
    // ----------------------------------------------------------------------
    function numOrNull(v) {
        if (v === null || v === undefined) return null;
        var n = Number(v);
        if (!isFinite(n)) return null;
        return n;
    }

    function valuePct(u, v) {
        if (v == null) return '--';
        return v.toFixed(1) + '%';
    }

    function hexToRgba(hex, a) {
        var h = hex.replace('#', '');
        if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
        var r = parseInt(h.substr(0, 2), 16);
        var g = parseInt(h.substr(2, 2), 16);
        var b = parseInt(h.substr(4, 2), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
    function escapeAttr(s) { return escapeHtml(s); }

    window.FwmonDeviceCharts = {
        init: init,
        destroy: destroy,
        setRange: setRange,
        getRange: function() { return state.range; }
    };
})();
