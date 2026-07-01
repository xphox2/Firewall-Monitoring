/* admin-bw-chart.js — shared 3-mode bandwidth chart for admin pages.
 *
 * Mirrors the public dashboard's interface bandwidth widget
 * (public-dashboard.js renderBandwidthChart) so the admin device-detail
 * interface and VPN-tunnel graphs offer the same three display modes and
 * visual style:
 *
 *   - 'rate'  (Throughput) — RX/TX line chart in Mbps
 *   - 'total' (Transfer)   — RX/TX bar chart of bytes-per-bucket
 *   - 'mix'   (Combined)   — Mbps lines (left axis) + byte bars (right axis)
 *
 * The caller passes already-normalized per-bucket series (rate in Mbps,
 * transfer in bytes) plus the active view; this module owns only the Chart.js
 * dataset/scale construction. Chart state (which view, which range) lives with
 * the caller so a single page can host many independent charts (one per
 * expanded interface / tunnel row).
 *
 *   var chart = FwmonBwChart.render(canvas, {
 *       labels:     [...],   // x-axis tick labels
 *       rxRate:     [...],   // Mbps
 *       txRate:     [...],   // Mbps
 *       rxTransfer: [...],   // bytes/bucket
 *       txTransfer: [...],   // bytes/bucket
 *       view:       'rate',  // 'rate' | 'total' | 'mix'
 *       rxLabel:    'In',    // series prefix (e.g. In/Out, RX/TX)
 *       txLabel:    'Out',
 *       onZoomSelect: function(loIdx, hiIdx) { ... } // optional drag-to-zoom
 *   });
 *
 * When onZoomSelect is supplied (and chartjs-plugin-zoom is loaded), the chart
 * enables drag-to-select on the x-axis; on release it reports the selected
 * category index range so the caller can re-query the backend for exactly that
 * window at finer resolution.
 */
(function () {
    'use strict';

    // The three display modes, in the same order/labels the public dashboard
    // header dropdown uses (#bw-view). Callers iterate this to render a toggle.
    var MODES = [
        { value: 'rate',  label: 'Throughput' },
        { value: 'total', label: 'Transfer' },
        { value: 'mix',   label: 'Combined' }
    ];

    var RX_COLOR = '#3fb950'; // green  — matches public dashboard RX
    var TX_COLOR = '#ff9500'; // orange — matches public dashboard TX

    // 1024-based, matching public-dashboard.js / admin-device-detail.js so the
    // chart's byte axis reads the same as the table cells right above it.
    function formatBytes(bytes) {
        if (bytes == null || isNaN(bytes) || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        var val = bytes;
        while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
        return val.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    // Common Chart.js options — dark NOC theme aligned with the rest of the
    // admin UI. scaleOverrides is merged on top of the shared x-axis.
    function chartOpts(scaleOverrides) {
        var scales = {
            x: { ticks: { color: '#484f58', maxTicksLimit: 12, maxRotation: 0, font: { size: 11 } }, grid: { color: '#21262d' } }
        };
        for (var key in scaleOverrides) {
            if (Object.prototype.hasOwnProperty.call(scaleOverrides, key)) {
                scales[key] = scaleOverrides[key];
            }
        }
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            interaction: { intersect: false, mode: 'index' },
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
            scales: scales
        };
    }

    function render(canvas, o) {
        var view = o.view || 'rate';
        var rxLabel = o.rxLabel || 'RX';
        var txLabel = o.txLabel || 'TX';
        var rxRate = o.rxRate || [];
        var txRate = o.txRate || [];
        var rxTransfer = o.rxTransfer || [];
        var txTransfer = o.txTransfer || [];

        // Single-series mode: when no TX data is supplied the chart renders just
        // the RX series (used for aggregate, non-directional traffic like the
        // Flows page's total throughput). The 3 view modes still apply.
        var single = txRate.length === 0 && txTransfer.length === 0;

        var datasets, scales;

        if (view === 'total') {
            // Transfer: per-bucket bytes as bars.
            datasets = [
                { type: 'bar', label: rxLabel + ' Transfer', data: rxTransfer, backgroundColor: 'rgba(63,185,80,0.6)', borderColor: RX_COLOR, borderWidth: 1 }
            ];
            if (!single) {
                datasets.push({ type: 'bar', label: txLabel + ' Transfer', data: txTransfer, backgroundColor: 'rgba(255,149,0,0.6)', borderColor: TX_COLOR, borderWidth: 1 });
            }
            scales = {
                y: { beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return formatBytes(v); } }, grid: { color: '#21262d' }, title: { display: true, text: 'Bytes / interval', color: '#484f58' } }
            };
        } else if (view === 'mix') {
            // Combined: Mbps lines on the left axis, byte bars on the right.
            datasets = [
                { label: rxLabel + ' (Mbps)', data: rxRate, borderColor: RX_COLOR, backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' }
            ];
            if (!single) {
                datasets.push({ label: txLabel + ' (Mbps)', data: txRate, borderColor: TX_COLOR, backgroundColor: 'rgba(255,149,0,0.08)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' });
            }
            datasets.push({ type: 'bar', label: rxLabel + ' Transfer', data: rxTransfer, backgroundColor: 'rgba(63,185,80,0.3)', borderWidth: 0, yAxisID: 'y1' });
            if (!single) {
                datasets.push({ type: 'bar', label: txLabel + ' Transfer', data: txTransfer, backgroundColor: 'rgba(255,149,0,0.3)', borderWidth: 0, yAxisID: 'y1' });
            }
            scales = {
                y:  { position: 'left',  beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return v.toFixed(1); } }, grid: { color: '#21262d' }, title: { display: true, text: 'Mbps', color: '#484f58' } },
                y1: { position: 'right', beginAtZero: true, grid: { display: false }, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return formatBytes(v); } }, title: { display: true, text: 'Bytes', color: '#484f58' } }
            };
        } else {
            // Throughput (default): Mbps as filled lines.
            datasets = [
                { label: rxLabel + ' (Mbps)', data: rxRate, borderColor: RX_COLOR, backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 }
            ];
            if (!single) {
                datasets.push({ label: txLabel + ' (Mbps)', data: txRate, borderColor: TX_COLOR, backgroundColor: 'rgba(255,149,0,0.1)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 });
            }
            scales = {
                y: { beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return v.toFixed(1) + ' Mbps'; } }, grid: { color: '#21262d' } }
            };
        }

        var options = chartOpts(scales);

        // Drag-to-zoom: select an x-range, then re-query the backend for that
        // window. Requires chartjs-plugin-zoom (auto-registers on load). On a
        // category x-axis the post-drag scale min/max are fractional category
        // indices; we snap outward (floor/ceil) and clamp to the data bounds.
        if (typeof o.onZoomSelect === 'function' && window.Chart && Chart.registry && hasZoomPlugin()) {
            var n = (o.labels || []).length;
            options.plugins.zoom = {
                zoom: {
                    drag: {
                        enabled: true,
                        backgroundColor: 'rgba(88,166,255,0.18)',
                        borderColor: 'rgba(88,166,255,0.8)',
                        borderWidth: 1
                    },
                    mode: 'x',
                    onZoomComplete: function (ctx) {
                        var sx = ctx && ctx.chart && ctx.chart.scales && ctx.chart.scales.x;
                        if (!sx) return;
                        var lo = Math.floor(sx.min);
                        var hi = Math.ceil(sx.max);
                        if (lo < 0) lo = 0;
                        if (hi > n - 1) hi = n - 1;
                        if (hi - lo < 1) return; // selection too small to be meaningful
                        o.onZoomSelect(lo, hi);
                    }
                }
            };
        }

        return new Chart(canvas, {
            type: 'line',
            data: { labels: o.labels || [], datasets: datasets },
            options: options
        });
    }

    // hasZoomPlugin reports whether chartjs-plugin-zoom registered itself.
    function hasZoomPlugin() {
        try {
            return !!Chart.registry.plugins.get('zoom');
        } catch (e) {
            return false;
        }
    }

    // ---- Series normalizers (shared by every admin bandwidth chart) ----------
    // These mirror the device-detail page so ALL bandwidth charts derive the same
    // per-bucket rate (Mbps) + transfer (bytes) from the two backend shapes:
    // cumulative counters (interface_stats / sFlow if_counters — must be delta'd)
    // and pre-computed per-bucket deltas (VPN/connection LAG() queries).

    function bucketMsArray(data) {
        return data.map(function (d) { return Number(d.bucket_ms) || 0; });
    }
    function medianIntervalSec(ms) {
        var diffs = [];
        for (var i = 1; i < ms.length; i++) { var d = ms[i] - ms[i - 1]; if (d > 0) diffs.push(d); }
        if (diffs.length === 0) return 60;
        diffs.sort(function (a, b) { return a - b; });
        return diffs[Math.floor(diffs.length / 2)] / 1000;
    }
    function makeLabels(data, spanMs) {
        var multiDay = spanMs > 36 * 3600 * 1000;
        return data.map(function (d) {
            var b = d.bucket || '';
            if (b.length <= 10) return b.substring(5);   // MM-DD (day bucket)
            if (multiDay) return b.substring(5, 13);     // MM-DD HH
            return b.substring(11, 16);                  // HH:MM
        });
    }

    // normalizeCumulative: in_bytes/out_bytes are CUMULATIVE counters — transfer
    // is the consecutive-bucket delta (clamped >=0 across resets), rate is that
    // delta over the actual bucket interval.
    function normalizeCumulative(data) {
        var ms = bucketMsArray(data);
        var span = ms.length > 1 ? (ms[ms.length - 1] - ms[0]) : 0;
        var medSec = medianIntervalSec(ms);
        var s = { labels: makeLabels(data, span), bucketMs: ms, rxRate: [], txRate: [], rxTransfer: [], txTransfer: [] };
        for (var i = 0; i < data.length; i++) {
            if (i === 0) { s.rxTransfer.push(0); s.txTransfer.push(0); s.rxRate.push(0); s.txRate.push(0); continue; }
            var dRx = data[i].in_bytes - data[i - 1].in_bytes; if (dRx < 0) dRx = 0;
            var dTx = data[i].out_bytes - data[i - 1].out_bytes; if (dTx < 0) dTx = 0;
            var sec = (ms[i] > ms[i - 1]) ? (ms[i] - ms[i - 1]) / 1000 : medSec;
            if (!(sec > 0)) sec = medSec;
            s.rxTransfer.push(dRx); s.txTransfer.push(dTx);
            s.rxRate.push(dRx * 8 / sec / 1e6); s.txRate.push(dTx * 8 / sec / 1e6);
        }
        return s;
    }

    // normalizeDeltas: in_bytes/out_bytes are ALREADY per-bucket deltas — transfer
    // is the value as-is, rate divides by the bucket interval.
    function normalizeDeltas(data) {
        var ms = bucketMsArray(data);
        var span = ms.length > 1 ? (ms[ms.length - 1] - ms[0]) : 0;
        var medSec = medianIntervalSec(ms);
        var s = { labels: makeLabels(data, span), bucketMs: ms, rxRate: [], txRate: [], rxTransfer: [], txTransfer: [] };
        for (var i = 0; i < data.length; i++) {
            var dRx = data[i].in_bytes < 0 ? 0 : data[i].in_bytes;
            var dTx = data[i].out_bytes < 0 ? 0 : data[i].out_bytes;
            var sec = (i > 0 && ms[i] > ms[i - 1]) ? (ms[i] - ms[i - 1]) / 1000 : medSec;
            if (!(sec > 0)) sec = medSec;
            s.rxTransfer.push(dRx); s.txTransfer.push(dTx);
            s.rxRate.push(dRx * 8 / sec / 1e6); s.txRate.push(dTx * 8 / sec / 1e6);
        }
        return s;
    }

    // mount: render a normalized series into canvas AND inject a compact 3-mode
    // toggle just above it (once), re-rendering on mode change. Returns an object
    // with a .destroy() so callers can treat it like a Chart instance. The active
    // mode is preserved across re-mounts (range changes) via the toggle's state.
    function mount(canvas, series, opts) {
        opts = opts || {};
        // The canvas lives inside a fixed-height sizing box (Chart.js responsive
        // needs that). The toggle must sit ABOVE that box — as a preceding
        // sibling in the box's parent — so it never eats into the chart height.
        var box = canvas.parentElement;
        var slot = box.parentElement || box;
        var prev = box.previousElementSibling;
        var toggle = (prev && prev.classList && prev.classList.contains('fwmon-bw-toggle')) ? prev : null;
        var view = opts.initialView || 'rate';
        if (toggle) {
            var cur = toggle.querySelector('.fwmon-bw-toggle-btn.active');
            if (cur) view = cur.getAttribute('data-bwm');
        }
        var chart = null;
        function draw() {
            if (chart) { chart.destroy(); chart = null; }
            chart = render(canvas, {
                labels: series.labels,
                rxRate: series.rxRate, txRate: series.txRate,
                rxTransfer: series.rxTransfer, txTransfer: series.txTransfer,
                view: view, rxLabel: opts.rxLabel, txLabel: opts.txLabel
            });
        }
        if (!toggle) {
            toggle = document.createElement('div');
            toggle.className = 'fwmon-bw-toggle';
            MODES.forEach(function (m) {
                var b = document.createElement('button');
                b.type = 'button';
                b.textContent = m.label;
                b.setAttribute('data-bwm', m.value);
                b.className = 'fwmon-bw-toggle-btn' + (m.value === view ? ' active' : '');
                toggle.appendChild(b);
            });
            slot.insertBefore(toggle, box);
            // The listener is attached ONCE, but a chart re-mounts on every range
            // change / 30s poll. So it dispatches to the LATEST mount's handler
            // (stored on the element) rather than closing over the first mount's
            // draw() — otherwise a click after a re-poll would bind a second
            // Chart.js instance to the same canvas ("Canvas is already in use").
            toggle.addEventListener('click', function (ev) {
                var b = ev.target && ev.target.closest && ev.target.closest('[data-bwm]');
                if (!b) return;
                var all = toggle.querySelectorAll('[data-bwm]');
                for (var i = 0; i < all.length; i++) { all[i].classList.toggle('active', all[i] === b); }
                if (toggle._fwmonApply) toggle._fwmonApply(b.getAttribute('data-bwm'));
            });
        }
        // Always (re)bind the apply handler to THIS mount's view + draw.
        toggle._fwmonApply = function (v) { view = v; draw(); };
        draw();
        return { destroy: function () { if (chart) chart.destroy(); } };
    }

    window.FwmonBwChart = {
        MODES: MODES,
        render: render,
        mount: mount,
        normalizeCumulative: normalizeCumulative,
        normalizeDeltas: normalizeDeltas,
        formatBytes: formatBytes
    };
})();
