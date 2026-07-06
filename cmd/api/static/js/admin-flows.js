/* admin-flows.js — v0.10.211 Flows-tab redesign.
 *
 * Owns the page rendered at /admin/flows. Replaces the previous Chart.js
 * implementations of:
 *   - Bandwidth-over-time chart → uPlot with brush-zoom
 *   - Top sources / dests / ports / protocols → HTML lists with click-to-filter
 *   - Filter row → pill-bar protocol selector, CIDR-capable IP inputs,
 *     auto-apply with debounce, URL-state sync.
 *
 * Public API (called from admin-main.js):
 *   FwmonFlows.init()                  // bind controls, sync from URL, fetch
 *   FwmonFlows.refresh()               // re-fetch with current filter state
 *   FwmonFlows.getState()              // current filter/range state (for tests)
 *   FwmonFlows.setFilter(key, value)   // programmatic filter set (drill-down)
 *
 * State model:
 *   {
 *     hours: 24,
 *     device_id: "", probe_id: "",
 *     protocol: "",
 *     src: "", dst: "", dport: ""
 *   }
 * Every state mutation calls syncURL() (replaceState), persistChips(), and
 * scheduleReload() (debounced apiFetch).
 */
(function() {
    'use strict';

    var SYNC_KEY = 'fwmon-flows';
    var DEFAULTS = {
        hours: 24,
        site_id: '',
        device_id: '',
        probe_id: '',
        protocol: '',
        src: '',
        dst: '',
        dport: '',
        category: '',   // app_category id (classify.Category), drives By Application filter
        direction: '',  // direction id (classify.Dir*), drives By Direction filter
        country: '',    // dst ISO country code, drives Top Countries filter
        asn: '',        // dst ASN number, drives Top ASNs filter
        source: '',     // flow_source id (0=sFlow..3=IPFIX); '' = all — NOTE '0' is a real filter
        event: '',      // firewall_event id (IE 233; 3=Denied); '' = all — '0' (None) is a real filter
        // Which view of the combined data card is active: 'conversations' | 'samples'.
        tab: 'conversations'
    };

    // URL params <-> state. URL is the source of truth on page load so
    // refresh / back / share preserves the view.
    var URL_KEYS = ['hours', 'site_id', 'device_id', 'probe_id', 'protocol', 'src', 'dst', 'dport', 'category', 'direction', 'country', 'asn', 'source', 'event', 'tab'];

    // Label <-> id maps for the classification breakdowns. These MIRROR
    // internal/classify (Category / Dir* — documented as stable). The widgets
    // display labels but filter by the numeric id the backend stores, so we map
    // the clicked label back to its id and render active-chip labels from ids.
    var CATEGORY_LABELS = {
        0: 'Unknown', 1: 'Web', 2: 'DNS', 3: 'Email', 4: 'File Share', 5: 'VPN',
        6: 'Database', 7: 'Remote Access', 8: 'Streaming', 9: 'VoIP', 10: 'Backup',
        11: 'Management', 12: 'P2P', 13: 'ICMP'
    };
    var DIRECTION_LABELS = { 0: 'Unknown', 1: 'Inbound', 2: 'Outbound', 3: 'Internal', 4: 'External' };
    // Exporting protocol (FlowSample.flow_source; absent on the wire = 0 = sFlow).
    var SOURCE_LABELS = { 0: 'sFlow', 1: 'NetFlow v5', 2: 'NetFlow v9', 3: 'IPFIX' };
    // Firewall event (FlowSample.firewall_event, IE 233 — NSEL/FortiGate).
    // MIRRORS models.FirewallEvent* (documented stable). 3 (Denied) is the one
    // operators hunt; 0 means an ordinary forwarded-traffic record.
    var EVENT_LABELS = { 0: 'None', 1: 'Created', 2: 'Deleted', 3: 'Denied', 4: 'Alert', 5: 'Update' };
    var CATEGORY_IDS = invertLabels(CATEGORY_LABELS);
    var DIRECTION_IDS = invertLabels(DIRECTION_LABELS);

    function invertLabels(m) {
        var out = {};
        Object.keys(m).forEach(function(id) { out[m[id]] = id; });
        return out;
    }

    var state = Object.assign({}, DEFAULTS);
    var inited = false;
    var charts = { bandwidth: null };
    var lastBwData = null; // cached stats payload, so a theme/mode toggle can rebuild the chart without refetching
    var flowsBwView = 'rate'; // 3-mode bandwidth view: 'rate' | 'total' | 'mix' (matches public dashboard)
    var themeWired = false;
    var flowsOffset = 0;
    var reloadTimer = null;
    var statsTimer = null;

    // Console design token reader; uPlot axes are canvas-drawn from JS values
    // read fresh at each (re)build, including on Day/Night toggle.
    function cssVar(name, fallback) {
        try {
            if (window.AdminCommon && AdminCommon.cssVar) return AdminCommon.cssVar(name, fallback);
            var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (e) { return fallback; }
    }

    // ----------------------------------------------------------------------
    // Boot
    // ----------------------------------------------------------------------
    function init() {
        if (inited) {
            // Re-init is a no-op other than re-reading URL — the user may have
            // navigated via tab switch. Force a refresh anyway.
            stateFromURL();
            applyStateToControls();
            reload();
            return;
        }
        inited = true;
        stateFromURL();
        bindControls();
        applyStateToControls();
        reload();
        // Rebuild the bandwidth uPlot on Day/Night toggle (canvas axes can't
        // be restyled in place) from the cached payload — no refetch.
        if (!themeWired) {
            themeWired = true;
            window.addEventListener('fwmon:themechange', function() {
                if (lastBwData) renderBandwidth(lastBwData);
            });
        }
    }

    function stateFromURL() {
        try {
            var url = new URL(window.location.href);
            URL_KEYS.forEach(function(k) {
                var v = url.searchParams.get(k);
                if (v == null || v === '') return;
                if (k === 'hours') {
                    var n = parseFloat(v);
                    if (isFinite(n) && n > 0) state.hours = n;
                } else if (k === 'tab') {
                    if (v === 'conversations' || v === 'samples') state.tab = v;
                } else {
                    state[k] = v;
                }
            });
        } catch (e) { /* old browsers — fall back to defaults */ }
    }

    function syncURL() {
        try {
            var url = new URL(window.location.href);
            URL_KEYS.forEach(function(k) {
                var v = state[k];
                if (v === '' || v == null ||
                    (k === 'hours' && Number(v) === DEFAULTS.hours) ||
                    (k === 'tab' && v === DEFAULTS.tab)) {
                    url.searchParams.delete(k);
                } else {
                    url.searchParams.set(k, String(v));
                }
            });
            window.history.replaceState(null, '', url.toString());
        } catch (e) { /* swallow */ }
    }

    // ----------------------------------------------------------------------
    // Control wiring
    // ----------------------------------------------------------------------
    function bindControls() {
        // CSV export button (v0.10.216, bundle F4).
        var exportBtn = document.getElementById('flows-export-csv-btn');
        if (exportBtn && !exportBtn.__fwmonBound) {
            exportBtn.__fwmonBound = true;
            exportBtn.addEventListener('click', exportCsv);
        }

        // Range pills
        var rangePills = document.getElementById('flows-range-pills');
        if (rangePills) {
            rangePills.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('.chart-range-pill');
                if (!btn) return;
                var h = parseFloat(btn.getAttribute('data-range'));
                if (isFinite(h)) {
                    state.hours = h;
                    applyStateToControls();
                    syncURL();
                    reload();
                }
            });
        }

        // Protocol pills
        var protoPills = document.getElementById('flows-protocol-pills');
        if (protoPills) {
            protoPills.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('.chart-range-pill');
                if (!btn) return;
                state.protocol = btn.getAttribute('data-protocol') || '';
                applyStateToControls();
                syncURL();
                reload();
            });
        }

        // Site / device / probe / source selects — auto-apply on change
        bindSelectAuto('flows-filter-site',   'site_id');
        bindSelectAuto('flows-filter-device', 'device_id');
        bindSelectAuto('flows-filter-probe',  'probe_id');
        bindSelectAuto('flows-filter-source', 'source');
        bindSelectAuto('flows-filter-event',  'event');

        // IP / port inputs — debounced auto-apply on input, immediate on Enter/blur
        bindInputAuto('flows-filter-src',   'src',   400);
        bindInputAuto('flows-filter-dst',   'dst',   400);
        bindInputAuto('flows-filter-dport', 'dport', 400);

        // "Clear filters" button
        var clearBtn = document.getElementById('flows-clear-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                state.site_id   = '';
                state.device_id = '';
                state.probe_id  = '';
                state.protocol  = '';
                state.src = '';
                state.dst = '';
                state.dport = '';
                state.category = '';
                state.direction = '';
                state.country = '';
                state.asn = '';
                state.source = '';
                state.event = '';
                applyStateToControls();
                syncURL();
                reload();
            });
        }

        // Bandwidth chart 3-mode toggle (Throughput / Transfer / Combined).
        var bwView = document.getElementById('flows-bw-view');
        if (bwView) {
            bwView.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('[data-bw-view]');
                if (!btn) return;
                flowsBwView = btn.getAttribute('data-bw-view');
                var pills = bwView.querySelectorAll('[data-bw-view]');
                for (var i = 0; i < pills.length; i++) {
                    pills[i].classList.toggle('active', pills[i] === btn);
                }
                if (lastBwData) renderBandwidth(lastBwData);
            });
        }

        // "Load more" pagination
        var loadMore = document.getElementById('flows-load-more');
        if (loadMore) loadMore.addEventListener('click', loadMoreSamples);

        // Top-talker rows — event delegation. Each list rendered with
        // data-filter-key / data-filter-value attributes.
        ['flows-top-sources', 'flows-top-destinations',
         'flows-top-ports', 'flows-top-protocols',
         'flows-by-category', 'flows-by-direction',
         'flows-top-countries', 'flows-top-asns'].forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.addEventListener('click', onTopTalkerClick);
        });

        // Top conversations rows — event delegation
        var convTable = document.getElementById('flows-conversations-table');
        if (convTable) convTable.addEventListener('click', onConversationClick);

        // Detections panel — "Show" opens the detail modal (event delegation).
        var detBody = document.getElementById('flows-detections-body');
        if (detBody) detBody.addEventListener('click', onDetectionsShow);
        var detModal = document.getElementById('flow-detection-modal');
        if (detModal) detModal.addEventListener('click', onDetectionModalClick);

        // Threat Intelligence — add form + delete buttons (event delegation)
        var tiForm = document.getElementById('flows-ti-form');
        if (tiForm) tiForm.addEventListener('submit', onThreatIntelSubmit);
        var tiBody = document.getElementById('flows-ti-body');
        if (tiBody) tiBody.addEventListener('click', onThreatIntelDelete);

        // View tabs (Conversations / Flow Samples) — switching is pure show/hide;
        // both data sources are already fetched on every reload, so no re-fetch.
        var viewTabs = document.getElementById('flows-view-tabs');
        if (viewTabs) {
            viewTabs.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('.fwmon-flows-tab');
                if (!btn) return;
                setActiveTab(btn.getAttribute('data-flows-tab'));
            });
        }

        // Resize handler for the bandwidth chart
        if (typeof ResizeObserver !== 'undefined') {
            var host = document.getElementById('flows-bandwidth-chart');
            if (host) {
                var ro = new ResizeObserver(function(entries) {
                    if (!charts.bandwidth || !charts.bandwidth.setSize) return;
                    var r = entries[0] && entries[0].contentRect;
                    if (!r || r.width === 0) return;
                    charts.bandwidth.setSize({ width: Math.max(280, r.width), height: 240 });
                });
                ro.observe(host);
            }
        }
    }

    function bindSelectAuto(elId, stateKey) {
        var el = document.getElementById(elId);
        if (!el) return;
        el.addEventListener('change', function() {
            state[stateKey] = el.value || '';
            syncURL();
            reload();
        });
    }

    function bindInputAuto(elId, stateKey, debounceMs) {
        var el = document.getElementById(elId);
        if (!el) return;
        var pending = null;
        el.addEventListener('input', function() {
            if (pending) clearTimeout(pending);
            pending = setTimeout(function() {
                state[stateKey] = el.value.trim();
                syncURL();
                reload();
            }, debounceMs);
        });
        el.addEventListener('blur', function() {
            if (pending) { clearTimeout(pending); pending = null; }
            if (state[stateKey] !== el.value.trim()) {
                state[stateKey] = el.value.trim();
                syncURL();
                reload();
            }
        });
        el.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') {
                if (pending) { clearTimeout(pending); pending = null; }
                state[stateKey] = el.value.trim();
                syncURL();
                reload();
            }
        });
    }

    function applyStateToControls() {
        // Range pills
        var rangePills = document.querySelectorAll('#flows-range-pills .chart-range-pill');
        for (var i = 0; i < rangePills.length; i++) {
            var p = rangePills[i];
            var h = parseFloat(p.getAttribute('data-range'));
            p.classList.toggle('active', isFinite(h) && h === Number(state.hours));
        }
        // Protocol pills
        var protoPills = document.querySelectorAll('#flows-protocol-pills .chart-range-pill');
        for (var j = 0; j < protoPills.length; j++) {
            var pp = protoPills[j];
            pp.classList.toggle('active', pp.getAttribute('data-protocol') === state.protocol);
        }
        // Selects + inputs
        setVal('flows-filter-site',   state.site_id);
        setVal('flows-filter-device', state.device_id);
        setVal('flows-filter-probe',  state.probe_id);
        setVal('flows-filter-source', state.source);
        setVal('flows-filter-event',  state.event);
        setVal('flows-filter-src',    state.src);
        setVal('flows-filter-dst',    state.dst);
        setVal('flows-filter-dport',  state.dport);
        applyTabView();
        renderActiveChips();
    }

    // Toggle the active view of the combined data card. Both tables stay in the
    // DOM (already populated by the last reload); we just show/hide them and the
    // samples-only "Load more" row, and update the contextual hint.
    function setActiveTab(tab) {
        if (tab !== 'conversations' && tab !== 'samples') return;
        if (state.tab === tab) return;
        state.tab = tab;
        syncURL();
        applyTabView();
    }

    function applyTabView() {
        var tab = state.tab === 'samples' ? 'samples' : 'conversations';
        var tabs = document.querySelectorAll('#flows-view-tabs .fwmon-flows-tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle('active', tabs[i].getAttribute('data-flows-tab') === tab);
        }
        var convView = document.getElementById('flows-view-conversations');
        var sampView = document.getElementById('flows-view-samples');
        var loadMore = document.getElementById('flows-loadmore-row');
        if (convView) convView.hidden = (tab !== 'conversations');
        if (sampView) sampView.hidden = (tab !== 'samples');
        if (loadMore) loadMore.hidden = (tab !== 'samples');
        var hint = document.getElementById('flows-view-hint');
        if (hint) {
            hint.textContent = (tab === 'samples')
                ? 'raw flow records · newest first'
                : 'click a conversation to inspect its raw flows';
        }
    }

    function setVal(id, v) {
        var el = document.getElementById(id);
        if (el && el.value !== v) el.value = v || '';
    }

    function renderActiveChips() {
        var host = document.getElementById('flows-active-filter-chips');
        if (!host) return;
        var chips = [];
        if (state.src)       chips.push({ key: 'src',   val: state.src,   stateKey: 'src' });
        if (state.dst)       chips.push({ key: 'dst',   val: state.dst,   stateKey: 'dst' });
        if (state.dport)     chips.push({ key: 'dport', val: state.dport, stateKey: 'dport' });
        if (state.protocol)  chips.push({ key: 'proto', val: protocolName(state.protocol), stateKey: 'protocol' });
        if (state.category !== '')  chips.push({ key: 'app',       val: CATEGORY_LABELS[state.category]  || state.category,  stateKey: 'category' });
        if (state.direction !== '') chips.push({ key: 'direction', val: DIRECTION_LABELS[state.direction] || state.direction, stateKey: 'direction' });
        if (state.country)   chips.push({ key: 'country', val: state.country,         stateKey: 'country' });
        if (state.asn)       chips.push({ key: 'asn',     val: 'AS' + state.asn,       stateKey: 'asn' });
        if (state.source !== '') chips.push({ key: 'source', val: SOURCE_LABELS[state.source] || state.source, stateKey: 'source' });
        if (state.event !== '')  chips.push({ key: 'event',  val: EVENT_LABELS[state.event]   || state.event,  stateKey: 'event' });
        if (state.site_id)   chips.push({ key: 'site',   val: siteLabel(state.site_id),     stateKey: 'site_id' });
        if (state.device_id) chips.push({ key: 'device', val: deviceLabel(state.device_id), stateKey: 'device_id' });
        if (state.probe_id)  chips.push({ key: 'probe',  val: probeLabel(state.probe_id),   stateKey: 'probe_id' });

        if (chips.length === 0) { host.innerHTML = ''; return; }
        host.innerHTML = chips.map(function(c) {
            return '<span class="fwmon-flows-chip" data-stateKey="' + esc(c.stateKey) + '">' +
                '<span class="fwmon-flows-chip-key">' + esc(c.key) + '</span>' +
                '<span class="fwmon-flows-chip-val">' + esc(c.val) + '</span>' +
                '<button type="button" class="fwmon-flows-chip-clear" title="Clear filter">×</button>' +
            '</span>';
        }).join('');
        // Delegated click on the chip ×
        host.querySelectorAll('.fwmon-flows-chip-clear').forEach(function(btn) {
            btn.addEventListener('click', function(ev) {
                var chip = ev.target.closest('.fwmon-flows-chip');
                if (!chip) return;
                var k = chip.getAttribute('data-stateKey');
                if (k) {
                    state[k] = '';
                    applyStateToControls();
                    syncURL();
                    reload();
                }
            });
        });
    }

    // ----------------------------------------------------------------------
    // Reload — schedule a debounced fetch of /flows + /flows/stats
    // ----------------------------------------------------------------------
    function reload() {
        flowsOffset = 0;
        scheduleStats();
        scheduleSamples();
        loadDetections();
        loadThreatIntel();
    }

    function refresh() { reload(); }

    function scheduleStats() {
        if (statsTimer) clearTimeout(statsTimer);
        statsTimer = setTimeout(loadStats, 0);
    }
    function scheduleSamples() {
        if (reloadTimer) clearTimeout(reloadTimer);
        reloadTimer = setTimeout(loadSamples, 0);
    }

    function statsURL() {
        // Stats drives the aggregate views (top talkers, conversations, chart).
        // It honors the same filter set as the samples list so the shared filter
        // row narrows both tabs — except src_port, which rollups don't store.
        var params = ['hours=' + encodeURIComponent(state.hours)];
        if (state.site_id)   params.push('site_id='   + encodeURIComponent(state.site_id));
        if (state.device_id) params.push('device_id=' + encodeURIComponent(state.device_id));
        if (state.probe_id)  params.push('probe_id='  + encodeURIComponent(state.probe_id));
        if (state.protocol)  params.push('protocol='  + encodeURIComponent(state.protocol));
        if (state.src)       params.push('src_addr='  + encodeURIComponent(state.src));
        if (state.dst)       params.push('dst_addr='  + encodeURIComponent(state.dst));
        if (state.dport)     params.push('dst_port='  + encodeURIComponent(state.dport));
        if (state.category !== '')  params.push('app_category=' + encodeURIComponent(state.category));
        if (state.direction !== '') params.push('direction='   + encodeURIComponent(state.direction));
        if (state.country)   params.push('dst_country=' + encodeURIComponent(state.country));
        if (state.asn)       params.push('dst_asn='     + encodeURIComponent(state.asn));
        if (state.source !== '') params.push('flow_source=' + encodeURIComponent(state.source));
        if (state.event !== '')  params.push('firewall_event=' + encodeURIComponent(state.event));
        return '/admin/api/flows/stats?' + params.join('&');
    }

    function samplesURL(limit, offset) {
        var p = ['limit=' + limit];
        if (offset > 0) p.push('offset=' + offset);
        // hours bounds the samples list (and the CSV export) to the page's
        // range pills — without it the "24h" label lied and the list was just
        // "newest N rows regardless of range" (LC-36).
        if (state.hours) p.push('hours=' + encodeURIComponent(state.hours));
        if (state.site_id)   p.push('site_id='   + encodeURIComponent(state.site_id));
        if (state.device_id) p.push('device_id=' + encodeURIComponent(state.device_id));
        if (state.probe_id)  p.push('probe_id='  + encodeURIComponent(state.probe_id));
        if (state.protocol)  p.push('protocol='  + encodeURIComponent(state.protocol));
        if (state.src)       p.push('src_addr='  + encodeURIComponent(state.src));
        if (state.dst)       p.push('dst_addr='  + encodeURIComponent(state.dst));
        if (state.dport)     p.push('dst_port='  + encodeURIComponent(state.dport));
        if (state.category !== '')  p.push('app_category=' + encodeURIComponent(state.category));
        if (state.direction !== '') p.push('direction='   + encodeURIComponent(state.direction));
        if (state.country)   p.push('dst_country=' + encodeURIComponent(state.country));
        if (state.asn)       p.push('dst_asn='     + encodeURIComponent(state.asn));
        if (state.source !== '') p.push('flow_source=' + encodeURIComponent(state.source));
        if (state.event !== '')  p.push('firewall_event=' + encodeURIComponent(state.event));
        return '/admin/api/flows?' + p.join('&');
    }

    // ----------------------------------------------------------------------
    // Stats fetch → top-talkers, bandwidth chart, sampling chip, stat tiles
    // ----------------------------------------------------------------------
    function loadStats() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        showChartLoading();
        AC.apiFetch(statsURL()).then(function(result) {
            if (!result || !result.data) {
                showChartEmpty('No data');
                clearTopTalkers();
                return;
            }
            renderStats(result.data);
        }).catch(function(e) {
            console.error('FwmonFlows: stats fetch failed', e);
            showChartEmpty('Error');
            clearTopTalkers();
        });
    }

    function renderStats(d) {
        // Dual-export warning: devices reporting via BOTH sFlow and NetFlow
        // double-count every byte. Normally prevented by the collector's
        // PROBE_FLOW_DEDUP policy; this banner covers dedup=off and
        // multi-collector splits.
        var mixedBar = document.getElementById('flows-mixed-source-warning');
        if (mixedBar) {
            var mixed = d.mixed_source_devices || [];
            if (mixed.length > 0) {
                var esc = (window.AdminCommon && AdminCommon.escapeHtml) || function(s) { return s; };
                mixedBar.hidden = false;
                mixedBar.innerHTML = '⚠ ' + mixed.map(function(n) { return '<strong>' + esc(n) + '</strong>'; }).join(', ') +
                    (mixed.length === 1 ? ' is' : ' are') +
                    ' reporting flows via both sFlow and NetFlow — byte totals may be double-counted. Prefer one flow protocol per device (see SUPPORT-MATRIX).';
            } else {
                mixedBar.hidden = true;
            }
        }

        // Stat tiles
        setText('flows-total',      (d.total_flows || 0).toLocaleString());
        setText('flows-bytes',      formatBytes(d.total_bytes || 0));
        setText('flows-throughput', formatBps(d.bits_per_second || 0));
        setText('flows-packets',    (d.total_packets || 0).toLocaleString());
        var us = (d.unique_sources || 0).toLocaleString();
        var ud = (d.unique_dests   || 0).toLocaleString();
        setText('flows-fanout',     us + ' / ' + ud);
        setText('flows-protocols',  (d.protocol_count || 0).toLocaleString());

        // Sampling chip
        var samplingValue = document.getElementById('flows-sampling-rate-chip');
        if (samplingValue) {
            var r = d.avg_sampling_rate || 0;
            samplingValue.textContent = r > 1 ? '1:' + Math.round(r) : '1:1';
        }

        // Local-traffic notice
        var localBar = document.getElementById('flows-local-traffic-bar');
        if (localBar && d.local_traffic && d.local_traffic.bytes > 0) {
            localBar.hidden = false;
            setText('flows-local-bytes',   formatBytes(d.local_traffic.bytes));
            setText('flows-local-flows',   (d.local_traffic.flows || 0).toLocaleString());
            setText('flows-local-packets', (d.local_traffic.packets || 0).toLocaleString());
        } else if (localBar) {
            localBar.hidden = true;
        }

        // Bandwidth chart
        renderBandwidth(d);

        // Top talkers
        renderTopTalkers(d);
    }

    // ----------------------------------------------------------------------
    // Detections panel — good-vs-bad traffic findings (sFlow detection engine)
    // ----------------------------------------------------------------------
    function loadDetections() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        var url = '/admin/api/flows/detections?unacked=true&limit=100&hours=' + encodeURIComponent(state.hours);
        AC.apiFetch(url).then(function(result) {
            renderDetections((result && result.data) || []);
        }).catch(function(e) {
            console.error('FwmonFlows: detections fetch failed', e);
        });
    }

    var SEV_RANK = { critical: 0, warning: 1, info: 2 };
    // Full detection rows keyed by id, so the "Show" detail view has everything
    // without a re-fetch.
    var detById = {};

    function renderDetections(rows) {
        var card = document.getElementById('flows-detections-card');
        var body = document.getElementById('flows-detections-body');
        if (!card || !body) return;
        if (!rows.length) { card.hidden = true; body.innerHTML = ''; return; }
        // Most severe, then newest, first.
        rows.sort(function(a, b) {
            var ra = SEV_RANK[a.severity] != null ? SEV_RANK[a.severity] : 9;
            var rb = SEV_RANK[b.severity] != null ? SEV_RANK[b.severity] : 9;
            if (ra !== rb) return ra - rb;
            return new Date(b.detected_at) - new Date(a.detected_at);
        });
        detById = {};
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            detById[r.id] = r;
            var sev = r.severity || 'info';
            html += '<tr>' +
                '<td><span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span></td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td><code>' + esc(r.detector || '') + '</code></td>' +
                '<td>' + esc(r.message || '') + '</td>' +
                '<td title="' + esc(r.detected_at || '') + '">' + esc(detAgo(r.detected_at)) + '</td>' +
                '<td><button type="button" class="fwmon-det-show" data-det-id="' + esc(r.id) + '">Show</button></td>' +
            '</tr>';
        }
        body.innerHTML = html;
        card.hidden = false;
    }

    // detAgo formats an ISO timestamp as a compact relative age.
    function detAgo(iso) {
        if (!iso) return '';
        var t = new Date(iso).getTime();
        if (!isFinite(t)) return '';
        var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
        if (s < 60) return s + 's ago';
        if (s < 3600) return Math.floor(s / 60) + 'm ago';
        if (s < 86400) return Math.floor(s / 3600) + 'h ago';
        return Math.floor(s / 86400) + 'd ago';
    }

    // onDetectionsShow opens the unified detail view for a detection (the "Show"
    // button replaced the old inline Ack — acknowledging now lives inside the
    // detail modal, alongside the sampled-flow context).
    function onDetectionsShow(ev) {
        var btn = ev.target && ev.target.closest && ev.target.closest('.fwmon-det-show');
        if (!btn) return;
        showDetectionDetail(btn.getAttribute('data-det-id'));
    }

    // showDetectionDetail maps a detection + the sampled flows that triggered it
    // (and a link to the escalated alert, if any) into one modal.
    function showDetectionDetail(id) {
        var AC = window.AdminCommon;
        var r = detById[id];
        var body = document.getElementById('flow-detection-body');
        if (!r || !AC || !body) return;

        var sev = r.severity || 'info';
        var route = esc(r.src_addr || '?') +
            (r.dst_addr ? ' → ' + esc(r.dst_addr) : '') +
            (r.dst_port ? ':' + esc(String(r.dst_port)) : '');
        var detailsHtml = '';
        try {
            if (r.details) {
                var d = JSON.parse(r.details);
                detailsHtml = Object.keys(d).map(function(k) {
                    return '<div><span style="color:var(--fwmon-text-faint);">' + esc(k) + ':</span> ' + esc(String(d[k])) + '</div>';
                }).join('');
            }
        } catch (e) { /* details is best-effort */ }
        var alertHtml = r.alert_id
            ? '<a href="#alert/' + esc(String(r.alert_id)) + '" data-action="close-flow-detection" style="color:#58a6ff;">View alert #' + esc(String(r.alert_id)) + ' ↗</a>'
            : '<span style="color:var(--fwmon-text-faint);">not escalated to an alert</span>';

        body.innerHTML =
            '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px 16px;margin-bottom:12px;">' +
                '<div><span style="color:var(--fwmon-text-faint);">Severity:</span> <span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span></div>' +
                '<div><span style="color:var(--fwmon-text-faint);">Detector:</span> <code>' + esc(r.detector || '') + '</code></div>' +
                '<div><span style="color:var(--fwmon-text-faint);">Category:</span> ' + esc(r.category || '') + '</div>' +
                '<div><span style="color:var(--fwmon-text-faint);">When:</span> ' + esc(formatDate(r.detected_at)) + '</div>' +
                '<div><span style="color:var(--fwmon-text-faint);">Flow:</span> <span style="font-family:monospace;">' + route + '</span></div>' +
                '<div><span style="color:var(--fwmon-text-faint);">Alert:</span> ' + alertHtml + '</div>' +
            '</div>' +
            '<div style="margin-bottom:12px;"><span style="color:var(--fwmon-text-faint);">Message:</span> ' + esc(r.message || '') + '</div>' +
            (detailsHtml ? '<div style="background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:6px;padding:10px;margin-bottom:12px;font-family:monospace;font-size:0.82rem;">' + detailsHtml + '</div>' : '') +
            '<div style="color:var(--fwmon-text-faint);text-transform:uppercase;font-size:0.72rem;letter-spacing:0.04em;margin-bottom:6px;">Sampled flows</div>' +
            '<div id="flow-detection-samples" style="max-height:40vh;overflow:auto;">Loading…</div>' +
            '<div style="margin-top:14px;"><button type="button" class="btn sm" data-det-ack="' + esc(String(r.id)) + '">Acknowledge &amp; dismiss</button></div>';

        AC.openModal('flow-detection-modal');
        loadDetectionSamples(r);
    }

    // loadDetectionSamples fetches the raw sFlow samples behind a detection and
    // renders them with country flag + ASN owner, inside the detail modal.
    function loadDetectionSamples(r) {
        var AC = window.AdminCommon;
        var hours = Math.max(1, state.hours || 24);
        var q = '/admin/api/flows/samples?limit=50&hours=' + encodeURIComponent(hours);
        if (r.src_addr) q += '&src_addr=' + encodeURIComponent(r.src_addr);
        if (r.dst_addr) q += '&dst_addr=' + encodeURIComponent(r.dst_addr);
        if (r.dst_port) q += '&dst_port=' + encodeURIComponent(r.dst_port);
        AC.apiFetch(q).then(function(res) {
            var samples = (res && res.data) || [];
            var el = document.getElementById('flow-detection-samples');
            if (!el) return;
            if (!samples.length) {
                el.innerHTML = '<div style="color:var(--fwmon-text-faint);">No matching samples in the last ' + hours + 'h.</div>';
                return;
            }
            var rowsHtml = samples.map(function(f) {
                return '<tr>' +
                    '<td>' + esc(formatDate(f.timestamp)) + '</td>' +
                    '<td style="white-space:nowrap;">' + flagEmoji(f.src_country) + esc(f.src_addr) + ':' + esc(String(f.src_port)) + asnChip(f.src_asn, f.src_asn_org) + '</td>' +
                    '<td style="white-space:nowrap;">' + flagEmoji(f.dst_country) + esc(f.dst_addr) + ':' + esc(String(f.dst_port)) + asnChip(f.dst_asn, f.dst_asn_org) + '</td>' +
                    '<td>' + esc(protocolName(f.protocol)) + '</td>' +
                    '<td class="num">' + formatBytes(f.bytes) + '</td>' +
                    '<td class="num">' + (f.packets || 0).toLocaleString() + '</td>' +
                '</tr>';
            }).join('');
            el.innerHTML = '<table class="fwmon-table"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Bytes</th><th>Pkts</th></tr></thead><tbody>' + rowsHtml + '</tbody></table>';
        }).catch(function(e) {
            console.error('FwmonFlows: detection samples fetch failed', e);
            var el = document.getElementById('flow-detection-samples');
            if (el) el.innerHTML = '<div style="color:var(--fwmon-text-faint);">Failed to load samples.</div>';
        });
    }

    // onDetectionModalClick handles the in-modal Close and Acknowledge actions.
    function onDetectionModalClick(ev) {
        var AC = window.AdminCommon;
        if (!AC) return;
        if (ev.target.closest('[data-action="close-flow-detection"]')) {
            AC.closeModal('flow-detection-modal');
            return;
        }
        var ackBtn = ev.target.closest('[data-det-ack]');
        if (ackBtn) {
            var id = ackBtn.getAttribute('data-det-ack');
            ackBtn.disabled = true;
            AC.apiFetch('/admin/api/flows/detections/' + encodeURIComponent(id) + '/ack', { method: 'POST' })
                .then(function() { AC.closeModal('flow-detection-modal'); loadDetections(); })
                .catch(function(e) {
                    console.error('FwmonFlows: ack failed', e);
                    ackBtn.disabled = false;
                });
        }
    }

    // ----------------------------------------------------------------------
    // Threat Intelligence — manage the known-bad address feed (CIDR/IP)
    // ----------------------------------------------------------------------
    function loadThreatIntel() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        AC.apiFetch('/admin/api/flows/threat-intel?limit=500').then(function(result) {
            renderThreatIntel((result && result.data) || {});
        }).catch(function(e) {
            window.fwmonLog.error('FwmonFlows: threat-intel fetch failed', e);
        });
    }

    function renderThreatIntel(d) {
        var statusEl = document.getElementById('flows-ti-status');
        var body = document.getElementById('flows-ti-body');
        var rows = (d && d.entries) || [];
        if (statusEl) {
            var active = (d && d.active_count) || 0;
            var loaded = (d && d.loaded_count) || 0;
            if (d && d.feeds_enabled === false && active === 0) {
                statusEl.textContent = 'online feeds disabled — set THREAT_FEEDS_ENABLED=true (manual entries still work)';
            } else {
                statusEl.textContent = active + ' active · ' + loaded + ' loaded in matcher';
            }
        }
        if (!body) return;
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="6" class="fwmon-ti-empty">No entries. Add a CIDR/IP above to start flagging known-bad traffic.</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            var sev = r.severity || 'warning';
            html += '<tr>' +
                '<td><code>' + esc(r.cidr || '') + '</code></td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td>' + esc(r.source || '') + '</td>' +
                '<td><span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span></td>' +
                '<td title="' + esc(r.expires_at || '') + '">' + esc(tiExpiry(r.expires_at)) + '</td>' +
                '<td><button type="button" class="fwmon-det-ack fwmon-ti-del" data-ti-id="' + esc(r.id) + '">Delete</button></td>' +
            '</tr>';
        }
        body.innerHTML = html;
    }

    // tiExpiry formats the expiry as a short date, or "never" when unset.
    function tiExpiry(iso) {
        if (!iso) return 'never';
        var t = new Date(iso);
        if (isNaN(t.getTime())) return 'never';
        return t.toISOString().slice(0, 10);
    }

    function onThreatIntelSubmit(ev) {
        ev.preventDefault();
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        var errEl = document.getElementById('flows-ti-error');
        var btn = document.getElementById('ti-add-btn');
        var cidr = (val('ti-cidr') || '').trim();
        if (!cidr) return;
        var body = {
            cidr: cidr,
            category: val('ti-category'),
            severity: val('ti-severity'),
            source: (val('ti-source') || '').trim() || 'manual'
        };
        var exp = val('ti-expires');
        if (exp) {
            var d = new Date(exp + 'T00:00:00Z');
            if (!isNaN(d.getTime())) body.expires_at = d.toISOString();
        }
        if (errEl) { errEl.hidden = true; errEl.textContent = ''; }
        if (btn) btn.disabled = true;
        AC.apiFetch('/admin/api/flows/threat-intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        }).then(function() {
            var f = document.getElementById('ti-cidr'); if (f) f.value = '';
            var s = document.getElementById('ti-source'); if (s) s.value = '';
            var e = document.getElementById('ti-expires'); if (e) e.value = '';
            loadThreatIntel();
        }).catch(function(err) {
            if (errEl) {
                errEl.textContent = (err && err.message) ? err.message : 'Failed to add entry — check the CIDR/IP.';
                errEl.hidden = false;
            }
        }).then(function() {
            if (btn) btn.disabled = false;
        });
    }

    // val reads an input/select value by element id.
    function val(id) {
        var el = document.getElementById(id);
        return el ? el.value : '';
    }

    function onThreatIntelDelete(ev) {
        var btn = ev.target && ev.target.closest && ev.target.closest('.fwmon-ti-del');
        if (!btn) return;
        var id = btn.getAttribute('data-ti-id');
        if (!id) return;
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        btn.disabled = true;
        AC.apiFetch('/admin/api/flows/threat-intel/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function() { loadThreatIntel(); })
            .catch(function(e) {
                window.fwmonLog.error('FwmonFlows: threat-intel delete failed', e);
                btn.disabled = false;
            });
    }

    // ----------------------------------------------------------------------
    // Bandwidth chart (uPlot)
    // ----------------------------------------------------------------------
    // renderBandwidth draws the flows throughput chart with the shared 3-mode
    // component (FwmonBwChart), matching the public dashboard: Throughput (Mbps
    // line), Transfer (bytes/bucket bars), Combined. Flow traffic is a single
    // bidirectional aggregate, so it's rendered as one "Traffic" series (no
    // RX/TX split). bytes_over_time.count is a per-bucket SUM (already a rate
    // when divided by the bucket interval) — it does not accumulate.
    function renderBandwidth(d) {
        var host = document.getElementById('flows-bandwidth-chart');
        if (!host) return;
        if (typeof FwmonBwChart === 'undefined' || typeof Chart === 'undefined') {
            showChartEmpty('chart library unavailable');
            return;
        }
        var points = d.bytes_over_time || [];
        if (!points.length) {
            if (charts.bandwidth) { charts.bandwidth.destroy(); charts.bandwidth = null; }
            lastBwData = null; // don't let a theme toggle redraw the prior filter's chart (audit L21)
            host.innerHTML = '<div class="chart-empty">No traffic in this range</div>';
            return;
        }
        // A prior empty-state replaced the canvas with a message div — restore it.
        var canvas = document.getElementById('flows-bandwidth-canvas');
        if (!canvas) {
            host.innerHTML = '<canvas id="flows-bandwidth-canvas"></canvas>';
            canvas = document.getElementById('flows-bandwidth-canvas');
        }

        var intervalSec = d.bucket_seconds || 3600;
        var labels = [], rate = [], transfer = [];
        for (var i = 0; i < points.length; i++) {
            labels.push(bwLabel(points[i].bucket));
            transfer.push(points[i].count);                        // bytes / bucket
            rate.push((points[i].count * 8) / intervalSec / 1e6);  // Mbps
        }

        lastBwData = d; // remember for instant rebuild on mode/theme toggle
        if (charts.bandwidth) { charts.bandwidth.destroy(); charts.bandwidth = null; }
        charts.bandwidth = FwmonBwChart.render(canvas, {
            labels: labels,
            rxRate: rate,
            rxTransfer: transfer,
            rxLabel: 'Traffic',
            view: flowsBwView
        });
    }

    // bwLabel formats a bytes_over_time bucket string into a compact x-axis label.
    function bwLabel(bucket) {
        var ms = parseBucketToMs(bucket);
        if (!ms) return String(bucket);
        var dt = new Date(ms);
        return dt.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    function showChartLoading() {
        var host = document.getElementById('flows-bandwidth-chart');
        if (host && !charts.bandwidth) {
            host.innerHTML = '<div class="chart-loading">loading…</div>';
        }
    }
    function showChartEmpty(msg) {
        // Tear down any live chart + cached data before replacing the host
        // innerHTML: the replacement orphans the canvas, so a surviving
        // charts.bandwidth instance leaks, and a stale lastBwData would let a
        // theme/mode toggle redraw the previous filter's chart over this empty
        // state (audit L21).
        if (charts.bandwidth) { charts.bandwidth.destroy(); charts.bandwidth = null; }
        lastBwData = null;
        var host = document.getElementById('flows-bandwidth-chart');
        if (host) host.innerHTML = '<div class="chart-empty">' + esc(msg) + '</div>';
    }

    // ----------------------------------------------------------------------
    // Top-talker lists
    // ----------------------------------------------------------------------
    function renderTopTalkers(d) {
        renderList('flows-top-sources',      d.top_sources      || [], 'sources',   'src',      function(v) { return v; });
        renderList('flows-top-destinations', d.top_destinations || [], 'dests',     'dst',      function(v) { return v; });
        renderList('flows-top-ports',        d.top_ports        || [], 'ports',     'dport',    function(v) { return v; });
        renderList('flows-top-protocols',    d.by_protocol      || [], 'protocols', 'protocol', protocolNumber);
        // Classification breakdowns — ingest-time app/L7 category and direction.
        // Counts are flow counts (formatCount). Click-to-filter: the widgets show
        // labels but filter by the numeric id the backend stores, so toFilterValue
        // maps the clicked label -> id.
        renderList('flows-by-category',  d.by_category  || [], 'category',  'category',  function(label) { return CATEGORY_IDS[label] || ''; }, formatCount);
        renderList('flows-by-direction', d.by_direction || [], 'direction', 'direction', function(label) { return DIRECTION_IDS[label] || ''; }, formatCount);
        // Geo/ASN breakdowns (v0.10.506) — byte-valued, destination-oriented,
        // click-to-filter (country code / ASN number). The cards stay hidden
        // unless GeoIP enrichment produced data, so deployments without GeoLite2
        // don't see empty widgets.
        // Country rows display the ISO code, which is also the filter value.
        renderGeoCard('flows-card-countries', 'flows-top-countries', d.top_countries || [], 'countries', 'country', function(label) { return label; }, d.geo_enabled, d.geo_source);
        // ASN rows display "AS15169"; the filter value is the bare number.
        renderGeoCard('flows-card-asns', 'flows-top-asns', d.top_asns || [], 'asns', 'asn', function(label) { return String(label).replace(/^AS/i, ''); }, d.geo_enabled, d.geo_source);
    }

    // renderGeoCard renders the clickable byte-valued bar list. Instead of hiding
    // silently when empty (which made geo look "not built"), it always shows the
    // card and explains WHY it's empty: geo disabled, or enabled-but-no-data-yet.
    function renderGeoCard(cardId, listId, rows, colorTag, stateKey, toFilterValue, geoEnabled, geoSource) {
        var card = document.getElementById(cardId);
        var list = document.getElementById(listId);
        var has = rows && rows.length > 0;
        if (card) card.hidden = false;
        if (has) {
            renderList(listId, rows, colorTag, stateKey, toFilterValue);
        } else if (list) {
            var msg = geoEnabled === false
                ? 'GeoIP disabled — set GEOIP_ENABLED=true'
                : ('no geo data yet' + (geoSource ? ' · ' + geoSource : ''));
            list.innerHTML = '<li class="fwmon-toptalk-empty">' + msg + '</li>';
        }
    }

    function clearTopTalkers() {
        ['flows-top-sources', 'flows-top-destinations',
         'flows-top-ports', 'flows-top-protocols',
         'flows-by-category', 'flows-by-direction'].forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.innerHTML = '<li class="fwmon-toptalk-empty">No data</li>';
        });
        // Geo cards stay visible with a placeholder (they're no longer hidden on
        // empty — see renderGeoCard); reset their lists to "No data" on clear.
        ['flows-top-countries', 'flows-top-asns'].forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.innerHTML = '<li class="fwmon-toptalk-empty">No data</li>';
        });
    }

    // formatCount renders a flow count compactly (1234 -> "1.2k", 12 -> "12").
    function formatCount(n) {
        n = Number(n) || 0;
        if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
        return String(n);
    }

    // renderList renders a horizontal-bar list. When stateKey is falsy the rows
    // are non-clickable (no data-filter-key, so onTopTalkerClick ignores them)
    // and never marked active. valueFmt formats the per-row value (defaults to
    // formatBytes for the byte-valued top-talker lists).
    function renderList(elId, rows, colorTag, stateKey, toFilterValue, valueFmt) {
        var el = document.getElementById(elId);
        if (!el) return;
        var fmt = valueFmt || formatBytes;
        var clickable = !!stateKey;
        el.setAttribute('data-color', colorTag);
        if (!rows.length) {
            el.innerHTML = '<li class="fwmon-toptalk-empty">No data</li>';
            return;
        }
        var max = 0;
        for (var i = 0; i < rows.length; i++) { if (rows[i].count > max) max = rows[i].count; }
        if (max === 0) max = 1;
        var html = '';
        for (var j = 0; j < rows.length; j++) {
            var r = rows[j];
            var pct = (r.count / max) * 100;
            var attrs = '';
            var activeCls = '';
            if (clickable) {
                var filterVal = toFilterValue(r.key);
                if (String(state[stateKey]) === String(filterVal)) activeCls = ' active';
                attrs = ' data-filter-key="' + esc(stateKey) +
                        '" data-filter-value="' + esc(filterVal) + '"';
            }
            html += '<li class="fwmon-toptalk-row' + activeCls + '"' + attrs +
                ' style="--bar-pct:' + pct.toFixed(1) + '%">' +
                '<span class="fwmon-toptalk-row-label" title="' + esc(r.key) + '">' + esc(r.key) + '</span>' +
                '<span class="fwmon-toptalk-row-value">' + fmt(r.count) + '</span>' +
                '<span class="fwmon-toptalk-row-bar"></span>' +
            '</li>';
        }
        el.innerHTML = html;
    }

    function onTopTalkerClick(ev) {
        var row = ev.target && ev.target.closest && ev.target.closest('.fwmon-toptalk-row');
        if (!row) return;
        var k = row.getAttribute('data-filter-key');
        var v = row.getAttribute('data-filter-value');
        if (!k) return;
        // Toggle: clicking the active row clears the filter.
        if (String(state[k]) === String(v)) {
            state[k] = '';
        } else {
            state[k] = v;
        }
        applyStateToControls();
        syncURL();
        reload();
    }

    function onConversationClick(ev) {
        var row = ev.target && ev.target.closest && ev.target.closest('tr.fwmon-clickable');
        if (!row) return;
        var src   = row.getAttribute('data-src') || '';
        var dst   = row.getAttribute('data-dst') || '';
        var dport = row.getAttribute('data-dport') || '';
        state.src = src;
        state.dst = dst;
        state.dport = dport;
        // Drill-down: jump to the Samples view so the operator immediately sees
        // the raw flows for the conversation they clicked.
        state.tab = 'samples';
        applyStateToControls();
        syncURL();
        reload();
    }

    // ----------------------------------------------------------------------
    // Samples table (paginated raw FlowSample rows)
    // ----------------------------------------------------------------------
    function loadSamples() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        AC.apiFetch(samplesURL(100, 0)).then(function(result) {
            if (!result) return;
            var samples = result.data || [];
            renderSamples(samples, false);
            flowsOffset = samples.length;
            updateLoadedCount();
            renderConversations(); // re-renders existing conversation rows with current click target
        }).catch(function(e) {
            console.error('FwmonFlows: samples fetch failed', e);
        });
    }

    function loadMoreSamples() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        AC.apiFetch(samplesURL(100, flowsOffset)).then(function(result) {
            if (!result || !result.data) return;
            var samples = result.data || [];
            renderSamples(samples, true);
            flowsOffset += samples.length;
            updateLoadedCount();
        }).catch(function(e) {
            console.error('FwmonFlows: load-more failed', e);
        });
    }

    /* ------------------------------------------------------------------
     * CSV export (v0.10.216, bundle F4).
     *
     * Pulls every flow row that matches the current filter state INCLUDING
     * the selected time range (samplesURL sends hours, LC-36) — up to
     * a hard cap of EXPORT_MAX rows — and triggers a browser download
     * with the operator's filter signature in the filename so successive
     * exports don't overwrite each other in the Downloads folder.
     *
     * We export server-fetched rows rather than just the currently-loaded
     * page because operators usually want "the whole filtered slice", not
     * "what's on screen right now". Capped at EXPORT_MAX to bound memory
     * (very wide ranges can return tens of thousands of rows; at 50 KB/row
     * average that's a few MB — acceptable but worth a hard ceiling).
     * ------------------------------------------------------------------ */
    var EXPORT_MAX = 10000;

    function exportCsv() {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return;
        var btn = document.getElementById('flows-export-csv-btn');
        if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }
        AC.apiFetch(samplesURL(EXPORT_MAX, 0)).then(function(result) {
            var samples = (result && result.data) || [];
            if (samples.length === 0) {
                if (AC.showError) AC.showError('No flow samples to export');
                return;
            }
            var headers = ['timestamp', 'src_addr', 'src_port', 'dst_addr', 'dst_port',
                           'protocol', 'protocol_name', 'flow_source', 'firewall_event', 'bytes', 'packets', 'sampling_rate',
                           'device_id', 'probe_id', 'sampler_address',
                           'src_country', 'dst_country', 'src_asn', 'src_asn_org', 'dst_asn', 'dst_asn_org'];
            var lines = [headers.join(',')];
            for (var i = 0; i < samples.length; i++) {
                var f = samples[i];
                var row = [
                    csvField(f.timestamp),
                    csvField(f.src_addr),
                    f.src_port == null ? '' : f.src_port,
                    csvField(f.dst_addr),
                    f.dst_port == null ? '' : f.dst_port,
                    f.protocol == null ? '' : f.protocol,
                    csvField(protocolName(f.protocol)),
                    csvField(SOURCE_LABELS[f.flow_source || 0] || ''),
                    csvField(EVENT_LABELS[f.firewall_event || 0] || ''),
                    f.bytes == null ? '' : f.bytes,
                    f.packets == null ? '' : f.packets,
                    f.sampling_rate == null ? '' : f.sampling_rate,
                    f.device_id == null ? '' : f.device_id,
                    f.probe_id == null ? '' : f.probe_id,
                    csvField(f.sampler_address),
                    csvField(f.src_country),
                    csvField(f.dst_country),
                    f.src_asn == null ? '' : f.src_asn,
                    csvField(f.src_asn_org),
                    f.dst_asn == null ? '' : f.dst_asn,
                    csvField(f.dst_asn_org)
                ];
                lines.push(row.join(','));
            }
            var csv = lines.join('\r\n') + '\r\n';
            var ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            var sig = filterSignature();
            var filename = 'flows-' + ts + (sig ? '-' + sig : '') + '.csv';
            triggerCsvDownload(csv, filename);

            if (samples.length >= EXPORT_MAX && AC.showError) {
                AC.showError('Export capped at ' + EXPORT_MAX.toLocaleString() +
                             ' rows — refine the filter for the full set.');
            }
        }).catch(function(e) {
            console.error('FwmonFlows: csv export failed', e);
            if (AC.showError) AC.showError('Export failed: ' + (e.message || 'unknown'));
        }).finally(function() {
            if (btn) { btn.disabled = false; btn.textContent = 'Export CSV'; }
        });
    }

    // RFC 4180-ish escaping: wrap in quotes if the field contains a
    // comma / quote / CR / LF, and double up any embedded quotes.
    function csvField(v) {
        if (v == null) return '';
        var s = String(v);
        if (s.indexOf(',') === -1 && s.indexOf('"') === -1 &&
            s.indexOf('\r') === -1 && s.indexOf('\n') === -1) {
            return s;
        }
        return '"' + s.replace(/"/g, '""') + '"';
    }

    // Filter signature for the filename — encodes the most distinctive
    // filter so successive exports don't clobber each other. Best-effort,
    // not bulletproof.
    function filterSignature() {
        var bits = [];
        if (state.hours)     bits.push(state.hours + 'h');
        if (state.device_id) bits.push('dev' + state.device_id);
        if (state.probe_id)  bits.push('probe' + state.probe_id);
        if (state.protocol)  bits.push('proto' + state.protocol);
        if (state.src)       bits.push('src-' + state.src.replace(/[^a-z0-9._-]/gi, ''));
        if (state.dst)       bits.push('dst-' + state.dst.replace(/[^a-z0-9._-]/gi, ''));
        if (state.dport)     bits.push('port' + state.dport);
        if (state.source !== '') bits.push('src' + state.source);
        if (state.event !== '')  bits.push('evt' + state.event);
        return bits.join('-');
    }

    function triggerCsvDownload(content, filename) {
        var blob = new Blob([content], { type: 'text/csv;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Defer revoke so Safari has time to start the download.
        setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
    }

    // flagEmoji renders the regional-indicator flag for a 2-letter ISO country
    // code plus the code itself. Empty for missing/private (no geo) addresses.
    function flagEmoji(cc) {
        if (!cc || cc.length !== 2) return '';
        cc = cc.toUpperCase();
        var a = cc.charCodeAt(0), b = cc.charCodeAt(1);
        if (a < 65 || a > 90 || b < 65 || b > 90) return '';
        return '<span title="' + esc(cc) + '" style="margin-right:4px;">' +
            String.fromCodePoint(0x1F1E6 + (a - 65), 0x1F1E6 + (b - 65)) + '</span>' +
            '<span style="color:var(--fwmon-text-faint);font-size:0.7rem;margin-right:4px;">' + esc(cc) + '</span>';
    }

    // asnChip renders an ASN as a small chip whose hover tooltip reveals the owner
    // company/org name (when known from the geo DB).
    function asnChip(asn, org) {
        if (!asn) return '';
        var title = org ? (org + ' (AS' + asn + ')') : ('AS' + asn);
        return ' <span title="' + esc(title) + '" style="cursor:help;color:#58a6ff;font-size:0.7rem;border:1px solid #30363d;border-radius:6px;padding:0 4px;margin-left:4px;">AS' + esc(String(asn)) + '</span>';
    }

    function renderSamples(samples, append) {
        var tbody = document.querySelector('#flows-table tbody');
        if (!tbody) return;
        var html = samples.map(function(f) {
            return '<tr>' +
                '<td>' + esc(formatDate(f.timestamp)) + '</td>' +
                '<td style="white-space:nowrap;">' + flagEmoji(f.src_country) + esc(f.src_addr) + ':' + f.src_port + asnChip(f.src_asn, f.src_asn_org) + '</td>' +
                '<td>→</td>' +
                '<td style="white-space:nowrap;">' + flagEmoji(f.dst_country) + esc(f.dst_addr) + ':' + f.dst_port + asnChip(f.dst_asn, f.dst_asn_org) + '</td>' +
                '<td>' + esc(protocolName(f.protocol)) + '</td>' +
                '<td>' + esc(SOURCE_LABELS[f.flow_source || 0] || '—') + '</td>' +
                // Event column: only NSEL/FortiGate event records carry IE 233;
                // plain forwarded-traffic rows (0) render as an em dash.
                '<td>' + (f.firewall_event ? esc(EVENT_LABELS[f.firewall_event] || f.firewall_event) : '—') + '</td>' +
                '<td class="num">' + formatBytes(f.bytes) + '</td>' +
                '<td class="num">' + (f.packets || 0).toLocaleString() + '</td>' +
                '<td class="num">' + (f.sampling_rate ? '1:' + f.sampling_rate : '—') + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="10" class="empty-state">No flow samples match these filters</td></tr>';
    }

    function updateLoadedCount() {
        var el = document.getElementById('flows-loaded-count');
        if (el) el.textContent = flowsOffset.toLocaleString() + ' loaded';
    }

    function renderConversations() {
        // Conversations come from stats; re-render is triggered by stats fetch.
        // This stub is a placeholder for any future post-samples reconciliation.
    }

    // ----------------------------------------------------------------------
    // Top conversations table (rendered from stats payload)
    //
    // Hooked into renderStats — append rows with click targets for src+dst+port.
    // ----------------------------------------------------------------------
    var originalRenderStats = renderStats;
    renderStats = function(d) {
        originalRenderStats(d);
        var tbody = document.querySelector('#flows-conversations-table tbody');
        if (!tbody) return;
        var total = d.total_bytes || 1;
        var convos = d.top_conversations || [];
        if (!convos.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No conversations</td></tr>';
            return;
        }
        tbody.innerHTML = convos.map(function(c) {
            var pct = ((c.bytes / total) * 100).toFixed(1);
            return '<tr class="fwmon-clickable" data-src="' + esc(c.src_addr) +
                '" data-dst="' + esc(c.dst_addr) +
                '" data-dport="' + esc(String(c.dst_port || '')) + '">' +
                '<td>' + esc(c.src_addr) + '</td>' +
                '<td>→</td>' +
                '<td>' + esc(c.dst_addr) + ':' + (c.dst_port || '0') + '</td>' +
                '<td>' + esc(c.protocol) + '</td>' +
                '<td class="num">' + formatBytes(c.bytes) + '</td>' +
                '<td class="num">' + (c.packets || 0).toLocaleString() + '</td>' +
                '<td class="num">' + pct + '%</td>' +
            '</tr>';
        }).join('');
    };

    // ----------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------
    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // Bucket strings come from the backend's TimeBucket dialect: either
    // "2026-05-16 14:30" / "2026-05-16 14:00" / "2026-05-16" depending on
    // granularity. Parse → ms.
    function parseBucketToMs(s) {
        if (!s) return 0;
        // Pad short forms to a parseable ISO-ish string.
        var t = s.indexOf(' ') >= 0 ? s.replace(' ', 'T') : (s.length === 10 ? s + 'T00:00:00' : s);
        var d = new Date(t);
        if (!isNaN(d.getTime())) return d.getTime();
        return 0;
    }

    function formatBytes(b) {
        if (!b && b !== 0) return '--';
        if (b < 1024) return b + ' B';
        var k = b / 1024;
        if (k < 1024) return k.toFixed(1) + ' KB';
        var m = k / 1024;
        if (m < 1024) return m.toFixed(1) + ' MB';
        var g = m / 1024;
        if (g < 1024) return g.toFixed(2) + ' GB';
        return (g / 1024).toFixed(2) + ' TB';
    }
    function formatBps(b) {
        if (!b && b !== 0) return '--';
        if (b < 1000) return Math.round(b) + ' bps';
        var k = b / 1000;
        if (k < 1000) return k.toFixed(1) + ' kbps';
        var m = k / 1000;
        if (m < 1000) return m.toFixed(2) + ' Mbps';
        return (m / 1000).toFixed(2) + ' Gbps';
    }
    function formatBpsShort(v) {
        if (v < 1000) return Math.round(v) + '';
        if (v < 1e6)  return (v / 1e3).toFixed(0) + 'k';
        if (v < 1e9)  return (v / 1e6).toFixed(1) + 'M';
        return (v / 1e9).toFixed(1) + 'G';
    }
    function formatDate(ts) {
        if (!ts) return '--';
        var d = new Date(ts);
        if (isNaN(d.getTime())) return '--';
        var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
        return pad(d.getMonth() + 1) + '/' + pad(d.getDate()) + ' ' +
               pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }
    // IP protocol number -> name. MUST mirror the backend's protoNames map
    // (internal/database/flows.go): the Protocols top-talker rows arrive from
    // /flows/stats as NAMES, and clicking one reverse-maps the name back to a
    // number to drive the filter. Any protocol missing here is unfilterable AND
    // renders falsely "active" — its empty reverse-lookup value ('') matches the
    // default empty protocol filter. (This is what made "IPv6" appear
    // pre-selected and refuse to filter when the map lacked 41.)
    var PROTOCOLS = {
        '0':'HOPOPT', '1':'ICMP', '2':'IGMP', '4':'IPv4', '6':'TCP', '8':'EGP',
        '17':'UDP', '41':'IPv6', '43':'IPv6-Route', '44':'IPv6-Frag', '47':'GRE',
        '50':'ESP', '51':'AH', '58':'ICMPv6', '59':'IPv6-NoNxt', '60':'IPv6-Opts',
        '88':'EIGRP', '89':'OSPF', '103':'PIM', '112':'VRRP', '132':'SCTP', '137':'MPLS-in-IP'
    };
    function protocolName(p) {
        if (p == null || p === '') return '';
        var s = String(p);
        return PROTOCOLS[s] || s;
    }
    function protocolNumber(name) {
        // Reverse lookup — used when clicking a top-protocol row whose key is
        // a NAME ("TCP", "IPv6") that needs to become a NUMBER ("6", "41") for
        // the filter.
        if (name == null) return '';
        var s = String(name);
        for (var k in PROTOCOLS) {
            if (PROTOCOLS[k] === s) return k;
        }
        // Backend emits "Proto N" for numbers it doesn't name — extract N so
        // even unmapped protocols stay filterable.
        var m = /^Proto (\d+)$/.exec(s);
        if (m) return m[1];
        // Already a bare number?
        return /^\d+$/.test(s) ? s : '';
    }

    function deviceLabel(id) {
        try {
            var devs = (window.adminMainState && window.adminMainState.devices) || [];
            for (var i = 0; i < devs.length; i++) {
                if (String(devs[i].id) === String(id)) return devs[i].name || ('dev:' + id);
            }
        } catch (e) {}
        return 'dev:' + id;
    }
    function probeLabel(id) {
        try {
            var probes = (window.adminMainState && window.adminMainState.probes) || [];
            for (var i = 0; i < probes.length; i++) {
                if (String(probes[i].id) === String(id)) return probes[i].name || ('probe:' + id);
            }
        } catch (e) {}
        return 'probe:' + id;
    }
    function siteLabel(id) {
        try {
            var sites = (window.adminMainState && window.adminMainState.sites) || [];
            for (var i = 0; i < sites.length; i++) {
                if (String(sites[i].id) === String(id)) return sites[i].name || ('site:' + id);
            }
        } catch (e) {}
        return 'site:' + id;
    }

    function setFilter(key, value) {
        if (!(key in state)) return;
        state[key] = value;
        applyStateToControls();
        syncURL();
        reload();
    }

    function getState() { return Object.assign({}, state); }

    window.FwmonFlows = {
        init: init,
        refresh: refresh,
        setFilter: setFilter,
        getState: getState,
        exportCsv: exportCsv
    };
})();
