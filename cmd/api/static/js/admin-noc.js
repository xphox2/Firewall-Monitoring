/*
 * admin-noc.js — real-time NOC dashboard.
 *
 * Subscribes to the server's Server-Sent Events stream (/admin/api/noc/stream),
 * which pushes a fresh snapshot every few seconds, and renders six zones:
 * throughput vitals, top sources, top destinations, application + direction mix,
 * top countries, and a live detections feed. EventSource carries the admin
 * auth cookie automatically and auto-reconnects on drop.
 *
 * Public API (window.FwmonNOC):
 *   init()  — open the stream and start rendering (called when the NOC page opens)
 *   stop()  — close the stream (called when navigating away)
 */
(function () {
    'use strict';

    var STREAM_URL = '/admin/api/noc/stream';
    var es = null;

    // Stable id → label maps mirroring internal/classify (do not reorder).
    var CATEGORY_LABELS = {
        '0': 'Unknown', '1': 'Web', '2': 'DNS', '3': 'Email', '4': 'File Share',
        '5': 'VPN', '6': 'Database', '7': 'Remote Access', '8': 'Streaming',
        '9': 'VoIP', '10': 'Backup', '11': 'Management', '12': 'P2P', '13': 'ICMP'
    };
    var DIRECTION_LABELS = {
        '0': 'Unknown', '1': 'Inbound', '2': 'Outbound', '3': 'Internal', '4': 'External'
    };
    var SEV_RANK = { critical: 0, warning: 1, info: 2 };

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtCount(n) {
        n = Number(n) || 0;
        if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
        return String(n);
    }

    function fmtBytes(n) {
        n = Number(n) || 0;
        var u = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return n.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
    }

    function fmtBps(bits) {
        bits = Number(bits) || 0;
        var u = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
        var i = 0;
        while (bits >= 1000 && i < u.length - 1) { bits /= 1000; i++; }
        return bits.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
    }

    function ago(iso) {
        if (!iso) return '';
        var t = new Date(iso).getTime();
        if (!isFinite(t)) return '';
        var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
        if (s < 60) return s + 's';
        if (s < 3600) return Math.floor(s / 60) + 'm';
        if (s < 86400) return Math.floor(s / 3600) + 'h';
        return Math.floor(s / 86400) + 'd';
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // renderList fills a fwmon-toptalk-list <ul>, matching the read-only markup
    // admin-flows.js uses (so the shared CSS bars/colors apply). colorTag drives
    // the bar gradient; labelFn maps a row's Key to display text; valFn formats
    // the count. NOC lists are display-only (not click-to-filter).
    function renderList(id, rows, colorTag, labelFn, valFn) {
        var el = document.getElementById(id);
        if (!el) return;
        rows = rows || [];
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
            var label = labelFn ? labelFn(r.key) : r.key;
            html += '<li class="fwmon-toptalk-row" style="--bar-pct:' + pct.toFixed(1) + '%">' +
                '<span class="fwmon-toptalk-row-label" title="' + esc(label) + '">' + esc(label) + '</span>' +
                '<span class="fwmon-toptalk-row-value">' + esc(valFn(r.count)) + '</span>' +
                '<span class="fwmon-toptalk-row-bar"></span>' +
            '</li>';
        }
        el.innerHTML = html;
    }

    function render(d) {
        if (!d) return;
        setText('noc-bps', fmtBps(d.bits_per_second));
        setText('noc-flows', fmtCount(d.total_flows) + ' / ' + fmtBytes(d.total_bytes));
        setText('noc-srcs', fmtCount(d.unique_sources) + ' → ' + fmtCount(d.unique_dests));
        setText('noc-threat-flows', fmtCount(d.threat_flows));
        setText('noc-probes', (d.probes_online || 0) + ' up / ' + (d.probes_offline || 0) + ' down');
        setText('noc-ti', fmtCount(d.active_threat_intel));

        var winHint = document.getElementById('noc-window-hint');
        if (winHint) winHint.textContent = 'last ' + Math.round((d.window_seconds || 300) / 60) + ' min · live';

        renderList('noc-top-sources', d.top_sources, 'sources', null, fmtBytes);
        renderList('noc-top-dests', d.top_destinations, 'dests', null, fmtBytes);
        renderList('noc-by-category', d.by_category, 'category', function (k) { return CATEGORY_LABELS[k] || k; }, fmtCount);
        renderList('noc-by-direction', d.by_direction, 'direction', function (k) { return DIRECTION_LABELS[k] || k; }, fmtCount);

        var countriesCard = document.getElementById('noc-card-countries');
        var hasCountries = d.top_countries && d.top_countries.length > 0;
        if (countriesCard) countriesCard.hidden = !hasCountries;
        if (hasCountries) renderList('noc-top-countries', d.top_countries, 'countries', null, fmtBytes);

        renderDetections(d.detections || []);
    }

    function renderDetections(rows) {
        var body = document.getElementById('noc-detections-body');
        if (!body) return;
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="5" class="fwmon-ti-empty">No detections in the last 15 minutes.</td></tr>';
            return;
        }
        rows = rows.slice().sort(function (a, b) {
            var ra = SEV_RANK[a.severity] != null ? SEV_RANK[a.severity] : 9;
            var rb = SEV_RANK[b.severity] != null ? SEV_RANK[b.severity] : 9;
            if (ra !== rb) return ra - rb;
            return new Date(b.detected_at) - new Date(a.detected_at);
        });
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            var sev = r.severity || 'info';
            html += '<tr>' +
                '<td><span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span></td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td><code>' + esc(r.detector || '') + '</code></td>' +
                '<td>' + esc(r.message || '') + '</td>' +
                '<td title="' + esc(r.detected_at || '') + '">' + esc(ago(r.detected_at)) + ' ago</td>' +
            '</tr>';
        }
        body.innerHTML = html;
    }

    function setStatus(txt, cls) {
        var el = document.getElementById('noc-conn-status');
        if (!el) return;
        el.textContent = txt;
        el.className = 'fwmon-noc-status' + (cls ? ' ' + cls : '');
    }

    function init() {
        stop(); // never stack streams on re-entry
        if (typeof EventSource === 'undefined') {
            setStatus('live updates unsupported', 'bad');
            // Fall back to a single snapshot fetch.
            if (window.AdminCommon && window.AdminCommon.apiFetch) {
                window.AdminCommon.apiFetch('/admin/api/noc/snapshot')
                    .then(function (res) { render(res && res.data); })
                    .catch(function () {});
            }
            return;
        }
        setStatus('connecting…');
        es = new EventSource(STREAM_URL);
        es.onopen = function () { setStatus('● live', 'ok'); };
        es.onmessage = function (ev) {
            setStatus('● live', 'ok');
            try { render(JSON.parse(ev.data)); }
            catch (e) { window.fwmonLog.error('FwmonNOC: bad frame', e); }
        };
        es.onerror = function () {
            // EventSource auto-reconnects; reflect the transient state.
            setStatus('reconnecting…', 'warn');
        };
    }

    function stop() {
        if (es) { es.close(); es = null; }
    }

    window.FwmonNOC = { init: init, stop: stop };
})();
