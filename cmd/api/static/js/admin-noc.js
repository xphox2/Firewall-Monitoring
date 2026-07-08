/*
 * admin-noc.js — NOC operations breakdown (per-site → per-device).
 *
 * Subscribes to the server's Server-Sent Events stream (/admin/api/noc/stream),
 * which pushes a fresh snapshot every few seconds. The snapshot carries fleet
 * vitals, a live per-site/device health breakdown (snapshot.sites) and a recent
 * detections feed — the whole page renders from that ONE stream (no extra poll).
 *
 * Every site/device card is a link into Alert History, filtered to that entity:
 *   - site card    → /admin/alerts?site_id=ID   (or ?site_id=unassigned)
 *   - device card  → /admin/alerts?device_id=ID
 * so a click lands on the live alerts for that site/device. Navigation is plain
 * <a href>, handled by the SPA click-interceptor (no router code here).
 *
 * Public API (window.FwmonNOC):
 *   init()  — open the stream and start rendering (called when the NOC page opens)
 *   stop()  — close the stream (called when navigating away)
 */
(function () {
    'use strict';

    var STREAM_URL = '/admin/api/noc/stream';
    var es = null;
    var latest = null;               // most recent snapshot object
    var mode = 'site';               // 'site' | 'device'
    var wired = false;

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
    function sevClass(sev) {
        return sev ? ('sev-' + sev) : '';
    }
    // siteKey maps a SiteBreakdown to the token used in ?site_id=KEY: the numeric
    // site id, or 'unassigned' for the null bucket (the alerts filter understands
    // both — see applyAlertFilters).
    function siteKey(s) {
        return (s && s.site_id != null) ? String(s.site_id) : 'unassigned';
    }

    // ── render entry point ──────────────────────────────────────────────────

    function render(d) {
        if (!d) return;
        latest = d;
        renderVitals(d);
        renderDetections(d);
        renderBreakdown(d);
    }

    function renderVitals(d) {
        setText('noc-bps', fmtBps(d.bits_per_second));
        setText('noc-flows', fmtCount(d.total_flows) + ' / ' + fmtBytes(d.total_bytes));
        setText('noc-srcs', fmtCount(d.unique_sources) + ' → ' + fmtCount(d.unique_dests));
        setText('noc-threat-flows', fmtCount(d.threat_flows));
        setText('noc-ti', fmtCount(d.active_threat_intel));
        var winHint = document.getElementById('noc-window-hint');
        if (winHint) winHint.textContent = 'last ' + Math.round((d.window_seconds || 300) / 60) + ' min · live';
    }

    function renderBreakdown(d) {
        var sites = d.sites || [];
        var sitesGrid = document.getElementById('noc-sites-grid');
        var devGrid = document.getElementById('noc-devices-grid');
        if (sitesGrid) sitesGrid.hidden = mode !== 'site';
        if (devGrid) devGrid.hidden = mode !== 'device';
        if (mode === 'site') renderSiteCards(sites);
        else renderDeviceCards(sites);
    }

    // ── By Site: one card per site (links to Alert History for that site) ────

    function sevBadges(critical, warning) {
        var out = '';
        if (critical > 0) out += '<span class="fwmon-noc-badge crit">' + critical + ' crit</span>';
        if (warning > 0) out += '<span class="fwmon-noc-badge warn">' + warning + ' warn</span>';
        if (!out) out += '<span class="fwmon-noc-badge ok">no alerts</span>';
        return out;
    }

    function renderSiteCards(sites) {
        var el = document.getElementById('noc-sites-grid');
        if (!el) return;
        if (!sites.length) {
            el.innerHTML = '<div class="fwmon-noc-empty">No sites or devices yet. Add devices under Infrastructure → Sites.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < sites.length; i++) {
            var s = sites[i];
            var key = siteKey(s);
            var sc = sevClass(s.worst_severity);
            var total = (s.devices_online || 0) + (s.devices_offline || 0);
            var probeWarn = s.probe_offline ? '<span class="fwmon-noc-badge crit">probe down</span>' : '';
            html += '<a class="fwmon-noc-card ' + sc + '" href="/admin/alerts?site_id=' + encodeURIComponent(key) + '"' +
                ' title="View alerts for ' + esc(s.site_name || 'this site') + '">' +
                '<div class="fwmon-noc-card-head">' +
                    '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                    '<span class="fwmon-noc-card-title">' + esc(s.site_name || 'Site') + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-badges">' + sevBadges(s.alerts_critical || 0, s.alerts_warning || 0) + probeWarn + '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span>' + (s.devices_online || 0) + '/' + total + ' up</span>' +
                    '<span class="bps">' + fmtBps(s.bits_per_second) + '</span>' +
                '</div>' +
            '</a>';
        }
        el.innerHTML = html;
    }

    // ── By Device: flat device grid, each card links to that device's alerts ─

    function flattenDevices(sites) {
        var out = [];
        for (var i = 0; i < sites.length; i++) {
            var s = sites[i];
            var devs = s.devices || [];
            for (var j = 0; j < devs.length; j++) {
                out.push({ dev: devs[j], siteName: s.site_name || 'Unassigned' });
            }
        }
        // Worst severity first, then by bps desc.
        out.sort(function (a, b) {
            var ra = SEV_RANK[a.dev.worst_severity] != null ? SEV_RANK[a.dev.worst_severity] : 9;
            var rb = SEV_RANK[b.dev.worst_severity] != null ? SEV_RANK[b.dev.worst_severity] : 9;
            if (ra !== rb) return ra - rb;
            return (b.dev.bits_per_second || 0) - (a.dev.bits_per_second || 0);
        });
        return out;
    }

    function renderDeviceCards(sites) {
        var el = document.getElementById('noc-devices-grid');
        if (!el) return;
        var rows = flattenDevices(sites);
        if (!rows.length) {
            el.innerHTML = '<div class="fwmon-noc-empty">No devices yet.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var dev = rows[i].dev;
            var sc = sevClass(dev.worst_severity);
            var online = dev.status === 'online' || dev.status === 'up';
            html += '<a class="fwmon-noc-card ' + sc + '" href="/admin/alerts?device_id=' + encodeURIComponent(dev.id) + '"' +
                ' title="View alerts for ' + esc(dev.name || ('DEV-' + dev.id)) + '">' +
                '<div class="fwmon-noc-card-head">' +
                    '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                    '<span class="fwmon-noc-card-title">' + esc(dev.name || ('DEV-' + dev.id)) + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span class="site">' + esc(rows[i].siteName) + '</span>' +
                    '<span>' + (online ? 'online' : esc(dev.status || 'offline')) + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span class="ip">' + esc(dev.ip || '') + '</span>' +
                    '<span class="bps">' + fmtBps(dev.bits_per_second) + '</span>' +
                '</div>' +
            '</a>';
        }
        el.innerHTML = html;
    }

    // ── Detections feed ─────────────────────────────────────────────────────

    // deviceNameMap builds an id→name lookup from the snapshot's site breakdown so
    // a detection's device_id can be shown as a name (no extra fetch).
    function deviceNameMap(d) {
        var map = {};
        var sites = (d && d.sites) || [];
        for (var i = 0; i < sites.length; i++) {
            var devs = sites[i].devices || [];
            for (var j = 0; j < devs.length; j++) map[String(devs[j].id)] = devs[j].name;
        }
        return map;
    }

    // ipRef renders an IP as a threat-intel-enrichable reference (populated by
    // AdminCommon.enrichIps after paint), falling back to plain text.
    function ipRef(addr) {
        if (!addr) return '';
        var AC = window.AdminCommon;
        return (AC && AC.ipRef) ? AC.ipRef(addr) : esc(addr);
    }

    function renderDetections(d) {
        var body = document.getElementById('noc-detections-body');
        if (!body) return;
        var rows = (d && d.detections) || [];
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="fwmon-ti-empty">No detections in the last 6 hours.</td></tr>';
            return;
        }
        var devNames = deviceNameMap(d);
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
            var dst = r.dst_addr ? (ipRef(r.dst_addr) + (r.dst_port ? ':' + esc(r.dst_port) : '')) : '—';
            var route = r.src_addr ? (ipRef(r.src_addr) + ' → ' + dst) : (r.dst_addr ? dst : '—');
            var devName = (r.device_id && devNames[String(r.device_id)]) || (r.device_id ? ('DEV-' + r.device_id) : '—');
            html += '<tr>' +
                '<td><span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span></td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td><code>' + esc(r.detector || '') + '</code></td>' +
                '<td style="font-family:var(--fwmon-font-mono,monospace);white-space:nowrap;">' + route + '</td>' +
                '<td>' + esc(devName) + '</td>' +
                '<td>' + esc(r.message || '') + '</td>' +
                '<td title="' + esc(r.detected_at || '') + '">' + esc(ago(r.detected_at)) + ' ago</td>' +
            '</tr>';
        }
        body.innerHTML = html;
        if (window.AdminCommon && window.AdminCommon.enrichIps) window.AdminCommon.enrichIps(body);
    }

    // ── mode toggle / interaction ───────────────────────────────────────────

    function setMode(m) {
        if (m !== 'site' && m !== 'device') return;
        mode = m;
        var btns = document.querySelectorAll('.fwmon-noc-mode');
        for (var i = 0; i < btns.length; i++) {
            var on = btns[i].getAttribute('data-noc-mode') === m;
            btns[i].classList.toggle('active', on);
            btns[i].setAttribute('aria-selected', on ? 'true' : 'false');
        }
        if (latest) renderBreakdown(latest);
    }

    function onClick(ev) {
        var t = ev.target;
        // Mode toggle (By Site / By Device). Cards are plain <a> links and fall
        // through to the SPA click-interceptor, so no card handling is needed here.
        var modeBtn = t.closest && t.closest('.fwmon-noc-mode');
        if (modeBtn) { setMode(modeBtn.getAttribute('data-noc-mode')); return; }
    }

    function setStatus(txt, cls) {
        var el = document.getElementById('noc-conn-status');
        if (!el) return;
        el.textContent = txt;
        el.className = 'fwmon-noc-status' + (cls ? ' ' + cls : '');
    }

    function wire() {
        if (wired) return;
        var page = document.getElementById('page-noc');
        if (page) page.addEventListener('click', onClick);
        wired = true;
    }

    function init() {
        stop(); // never stack streams on re-entry
        wire();

        if (typeof EventSource === 'undefined') {
            setStatus('live updates unsupported', 'bad');
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
            catch (e) { if (window.fwmonLog) window.fwmonLog.error('FwmonNOC: bad frame', e); }
        };
        es.onerror = function () { setStatus('reconnecting…', 'warn'); };
    }

    function stop() {
        if (es) { es.close(); es = null; }
    }

    window.FwmonNOC = { init: init, stop: stop };
})();
