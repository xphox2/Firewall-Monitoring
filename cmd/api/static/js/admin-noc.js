/*
 * admin-noc.js — NOC operations breakdown (per-site → per-device).
 *
 * Subscribes to the server's Server-Sent Events stream (/admin/api/noc/stream),
 * which pushes a fresh snapshot every few seconds. The snapshot carries fleet
 * vitals, a live per-site/device health breakdown (snapshot.sites) and a recent
 * detections feed — the whole page renders from that ONE stream (no extra poll).
 *
 * The same alert/issue state shown here colours the Connections-map nodes, so the
 * two Monitoring tabs stay in sync. Every card/row is clickable:
 *   - site card  → opens an in-page drill-down (device rows + site actions)
 *   - device row → /admin/connections?focus=device:ID  (focus that node on the map)
 *   - "View on map"  → /admin/connections?focus=site:ID
 *   - "View flows"   → /admin/flows?site_id=ID | ?device_id=ID
 * All navigation reuses the SPA click-interceptor (plain <a href> links), so no
 * custom router code lives here.
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
    var selected = null;             // { kind:'site'|'device', id:<num|'unassigned'> }
    var pendingFocus = null;         // parsed from ?focus= on init, applied after first frame
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
    // siteKey maps a SiteBreakdown to the token used in ?focus=site:KEY and as the
    // selection id: the numeric site id, or 'unassigned' for the null bucket.
    function siteKey(s) {
        return (s && s.site_id != null) ? String(s.site_id) : 'unassigned';
    }

    // ── render entry point ──────────────────────────────────────────────────

    function render(d) {
        if (!d) return;
        latest = d;
        renderVitals(d);
        renderDetections(d.detections || []);
        renderBreakdown(d);
        // Apply a pending deep-link focus once the first frame with data lands.
        if (pendingFocus) {
            var pf = pendingFocus;
            pendingFocus = null;
            applyFocus(pf.kind, pf.id);
        }
    }

    function renderVitals(d) {
        setText('noc-bps', fmtBps(d.bits_per_second));
        setText('noc-flows', fmtCount(d.total_flows) + ' / ' + fmtBytes(d.total_bytes));
        setText('noc-srcs', fmtCount(d.unique_sources) + ' → ' + fmtCount(d.unique_dests));
        setText('noc-threat-flows', fmtCount(d.threat_flows));
        setText('noc-probes', (d.probes_online || 0) + ' up / ' + (d.probes_offline || 0) + ' down');
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
        renderDrill(d);
    }

    // ── By Site: one card per site ──────────────────────────────────────────

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
            var isSel = selected && selected.kind === 'site' && String(selected.id) === key;
            html += '<button type="button" class="fwmon-noc-card ' + sc + (isSel ? ' selected' : '') + '" data-noc-site="' + esc(key) + '">' +
                '<div class="fwmon-noc-card-head">' +
                    '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                    '<span class="fwmon-noc-card-title">' + esc(s.site_name || 'Site') + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-badges">' + sevBadges(s.alerts_critical || 0, s.alerts_warning || 0) + probeWarn + '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span>' + (s.devices_online || 0) + '/' + total + ' up</span>' +
                    '<span class="bps">' + fmtBps(s.bits_per_second) + '</span>' +
                '</div>' +
            '</button>';
        }
        el.innerHTML = html;
    }

    // ── By Device: flat device grid across all sites ────────────────────────

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
            var isSel = selected && selected.kind === 'device' && String(selected.id) === String(dev.id);
            html += '<button type="button" class="fwmon-noc-card ' + sc + (isSel ? ' selected' : '') + '" data-noc-device="' + dev.id + '">' +
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
            '</button>';
        }
        el.innerHTML = html;
    }

    // ── Drill-down (live: re-rendered from every frame while open) ───────────

    function renderDrill(d) {
        var el = document.getElementById('noc-drill');
        if (!el) return;
        if (!selected) { el.hidden = true; el.innerHTML = ''; return; }
        if (selected.kind === 'site') renderSiteDrill(el, d);
        else renderDeviceDrill(el, d);
    }

    function findSite(d, key) {
        var sites = d.sites || [];
        for (var i = 0; i < sites.length; i++) {
            if (siteKey(sites[i]) === String(key)) return sites[i];
        }
        return null;
    }
    function findDevice(d, id) {
        var sites = d.sites || [];
        for (var i = 0; i < sites.length; i++) {
            var devs = sites[i].devices || [];
            for (var j = 0; j < devs.length; j++) {
                if (String(devs[j].id) === String(id)) return { dev: devs[j], site: sites[i] };
            }
        }
        return null;
    }

    function miniStat(label, value) {
        return '<span class="m"><b>' + esc(value) + '</b>' + esc(label) + '</span>';
    }

    function renderSiteDrill(el, d) {
        var s = findSite(d, selected.id);
        if (!s) { el.hidden = true; el.innerHTML = ''; selected = null; return; }
        var key = siteKey(s);
        var total = (s.devices_online || 0) + (s.devices_offline || 0);
        var mapLink = '/admin/connections?focus=site:' + encodeURIComponent(key);
        var flowsLink = (s.site_id != null) ? ('/admin/flows?site_id=' + s.site_id) : '';

        var rows = '';
        var devs = s.devices || [];
        if (!devs.length) {
            rows = '<div class="fwmon-noc-empty">No devices in this site.</div>';
        }
        for (var i = 0; i < devs.length; i++) {
            var dev = devs[i];
            var sc = sevClass(dev.worst_severity);
            var online = dev.status === 'online' || dev.status === 'up';
            // Whole row is a link that focuses this device on the connection map.
            rows += '<a class="fwmon-noc-devrow" href="/admin/connections?focus=device:' + dev.id + '">' +
                '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                '<span class="dname">' + esc(dev.name || ('DEV-' + dev.id)) + '</span>' +
                '<span class="ip">' + esc(dev.ip || '') + '</span>' +
                '<span class="bps">' + fmtBps(dev.bits_per_second) + '</span>' +
                '<span>' + (online ? 'online' : esc(dev.status || 'offline')) + '</span>' +
            '</a>';
        }

        el.hidden = false;
        el.innerHTML = '<div class="fwmon-noc-drill">' +
            '<div class="fwmon-noc-drill-head">' +
                '<span class="fwmon-noc-dot ' + sevClass(s.worst_severity) + '"></span>' +
                '<span class="fwmon-noc-drill-title">' + esc(s.site_name || 'Site') + '</span>' +
                '<div class="fwmon-noc-drill-actions">' +
                    '<a class="btn secondary sm" href="' + mapLink + '">View on map</a>' +
                    (flowsLink ? '<a class="btn secondary sm" href="' + flowsLink + '">View flows</a>' : '') +
                    '<button type="button" class="btn secondary sm" data-noc-close>Close</button>' +
                '</div>' +
            '</div>' +
            '<div class="fwmon-noc-drill-mini">' +
                miniStat(' devices up', (s.devices_online || 0) + '/' + total) +
                miniStat(' throughput', fmtBps(s.bits_per_second)) +
                miniStat(' bytes (5m)', fmtBytes(s.total_bytes)) +
                miniStat(' threat flows', fmtCount(s.threat_flows)) +
                miniStat(' open alerts', (s.alerts_critical || 0) + ' crit / ' + (s.alerts_warning || 0) + ' warn') +
            '</div>' +
            rows +
        '</div>';
    }

    function renderDeviceDrill(el, d) {
        var found = findDevice(d, selected.id);
        if (!found) { el.hidden = true; el.innerHTML = ''; selected = null; return; }
        var dev = found.dev;
        var online = dev.status === 'online' || dev.status === 'up';
        el.hidden = false;
        el.innerHTML = '<div class="fwmon-noc-drill">' +
            '<div class="fwmon-noc-drill-head">' +
                '<span class="fwmon-noc-dot ' + sevClass(dev.worst_severity) + '"></span>' +
                '<span class="fwmon-noc-drill-title">' + esc(dev.name || ('DEV-' + dev.id)) + '</span>' +
                '<div class="fwmon-noc-drill-actions">' +
                    '<a class="btn secondary sm" href="/admin/connections?focus=device:' + dev.id + '">View on map</a>' +
                    '<a class="btn secondary sm" href="/admin/flows?device_id=' + dev.id + '">View flows</a>' +
                    '<a class="btn secondary sm" href="/admin/devices/' + dev.id + '">Device detail</a>' +
                    '<button type="button" class="btn secondary sm" data-noc-close>Close</button>' +
                '</div>' +
            '</div>' +
            '<div class="fwmon-noc-drill-mini">' +
                miniStat(' site', found.site.site_name || 'Unassigned') +
                miniStat(' status', online ? 'online' : (dev.status || 'offline')) +
                miniStat(' address', dev.ip || '—') +
                miniStat(' throughput', fmtBps(dev.bits_per_second)) +
                miniStat(' last polled', dev.last_polled ? (ago(dev.last_polled) + ' ago') : '—') +
            '</div>' +
        '</div>';
    }

    // ── Detections feed (kept from the previous NOC) ────────────────────────

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

    // ── selection / mode / interaction ──────────────────────────────────────

    function setMode(m) {
        if (m !== 'site' && m !== 'device') return;
        mode = m;
        selected = null; // clear drill when switching lens
        var btns = document.querySelectorAll('.fwmon-noc-mode');
        for (var i = 0; i < btns.length; i++) {
            var on = btns[i].getAttribute('data-noc-mode') === m;
            btns[i].classList.toggle('active', on);
            btns[i].setAttribute('aria-selected', on ? 'true' : 'false');
        }
        if (latest) renderBreakdown(latest);
        syncFocusURL();
    }

    function selectSite(key) {
        selected = { kind: 'site', id: key };
        if (latest) { renderSiteCards(latest.sites || []); renderDrill(latest); }
        syncFocusURL();
        scrollDrillIntoView();
    }
    function selectDevice(id) {
        selected = { kind: 'device', id: id };
        if (latest) { renderDeviceCards(latest.sites || []); renderDrill(latest); }
        syncFocusURL();
        scrollDrillIntoView();
    }
    function closeDrill() {
        selected = null;
        if (latest) renderBreakdown(latest);
        syncFocusURL();
    }
    function scrollDrillIntoView() {
        var el = document.getElementById('noc-drill');
        if (el && !el.hidden && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // applyFocus is used by deep-links (?focus=) — switch to the right lens and
    // open the drill for that entity.
    function applyFocus(kind, id) {
        if (kind === 'device') { setMode('device'); selectDevice(id); }
        else { setMode('site'); selectSite(id); }
    }

    // Keep the URL in step so refresh / back re-opens the same drill.
    function syncFocusURL() {
        if (!window.history || !window.history.replaceState) return;
        var base = '/admin/noc';
        var q = '';
        if (selected) q = '?focus=' + selected.kind + ':' + encodeURIComponent(selected.id);
        try { window.history.replaceState(null, '', base + q); } catch (e) { /* ignore */ }
    }

    function parseFocus() {
        var m = /[?&]focus=(site|device):([^&]+)/.exec(window.location.search || '');
        if (!m) return null;
        // A malformed percent-escape (e.g. ?focus=device:%ZZ) makes
        // decodeURIComponent throw a URIError; catching it keeps a hand-edited or
        // truncated URL from aborting NOC init entirely (audit L6).
        var id;
        try { id = decodeURIComponent(m[2]); } catch (e) { return null; }
        return { kind: m[1], id: id };
    }

    function onClick(ev) {
        var t = ev.target;
        // Mode toggle.
        var modeBtn = t.closest && t.closest('.fwmon-noc-mode');
        if (modeBtn) { setMode(modeBtn.getAttribute('data-noc-mode')); return; }
        // Close drill.
        if (t.closest && t.closest('[data-noc-close]')) { closeDrill(); return; }
        // Let real <a> links fall through to the SPA click-interceptor.
        if (t.closest && t.closest('a[href]')) return;
        // Site card.
        var siteCard = t.closest && t.closest('[data-noc-site]');
        if (siteCard) { selectSite(siteCard.getAttribute('data-noc-site')); return; }
        // Device card.
        var devCard = t.closest && t.closest('[data-noc-device]');
        if (devCard) { selectDevice(devCard.getAttribute('data-noc-device')); return; }
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
        pendingFocus = parseFocus();
        // If a device deep-link is present, pre-select the device lens so the grid
        // paints in the right mode even before the first frame lands.
        if (pendingFocus && pendingFocus.kind === 'device') mode = 'device';

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
