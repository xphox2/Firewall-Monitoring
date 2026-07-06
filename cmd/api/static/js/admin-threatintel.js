// admin-threatintel.js — the dedicated Threat Intelligence admin page.
// Owns the IP/ASN lookup tool, the per-source feed status table, and the
// searchable/paginated indicator table + manual add. Backed by
//   GET  /admin/api/threat-intel/lookup?q=
//   GET  /admin/api/threat-intel/search?q=&source=&category=&severity=&offset=&limit=
//   GET  /admin/api/threat-intel/feeds
//   POST /admin/api/flows/threat-intel      (manual add)
//   DELETE /admin/api/flows/threat-intel/:id
// Exposed as window.FwmonThreatIntel with init(); admin-main.js calls init()
// when the threat-intel page activates.
(function() {
    'use strict';

    var PAGE_SIZE = 100;
    var searchOffset = 0;
    var searchTotal = 0;
    var wired = false;

    function esc(s) {
        var f = (window.AdminCommon && window.AdminCommon.escapeHtml);
        return f ? f(String(s == null ? '' : s)) : String(s == null ? '' : s);
    }
    function api(path, opts) {
        var AC = window.AdminCommon;
        if (!AC || !AC.apiFetch) return Promise.reject(new Error('AdminCommon unavailable'));
        return AC.apiFetch(path, opts);
    }
    function el(id) { return document.getElementById(id); }

    function init() {
        wire();
        loadFeeds();
        runSearch(0);
        var r = el('ti-lookup-result'); if (r) r.innerHTML = '';
    }

    function wire() {
        if (wired) return;
        wired = true;
        var lookupForm = el('ti-lookup-form');
        if (lookupForm) lookupForm.addEventListener('submit', onLookup);
        var searchBtn = el('ti-search-btn');
        if (searchBtn) searchBtn.addEventListener('click', function() { runSearch(0); });
        var q = el('ti-search-q');
        if (q) q.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); runSearch(0); } });
        var prev = el('ti-search-prev');
        if (prev) prev.addEventListener('click', function() { if (searchOffset > 0) runSearch(searchOffset - PAGE_SIZE); });
        var next = el('ti-search-next');
        if (next) next.addEventListener('click', function() { if (searchOffset + PAGE_SIZE < searchTotal) runSearch(searchOffset + PAGE_SIZE); });
        var addForm = el('ti-add-form');
        if (addForm) addForm.addEventListener('submit', onAdd);
        var body = el('ti-search-body');
        if (body) body.addEventListener('click', onDelete);
    }

    // ---- Lookup ------------------------------------------------------------
    function onLookup(ev) {
        ev.preventDefault();
        var q = (el('ti-lookup-q').value || '').trim();
        if (!q) return;
        var errEl = el('ti-lookup-error');
        if (errEl) { errEl.hidden = true; errEl.textContent = ''; }
        api('/admin/api/threat-intel/lookup?q=' + encodeURIComponent(q))
            .then(function(res) { renderLookup((res && res.data) || {}); })
            .catch(function(e) {
                if (errEl) { errEl.textContent = (e && e.message) || 'Lookup failed.'; errEl.hidden = false; }
            });
    }

    function renderLookup(d) {
        var host = el('ti-lookup-result');
        if (!host) return;
        var rows = [];
        rows.push(kv('Query', d.query));
        if (d.kind === 'asn') {
            rows.push(kv('AS number', 'AS' + esc(d.asn)));
        } else {
            rows.push(kv('Country', d.country || '—'));
            rows.push(kv('ASN', d.asn ? ('AS' + esc(d.asn) + (d.asn_org ? ' · ' + esc(d.asn_org) : '')) : '—'));
            if (d.asn_prefix) rows.push(kv('Network', esc(d.asn_prefix)));
            if (d.geo_enabled === false) rows.push(kv('Geo', 'disabled'));
        }
        var verdict;
        if (d.known_bad) {
            var threats = d.threats || (d.threat ? [d.threat] : []);
            var parts = threats.map(function(t) {
                return '<span class="fwmon-det-sev fwmon-det-sev-' + esc(t.severity || 'warning') + '">' +
                    esc(t.scope) + ': ' + esc(t.category || '') + '</span>';
            });
            verdict = '<strong style="color:var(--fwmon-danger,#e5484d)">KNOWN-BAD</strong> ' + parts.join(' ');
        } else {
            verdict = '<span class="fwmon-toptalk-hint">not on any loaded feed</span>';
        }
        rows.push(kv('Threat', verdict));
        host.innerHTML = '<div class="fwmon-ti-lookup-card">' + rows.join('') + '</div>';
    }

    function kv(k, v) {
        return '<div style="display:flex; gap:10px; padding:3px 0;">' +
            '<div style="min-width:110px; color:var(--fwmon-text-muted,#8a94a6);">' + esc(k) + '</div>' +
            '<div>' + v + '</div></div>';
    }

    // ---- Feed status -------------------------------------------------------
    function loadFeeds() {
        api('/admin/api/threat-intel/feeds')
            .then(function(res) { renderFeeds((res && res.data) || {}); })
            .catch(function(e) { window.fwmonLog && window.fwmonLog.error('threat-intel feeds fetch failed', e); });
    }

    function renderFeeds(d) {
        var hint = el('ti-feeds-hint');
        if (hint) {
            hint.textContent = d.feeds_enabled === false
                ? 'online feeds DISABLED — set THREAT_FEEDS_ENABLED=true'
                : 'every ' + esc(d.interval || '?') + ' · TTL ' + esc(d.ttl_days) + 'd · ' + esc(d.loaded_count || 0) + ' loaded';
        }
        var summary = el('ti-summary');
        if (summary) {
            summary.textContent = (d.feeds_enabled === false ? 'Feeds disabled · ' : 'Feeds enabled · ') +
                (d.loaded_count || 0) + ' indicators loaded in matcher';
        }
        var body = el('ti-feeds-body');
        if (!body) return;
        var rows = (d.status) || [];
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="6" class="fwmon-ti-empty">No feed syncs recorded yet. The poller fetches ~1 min after startup, then every ' + esc(d.interval || 'interval') + '.</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            var status = r.last_error
                ? '<span class="fwmon-det-sev fwmon-det-sev-critical" title="' + esc(r.last_error) + '">error</span>'
                : '<span class="fwmon-det-sev fwmon-det-sev-info">ok</span>';
            html += '<tr>' +
                '<td>' + esc(r.source) + '</td>' +
                '<td>' + esc(r.kind || 'ip') + '</td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td>' + esc(r.entry_count || 0) + '</td>' +
                '<td>' + fmtTime(r.last_sync_at) + '</td>' +
                '<td>' + status + '</td>' +
            '</tr>';
        }
        body.innerHTML = html;
    }

    // ---- Search ------------------------------------------------------------
    function runSearch(offset) {
        searchOffset = offset < 0 ? 0 : offset;
        var params = 'offset=' + searchOffset + '&limit=' + PAGE_SIZE +
            '&q=' + encodeURIComponent((el('ti-search-q').value || '').trim()) +
            '&source=' + encodeURIComponent((el('ti-search-source').value || '').trim()) +
            '&category=' + encodeURIComponent((el('ti-search-category').value || '').trim()) +
            '&severity=' + encodeURIComponent(el('ti-search-severity').value || '');
        api('/admin/api/threat-intel/search?' + params)
            .then(function(res) { renderSearch((res && res.data) || {}); })
            .catch(function(e) { window.fwmonLog && window.fwmonLog.error('threat-intel search failed', e); });
    }

    function renderSearch(d) {
        searchTotal = d.total || 0;
        var body = el('ti-search-body');
        if (body) {
            var rows = d.entries || [];
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="6" class="fwmon-ti-empty">No matching indicators.</td></tr>';
            } else {
                var AC = window.AdminCommon;
                var html = '';
                for (var i = 0; i < rows.length; i++) {
                    var r = rows[i];
                    html += '<tr>' +
                        '<td><code>' + AC.ipRef(r.cidr) + '</code></td>' +
                        '<td>' + esc(r.category || '') + '</td>' +
                        '<td>' + esc(r.source || '') + '</td>' +
                        '<td><span class="fwmon-det-sev fwmon-det-sev-' + esc(r.severity || 'warning') + '">' + esc(r.severity || 'warning') + '</span></td>' +
                        '<td>' + fmtExpiry(r.expires_at) + '</td>' +
                        '<td><button type="button" class="fwmon-det-ack fwmon-ti-del" data-ti-id="' + esc(r.id) + '">Delete</button></td>' +
                    '</tr>';
                }
                body.innerHTML = html;
                AC.enrichIps(body);
            }
        }
        var pageEl = el('ti-search-page');
        if (pageEl) {
            var from = searchTotal === 0 ? 0 : searchOffset + 1;
            var to = Math.min(searchOffset + PAGE_SIZE, searchTotal);
            pageEl.textContent = from + '–' + to + ' of ' + searchTotal;
        }
        var prev = el('ti-search-prev'); if (prev) prev.disabled = searchOffset <= 0;
        var next = el('ti-search-next'); if (next) next.disabled = searchOffset + PAGE_SIZE >= searchTotal;
    }

    // ---- Add / delete ------------------------------------------------------
    function onAdd(ev) {
        ev.preventDefault();
        var errEl = el('ti-add-error');
        if (errEl) { errEl.hidden = true; errEl.textContent = ''; }
        var cidr = (el('ti-add-cidr').value || '').trim();
        if (!cidr) return;
        var body = {
            cidr: cidr,
            category: el('ti-add-category').value,
            severity: el('ti-add-severity').value,
            source: (el('ti-add-source').value || '').trim() || 'manual'
        };
        var exp = el('ti-add-expires').value;
        if (exp) {
            var dt = new Date(exp + 'T00:00:00Z');
            if (!isNaN(dt.getTime())) body.expires_at = dt.toISOString();
        }
        var btn = el('ti-add-btn2'); if (btn) btn.disabled = true;
        api('/admin/api/flows/threat-intel', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        }).then(function() {
            el('ti-add-cidr').value = ''; el('ti-add-source').value = ''; el('ti-add-expires').value = '';
            runSearch(0); loadFeeds();
        }).catch(function(e) {
            if (errEl) { errEl.textContent = (e && e.message) || 'Failed to add — check the value.'; errEl.hidden = false; }
        }).then(function() { if (btn) btn.disabled = false; });
    }

    function onDelete(ev) {
        var btn = ev.target && ev.target.closest && ev.target.closest('.fwmon-ti-del');
        if (!btn) return;
        var id = btn.getAttribute('data-ti-id');
        if (!id) return;
        btn.disabled = true;
        api('/admin/api/flows/threat-intel/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function() { runSearch(searchOffset); loadFeeds(); })
            .catch(function(e) { window.fwmonLog && window.fwmonLog.error('threat-intel delete failed', e); btn.disabled = false; });
    }

    // ---- helpers -----------------------------------------------------------
    function fmtExpiry(iso) {
        if (!iso) return 'never';
        var t = new Date(iso);
        return isNaN(t.getTime()) ? 'never' : t.toISOString().slice(0, 10);
    }
    function fmtTime(iso) {
        if (!iso) return '—';
        var t = new Date(iso);
        if (isNaN(t.getTime())) return '—';
        var s = Math.floor((Date.now() - t.getTime()) / 1000);
        if (s < 0) return '—';
        if (s < 60) return s + 's ago';
        if (s < 3600) return Math.floor(s / 60) + 'm ago';
        if (s < 86400) return Math.floor(s / 3600) + 'h ago';
        return Math.floor(s / 86400) + 'd ago';
    }

    window.FwmonThreatIntel = { init: init };
})();
