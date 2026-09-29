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

    // AUDIT-233: AC must live at MODULE scope. onMasterToggle/onFeedToggle/
    // onStormSave reference bare `AC.showToast`; without a module-scope binding
    // those threw ReferenceError, which the chained .catch swallowed — so no
    // success toast ever appeared and onFeedToggle's table did not refresh after
    // a successful toggle (the throw skipped the .then's loadFeeds(), and its
    // .catch does not reload). admin-threatintel.js is deferred after
    // admin-common.js, which sets window.AdminCommon before this runs.
    var AC = window.AdminCommon;

    var PAGE_SIZE = 100;
    var searchOffset = 0;
    var searchTotal = 0;
    var wired = false;

    function esc(s) {
        var f = (window.AdminCommon && window.AdminCommon.escapeHtml);
        return f ? f(String(s == null ? '' : s)) : String(s == null ? '' : s);
    }
    function api(path, opts) {
        if (!AC || !AC.apiFetch) return Promise.reject(new Error('AdminCommon unavailable'));
        return AC.apiFetch(path, opts);
    }
    function el(id) { return document.getElementById(id); }

    function init() {
        wire();
        loadFeeds();
        loadStormTuning();
        runSearch(0);
        var r = el('ti-lookup-result'); if (r) r.innerHTML = '';
        shownLookupQ = null; // the result area was just cleared
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
        // Paging continues the search whose rows are shown (lastSearch), not
        // what is typed in the box, and waits for a search still running.
        if (prev) prev.addEventListener('click', function() { if (searchOffset > 0) pageSearch(searchOffset - PAGE_SIZE); });
        var next = el('ti-search-next');
        if (next) next.addEventListener('click', function() { if (searchOffset + PAGE_SIZE < searchTotal) pageSearch(searchOffset + PAGE_SIZE); });
        var addForm = el('ti-add-form');
        if (addForm) addForm.addEventListener('submit', onAdd);
        var body = el('ti-search-body');
        if (body) body.addEventListener('click', onDelete);
        // v0.11.46: feed controls.
        var master = el('ti-master-toggle');
        if (master) master.addEventListener('change', onMasterToggle);
        var feedsBody = el('ti-feeds-body');
        if (feedsBody) feedsBody.addEventListener('click', onFeedToggle);
        var stormSave = el('ti-storm-save');
        if (stormSave) stormSave.addEventListener('click', onStormSave);
    }

    // ---- Lookup ------------------------------------------------------------
    // The lookup whose result is on screen (null before the first one).
    var shownLookupQ = null;

    function onLookup(ev) {
        ev.preventDefault();
        var q = (el('ti-lookup-q').value || '').trim();
        if (!q) return;
        var errEl = el('ti-lookup-error');
        if (errEl) { errEl.hidden = true; errEl.textContent = ''; }
        var host = el('ti-lookup-result');
        AC.chartLoad(host, function(signal) {
            return api('/admin/api/threat-intel/lookup?q=' + encodeURIComponent(q), { signal: signal });
        }, { key: 'ti-lookup', label: 'Looking up…', escScope: el('ti-lookup-form') }).then(function(r) {
            if (r.superseded) return;
            if (r.cancelled) {
                // The box goes back to the lookup whose result is shown.
                if (shownLookupQ !== null) el('ti-lookup-q').value = shownLookupQ;
                AC.chartNotice(host, shownLookupQ !== null ? 'Cancelled — showing the previous results' : 'Cancelled', { dim: false, onRetry: function() {
                    el('ti-lookup-q').value = q; // re-apply the cancelled lookup
                    onLookup({ preventDefault: function() {} });
                } });
                return;
            }
            if (r.error) {
                // The reason (often "not an IP or ASN") stays next to the box,
                // and the typed text is kept so it can be corrected; the notice
                // over the previous result offers Retry.
                if (errEl) { errEl.textContent = (r.error && r.error.message) || 'Lookup failed.'; errEl.hidden = false; }
                AC.chartNotice(host, shownLookupQ !== null ? 'Could not look up — showing the previous result' : 'Could not look up', { dim: false, onRetry: function() {
                    el('ti-lookup-q').value = q;
                    onLookup({ preventDefault: function() {} });
                } });
                return;
            }
            shownLookupQ = q;
            renderLookup((r.data && r.data.data) || {});
        });
    }

    function renderLookup(d) {
        var host = el('ti-lookup-result');
        if (!host) return;
        var rows = [];
        rows.push(kv('Query', esc(d.query)));
        if (d.kind === 'asn') {
            rows.push(kv('AS number', 'AS' + esc(d.asn)));
        } else {
            rows.push(kv('Country', d.country ? esc(d.country) : '—'));
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
            '<div style="min-width:110px; color:var(--fwmon-text-faint);">' + esc(k) + '</div>' +
            '<div>' + v + '</div></div>';
    }

    // ---- Feed status -------------------------------------------------------
    function loadFeeds() {
        api('/admin/api/threat-intel/feeds')
            .then(function(res) { renderFeeds((res && res.data) || {}); })
            .catch(function(e) { window.fwmonLog && window.fwmonLog.error('threat-intel feeds fetch failed', e); });
    }

    function renderFeeds(d) {
        var masterOn = d.feeds_enabled !== false;
        var hint = el('ti-feeds-hint');
        if (hint) {
            hint.textContent = !masterOn
                ? 'online feeds DISABLED via master switch'
                : 'every ' + esc(d.interval || '?') + ' · TTL ' + esc(d.ttl_days) + 'd · ' + esc(d.loaded_count || 0) + ' loaded';
        }
        var summary = el('ti-summary');
        if (summary) {
            summary.textContent = (!masterOn ? 'Feeds disabled · ' : 'Feeds enabled · ') +
                (d.loaded_count || 0) + ' indicators loaded in matcher';
        }
        var master = el('ti-master-toggle');
        if (master) master.checked = masterOn;
        var mnote = el('ti-master-note');
        if (mnote) mnote.textContent = masterOn ? '' : 'matching is off — indicators retained for instant re-enable';

        var body = el('ti-feeds-body');
        if (!body) return;
        var rows = (d.status) || [];
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="fwmon-ti-empty">No feed syncs recorded yet. The poller fetches ~1 min after startup, then every ' + esc(d.interval || 'interval') + '.</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            var feedOn = r.enabled !== false;
            var status = r.last_error
                ? '<span class="fwmon-det-sev fwmon-det-sev-critical" title="' + esc(r.last_error) + '">error</span>'
                : (feedOn ? '<span class="fwmon-det-sev fwmon-det-sev-info">ok</span>'
                          : '<span class="fwmon-det-sev fwmon-det-sev-warning" title="disabled — excluded from matching">disabled</span>');
            var toggle = '<button type="button" class="btn sm ti-feed-toggle" data-source="' + esc(r.source) +
                '" data-enabled="' + (feedOn ? '1' : '0') + '">' + (feedOn ? 'Disable' : 'Enable') + '</button>';
            html += '<tr>' +
                '<td>' + esc(r.source) + '</td>' +
                '<td>' + esc(r.kind || 'ip') + '</td>' +
                '<td>' + esc(r.category || '') + '</td>' +
                '<td>' + esc(r.entry_count || 0) + '</td>' +
                '<td>' + fmtTime(r.last_sync_at) + '</td>' +
                '<td>' + status + '</td>' +
                '<td>' + toggle + '</td>' +
            '</tr>';
        }
        body.innerHTML = html;
    }

    // ---- Feed controls (v0.11.46) -----------------------------------------
    function onMasterToggle(ev) {
        var enabled = !!(ev.target && ev.target.checked);
        api('/admin/api/threat-intel/global', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        }).then(function(res) {
            var note = res && res.data && res.data.note;
            if (note && AC && AC.showToast) AC.showToast(note);
            loadFeeds();
        }).catch(function(e) {
            window.fwmonLog && window.fwmonLog.error('master toggle failed', e);
            loadFeeds(); // revert the checkbox to server truth
        });
    }

    function onFeedToggle(ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest('.ti-feed-toggle') : null;
        if (!btn) return;
        var source = btn.getAttribute('data-source');
        var enable = btn.getAttribute('data-enabled') === '0'; // currently off → enable
        if (!enable && !window.confirm('Disable feed "' + source + '"? Its indicators will be purged from matching immediately.')) return;
        btn.disabled = true;
        api('/admin/api/threat-intel/feeds/' + encodeURIComponent(source), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enable })
        }).then(function(res) {
            var note = res && res.data && res.data.note;
            if (note && AC && AC.showToast) AC.showToast(note);
            loadFeeds();
        }).catch(function(e) {
            window.fwmonLog && window.fwmonLog.error('feed toggle failed', e);
            btn.disabled = false;
        });
    }

    function loadStormTuning() {
        api('/admin/api/threat-intel/storm-tuning')
            .then(function(res) {
                var v = res && res.data && res.data.storm_sources;
                var input = el('ti-storm-input');
                if (input && v != null) input.value = v;
            })
            .catch(function(e) { window.fwmonLog && window.fwmonLog.error('storm tuning fetch failed', e); });
    }

    function onStormSave() {
        var input = el('ti-storm-input');
        if (!input) return;
        var n = parseInt(input.value, 10);
        if (isNaN(n) || n < 0) { if (AC && AC.showToast) AC.showToast('Enter a number ≥ 0 (0 disables the digest)'); return; }
        api('/admin/api/threat-intel/storm-tuning', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ storm_sources: n })
        }).then(function(res) {
            var v = res && res.data && res.data.storm_sources;
            if (v != null) input.value = v;
            if (AC && AC.showToast) AC.showToast(n === 0 ? 'Storm digest disabled globally' : 'Storm threshold saved: ' + v + ' sources');
        }).catch(function(e) { window.fwmonLog && window.fwmonLog.error('storm tuning save failed', e); });
    }

    // ---- Search ------------------------------------------------------------
    // The search controls have no state object: lastSearch is the query whose
    // results are on screen, written back into the controls if a newer search
    // is cancelled. The offset changes only when results arrive.
    var lastSearch = null;
    function searchControls() {
        return {
            q: (el('ti-search-q').value || '').trim(),
            source: (el('ti-search-source').value || '').trim(),
            category: (el('ti-search-category').value || '').trim(),
            severity: el('ti-search-severity').value || ''
        };
    }
    function setSearchControls(c) {
        el('ti-search-q').value = c.q;
        el('ti-search-source').value = c.source;
        el('ti-search-category').value = c.category;
        el('ti-search-severity').value = c.severity;
    }

    // A refresh asked for while a search runs (after a delete) is deferred to
    // when it settles — a cancelled/failed search keeps the old rows.
    var searchRefreshDeferred = false;
    // Whether a deferred refresh goes back to page 1 (after an add) or re-shows
    // the page on screen WHEN IT RUNS (after a delete). The intent is kept, not
    // the offset: a newer search or page change in between must not be paired
    // with an offset from before it.
    var searchRefreshToStart = false;
    function pageSearch(offset, isRefresh) {
        if (AC.chartLoadBusy('ti-search', true)) { if (isRefresh) { searchRefreshDeferred = true; searchRefreshToStart = searchRefreshToStart || offset === 0; } return; }
        runSearch(offset, lastSearch, isRefresh);
    }
    function runDeferredSearchRefresh() {
        if (!searchRefreshDeferred || AC.chartLoadBusy('ti-search', true)) return;
        searchRefreshDeferred = false; // consumed either way: init() reloads on return
        var tiPage = document.getElementById('page-threat-intel');
        if (!tiPage || !tiPage.classList.contains('active')) return;
        searchRefreshDeferred = false;
        var toStart = searchRefreshToStart;
        searchRefreshToStart = false;
        pageSearch(toStart ? 0 : searchOffset, true);
    }

    // The search form (its inputs) — Esc there cancels the search; Esc in the
    // manual-add form below does not.
    function searchForm() {
        var q = el('ti-search-q');
        return (q && q.closest) ? (q.closest('.fwmon-ti-form') || q.parentNode) : [];
    }
    function typingNewSearch(failed) {
        var a = document.activeElement;
        var ids = { 'ti-search-q': 'q', 'ti-search-source': 'source', 'ti-search-category': 'category' };
        var k = a && ids[a.id];
        return !!k && (a.value || '').trim() !== (failed[k] || '');
    }
    // Deferred refreshes run after the current search's .then has finished.
    function runDeferredSearchRefreshSoon() { setTimeout(runDeferredSearchRefresh, 0); }

    // snap (optional): the query to run — paging passes lastSearch; a new
    // search reads the controls.
    // isRefresh: this search re-shows the list after a delete; if another
    // search interrupts it, the refresh is re-armed for when that one settles.
    function runSearch(offset, snap, isRefresh) {
        var target = offset < 0 ? 0 : offset;
        var query = snap ? Object.assign({}, snap) : searchControls();
        var params = 'offset=' + target + '&limit=' + PAGE_SIZE +
            '&q=' + encodeURIComponent(query.q) +
            '&source=' + encodeURIComponent(query.source) +
            '&category=' + encodeURIComponent(query.category) +
            '&severity=' + encodeURIComponent(query.severity);
        var host = el('ti-search-host');
        AC.chartLoad(host, function(signal) {
            return api('/admin/api/threat-intel/search?' + params, { signal: signal });
        }, { key: 'ti-search', label: 'Searching…', escScope: searchForm() }).then(function(r) {
            if (r.superseded) {
                if (isRefresh && AC.chartLoadBusy('ti-search', true)) { searchRefreshDeferred = true; searchRefreshToStart = searchRefreshToStart || target === 0; }
                // Left the page (nothing newer took over): init() reloads on
                // return, so a deferred refresh is consumed, not replayed.
                else if (!AC.chartLoadBusy('ti-search', true)) searchRefreshDeferred = false;
                return;
            }
            runDeferredSearchRefreshSoon();
            // A paging load (snap) never changed the controls, so neither its
            // Cancel nor its Retry touches them — the box may hold a new,
            // unsubmitted search.
            var paging = !!snap;
            var retry = function() { if (!paging) setSearchControls(query); runSearch(target, paging ? query : undefined); };
            if (r.cancelled) {
                if (lastSearch && !paging) setSearchControls(lastSearch);
                AC.chartNotice(host, lastSearch ? 'Cancelled — showing the previous results' : 'Cancelled', { dim: false, onRetry: retry });
                return;
            }
            if (r.error) {
                if (window.fwmonLog) window.fwmonLog.error('threat-intel search failed', r.error);
                // Like Cancel, the controls go back to the search whose rows
                // are shown — unless the user is typing the next one (a field
                // of the form has focus and differs from the failed query).
                if (lastSearch && !paging && !typingNewSearch(query)) setSearchControls(lastSearch);
                AC.chartNotice(host, 'Could not load results', { dim: false, onRetry: retry });
                return;
            }
            searchOffset = target;
            lastSearch = query;
            renderSearch((r.data && r.data.data) || {});
        });
    }

    function renderSearch(d) {
        searchTotal = d.total || 0;
        var body = el('ti-search-body');
        if (body) {
            var rows = d.entries || [];
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="6" class="fwmon-ti-empty">No matching indicators.</td></tr>';
            } else {
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
            // Like a delete: refresh the shown search (deferred while one runs,
            // nothing when the page was left — init() reloads on return).
            var tiPage = document.getElementById('page-threat-intel');
            if (tiPage && tiPage.classList.contains('active')) pageSearch(0, true);
            loadFeeds();
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
            .then(function() {
                // Like an add: nothing when the page was left (init() reloads).
                var tiPage = document.getElementById('page-threat-intel');
                if (tiPage && tiPage.classList.contains('active')) pageSearch(searchOffset, true);
                loadFeeds();
            })
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
