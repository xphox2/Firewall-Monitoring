/* admin-events.js — Events page (Phase 2, PR 1).
 *
 * Owns the page rendered at /admin/events: the first reader of the normalized
 * net_events table. A self-contained module in the FwmonFlows style — it binds
 * its own controls, keeps its filter state in the URL (replaceState), and
 * renders the newest-first event table with paging. admin-main.js only wires
 * the `case 'events'` in loadPageData and the `events-` load-key prefix.
 *
 * The int16 activity/action/direction columns are rendered as labels via
 * window.FwmonEnums (enums.js), the JS mirror of internal/normalize/enums.go —
 * kept in lockstep by TestEnumsJSMirror.
 *
 * Public API (called from admin-main.js):
 *   FwmonEvents.init()      // bind controls, sync from URL, fetch
 *   FwmonEvents.refresh()   // re-fetch with current filter state
 *   FwmonEvents.getState()  // current filter/range state (for tests)
 */
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var esc = AC.escapeHtml;
    var formatBytes = AC.formatBytes;
    var apiFetch = AC.apiFetch;

    var DEFAULTS = { hours: 24, site_id: '', device_id: '', probe_id: '', activity: '', action: '' };
    var URL_KEYS = ['hours', 'site_id', 'device_id', 'probe_id', 'activity', 'action'];

    var state = Object.assign({}, DEFAULTS);
    var inited = false;

    // Paging: offset is the number of rows shown so far (the page's end
    // position). First page starts at 0; Next continues at offset; Prev steps
    // back two pages. Reset on every filter change.
    var offset = 0;
    var total = 0;
    var totalCapped = false;
    var PAGE_SIZE = 50;

    // Backing lists for the filter selects (id -> object), loaded lazily once
    // and cached for the session.
    var devices = [], probes = [], sites = [];

    // Common IANA protocol numbers, display-only. The table stores proto as a
    // smallint and there is no PROTO enum in FwmonEnums, so anything unlisted
    // renders as the raw number.
    var PROTO_LABELS = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 51: 'ah' };

    // enumLabel maps an int16 enum value to its name via FwmonEnums, falling
    // back to the raw value when the map is absent or the value is unknown.
    function enumLabel(mapName, v) {
        if (v == null || v === '') return '';
        var m = window.FwmonEnums && window.FwmonEnums[mapName];
        if (!m) return String(v);
        for (var k in m) {
            if (m[k] === Number(v)) return k;
        }
        return String(v);
    }

    function protoLabel(v) {
        if (v == null) return '';
        return PROTO_LABELS[v] || String(v);
    }

    // Action badge: color by verdict (allow/deny/reject/timeout), matching the
    // .badge classes used elsewhere (online=green, offline=red, warning, info).
    function actionBadge(v) {
        var label = enumLabel('ACTION', v) || 'unknown';
        var cls = 'unknown';
        if (v === 1) cls = 'online';
        else if (v === 2) cls = 'offline';
        else if (v === 3) cls = 'warning';
        else if (v === 4) cls = 'info';
        return '<span class="badge ' + cls + '">' + esc(label) + '</span>';
    }

    function endpoint(ip, port) {
        if (!ip) return '—';
        return '<span class="mono">' + esc(ip) + (port ? ':' + esc(port) : '') + '</span>';
    }

    function countries(s, d) {
        if (!s && !d) return '';
        return (s ? esc(s) : '—') + ' → ' + (d ? esc(d) : '—');
    }

    function bytes(inb, outb) {
        // "in" is received by the device, "out" is sent; show both directions,
        // but collapse to an em-dash when the vendor supplied neither counter.
        if (inb == null && outb == null) return '—';
        return '↓ ' + formatBytes(inb) + ' / ↑ ' + formatBytes(outb);
    }

    function listLabel(list, id) {
        for (var i = 0; i < list.length; i++) {
            if (String(list[i].id) === String(id)) return list[i].name || ('id:' + id);
        }
        return 'id:' + id;
    }

    function chipLabel(stateKey) {
        switch (stateKey) {
            case 'site_id': return listLabel(sites, state.site_id);
            case 'device_id': return listLabel(devices, state.device_id);
            case 'probe_id': return listLabel(probes, state.probe_id);
            case 'activity': return enumLabel('ACTIVITY', state.activity);
            case 'action': return enumLabel('ACTION', state.action);
            default: return state[stateKey];
        }
    }

    // ----------------------------------------------------------------------
    // URL state
    // ----------------------------------------------------------------------
    function stateFromURL() {
        try {
            var url = new URL(window.location.href);
            URL_KEYS.forEach(function(k) {
                var v = url.searchParams.get(k);
                if (v == null || v === '') return;
                if (k === 'hours') {
                    var n = parseFloat(v);
                    if (isFinite(n) && n > 0) state.hours = n;
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
                if (v === '' || v == null || (k === 'hours' && Number(v) === DEFAULTS.hours)) {
                    url.searchParams.delete(k);
                } else {
                    url.searchParams.set(k, String(v));
                }
            });
            window.history.replaceState(null, '', url.toString());
        } catch (e) { /* swallow */ }
    }

    // ----------------------------------------------------------------------
    // Query building
    // ----------------------------------------------------------------------
    function eventsURL(limit, off) {
        var p = ['limit=' + limit];
        if (off > 0) p.push('offset=' + off);
        if (state.hours && Number(state.hours) !== 24) p.push('hours=' + encodeURIComponent(state.hours));
        if (state.site_id) p.push('site_id=' + encodeURIComponent(state.site_id));
        if (state.device_id) p.push('device_id=' + encodeURIComponent(state.device_id));
        if (state.probe_id) p.push('probe_id=' + encodeURIComponent(state.probe_id));
        if (state.activity !== '') p.push('activity=' + encodeURIComponent(state.activity));
        if (state.action !== '') p.push('action=' + encodeURIComponent(state.action));
        return '/admin/api/events?' + p.join('&');
    }

    // ----------------------------------------------------------------------
    // Backing-list loading (devices / probes / sites), cached for the session
    // ----------------------------------------------------------------------
    function ensureLists() {
        var needs = [];
        if (devices.length === 0) {
            needs.push(apiFetch('/admin/api/devices').then(function(r) { devices = (r && r.data) || []; }).catch(function() {}));
        }
        if (probes.length === 0) {
            needs.push(apiFetch('/admin/api/probes').then(function(r) { probes = (r && r.data) || []; }).catch(function() {}));
        }
        if (sites.length === 0) {
            needs.push(apiFetch('/admin/api/sites').then(function(r) { sites = (r && r.data) || []; }).catch(function() {}));
        }
        return Promise.all(needs).then(populateSelects);
    }

    function populateListSelect(id, list, field, allLabel) {
        var sel = document.getElementById(id);
        if (!sel) return;
        var current = sel.value;
        var html = '<option value="">' + allLabel + '</option>';
        for (var i = 0; i < list.length; i++) {
            var it = list[i];
            var label = it[field] || ('id:' + it.id);
            // Retired devices stay selectable (their events are still stored)
            // but are labelled so they read apart from the active fleet.
            if (id === 'events-filter-device' && it.retired_at) label += ' (retired)';
            html += '<option value="' + it.id + '"' + (String(it.id) === current ? ' selected' : '') + '>' + esc(label) + '</option>';
        }
        sel.innerHTML = html;
        sel.value = current;
    }

    function populateEnumSelect(id, mapName, allLabel) {
        var sel = document.getElementById(id);
        if (!sel) return;
        var m = window.FwmonEnums && window.FwmonEnums[mapName];
        if (!m) return;
        var current = sel.value;
        var keys = Object.keys(m).sort();
        var html = '<option value="">' + allLabel + '</option>';
        for (var i = 0; i < keys.length; i++) {
            html += '<option value="' + m[keys[i]] + '">' + esc(keys[i]) + '</option>';
        }
        sel.innerHTML = html;
        sel.value = current;
    }

    function populateSelects() {
        populateListSelect('events-filter-device', devices, 'name', 'All Devices');
        populateListSelect('events-filter-probe', probes, 'name', 'All Probes');
        populateListSelect('events-filter-site', sites, 'name', 'All Sites');
        populateEnumSelect('events-filter-activity', 'ACTIVITY', 'All Activity');
        populateEnumSelect('events-filter-action', 'ACTION', 'All Actions');
    }

    // ----------------------------------------------------------------------
    // Control wiring
    // ----------------------------------------------------------------------
    function bindControls() {
        var rangePills = document.getElementById('events-range-pills');
        if (rangePills && !rangePills.__fwmonEventsBound) {
            rangePills.__fwmonEventsBound = true;
            rangePills.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('.chart-range-pill');
                if (!btn) return;
                var h = parseFloat(btn.getAttribute('data-range'));
                if (isFinite(h)) {
                    state.hours = h;
                    applyState();
                    syncURL();
                    firstPage();
                }
            });
        }

        [
            { id: 'events-filter-site', key: 'site_id' },
            { id: 'events-filter-device', key: 'device_id' },
            { id: 'events-filter-probe', key: 'probe_id' },
            { id: 'events-filter-activity', key: 'activity' },
            { id: 'events-filter-action', key: 'action' }
        ].forEach(function(spec) { bindSelect(spec.id, spec.key); });

        var clearBtn = document.getElementById('events-clear-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                state.site_id = '';
                state.device_id = '';
                state.probe_id = '';
                state.activity = '';
                state.action = '';
                applyState();
                syncURL();
                firstPage();
            });
        }

        var pag = document.getElementById('events-pagination');
        if (pag && !pag.__fwmonEventsBound) {
            pag.__fwmonEventsBound = true;
            pag.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('[data-events-page]');
                if (!btn || btn.disabled) return;
                var dir = btn.getAttribute('data-events-page');
                if (dir === 'next') nextPage();
                else if (dir === 'prev') prevPage();
            });
        }
    }

    function bindSelect(elId, stateKey) {
        var el = document.getElementById(elId);
        if (!el || el.__fwmonEventsBound) return;
        el.__fwmonEventsBound = true;
        el.addEventListener('change', function() {
            state[stateKey] = el.value || '';
            applyState();
            syncURL();
            firstPage();
        });
    }

    function setVal(id, v) {
        var el = document.getElementById(id);
        if (el && el.value !== String(v || '')) el.value = v || '';
    }

    function applyState() {
        setVal('events-filter-site', state.site_id);
        setVal('events-filter-device', state.device_id);
        setVal('events-filter-probe', state.probe_id);
        setVal('events-filter-activity', state.activity);
        setVal('events-filter-action', state.action);
        activatePills();
        renderChips();
    }

    function activatePills() {
        var pills = document.querySelectorAll('#events-range-pills .chart-range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', parseFloat(pills[i].getAttribute('data-range')) === Number(state.hours));
        }
    }

    function renderChips() {
        var host = document.getElementById('events-active-chips');
        if (!host) return;
        var defs = [
            { key: 'site', stateKey: 'site_id' },
            { key: 'device', stateKey: 'device_id' },
            { key: 'probe', stateKey: 'probe_id' },
            { key: 'activity', stateKey: 'activity' },
            { key: 'action', stateKey: 'action' }
        ];
        var html = '';
        for (var i = 0; i < defs.length; i++) {
            var v = state[defs[i].stateKey];
            if (v === '' || v == null) continue;
            html += '<span class="fwmon-chip" data-statekey="' + esc(defs[i].stateKey) + '">' +
                '<span class="fwmon-chip-key">' + esc(defs[i].key) + '</span>' +
                '<span class="fwmon-chip-val">' + esc(chipLabel(defs[i].stateKey)) + '</span>' +
                '<button type="button" class="fwmon-chip-clear" aria-label="Clear filter">×</button></span>';
        }
        host.innerHTML = html;
        if (!html) return;
        var clears = host.querySelectorAll('.fwmon-chip-clear');
        for (var j = 0; j < clears.length; j++) {
            clears[j].addEventListener('click', function(ev) {
                var chip = ev.target.closest('.fwmon-chip');
                if (!chip) return;
                var k = chip.getAttribute('data-statekey');
                if (k) {
                    state[k] = '';
                    applyState();
                    syncURL();
                    firstPage();
                }
            });
        }
    }

    // ----------------------------------------------------------------------
    // Loading / paging
    // ----------------------------------------------------------------------
    function firstPage() {
        offset = 0;
        load(0);
    }

    function nextPage() {
        load(offset);
    }

    function prevPage() {
        load(Math.max(0, offset - 2 * PAGE_SIZE));
    }

    function load(targetOffset) {
        var host = document.getElementById('events-load-host');
        // chartLoad supersedes any in-flight 'events-list' load, so a fast
        // paging/filter click always wins over a stale one; leaving the page
        // cancels it silently (PAGE_LOAD_KEYS.events in admin-main.js).
        AC.chartLoad(host, function(signal) {
            return ensureLists().then(function() {
                return apiFetch(eventsURL(PAGE_SIZE, targetOffset), { signal: signal });
            });
        }, { key: 'events-list', label: 'Loading events…', escScope: document.getElementById('page-events') }).then(function(r) {
            if (r.superseded) return;
            if (r.cancelled) return; // the rows on screen stay
            if (r.error || !r.data) {
                if (window.fwmonLog) fwmonLog.error('FwmonEvents: fetch failed', r.error);
                AC.chartNotice(host, 'Could not load events', { dim: false, onRetry: function() { load(targetOffset); } });
                return;
            }
            var payload = r.data.data || {};
            offset = targetOffset + (payload.events || []).length;
            render(payload);
        });
    }

    // ----------------------------------------------------------------------
    // Rendering
    // ----------------------------------------------------------------------
    function render(payload) {
        var rows = payload.events || [];
        total = payload.total || 0;
        totalCapped = !!(payload.total_capped);
        var tbody = document.querySelector('#events-table tbody');
        if (!tbody) return;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="11" class="empty-state">No events in this range</td></tr>';
            document.getElementById('events-pagination').innerHTML = '';
            return;
        }
        tbody.innerHTML = rows.map(renderRow).join('');
        updatePagination(rows.length);
    }

    function renderRow(r) {
        var threat = r.threat_flag ? '<span class="badge critical" title="Threat-flagged event">THREAT</span>' : '';
        var direction = enumLabel('DIRECTION', r.direction);
        var app = r.app || r.app_cat || '';
        return '<tr>' +
            '<td class="td-nowrap">' + AC.formatDate(r.ts) + '</td>' +
            '<td>' + (r.device_name ? AC.deviceLink(r.device_id, r.device_name) : esc('DEV-' + r.device_id)) +
                (r.vendor ? ' <span class="badge unknown">' + esc(r.vendor) + '</span>' : '') + '</td>' +
            '<td>' + endpoint(r.src_ip, r.src_port) + ' → ' + endpoint(r.dst_ip, r.dst_port) +
                (r.proto ? ' <span class="badge info">' + esc(protoLabel(r.proto)) + '</span>' : '') + '</td>' +
            '<td>' + actionBadge(r.action) + '</td>' +
            '<td>' + esc(enumLabel('ACTIVITY', r.activity)) + '</td>' +
            '<td>' + esc(direction || '—') + '</td>' +
            '<td>' + esc(app || '—') + '</td>' +
            '<td>' + esc(r.user_name || '—') + '</td>' +
            '<td class="mono">' + countries(r.src_country, r.dst_country) + '</td>' +
            '<td class="td-nowrap">' + bytes(r.bytes_in, r.bytes_out) + '</td>' +
            '<td>' + threat + '</td>' +
        '</tr>';
    }

    function updatePagination(count) {
        var container = document.getElementById('events-pagination');
        if (!container) return;
        if (total === 0) {
            container.innerHTML = '';
            return;
        }
        var more = totalCapped ? '+' : '';
        var from = offset - count + 1;
        var to = offset;
        var currentPage = Math.floor(offset / PAGE_SIZE) + 1;
        var totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        // Past the cap the server stops counting, so "at end" is signalled by a
        // short page rather than by reaching the total.
        var atEnd = totalCapped ? count < PAGE_SIZE : offset >= total;
        container.innerHTML =
            '<span style="color:var(--fwmon-text-faint);">Showing ' + from + '-' + to + ' of ' + total.toLocaleString() + more + ' matching filters &nbsp;|&nbsp; </span>' +
            '<button type="button" class="btn secondary sm" data-events-page="prev"' + (offset <= 0 ? ' disabled' : '') + '>Prev</button> ' +
            '<span style="color:var(--fwmon-text-faint);">Page ' + currentPage + ' of ' + totalPages.toLocaleString() + more + ' &nbsp;</span>' +
            '<button type="button" class="btn secondary sm" data-events-page="next"' + (atEnd ? ' disabled' : '') + '>Next</button>';
    }

    // ----------------------------------------------------------------------
    // Boot
    // ----------------------------------------------------------------------
    function init() {
        if (inited) {
            // Re-init is a no-op other than re-reading the URL (the user may
            // have navigated back to the tab). Force a first-page reload.
            stateFromURL();
            applyState();
            firstPage();
            return;
        }
        inited = true;
        stateFromURL();
        bindControls();
        applyState();
        firstPage();
    }

    function refresh() { firstPage(); }
    function getState() { return Object.assign({}, state); }

    window.FwmonEvents = {
        init: init,
        refresh: refresh,
        getState: getState
    };
})();
