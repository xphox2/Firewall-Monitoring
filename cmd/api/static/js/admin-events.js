/* admin-events.js — Events page (Phase 2, PR 1 + PR 3 + PR 4 + PR 5 + PR 6 + PR 7).
 *
 * Owns the page rendered at /admin/events: the readers of the normalized
 * net_events (Network tab, PR 1) and sec_events (Security tab, PR 3) tables. A
 * self-contained module in the FwmonFlows style — it binds its own controls,
 * keeps its filter state in the URL (replaceState), and renders the
 * newest-first event tables with paging. admin-main.js only wires the
 * `case 'events'` in loadPageData and the `events-` load-key prefix.
 *
 * The two tabs share the time range (the page-level range pills) but otherwise
 * keep independent filter state: the Network tab filters by the net_events
 * columns, the Security tab by class plus its class-conditional columns. The
 * Security table's columns adapt to the class filter (finding → signature/threat/
 * hash, auth → admin user/source/method, config_change → path/object,
 * vpn_session → tunnel/peer, device_health → WAN/metric), falling back to
 * activity/action/message when no class is selected.
 *
 * The int16 activity/action/class columns are rendered as labels via
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

    var DEFAULTS = { hours: 24, site_id: '', device_id: '', probe_id: '', activity: '', action: '', src_ip: '', dst_ip: '', rule_key: '' };
    var URL_KEYS = ['hours', 'site_id', 'device_id', 'probe_id', 'activity', 'action', 'src_ip', 'dst_ip', 'rule_key'];

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

    // Security tab state (Phase 2, PR 3). The Security tab shares the network
    // tab's `state.hours` (the page-level range pills) but keeps its own filter
    // state and paging, so a class filter never bleeds into the Network tab.
    var SEC_URL_KEYS = ['sec_class', 'sec_device', 'sec_severity', 'sec_admin_user', 'sec_sig_name', 'sec_tunnel_name', 'sec_wan_name'];
    var secState = { sec_class: '', sec_device: '', sec_severity: '', sec_admin_user: '', sec_sig_name: '', sec_tunnel_name: '', sec_wan_name: '' };
    var secOffset = 0;
    var secTotal = 0;
    var secTotalCapped = false;
    var SEC_PAGE_SIZE = 50;
    var activeTab = 'network'; // 'network' | 'security'

    // Class-conditional columns for the Security table. The keys are the class
    // ids from FwmonEnums.CLASS; each entry is a [field, header] pair rendered
    // after the common Time/Device/Class/Severity columns. A missing/blank class
    // falls back to the generic activity/action/message set.
    var SEC_COLUMNS = {
        '2004': [['sig_name', 'Signature'], ['threat_cat', 'Threat cat'], ['file_hash', 'File hash']],           // finding
        '3002': [['admin_user', 'Admin user'], ['admin_src_ip', 'Admin src IP'], ['admin_method', 'Method']],    // auth
        '5019': [['config_path', 'Config path'], ['config_obj', 'Object']],                                      // config_change
        '4014': [['tunnel_name', 'Tunnel name'], ['tunnel_peer', 'Peer']],                                       // vpn_session
        '5001': [['wan_name', 'WAN name'], ['metric_name', 'Metric'], ['metric_value', 'Value']]                 // device_health
    };
    var SEC_COLUMNS_ALL = [['activity', 'Activity'], ['action', 'Action'], ['message', 'Message']];

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
            SEC_URL_KEYS.forEach(function(k) {
                var v = url.searchParams.get(k);
                if (v == null || v === '') return;
                secState[k] = v;
            });
            var tab = url.searchParams.get('events_tab');
            if (tab === 'network' || tab === 'security') activeTab = tab;
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
            SEC_URL_KEYS.forEach(function(k) {
                if (secState[k] === '' || secState[k] == null) {
                    url.searchParams.delete(k);
                } else {
                    url.searchParams.set(k, String(secState[k]));
                }
            });
            if (activeTab !== 'network') {
                url.searchParams.set('events_tab', activeTab);
            } else {
                url.searchParams.delete('events_tab');
            }
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
        if (state.src_ip) p.push('src_ip=' + encodeURIComponent(state.src_ip));
        if (state.dst_ip) p.push('dst_ip=' + encodeURIComponent(state.dst_ip));
        if (state.rule_key) p.push('rule_key=' + encodeURIComponent(state.rule_key));
        return '/admin/api/events?' + p.join('&');
    }

    // secEventsURL builds the Security tab's query. It shares `state.hours` (the
    // page-level range pills) but sends only the sec_events filter columns.
    function secEventsURL(limit, off) {
        var p = ['limit=' + limit];
        if (off > 0) p.push('offset=' + off);
        if (state.hours && Number(state.hours) !== 24) p.push('hours=' + encodeURIComponent(state.hours));
        if (secState.sec_class) p.push('class=' + encodeURIComponent(secState.sec_class));
        if (secState.sec_device) p.push('device_id=' + encodeURIComponent(secState.sec_device));
        if (secState.sec_severity !== '') p.push('severity=' + encodeURIComponent(secState.sec_severity));
        if (secState.sec_admin_user) p.push('admin_user=' + encodeURIComponent(secState.sec_admin_user));
        if (secState.sec_sig_name) p.push('sig_name=' + encodeURIComponent(secState.sec_sig_name));
        if (secState.sec_tunnel_name) p.push('tunnel_name=' + encodeURIComponent(secState.sec_tunnel_name));
        if (secState.sec_wan_name) p.push('wan_name=' + encodeURIComponent(secState.sec_wan_name));
        return '/admin/api/security-events?' + p.join('&');
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
        populateListSelect('sec-events-filter-device', devices, 'name', 'All Devices');
        populateSecClassSelect();
    }

    // populateSecClassSelect fills the Security tab's class dropdown from
    // FwmonEnums.CLASS, skipping 'network' — those events live on the Network
    // tab, so offering it here would only ever return an empty table.
    function populateSecClassSelect() {
        var sel = document.getElementById('sec-events-filter-class');
        if (!sel) return;
        var m = window.FwmonEnums && window.FwmonEnums['CLASS'];
        if (!m) return;
        var current = sel.value;
        var keys = Object.keys(m).sort();
        var html = '<option value="">All Classes</option>';
        for (var i = 0; i < keys.length; i++) {
            if (keys[i] === 'network') continue;
            html += '<option value="' + m[keys[i]] + '">' + esc(keys[i]) + '</option>';
        }
        sel.innerHTML = html;
        sel.value = current;
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
                    secApplyState();
                    syncURL();
                    if (activeTab === 'security') secFirstPage();
                    else firstPage();
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

        [
            { id: 'events-filter-src-ip', key: 'src_ip' },
            { id: 'events-filter-dst-ip', key: 'dst_ip' },
            { id: 'events-filter-rule-key', key: 'rule_key' }
        ].forEach(function(spec) { bindInput(spec.id, spec.key); });

        var clearBtn = document.getElementById('events-clear-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                state.site_id = '';
                state.device_id = '';
                state.probe_id = '';
                state.activity = '';
                state.action = '';
                state.src_ip = '';
                state.dst_ip = '';
                state.rule_key = '';
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

        bindSecControls();
        bindRowClicks();
        bindEventModal();
    }

    // bindEventModal wires the event-detail modal's own close buttons (the modal
    // is a static DOM element, so a delegated listener on it is enough and keeps
    // this module self-contained, matching admin-flows.js's detection modal).
    function bindEventModal() {
        var modal = document.getElementById('event-detail-modal');
        if (!modal || modal.__fwmonEventsBound) return;
        modal.__fwmonEventsBound = true;
        modal.addEventListener('click', function(ev) {
            if (ev.target.closest('[data-action="close-event-detail"]')) {
                AC.closeModal('event-detail-modal');
            }
        });
    }

    // bindRowClicks wires a delegated click on both event tables: a click on a
    // row (outside any in-row device link) opens the detail modal for that
    // event. Idempotent via the per-table __fwmonEventsRowBound guard.
    function bindRowClicks() {
        [
            { id: 'events-table', kind: 'net' },
            { id: 'sec-events-table', kind: 'sec' }
        ].forEach(function(spec) {
            var table = document.getElementById(spec.id);
            if (!table || table.__fwmonEventsRowBound) return;
            table.__fwmonEventsRowBound = true;
            table.addEventListener('click', function(ev) {
                if (ev.target.closest('a')) return; // in-row device links navigate
                var tr = ev.target.closest('tr[data-evt-id]');
                if (!tr) return;
                showEventDetail(tr.getAttribute('data-evt-id'), spec.kind);
            });
        });
    }

    // bindSecControls wires the Security tab: the class/device/severity selects,
    // the four text inputs, the clear button and the pagination. It is idempotent
    // via the same __fwmonEventsBound guard as the network controls.
    function bindSecControls() {
        var viewTabs = document.getElementById('events-view-tabs');
        if (viewTabs && !viewTabs.__fwmonEventsBound) {
            viewTabs.__fwmonEventsBound = true;
            viewTabs.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('.fwmon-flows-tab');
                if (!btn) return;
                setActiveTab(btn.getAttribute('data-events-tab'));
            });
        }

        [
            { id: 'sec-events-filter-class', key: 'sec_class' },
            { id: 'sec-events-filter-device', key: 'sec_device' },
            { id: 'sec-events-filter-severity', key: 'sec_severity' }
        ].forEach(function(spec) { bindSecSelect(spec.id, spec.key); });

        [
            { id: 'sec-events-filter-admin-user', key: 'sec_admin_user' },
            { id: 'sec-events-filter-sig-name', key: 'sec_sig_name' },
            { id: 'sec-events-filter-tunnel-name', key: 'sec_tunnel_name' },
            { id: 'sec-events-filter-wan-name', key: 'sec_wan_name' }
        ].forEach(function(spec) { bindSecInput(spec.id, spec.key); });

        var clearBtn = document.getElementById('sec-events-clear-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                secState.sec_class = '';
                secState.sec_device = '';
                secState.sec_severity = '';
                secState.sec_admin_user = '';
                secState.sec_sig_name = '';
                secState.sec_tunnel_name = '';
                secState.sec_wan_name = '';
                secApplyState();
                syncURL();
                secFirstPage();
            });
        }

        var pag = document.getElementById('sec-events-pagination');
        if (pag && !pag.__fwmonEventsBound) {
            pag.__fwmonEventsBound = true;
            pag.addEventListener('click', function(ev) {
                var btn = ev.target && ev.target.closest && ev.target.closest('[data-sec-events-page]');
                if (!btn || btn.disabled) return;
                var dir = btn.getAttribute('data-sec-events-page');
                if (dir === 'next') secNextPage();
                else if (dir === 'prev') secPrevPage();
            });
        }
    }

    function bindSecSelect(elId, stateKey) {
        var el = document.getElementById(elId);
        if (!el || el.__fwmonEventsBound) return;
        el.__fwmonEventsBound = true;
        el.addEventListener('change', function() {
            secState[stateKey] = el.value || '';
            secApplyState();
            syncURL();
            secFirstPage();
        });
    }

    function bindSecInput(elId, stateKey) {
        var el = document.getElementById(elId);
        if (!el || el.__fwmonEventsBound) return;
        el.__fwmonEventsBound = true;
        var pending = null;
        var commit = function() {
            secState[stateKey] = el.value.trim();
            secApplyState();
            syncURL();
            secFirstPage();
        };
        el.addEventListener('input', function() {
            if (pending) clearTimeout(pending);
            pending = setTimeout(commit, 400);
        });
        el.addEventListener('blur', function() {
            if (pending) { clearTimeout(pending); pending = null; }
            commit();
        });
        el.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') {
                if (pending) { clearTimeout(pending); pending = null; }
                commit();
            }
        });
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

    function bindInput(elId, stateKey) {
        var el = document.getElementById(elId);
        if (!el || el.__fwmonEventsBound) return;
        el.__fwmonEventsBound = true;
        var pending = null;
        var commit = function() {
            state[stateKey] = el.value.trim();
            applyState();
            syncURL();
            firstPage();
        };
        el.addEventListener('input', function() {
            if (pending) clearTimeout(pending);
            pending = setTimeout(commit, 400);
        });
        el.addEventListener('blur', function() {
            if (pending) { clearTimeout(pending); pending = null; }
            commit();
        });
        el.addEventListener('keydown', function(ev) {
            if (ev.key === 'Enter') {
                if (pending) { clearTimeout(pending); pending = null; }
                commit();
            }
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
        setVal('events-filter-src-ip', state.src_ip);
        setVal('events-filter-dst-ip', state.dst_ip);
        setVal('events-filter-rule-key', state.rule_key);
        activatePills();
        renderChips();
        // The rollup and short-window analytics share the device/site filters,
        // so a change there (or a clear) re-fetches them alongside the list.
        loadAnalytics();
        loadStats();
        // The capability gate is also device-scoped: re-read the active device's
        // verdicts (cached) so the cards hide/show as the device filter changes.
        loadGating();
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
            { key: 'action', stateKey: 'action' },
            { key: 'src_ip', stateKey: 'src_ip' },
            { key: 'dst_ip', stateKey: 'dst_ip' },
            { key: 'rule_key', stateKey: 'rule_key' }
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
        return '<tr class="events-row" data-evt-id="' + r.id + '">' +
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
    // Security tab: apply state, chips, tab switch, loading, rendering
    // ----------------------------------------------------------------------
    function secChipLabel(stateKey) {
        switch (stateKey) {
            case 'sec_class': return enumLabel('CLASS', secState.sec_class);
            case 'sec_device': return listLabel(devices, secState.sec_device);
            default: return secState[stateKey];
        }
    }

    function secApplyState() {
        setVal('sec-events-filter-class', secState.sec_class);
        setVal('sec-events-filter-device', secState.sec_device);
        setVal('sec-events-filter-severity', secState.sec_severity);
        setVal('sec-events-filter-admin-user', secState.sec_admin_user);
        setVal('sec-events-filter-sig-name', secState.sec_sig_name);
        setVal('sec-events-filter-tunnel-name', secState.sec_tunnel_name);
        setVal('sec-events-filter-wan-name', secState.sec_wan_name);
        secRenderChips();
        // The security analytics share the tab's device filter, so a change
        // (or a clear) re-fetches them alongside the list.
        loadSecStats();
        // Same device-scoped capability gate as the network tab's analytics.
        loadSecGating();
    }

    function secRenderChips() {
        var host = document.getElementById('sec-events-active-chips');
        if (!host) return;
        var defs = [
            { key: 'class', stateKey: 'sec_class' },
            { key: 'device', stateKey: 'sec_device' },
            { key: 'severity', stateKey: 'sec_severity' },
            { key: 'admin_user', stateKey: 'sec_admin_user' },
            { key: 'sig_name', stateKey: 'sec_sig_name' },
            { key: 'tunnel', stateKey: 'sec_tunnel_name' },
            { key: 'wan', stateKey: 'sec_wan_name' }
        ];
        var html = '';
        for (var i = 0; i < defs.length; i++) {
            var v = secState[defs[i].stateKey];
            if (v === '' || v == null) continue;
            html += '<span class="fwmon-chip" data-statekey="' + esc(defs[i].stateKey) + '">' +
                '<span class="fwmon-chip-key">' + esc(defs[i].key) + '</span>' +
                '<span class="fwmon-chip-val">' + esc(secChipLabel(defs[i].stateKey)) + '</span>' +
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
                    secState[k] = '';
                    secApplyState();
                    syncURL();
                    secFirstPage();
                }
            });
        }
    }

    // setActiveTab switches between the Network and Security views: toggles the
    // tab buttons, shows/hides the two view divs, persists the choice and loads
    // the newly active tab's first page.
    function setActiveTab(tab) {
        if (tab !== 'network' && tab !== 'security') tab = 'network';
        activeTab = tab;
        var tabs = document.querySelectorAll('#events-view-tabs .fwmon-flows-tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle('active', tabs[i].getAttribute('data-events-tab') === tab);
        }
        var net = document.getElementById('events-view-network');
        var sec = document.getElementById('events-view-security');
        if (net) net.hidden = (tab !== 'network');
        if (sec) sec.hidden = (tab !== 'security');
        syncURL();
        if (tab === 'network') firstPage();
        else { secFirstPage(); loadSecStats(); }
    }

    function secFirstPage() {
        secOffset = 0;
        secLoad(0);
    }

    function secNextPage() {
        secLoad(secOffset);
    }

    function secPrevPage() {
        secLoad(Math.max(0, secOffset - 2 * SEC_PAGE_SIZE));
    }

    function secLoad(targetOffset) {
        var host = document.getElementById('sec-events-load-host');
        // Same chartLoad discipline as the network tab: a fast paging/filter
        // click supersedes a stale load, and leaving the page cancels it (the
        // 'events-' prefix in PAGE_LOAD_KEYS.events covers both keys).
        AC.chartLoad(host, function(signal) {
            return ensureLists().then(function() {
                return apiFetch(secEventsURL(SEC_PAGE_SIZE, targetOffset), { signal: signal });
            });
        }, { key: 'events-sec-list', label: 'Loading security events…', escScope: document.getElementById('page-events') }).then(function(r) {
            if (r.superseded) return;
            if (r.cancelled) return;
            if (r.error || !r.data) {
                if (window.fwmonLog) fwmonLog.error('FwmonEvents: sec fetch failed', r.error);
                AC.chartNotice(host, 'Could not load security events', { dim: false, onRetry: function() { secLoad(targetOffset); } });
                return;
            }
            var payload = r.data.data || {};
            secOffset = targetOffset + (payload.events || []).length;
            secRender(payload);
        });
    }

    function secColumns() {
        return SEC_COLUMNS[secState.sec_class] || SEC_COLUMNS_ALL;
    }

    function classBadge(v) {
        if (!v) return '<span class="badge unknown">unknown</span>';
        return '<span class="badge info">' + esc(enumLabel('CLASS', v)) + '</span>';
    }

    function severityBadge(v) {
        if (v == null || v === '') return '—';
        var cls = 'info';
        if (v >= 7) cls = 'critical';
        else if (v >= 4) cls = 'warning';
        return '<span class="badge ' + cls + '">' + esc(String(v)) + '</span>';
    }

    function secCell(key, r) {
        var v = r[key];
        switch (key) {
            case 'activity': return esc(enumLabel('ACTIVITY', r.activity));
            case 'action': return actionBadge(r.action);
            case 'metric_value': return v == null ? '—' : esc(String(v));
            default: return v == null || v === '' ? '—' : esc(String(v));
        }
    }

    function secRenderHeader() {
        var cols = secColumns();
        var html = '<tr><th>Time</th><th>Device</th><th>Class</th><th>Severity</th>';
        for (var i = 0; i < cols.length; i++) html += '<th>' + esc(cols[i][1]) + '</th>';
        html += '</tr>';
        var head = document.querySelector('#sec-events-table thead');
        if (head) head.innerHTML = html;
    }

    function secRenderRow(r) {
        var cols = secColumns();
        var html = '<tr class="events-row" data-evt-id="' + r.id + '">' +
            '<td class="td-nowrap">' + AC.formatDate(r.ts) + '</td>' +
            '<td>' + (r.device_name ? AC.deviceLink(r.device_id, r.device_name) : esc('DEV-' + r.device_id)) +
                (r.vendor ? ' <span class="badge unknown">' + esc(r.vendor) + '</span>' : '') + '</td>' +
            '<td>' + classBadge(r.class) + '</td>' +
            '<td>' + severityBadge(r.severity) + '</td>';
        for (var i = 0; i < cols.length; i++) html += '<td>' + secCell(cols[i][0], r) + '</td>';
        return html + '</tr>';
    }

    function secRender(payload) {
        var rows = payload.events || [];
        secTotal = payload.total || 0;
        secTotalCapped = !!(payload.total_capped);
        secRenderHeader();
        var tbody = document.querySelector('#sec-events-table tbody');
        if (!tbody) return;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No security events in this range</td></tr>';
            document.getElementById('sec-events-pagination').innerHTML = '';
            return;
        }
        tbody.innerHTML = rows.map(secRenderRow).join('');
        secUpdatePagination(rows.length);
    }

    function secUpdatePagination(count) {
        var container = document.getElementById('sec-events-pagination');
        if (!container) return;
        if (secTotal === 0) {
            container.innerHTML = '';
            return;
        }
        var more = secTotalCapped ? '+' : '';
        var from = secOffset - count + 1;
        var to = secOffset;
        var currentPage = Math.floor(secOffset / SEC_PAGE_SIZE) + 1;
        var totalPages = Math.max(1, Math.ceil(secTotal / SEC_PAGE_SIZE));
        var atEnd = secTotalCapped ? count < SEC_PAGE_SIZE : secOffset >= secTotal;
        container.innerHTML =
            '<span style="color:var(--fwmon-text-faint);">Showing ' + from + '-' + to + ' of ' + secTotal.toLocaleString() + more + ' matching filters &nbsp;|&nbsp; </span>' +
            '<button type="button" class="btn secondary sm" data-sec-events-page="prev"' + (secOffset <= 0 ? ' disabled' : '') + '>Prev</button> ' +
            '<span style="color:var(--fwmon-text-faint);">Page ' + currentPage + ' of ' + totalPages.toLocaleString() + more + ' &nbsp;</span>' +
            '<button type="button" class="btn secondary sm" data-sec-events-page="next"' + (atEnd ? ' disabled' : '') + '>Next</button>';
    }

    // ----------------------------------------------------------------------
    // Rollup analytics (Phase 2, PR 4 — net_event_rollups, day-granular)
    // ----------------------------------------------------------------------
    // The page-level range pills drive every surface. The event lists and the
    // raw short-window cards take `hours`; the rollup cards are day-granular,
    // so their window is the pill range in whole days (a sub-day range looks at
    // today), capped at the rollup retention.
    function rangeDays() {
        var h = Number(state.hours) || 24;
        return Math.max(1, Math.min(365, Math.ceil(h / 24)));
    }
    var analyticsCharts = {};
    var ANALYTICS_COLORS = ['#58a6ff', '#3fb950', '#d2992a', '#bc8cff', '#f85149', '#39c5cf', '#ff7b72', '#8b949e'];

    // eventsChart is a minimal local Chart.js helper — admin-main.js's
    // createChart is module-private, so this module carries its own. It destroys
    // a previous instance and applies the same doughnut cutout as the other
    // pages; series colors are fixed hex (theme-safe) and doughnut segments are
    // borderless, matching the syslog severity chart.
    function eventsChart(canvasId, type, labels, datasets, opts) {
        var canvas = document.getElementById(canvasId);
        // The capability gate (PR 7) may have hidden this card because the
        // active device's vendor can't supply the dimension. Destroy any chart a
        // previous, still-ungated render drew into it and leave the hidden card
        // empty — Chart.js on a 0-sized canvas would otherwise only warn.
        if (canvas && canvas.offsetParent === null) {
            if (analyticsCharts[canvasId]) { analyticsCharts[canvasId].destroy(); delete analyticsCharts[canvasId]; }
            return;
        }
        if (analyticsCharts[canvasId]) { analyticsCharts[canvasId].destroy(); }
        if (!canvas || !window.Chart) return;
        var isDoughnut = type === 'doughnut' || type === 'pie';
        var options = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: isDoughnut ? 'bottom' : 'top' } },
            scales: isDoughnut ? {} : { x: { ticks: { maxRotation: 0, maxTicksLimit: 8 } }, y: { beginAtZero: true } }
        };
        if (isDoughnut) options.cutout = '75%';
        analyticsCharts[canvasId] = new window.Chart(canvas, {
            type: type, data: { labels: labels, datasets: datasets }, options: Object.assign({}, options, opts || {})
        });
    }

    function analyticsURL() {
        var p = ['days=' + rangeDays()];
        if (state.site_id) p.push('site_id=' + encodeURIComponent(state.site_id));
        if (state.device_id) p.push('device_id=' + encodeURIComponent(state.device_id));
        return '/admin/api/events/rollups?' + p.join('&');
    }

    function loadAnalytics() {
        var host = document.getElementById('events-analytics-host');
        if (!host) return;
        AC.chartLoad(host, function(signal) {
            return apiFetch(analyticsURL(), { signal: signal });
        }, { key: 'events-analytics', label: 'Loading analytics…', escScope: document.getElementById('page-events') }).then(function(r) {
            if (r.superseded || r.cancelled) return;
            if (r.error || !r.data) {
                AC.chartNotice(host, 'Could not load analytics', { dim: false, onRetry: loadAnalytics });
                return;
            }
            renderAnalytics(r.data.data || {});
        });
    }

    // truncateRuleKey keeps a long rule key readable on the "top rules" axis.
    function truncateRuleKey(k) {
        if (!k) return '';
        return k.length > 26 ? k.slice(0, 25) + '…' : k;
    }

    function renderAnalytics(d) {
        // Policy bytes: one line per direction of bytes, per day. FortiGate
        // "accept" records repeat cumulative session counters, so ingest only
        // stores bytes on records that end a session; a day's figure is what
        // closed that day. A retrofit marker (policy_bytes_from) starts the
        // series at the first day rebuilt from corrected data.
        var pb = d.policy_bytes || [];
        var pbHint = document.getElementById('events-policy-bytes-hint');
        if (pbHint) {
            pbHint.textContent = 'per day · bytes at session close' +
                (d.policy_bytes_from ? ' · repaired from ' + d.policy_bytes_from : '');
        }
        eventsChart('events-policy-bytes-chart', 'line', pb.map(function(b) { return b.day; }), [
            { label: 'In', data: pb.map(function(b) { return b.bytes_in; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.12)', fill: true, tension: 0.3 },
            { label: 'Out', data: pb.map(function(b) { return b.bytes_out; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.12)', fill: true, tension: 0.3 }
        ]);

        // Deny trend: denied hits per day.
        var deny = d.deny || [];
        eventsChart('events-deny-chart', 'bar', deny.map(function(b) { return b.day; }),
            [{ label: 'Denied', data: deny.map(function(b) { return b.hits; }), backgroundColor: '#f85149', borderRadius: 3 }]);

        // Top rules: horizontal bars, highest hits first.
        var rules = d.policy_hits || [];
        eventsChart('events-top-rules-chart', 'bar', rules.map(function(r) { return truncateRuleKey(r.rule_key); }),
            [{ label: 'Hits', data: rules.map(function(r) { return r.hits; }), backgroundColor: '#58a6ff', borderRadius: 3 }],
            { indexAxis: 'y' });

        // App categories: doughnut; the '' sentinel reads as "uncategorized".
        var appCats = d.app_categories || [];
        eventsChart('events-app-cat-chart', 'doughnut', appCats.map(function(c) { return c.key === '' ? 'uncategorized' : c.key; }),
            [{ data: appCats.map(function(c) { return c.count; }), backgroundColor: ANALYTICS_COLORS.slice(0, appCats.length), borderWidth: 0 }]);

        // Directions: doughnut labelled through the DIRECTION enum.
        var dirs = d.directions || [];
        eventsChart('events-direction-chart', 'doughnut', dirs.map(function(x) { return enumLabel('DIRECTION', x.direction); }),
            [{ data: dirs.map(function(x) { return x.hits; }), backgroundColor: ANALYTICS_COLORS.slice(0, dirs.length), borderWidth: 0 }]);

        // Rulesets: doughnut; the '' sentinel reads as "root".
        var rulesets = d.rulesets || [];
        eventsChart('events-ruleset-chart', 'doughnut', rulesets.map(function(c) { return c.key === '' ? 'root' : c.key; }),
            [{ data: rulesets.map(function(c) { return c.count; }), backgroundColor: ANALYTICS_COLORS.slice(0, rulesets.length), borderWidth: 0 }]);
    }

    // ----------------------------------------------------------------------
    // Short-window analytics (Phase 2, PR 5 — raw net_events, hour-granular)
    // ----------------------------------------------------------------------
    // The rollup analytics above are day-granular, so their window follows the
    // range pills in whole days. These cover the dimensions the rollups do NOT
    // retain (geo, identity, users, apps, web categories, DNS, NAT) and share
    // the page-level `hours` range pills plus the device/site filters with the
    // raw event lists.
    function statsURL() {
        var p = [];
        if (state.hours && Number(state.hours) !== 24) p.push('hours=' + encodeURIComponent(state.hours));
        if (state.site_id) p.push('site_id=' + encodeURIComponent(state.site_id));
        if (state.device_id) p.push('device_id=' + encodeURIComponent(state.device_id));
        return '/admin/api/events/analytics' + (p.length ? '?' + p.join('&') : '');
    }

    function loadStats() {
        var host = document.getElementById('events-stats-host');
        if (!host) return;
        // Nine partition-pruned scans over the raw table cost about a minute on
        // a 7-day production window, and the response must fit in 30 s. The
        // range still drives the list and the day-granular rollups above, so
        // for a multi-day range say where those dimensions went instead of
        // issuing a request that cannot come back in time.
        var note = document.getElementById('events-stats-note');
        if (rangeDays() > 1) {
            host.hidden = true;
            if (note) {
                note.hidden = false;
                note.textContent = 'Raw event dimensions (geo, users, apps, web, DNS, NAT) are available for ranges up to 24 h; the 7/30-day cards above use the daily rollups.';
            }
            return;
        }
        host.hidden = false;
        if (note) note.hidden = true;
        AC.chartLoad(host, function(signal) {
            return apiFetch(statsURL(), { signal: signal });
        }, { key: 'events-stats', label: 'Loading analytics…', escScope: document.getElementById('page-events') }).then(function(r) {
            if (r.superseded || r.cancelled) return;
            if (r.error || !r.data) {
                AC.chartNotice(host, 'Could not load analytics', { dim: false, onRetry: loadStats });
                return;
            }
            renderStats(r.data.data || {});
        });
    }

    // truncateKey keeps a long label readable on a ranking axis (DNS names and
    // NAT/identity pairs can be much longer than a card's tick).
    function truncateKey(k) {
        if (!k) return '';
        return k.length > 24 ? k.slice(0, 23) + '…' : k;
    }

    function renderStats(d) {
        // Top countries (source and destination): doughnuts of hits by ISO code.
        var geoSrc = d.geo_src || [];
        eventsChart('events-geo-src-chart', 'doughnut', geoSrc.map(function(g) { return g.country; }),
            [{ data: geoSrc.map(function(g) { return g.hits; }), backgroundColor: ANALYTICS_COLORS.slice(0, geoSrc.length), borderWidth: 0 }]);

        var geoDst = d.geo_dst || [];
        eventsChart('events-geo-dst-chart', 'doughnut', geoDst.map(function(g) { return g.country; }),
            [{ data: geoDst.map(function(g) { return g.hits; }), backgroundColor: ANALYTICS_COLORS.slice(0, geoDst.length), borderWidth: 0 }]);

        // Top users / apps / DNS: horizontal bars of hits, highest first.
        var users = d.users || [];
        eventsChart('events-users-chart', 'bar', users.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Hits', data: users.map(function(c) { return c.count; }), backgroundColor: '#58a6ff', borderRadius: 3 }],
            { indexAxis: 'y' });

        var apps = d.apps || [];
        eventsChart('events-apps-chart', 'bar', apps.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Hits', data: apps.map(function(c) { return c.count; }), backgroundColor: '#3fb950', borderRadius: 3 }],
            { indexAxis: 'y' });

        // Web categories: doughnut.
        var webCats = d.web_categories || [];
        eventsChart('events-web-cat-chart', 'doughnut', webCats.map(function(c) { return c.key === '' ? 'uncategorized' : c.key; }),
            [{ data: webCats.map(function(c) { return c.count; }), backgroundColor: ANALYTICS_COLORS.slice(0, webCats.length), borderWidth: 0 }]);

        var dns = d.dns || [];
        eventsChart('events-dns-chart', 'bar', dns.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Hits', data: dns.map(function(c) { return c.count; }), backgroundColor: '#d2992a', borderRadius: 3 }],
            { indexAxis: 'y' });

        // NAT pairs: "src → dst" before/after translation.
        var nat = d.nat || [];
        eventsChart('events-nat-chart', 'bar', nat.map(function(n) { return truncateKey(n.src_ip + ' → ' + n.dst_ip); }),
            [{ label: 'Hits', data: nat.map(function(n) { return n.hits; }), backgroundColor: '#bc8cff', borderRadius: 3 }],
            { indexAxis: 'y' });

        // Identity: "src_ip (src_mac)", MAC omitted when the vendor supplied none.
        var identity = d.identity || [];
        eventsChart('events-identity-chart', 'bar', identity.map(function(x) { return truncateKey(x.src_ip + (x.src_mac ? ' (' + x.src_mac + ')' : '')); }),
            [{ label: 'Hits', data: identity.map(function(x) { return x.hits; }), backgroundColor: '#39c5cf', borderRadius: 3 }],
            { indexAxis: 'y' });
    }

    // ----------------------------------------------------------------------
    // Security analytics (Phase 2, PR 6 — raw sec_events, day-bucketed)
    // ----------------------------------------------------------------------
    // The Security tab's class-scoped analytics: per-class day trends and
    // top-N rankings over the raw sec_events table. Day-bucketed like the
    // rollup analytics, so the window follows the range pills in whole days;
    // they share the Security tab's device filter — there is no site filter on
    // this tab, and the finding/auth/config/vpn/wan series all ride the same
    // class-scoped query.
    function secStatsURL() {
        var p = ['days=' + rangeDays()];
        if (secState.sec_device) p.push('device_id=' + encodeURIComponent(secState.sec_device));
        return '/admin/api/security-events/analytics?' + p.join('&');
    }

    function loadSecStats() {
        var host = document.getElementById('sec-events-analytics-host');
        if (!host) return;
        AC.chartLoad(host, function(signal) {
            return apiFetch(secStatsURL(), { signal: signal });
        }, { key: 'events-sec-stats', label: 'Loading analytics…', escScope: document.getElementById('page-events') }).then(function(r) {
            if (r.superseded || r.cancelled) return;
            if (r.error || !r.data) {
                AC.chartNotice(host, 'Could not load analytics', { dim: false, onRetry: loadSecStats });
                return;
            }
            renderSecStats(r.data.data || {});
        });
    }

    // renderWanHealth draws one line per WAN over the day buckets, plotting the
    // per-day average metric_value. Days missing a reading read as a gap (null)
    // rather than zero, so a silent WAN does not draw a false baseline.
    function renderWanHealth(rows) {
        var days = [];
        var seen = {};
        var byWan = {};
        for (var i = 0; i < rows.length; i++) {
            if (!seen[rows[i].day]) { seen[rows[i].day] = true; days.push(rows[i].day); }
            if (!byWan[rows[i].wan_name]) byWan[rows[i].wan_name] = {};
            byWan[rows[i].wan_name][rows[i].day] = rows[i].avg;
        }
        var wans = Object.keys(byWan).sort();
        var datasets = wans.map(function(wan, i) {
            return {
                label: wan,
                data: days.map(function(day) { return byWan[wan][day] == null ? null : byWan[wan][day]; }),
                borderColor: ANALYTICS_COLORS[i % ANALYTICS_COLORS.length],
                backgroundColor: 'transparent',
                fill: false,
                tension: 0.3
            };
        });
        eventsChart('sec-wan-health-chart', 'line', days, datasets);
    }

    function renderSecStats(d) {
        // Findings trend: per-day counts, oldest-first.
        var findings = d.findings || [];
        eventsChart('sec-findings-trend-chart', 'line', findings.map(function(b) { return b.day; }),
            [{ label: 'Findings', data: findings.map(function(b) { return b.count; }), borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.12)', fill: true, tension: 0.3 }]);

        // Top signatures: horizontal bars, highest count first.
        var sigs = d.top_signatures || [];
        eventsChart('sec-top-signatures-chart', 'bar', sigs.map(function(s) { return truncateKey(s.sig_name); }),
            [{ label: 'Findings', data: sigs.map(function(s) { return s.count; }), backgroundColor: '#f85149', borderRadius: 3 }],
            { indexAxis: 'y' });

        // Admin logins: per-day bar trend, and top admin users as bars.
        var logins = d.admin_logins || [];
        eventsChart('sec-admin-logins-chart', 'bar', logins.map(function(b) { return b.day; }),
            [{ label: 'Logins', data: logins.map(function(b) { return b.count; }), backgroundColor: '#58a6ff', borderRadius: 3 }]);

        var adminUsers = d.top_admin_users || [];
        eventsChart('sec-top-admin-users-chart', 'bar', adminUsers.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Logins', data: adminUsers.map(function(c) { return c.count; }), backgroundColor: '#58a6ff', borderRadius: 3 }],
            { indexAxis: 'y' });

        // Config changes: per-day bar trend, and top config paths as bars.
        var changes = d.config_changes || [];
        eventsChart('sec-config-changes-chart', 'bar', changes.map(function(b) { return b.day; }),
            [{ label: 'Changes', data: changes.map(function(b) { return b.count; }), backgroundColor: '#d2992a', borderRadius: 3 }]);

        var paths = d.top_config_paths || [];
        eventsChart('sec-top-config-paths-chart', 'bar', paths.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Changes', data: paths.map(function(c) { return c.count; }), backgroundColor: '#d2992a', borderRadius: 3 }],
            { indexAxis: 'y' });

        // VPN sessions: per-day bar trend, and top tunnels as bars.
        var vpn = d.vpn_sessions || [];
        eventsChart('sec-vpn-sessions-chart', 'bar', vpn.map(function(b) { return b.day; }),
            [{ label: 'Sessions', data: vpn.map(function(b) { return b.count; }), backgroundColor: '#3fb950', borderRadius: 3 }]);

        var tunnels = d.top_tunnels || [];
        eventsChart('sec-top-tunnels-chart', 'bar', tunnels.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Sessions', data: tunnels.map(function(c) { return c.count; }), backgroundColor: '#3fb950', borderRadius: 3 }],
            { indexAxis: 'y' });

        // Top admin source IPs and top tunnel peers: doughnuts.
        var adminSrc = d.top_admin_src_ips || [];
        eventsChart('sec-top-admin-src-chart', 'doughnut', adminSrc.map(function(c) { return c.key; }),
            [{ data: adminSrc.map(function(c) { return c.count; }), backgroundColor: ANALYTICS_COLORS.slice(0, adminSrc.length), borderWidth: 0 }]);

        var peers = d.top_tunnel_peers || [];
        eventsChart('sec-top-tunnel-peers-chart', 'doughnut', peers.map(function(c) { return c.key; }),
            [{ data: peers.map(function(c) { return c.count; }), backgroundColor: ANALYTICS_COLORS.slice(0, peers.length), borderWidth: 0 }]);

        // Top config admins (who changed what): horizontal bars.
        var cfgAdmins = d.top_config_admins || [];
        eventsChart('sec-top-config-admins-chart', 'bar', cfgAdmins.map(function(c) { return truncateKey(c.key); }),
            [{ label: 'Changes', data: cfgAdmins.map(function(c) { return c.count; }), backgroundColor: '#bc8cff', borderRadius: 3 }],
            { indexAxis: 'y' });

        // WAN health: one line per WAN, days on the x-axis, average metric.
        renderWanHealth(d.wan_health || []);
    }

    // ----------------------------------------------------------------------
    // Capability gating (Phase 2, PR 7 — "not available" instead of zeros)
    // ----------------------------------------------------------------------
    // A vendor's profile (internal/normalize/capability) says which normalized
    // fields it can supply; GET /admin/api/devices/:id/capabilities joins that
    // with what the device was observed sending over a 24 h window and returns a
    // per-feature verdict. We read the active device filter's verdicts once,
    // cache them per device, then hide/annotate the analytics cards whose
    // dimension that device can't fully report. The capability endpoints are
    // admin-only, so a viewer gets a 403 — we fall back to showing every section
    // ungated (best effort) rather than blank the page or chart zeros.
    var capCache = {};     // device_id -> { window_hours, fields, features }
    var capDenied = false; // set once a capability call is refused (e.g. viewer)

    var INACTIVE_HINT = 'No data observed in the last 24 h (feature unused / option off)';

    function deviceCapabilities(deviceId) {
        if (!deviceId || capDenied) return Promise.resolve(null);
        if (capCache[deviceId] !== undefined) return Promise.resolve(capCache[deviceId]);
        return apiFetch('/admin/api/devices/' + encodeURIComponent(deviceId) + '/capabilities')
            .then(function(r) {
                var d = (r && r.data) || null;
                capCache[deviceId] = d;
                return d;
            })
            .catch(function(err) {
                // Admin-only endpoint: a viewer 403s here. Treat any failure as
                // "no gating data" and stop asking — best effort, never blank.
                capDenied = true;
                if (window.fwmonLog) fwmonLog.warn('FwmonEvents: capability lookup unavailable, gating disabled', err);
                return null;
            });
    }

    // featureVerdict returns the capability API's verdict for one feature, or
    // null when unknown (unknown → ungated, matching the backend default).
    function featureVerdict(caps, feature) {
        if (!caps || !caps.features) return null;
        var f = caps.features[feature];
        return (f && f.state) ? f : null;
    }

    // featureNote joins the notes of the fields that decided a degraded verdict
    // (the profile's caveat, e.g. "needs `logtraffic all` on the policy").
    function featureNote(caps, verdict) {
        if (!caps || !caps.fields || !verdict || !verdict.fields || !verdict.fields.length) return '';
        var notes = [];
        for (var i = 0; i < verdict.fields.length; i++) {
            var cell = caps.fields[verdict.fields[i]];
            if (cell && cell.note && notes.indexOf(cell.note) === -1) notes.push(cell.note);
        }
        return notes.join('; ');
    }

    function gateCard(card, state, note) {
        var hint = card.querySelector('.capability-hint');
        if (hint) { hint.parentNode.removeChild(hint); }
        card.hidden = (state === 'unsupported');
        if (card.hidden || !note) return;
        var el = document.createElement('div');
        el.className = 'capability-hint' + (state === 'degraded' ? ' degraded' : '');
        el.textContent = note;
        var h3 = card.querySelector('h3');
        card.insertBefore(el, h3 ? h3.nextSibling : card.firstChild);
    }

    // applyGating walks one analytics host's data-feature cards and hides or
    // annotates them from the (already-resolved) capability payload. A null
    // payload means "no gating data" — every card is shown ungated.
    function applyGating(scopeId, caps) {
        var scope = document.getElementById(scopeId);
        if (!scope) return;
        var cards = scope.querySelectorAll('.chart-card[data-feature]');
        Array.prototype.forEach.call(cards, function(card) {
            var verdict = featureVerdict(caps, card.getAttribute('data-feature'));
            var state = verdict ? verdict.state : null;
            var note = state === 'inactive' ? INACTIVE_HINT :
                       state === 'degraded' ? featureNote(caps, verdict) : '';
            gateCard(card, state, note);
        });
        // Collapse a chart-row whose cards are all hidden so the gate doesn't
        // leave an empty grid cell where a dimension used to be.
        Array.prototype.forEach.call(scope.querySelectorAll('.chart-row'), function(row) {
            var any = false;
            Array.prototype.forEach.call(row.querySelectorAll('.chart-card'), function(c) {
                if (!c.hidden) any = true;
            });
            row.hidden = !any;
        });
    }

    function loadGating() {
        var deviceId = state.device_id;
        deviceCapabilities(deviceId).then(function(caps) {
            applyGating('events-analytics-host', caps);
            applyGating('events-stats-host', caps);
        });
    }

    function loadSecGating() {
        var deviceId = secState.sec_device;
        deviceCapabilities(deviceId).then(function(caps) {
            applyGating('sec-events-analytics-host', caps);
        });
    }

    // ----------------------------------------------------------------------
    // Event detail (Phase 2, PR 8 — row click → full event + raw syslog bridge)
    // ----------------------------------------------------------------------
    // A row click fetches the single-row detail endpoint and renders every
    // column the row carries (enums via FwmonEnums, addresses/bytes via the same
    // formatters as the list). When the event carries raw_id, the modal also
    // offers a "View raw syslog" link that fetches the original syslog line and
    // renders it inline; because that raw row may already be archived or out of
    // retention, a 404 degrades to a quiet inline note rather than an error.

    // kv renders one label/value cell of the two-column detail grid. The label
    // is escaped; the value is trusted HTML built by the formatters above.
    function kv(label, html) {
        if (html == null || html === '') return '';
        return '<span style="color:var(--fwmon-text-faint);">' + esc(label) + '</span><span>' + html + '</span>';
    }

    function detailDevice(r) {
        var dev = r.device_name ? AC.deviceLink(r.device_id, r.device_name) : esc('DEV-' + r.device_id);
        return dev + (r.vendor ? ' <span class="badge unknown">' + esc(r.vendor) + '</span>' : '');
    }

    function netEventFields(r) {
        var rows = [
            kv('ID', esc(String(r.id))),
            kv('Time', esc(AC.formatDate(r.ts))),
            kv('Device', detailDevice(r)),
            r.probe_id ? kv('Probe', esc(String(r.probe_id))) : '',
            kv('Activity', esc(enumLabel('ACTIVITY', r.activity))),
            kv('Action', actionBadge(r.action)),
            r.direction != null ? kv('Direction', esc(enumLabel('DIRECTION', r.direction))) : '',
            (r.src_ip || r.src_port) ? kv('Source', endpoint(r.src_ip, r.src_port)) : '',
            (r.dst_ip || r.dst_port) ? kv('Destination', endpoint(r.dst_ip, r.dst_port)) : '',
            r.proto != null ? kv('Protocol', esc(protoLabel(r.proto))) : '',
            r.app ? kv('App', esc(r.app)) : '',
            r.app_cat ? kv('App category', esc(r.app_cat)) : '',
            r.user_name ? kv('User', esc(r.user_name)) : '',
            (r.src_country || r.dst_country) ? kv('Countries', countries(r.src_country, r.dst_country)) : '',
            (r.bytes_in != null || r.bytes_out != null) ? kv('Bytes', bytes(r.bytes_in, r.bytes_out)) : '',
            r.threat_flag ? kv('Threat', '<span class="badge critical">THREAT</span>') : ''
        ];
        return rows.join('');
    }

    function secEventFields(r) {
        var rows = [
            kv('ID', esc(String(r.id))),
            kv('Time', esc(AC.formatDate(r.ts))),
            kv('Device', detailDevice(r)),
            r.probe_id ? kv('Probe', esc(String(r.probe_id))) : '',
            kv('Class', classBadge(r.class)),
            kv('Activity', esc(enumLabel('ACTIVITY', r.activity))),
            kv('Action', actionBadge(r.action)),
            kv('Severity', severityBadge(r.severity)),
            (r.src_ip || r.src_port) ? kv('Source', endpoint(r.src_ip, r.src_port)) : '',
            (r.dst_ip || r.dst_port) ? kv('Destination', endpoint(r.dst_ip, r.dst_port)) : '',
            r.proto != null ? kv('Protocol', esc(protoLabel(r.proto))) : '',
            r.user_name ? kv('User', esc(r.user_name)) : '',
            r.src_hostname ? kv('Source hostname', esc(r.src_hostname)) : '',
            r.admin_user ? kv('Admin user', esc(r.admin_user)) : '',
            r.admin_src_ip ? kv('Admin source IP', esc(r.admin_src_ip)) : '',
            r.admin_method ? kv('Admin method', esc(r.admin_method)) : '',
            r.sig_id ? kv('Signature ID', esc(r.sig_id)) : '',
            r.sig_name ? kv('Signature', esc(r.sig_name)) : '',
            r.threat_cat ? kv('Threat category', esc(r.threat_cat)) : '',
            r.file_hash ? kv('File hash', esc(r.file_hash)) : '',
            r.url_host ? kv('URL host', esc(r.url_host)) : '',
            r.tunnel_name ? kv('Tunnel', esc(r.tunnel_name)) : '',
            r.tunnel_type ? kv('Tunnel type', esc(r.tunnel_type)) : '',
            r.tunnel_peer ? kv('Tunnel peer', esc(r.tunnel_peer)) : '',
            r.config_path ? kv('Config path', esc(r.config_path)) : '',
            r.config_obj ? kv('Config object', esc(r.config_obj)) : '',
            r.config_old ? kv('Config old', esc(r.config_old)) : '',
            r.config_new ? kv('Config new', esc(r.config_new)) : '',
            r.wan_name ? kv('WAN', esc(r.wan_name)) : '',
            r.metric_name ? kv('Metric', esc(r.metric_name)) : '',
            r.metric_value != null ? kv('Value', esc(String(r.metric_value))) : '',
            r.message ? kv('Message', esc(r.message)) : ''
        ];
        return rows.join('');
    }

    // showEventDetail fetches one event by id and opens the detail modal. A 404
    // here means the event itself fell out of retention between the list render
    // and the click — surfaced as a toast, not a crash.
    function showEventDetail(id, kind) {
        var url = (kind === 'sec' ? '/admin/api/security-events/' : '/admin/api/events/') + encodeURIComponent(id);
        apiFetch(url).then(function(r) {
            var evt = r && r.data;
            if (!evt) {
                AC.showError('Failed to load event detail');
                return;
            }
            renderEventDetail(evt, kind);
            AC.openModal('event-detail-modal');
        }).catch(function(err) {
            if (err && err.status === 404) {
                AC.showError('This event is no longer available (outside retention)');
            } else {
                AC.showError('Failed to load event detail');
            }
        });
    }

    function renderEventDetail(evt, kind) {
        var title = document.getElementById('event-detail-modal-title');
        var body = document.getElementById('event-detail-body');
        if (!body) return;
        if (title) title.textContent = (kind === 'sec' ? 'Security Event' : 'Network Event') + ' #' + evt.id;
        var fields = kind === 'sec' ? secEventFields(evt) : netEventFields(evt);
        body.innerHTML = '<div style="display:grid;grid-template-columns:160px 1fr;row-gap:8px;column-gap:16px;align-items:baseline;">' + fields + '</div>';
        renderRawSyslog(evt);
    }

    // renderRawSyslog builds the "View raw syslog" control when the event has a
    // raw_id. It renders the button eagerly but fetches the line only on click,
    // so the common case (no click) costs nothing.
    function renderRawSyslog(evt) {
        var host = document.getElementById('event-detail-raw');
        if (!host) return;
        if (evt.raw_id == null) {
            host.innerHTML = '';
            return;
        }
        host.innerHTML = '<button type="button" class="btn secondary sm" id="event-detail-raw-link">View raw syslog</button>' +
            '<span id="event-detail-raw-result" style="margin-left:12px;"></span>';
        document.getElementById('event-detail-raw-link').addEventListener('click', function() {
            loadRawSyslog(evt);
        });
    }

    // loadRawSyslog fetches the original syslog line by (id, ts) and renders it
    // inline. The raw row is best-effort: it may already be archived or out of
    // retention, so a 404 becomes a quiet inline note, never an error toast.
    function loadRawSyslog(evt) {
        var result = document.getElementById('event-detail-raw-result');
        if (!result) return;
        result.innerHTML = '<span style="color:var(--fwmon-text-faint);">Loading…</span>';
        var url = '/admin/api/syslog/' + encodeURIComponent(evt.raw_id);
        if (evt.raw_ts) url += '?ts=' + encodeURIComponent(evt.raw_ts);
        apiFetch(url).then(function(r) {
            var m = r && r.data;
            if (!m) {
                result.innerHTML = '<span style="color:var(--fwmon-text-faint);">raw line no longer available (archived or outside retention)</span>';
                return;
            }
            result.innerHTML = rawSyslogHtml(m);
        }).catch(function(err) {
            if (err && err.status === 404) {
                result.innerHTML = '<span style="color:var(--fwmon-text-faint);">raw line no longer available (archived or outside retention)</span>';
            } else {
                result.innerHTML = '<span style="color:var(--fwmon-text-faint);">raw syslog could not be loaded</span>';
            }
        });
    }

    // rawSyslogHtml renders the fetched syslog line: a parsed view when the
    // FortiGate formatter is present (same as the Syslog detail modal), else the
    // escaped raw message in a pre block.
    function rawSyslogHtml(m) {
        var meta = '';
        if (m.source_ip) meta += '<div style="margin-bottom:4px;"><span style="color:var(--fwmon-text-faint);">Source:</span> <span class="mono">' + esc(m.source_ip) + '</span></div>';
        if (m.hostname) meta += '<div style="margin-bottom:4px;"><span style="color:var(--fwmon-text-faint);">Host:</span> ' + esc(m.hostname) + '</div>';
        var msg = (typeof window.formatFortiGateLogHtml === 'function' && m.message)
            ? window.formatFortiGateLogHtml(m.message)
            : '<pre style="white-space:pre-wrap;word-break:break-all;margin:0;">' + esc(m.message || '') + '</pre>';
        return '<div style="margin-top:8px;">' + meta + msg + '</div>';
    }

    // ----------------------------------------------------------------------
    // Boot
    // ----------------------------------------------------------------------
    function init() {
        if (inited) {
            // Re-init is a no-op other than re-reading the URL (the user may
            // have navigated back to the tab). Force a first-page reload of the
            // active tab.
            stateFromURL();
            applyState();
            secApplyState();
            setActiveTab(activeTab);
            return;
        }
        inited = true;
        stateFromURL();
        bindControls();
        applyState();
        secApplyState();
        setActiveTab(activeTab);
    }

    function refresh() {
        if (activeTab === 'security') secFirstPage();
        else firstPage();
        loadAnalytics();
        loadStats();
        loadSecStats();
    }
    function getState() { return Object.assign({}, state); }

    window.FwmonEvents = {
        init: init,
        refresh: refresh,
        getState: getState
    };
})();
