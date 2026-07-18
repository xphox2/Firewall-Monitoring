/* admin-event-profiles.js — Event Rule Profiles UI (v0.11.115).
 *
 * Drives the three in-page states of #page-event-rules:
 *   grid      — profile cards (Default pinned) + stats + effective-view entry
 *   detail    — one profile: Toggles | Rules | Assignments tabs
 *   effective — pick a device/site, see the resolved chain/toggles/rules
 *
 * Sub-state rides the hash (#profile-<id>/<tab>, #effective) via
 * history.replaceState ONLY — the SPA's global popstate handler re-inits the
 * page from pathname on Back, so pushState here would clobber sub-state
 * (same discipline as admin-settings.js). The hashchange listener no-ops
 * unless this page is active.
 *
 * FwmonEventRules stays the rule table/builder engine; this module owns the
 * views and calls into it. All backend routes are admin-only; non-admins get
 * a graceful placeholder.
 */
(function () {
    'use strict';
    var AC = window.AdminCommon;
    var API = '/admin/api';

    var profiles = [];       // [{...profile, counts:{}}]
    var registry = [];       // [{type, family, description}] from /alert-types
    var currentId = 0;       // profile open in detail view
    var currentTab = 'toggles';
    var baseToggles = {};    // alert_type -> bool (saved state, sparse)
    var workToggles = {};    // draft copy the matrix edits
    var collapsed = {};      // family -> bool
    var wired = false;
    var forbidden = false;

    function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }
    function $(id) { return document.getElementById(id); }
    function log() { if (window.fwmonLog && window.fwmonLog.warn) window.fwmonLog.warn.apply(null, arguments); }

    function defaultProfile() {
        for (var i = 0; i < profiles.length; i++) if (profiles[i].is_default) return profiles[i];
        return null;
    }
    function profileById(id) {
        for (var i = 0; i < profiles.length; i++) if (profiles[i].id === id) return profiles[i];
        return null;
    }

    // ---- init + routing ----------------------------------------------------

    function init() {
        if (!wired) { wire(); wired = true; }
        var pending = window.FwmonEventRules.takePendingPrefill();
        Promise.all([loadProfiles(), loadRegistry(), window.FwmonEventRules.prepare()]).then(function () {
            if (forbidden) { renderForbidden(); return; }
            if (pending) {
                // Create-from-alert lands in the target profile's Rules tab with
                // the builder open. The editId (customize) path must WAIT for an
                // UNFILTERED rules load — this is a fresh page load, and
                // openRuleModal finds the firing rule in the in-memory list —
                // then land in that rule's OWN profile. The modal opens BEFORE
                // showDetail so the tab's async profile-filtered reload can't
                // race the lookup.
                if (pending.editId) {
                    window.FwmonEventRules.loadRules(0).then(function () {
                        var r = window.FwmonEventRules.getRules().find(function (x) { return x.id === pending.editId; });
                        window.FwmonEventRules.openFromPrefill(pending);
                        showDetail((r && r.profile_id) || (defaultProfile() || {}).id || 0, 'rules');
                    });
                    return;
                }
                var pid = (pending.rule && pending.rule.profile_id) || (defaultProfile() || {}).id || 0;
                window.FwmonEventRules.openFromPrefill(pending);
                showDetail(pid, 'rules');
                return;
            }
            routeFromHash();
        });
    }

    function pageActive() {
        var page = $('page-event-rules');
        return page && page.classList.contains('active');
    }

    function routeFromHash() {
        var h = window.location.hash || '';
        var m = /^#profile-(\d+)(?:\/(toggles|rules|assignments))?$/.exec(h);
        if (m) { showDetail(parseInt(m[1], 10), m[2] || 'toggles'); return; }
        if (h === '#effective') { showEffective(); return; }
        showGrid();
    }

    function setHash(h) {
        // replaceState, never pushState: Back must leave the page (the SPA
        // popstate handler re-inits it), not walk sub-states.
        try { history.replaceState(null, '', window.location.pathname + (h || '')); } catch (e) { /* ignore */ }
    }

    function setView(view) {
        $('ep-grid-view').style.display = view === 'grid' ? '' : 'none';
        $('ep-detail-view').style.display = view === 'detail' ? '' : 'none';
        $('ep-effective-view').style.display = view === 'effective' ? '' : 'none';
    }

    // ---- data --------------------------------------------------------------

    function loadProfiles() {
        return AC.apiFetch(API + '/event-rule-profiles').then(function (res) {
            profiles = res.data || [];
        }).catch(function (err) {
            if (/role|forbidden|allow this action/i.test(err.message)) { forbidden = true; return; }
            AC.showError('Failed to load event profiles: ' + err.message);
        });
    }

    function loadRegistry() {
        return AC.apiFetch(API + '/alert-types').then(function (res) {
            registry = res.data || [];
        }).catch(function () { registry = []; });
    }

    function renderForbidden() {
        setView('grid');
        $('ep-profile-grid').innerHTML = '<div class="empty-state" style="padding:32px;text-align:center;color:var(--fwmon-text-faint)">' +
            'Admin role required to manage event profiles and rules.</div>';
        ['ep-stat-profiles', 'er-stat-total', 'er-stat-suppress', 'ep-stat-temp'].forEach(function (id) {
            if ($(id)) $(id).textContent = '--';
        });
    }

    // ---- State A: grid -----------------------------------------------------

    function showGrid() {
        setHash('');
        setView('grid');
        loadProfiles().then(function () {
            if (forbidden) { renderForbidden(); return; }
            renderStats();
            renderGrid();
            renderMigrationBanner();
        });
    }

    function renderStats() {
        var rules = 0, suppress = 0, temp = 0;
        profiles.forEach(function (p) {
            var c = p.counts || {};
            rules += c.rule_count || 0;
            temp += c.temp_rule_count || 0;
        });
        if ($('ep-stat-profiles')) $('ep-stat-profiles').textContent = profiles.length;
        if ($('er-stat-total')) $('er-stat-total').textContent = rules;
        if ($('ep-stat-temp')) $('ep-stat-temp').textContent = temp;
        // Suppress is FLEET-wide, so always fetch the unfiltered list — the
        // engine's cache may hold one profile's rules after a Rules-tab visit,
        // and a partial count here would silently lie on the landing page.
        AC.apiFetch(API + '/event-rules').then(function (res) {
            suppress = (res.data || []).filter(function (r) { return r.action === 'suppress'; }).length;
            if ($('er-stat-suppress')) $('er-stat-suppress').textContent = suppress;
        }).catch(function () { });
    }

    function renderMigrationBanner() {
        var el = $('ep-migration-banner');
        if (!el) return;
        var seen = false;
        try { seen = localStorage.getItem('fwmon_ep_banner_seen') === '1'; } catch (e) { seen = true; }
        if (seen) { el.style.display = 'none'; return; }
        el.style.display = '';
        el.innerHTML = '<div style="display:flex;gap:10px;align-items:center;background:var(--fwmon-card-bg);border:1px solid var(--fwmon-accent,#58a6ff);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:0.85rem;color:var(--fwmon-text-dim)">' +
            '<span>Event rules now live in <b>profiles</b>. All existing rules are in <b>Default</b>, which still applies to everything. Create profiles to customize alerting per site or device.</span>' +
            '<button class="btn secondary sm" id="ep-banner-dismiss" style="margin-left:auto">Got it</button></div>';
        var btn = $('ep-banner-dismiss');
        if (btn) btn.addEventListener('click', function () {
            try { localStorage.setItem('fwmon_ep_banner_seen', '1'); } catch (e) { /* ignore */ }
            el.style.display = 'none';
        });
    }

    function renderGrid() {
        var grid = $('ep-profile-grid');
        if (!grid) return;
        var cards = profiles.map(function (p) {
            var c = p.counts || {};
            var isDef = !!p.is_default;
            var assigned = isDef
                ? 'Applies to everything without a site or device profile'
                : 'Assigned: ' + (c.site_count || 0) + ' site' + (c.site_count === 1 ? '' : 's') + ' · ' + (c.device_count || 0) + ' device' + (c.device_count === 1 ? '' : 's');
            var actions = AC.iconButton({ icon: 'pencil', title: 'Rename / description', action: 'ep-edit', id: p.id, minRole: 'admin' }) +
                AC.iconButton({ icon: 'copy', title: 'Clone profile (toggles + rules)', action: 'ep-clone', id: p.id, minRole: 'admin' });
            if (!isDef) actions += AC.iconButton({ icon: 'trash', title: 'Delete profile', action: 'ep-delete', id: p.id, minRole: 'admin', danger: true });
            return '<div class="ep-card' + (isDef ? ' is-default' : '') + '">' +
                '<div class="ep-card-title">' + esc(p.name) +
                (isDef ? ' <span class="badge" style="background:var(--fwmon-accent-bg);color:var(--fwmon-accent)">ROOT</span>' : '') + '</div>' +
                '<div class="ep-card-desc">' + esc(p.description || '') + '</div>' +
                '<div class="ep-card-stats">' +
                '<span><b>' + (c.toggle_count || 0) + '</b> toggles' + ((c.toggle_off_count || 0) ? ' (<b>' + c.toggle_off_count + '</b> off)' : '') + '</span>' +
                '<span><b>' + (c.rule_count || 0) + '</b> rules</span>' +
                ((c.temp_rule_count || 0) ? '<span title="Temporary rules"><b>' + c.temp_rule_count + '</b> ⏱</span>' : '') +
                '</div>' +
                '<div class="ep-card-footer">' +
                '<span class="ep-card-assigned">' + esc(assigned) + '</span>' +
                '<span style="display:flex;gap:2px">' +
                '<button class="btn secondary sm" data-action="ep-open" data-id="' + p.id + '">Open</button>' + actions + '</span>' +
                '</div></div>';
        }).join('');
        grid.innerHTML = cards || '<div class="empty-state" style="padding:32px;text-align:center;color:var(--fwmon-text-faint)">No profiles yet.</div>';
    }

    // ---- State B: detail ---------------------------------------------------

    function showDetail(id, tab) {
        var p = profileById(id);
        if (!p) {
            // Deep link to a deleted profile — fall back to the grid.
            return loadProfiles().then(function () {
                if (profileById(id)) { showDetailLoaded(id, tab); } else { showGrid(); }
            });
        }
        showDetailLoaded(id, tab);
    }

    function showDetailLoaded(id, tab) {
        if (id !== currentId) collapsed = {}; // family-collapse state is per-profile
        currentId = id;
        currentTab = tab || 'toggles';
        setHash('#profile-' + id + '/' + currentTab);
        setView('detail');
        renderDetailHeader();
        selectTab(currentTab, true);
    }

    function renderDetailHeader() {
        var p = profileById(currentId);
        if (!p) return;
        var c = p.counts || {};
        var head = $('ep-detail-header');
        var actions = AC.iconButton({ icon: 'pencil', title: 'Rename / description', action: 'ep-edit', id: p.id, minRole: 'admin' }) +
            AC.iconButton({ icon: 'copy', title: 'Clone profile (toggles + rules)', action: 'ep-clone', id: p.id, minRole: 'admin' });
        if (!p.is_default) actions += AC.iconButton({ icon: 'trash', title: 'Delete profile', action: 'ep-delete', id: p.id, minRole: 'admin', danger: true });
        head.innerHTML =
            '<div class="flex justify-between items-center" style="gap:10px;flex-wrap:wrap">' +
            '<div style="display:flex;align-items:center;gap:10px;min-width:0">' +
            '<button class="btn secondary sm" data-action="ep-back">← Profiles</button>' +
            '<h2 class="text-xl font-bold font-outfit" style="margin:0">' + esc(p.name) + '</h2>' +
            (p.is_default ? '<span class="badge" style="background:var(--fwmon-accent-bg);color:var(--fwmon-accent)">ROOT</span>' : '') +
            '</div><div style="display:flex;gap:2px">' + actions + '</div></div>' +
            '<p class="text-xs" style="color:var(--fwmon-text-faint);margin:6px 0 0">' +
            esc(p.description || '') +
            (p.is_default
                ? (p.description ? ' — ' : '') + 'This is the root: every alert type resolves here when nothing above overrides it. Turning a type Off here affects every device without a site/device override.'
                : '') + '</p>' +
            '<div class="ep-card-stats" style="margin-top:6px">' +
            '<span><b>' + (c.toggle_off_count || 0) + '</b> toggles off</span>' +
            '<span><b>' + (c.rule_count || 0) + '</b> rules' + ((c.temp_rule_count || 0) ? ' (<b>' + c.temp_rule_count + '</b> ⏱)' : '') + '</span>' +
            '<span>' + (p.is_default ? 'applies to everything' : 'assigned to <b>' + (c.site_count || 0) + '</b> sites · <b>' + (c.device_count || 0) + '</b> devices') + '</span>' +
            '</div>';
    }

    // confirmDiscard gates navigation away from unsaved toggle edits (AC.confirm,
    // not window.confirm — retired for a11y). Resolves true when safe to leave.
    function confirmDiscard() {
        if (!isDirty()) return Promise.resolve(true);
        return AC.confirm('Discard unsaved toggle changes?', { title: 'Unsaved changes', confirmLabel: 'Discard', danger: true });
    }

    function selectTab(tab, force) {
        if (!force && tab === currentTab) return;
        if (!force && currentTab === 'toggles' && tab !== 'toggles') {
            confirmDiscard().then(function (ok) {
                if (!ok) return;
                workToggles = Object.assign({}, baseToggles);
                selectTab(tab, true);
            });
            return;
        }
        currentTab = tab;
        setHash('#profile-' + currentId + '/' + tab);
        document.querySelectorAll('#ep-tabs .settings-nav-item').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-ep-tab') === tab);
        });
        $('ep-tab-toggles').style.display = tab === 'toggles' ? '' : 'none';
        $('ep-tab-rules').style.display = tab === 'rules' ? '' : 'none';
        $('ep-tab-assignments').style.display = tab === 'assignments' ? '' : 'none';
        if (tab === 'toggles') loadToggles();
        if (tab === 'rules') renderRulesTab();
        if (tab === 'assignments') renderAssignments();
    }

    // ---- Toggles matrix ----------------------------------------------------

    function loadToggles() {
        AC.apiFetch(API + '/event-rule-profiles/' + currentId).then(function (res) {
            var d = res.data || {};
            baseToggles = {};
            (d.toggles || []).forEach(function (t) { baseToggles[t.alert_type] = !!t.enabled; });
            workToggles = Object.assign({}, baseToggles);
            renderMatrix();
        }).catch(function (err) { AC.showError('Failed to load toggles: ' + err.message); });
    }

    function isDirty() {
        var keys = {};
        Object.keys(baseToggles).forEach(function (k) { keys[k] = 1; });
        Object.keys(workToggles).forEach(function (k) { keys[k] = 1; });
        return Object.keys(keys).some(function (k) { return baseToggles[k] !== workToggles[k]; });
    }

    function dirtyCount() {
        var n = 0, keys = {};
        Object.keys(baseToggles).forEach(function (k) { keys[k] = 1; });
        Object.keys(workToggles).forEach(function (k) { keys[k] = 1; });
        Object.keys(keys).forEach(function (k) { if (baseToggles[k] !== workToggles[k]) n++; });
        return n;
    }

    // stateOf: 'on' | 'off' | 'inherit' (absent from workToggles = inherit).
    function stateOf(at) {
        if (!(at in workToggles)) return 'inherit';
        return workToggles[at] ? 'on' : 'off';
    }

    // inheritHint: the wording for an Inherit row. A non-root profile can't
    // know the full chain locally (per-type resolution is the effective
    // view's job), so this is deliberately a constant honest sentence.
    function inheritHint() {
        return 'Inherits (Default decides; no rows anywhere = On)';
    }

    function familiesInOrder() {
        var seen = {}, out = [];
        registry.forEach(function (r) {
            if (!seen[r.family]) { seen[r.family] = { name: r.family, types: [] }; out.push(seen[r.family]); }
            seen[r.family].types.push(r);
        });
        return out;
    }

    function renderMatrix() {
        var wrap = $('ep-matrix');
        if (!wrap) return;
        var p = profileById(currentId);
        var isRoot = p && p.is_default;
        var filter = ($('ep-matrix-filter').value || '').toLowerCase();
        var html = familiesInOrder().map(function (fam) {
            var rows = fam.types.filter(function (t) {
                return !filter || t.type.toLowerCase().indexOf(filter) >= 0 || fam.name.toLowerCase().indexOf(filter) >= 0;
            });
            if (!rows.length) return '';
            var counts = { on: 0, off: 0, inherit: 0 };
            fam.types.forEach(function (t) { counts[stateOf(t.type)]++; });
            var countsTxt = isRoot
                ? (counts.off ? counts.off + ' off' : 'all on')
                : (counts.inherit + ' inherit · ' + counts.on + ' on · ' + counts.off + ' off');
            var isCollapsed = collapsed[fam.name] && !filter;
            var head = '<div class="ep-matrix-group-head" data-ep-group="' + esc(fam.name) + '">' +
                '<span>' + (isCollapsed ? '▸' : '▾') + ' ' + esc(fam.name) + ' (' + fam.types.length + ')</span>' +
                '<span class="ep-group-counts">' + countsTxt + '</span>' +
                '<span class="ep-group-bulk">' +
                (isRoot ? '' : '<button type="button" class="btn secondary sm" data-ep-bulk="inherit" data-ep-fam="' + esc(fam.name) + '">All Inherit</button>') +
                '<button type="button" class="btn secondary sm" data-ep-bulk="off" data-ep-fam="' + esc(fam.name) + '">All Off</button>' +
                '</span></div>';
            if (isCollapsed) return head;
            var body = rows.map(function (t) {
                var st = stateOf(t.type);
                var hint;
                if (st === 'inherit') hint = '<span class="ep-row-hint">' + esc(inheritHint()) + '</span>';
                else hint = '<span class="ep-row-hint is-override">Overridden here — ' + (st === 'on' ? 'On' : 'Off') + '</span>';
                if (isRoot && st === 'inherit') { st = 'on'; hint = '<span class="ep-row-hint">On (root default)</span>'; }
                var seg = function (val, label) {
                    var active = st === val;
                    return '<button type="button" class="er-tri-seg' + (active ? ' active' : '') + (active && val === 'off' ? ' is-off' : '') + '"' +
                        ' data-ep-seg="' + val + '" data-ep-type="' + esc(t.type) + '" aria-pressed="' + (active ? 'true' : 'false') + '">' + label + '</button>';
                };
                var control = '<span class="er-tri" role="group" aria-label="' + esc(t.type) + ' state">' +
                    (isRoot ? '' : seg('inherit', 'Inherit')) + seg('on', 'On') + seg('off', 'Off') + '</span>';
                return '<div class="ep-matrix-row">' +
                    '<span class="badge" title="' + esc(t.description || '') + '">' + esc(t.type) + '</span>' +
                    hint + control + '</div>';
            }).join('');
            return head + body;
        }).join('');
        wrap.innerHTML = html || '<div class="empty-state" style="padding:24px;text-align:center;color:var(--fwmon-text-faint)">No alert types match the filter.</div>';
        renderSaveBar();
    }

    function renderSaveBar() {
        var n = dirtyCount();
        $('ep-save-bar').style.display = n ? '' : 'none';
        if (n) $('ep-dirty-count').textContent = n + ' unsaved toggle change' + (n === 1 ? '' : 's');
    }

    function setToggle(at, state) {
        if (state === 'inherit') delete workToggles[at];
        else workToggles[at] = state === 'on';
        renderMatrix();
    }

    function bulkSet(family, state) {
        var p = profileById(currentId);
        var apply = function () {
            registry.forEach(function (t) {
                if (t.family !== family) return;
                if (state === 'inherit') delete workToggles[t.type];
                else workToggles[t.type] = state === 'on';
            });
            renderMatrix();
        };
        if (state === 'off' && p && p.is_default) {
            var n = registry.filter(function (t) { return t.family === family; }).length;
            AC.confirm('This turns off ' + n + ' alert type(s) in the DEFAULT profile — every device without a site/device override stops alerting on them. Continue?',
                { title: 'Turn off ' + family + ' everywhere?', confirmLabel: 'Turn off', danger: true }).then(function (ok) { if (ok) apply(); });
            return;
        }
        apply();
    }

    function saveToggles() {
        var p = profileById(currentId);
        var body = { toggles: [] };
        Object.keys(workToggles).forEach(function (at) {
            body.toggles.push({ alert_type: at, enabled: !!workToggles[at] });
        });
        var offs = body.toggles.filter(function (t) { return !t.enabled; }).length;
        var proceed = Promise.resolve(true);
        if (p && p.is_default && offs > 0) {
            proceed = AC.confirm('Saving turns ' + offs + ' alert type(s) OFF in the DEFAULT profile — the whole fleet inherits that unless a site/device profile overrides it. Continue?',
                { title: 'Change Default alerting?', confirmLabel: 'Save', danger: true });
        }
        proceed.then(function (ok) {
            if (!ok) return;
            AC.apiFetch(API + '/event-rule-profiles/' + currentId + '/toggles', { method: 'PUT', body: body }).then(function () {
                baseToggles = Object.assign({}, workToggles);
                AC.showSuccess('Toggles saved');
                renderSaveBar();
                loadProfiles().then(renderDetailHeader);
            }).catch(function (err) { AC.showError('Save failed: ' + err.message); });
        });
    }

    // ---- Rules tab ---------------------------------------------------------

    var rulesFilter = 'all';

    function renderRulesTab() {
        var chips = [
            { k: 'all', label: 'All' }, { k: 'alert', label: 'Alert' }, { k: 'suppress', label: 'Suppress' },
            { k: 'temp', label: 'Temporary ⏱' }, { k: 'disabled', label: 'Disabled' }
        ];
        $('ep-rules-filter').innerHTML = '<span class="chart-range-pills">' + chips.map(function (c) {
            return '<button type="button" class="chart-range-pill' + (rulesFilter === c.k ? ' active' : '') + '" data-ep-rulefilter="' + c.k + '">' + c.label + '</button>';
        }).join('') + '</span>';
        window.FwmonEventRules.loadRules(currentId, rulesFilter);
    }

    // ---- Assignments tab ---------------------------------------------------

    var allDevices = [], allSites = [];

    function renderAssignments() {
        var p = profileById(currentId);
        var wrap = $('ep-assignments');
        if (!wrap) return;
        if (p && p.is_default) {
            wrap.innerHTML = '<div class="empty-state" style="padding:24px;color:var(--fwmon-text-faint)">' +
                'The Default profile applies to everything that has no site or device profile — it is never assigned directly. ' +
                'Assign other profiles from their own Assignments tab, or from the site/device alert-config dialogs.</div>';
            return;
        }
        Promise.all([
            AC.apiFetch(API + '/event-rule-profiles/' + currentId + '/assignments'),
            AC.apiFetch(API + '/sites').catch(function () { return { data: [] }; }),
            AC.apiFetch(API + '/devices').catch(function () { return { data: [] }; })
        ]).then(function (r) {
            var a = r[0].data || { sites: [], devices: [] };
            allSites = r[1].data || [];
            allDevices = r[2].data || [];
            var chip = function (kind, it) {
                return '<span class="ep-chip">' + esc(it.name) +
                    '<button type="button" title="Unassign (falls back to inherit)" aria-label="Unassign ' + esc(it.name) + '" data-ep-unassign="' + kind + '" data-id="' + it.id + '">×</button></span>';
            };
            var opts = function (items, exclude) {
                var excludeSet = {};
                (exclude || []).forEach(function (e) { excludeSet[e.id] = 1; });
                return items.filter(function (it) { return !excludeSet[it.id]; })
                    .map(function (it) { return '<option value="' + it.id + '">' + esc(it.name) + '</option>'; }).join('');
            };
            wrap.innerHTML =
                '<div class="policy-section"><div class="policy-section-header"><h3>Sites</h3></div><div class="policy-section-body">' +
                '<div class="ep-chip-list">' + ((a.sites || []).map(function (s) { return chip('site', s); }).join('') || '<span style="color:var(--fwmon-text-faint);font-size:0.8rem">No sites assigned.</span>') + '</div>' +
                '<div class="form-row" style="max-width:420px"><div class="form-group"><label for="ep-add-site">Assign a site</label>' +
                '<select id="ep-add-site"><option value="">— pick a site —</option>' + opts(allSites, a.sites) + '</select></div>' +
                '<div class="form-group" style="align-self:end"><button type="button" class="btn secondary sm" id="ep-add-site-btn" data-min-role="admin">Assign</button></div></div>' +
                '</div></div>' +
                '<div class="policy-section"><div class="policy-section-header"><h3>Devices</h3></div><div class="policy-section-body">' +
                '<div class="ep-chip-list">' + ((a.devices || []).map(function (d) { return chip('device', d); }).join('') || '<span style="color:var(--fwmon-text-faint);font-size:0.8rem">No devices assigned.</span>') + '</div>' +
                '<div class="form-row" style="max-width:420px"><div class="form-group"><label for="ep-add-device">Assign a device</label>' +
                '<select id="ep-add-device"><option value="">— pick a device —</option>' + opts(allDevices, a.devices) + '</select></div>' +
                '<div class="form-group" style="align-self:end"><button type="button" class="btn secondary sm" id="ep-add-device-btn" data-min-role="admin">Assign</button></div></div>' +
                '<p class="field-hint">A device profile beats its site profile; both inherit anything they don\'t override from Default.</p>' +
                '</div></div>';
            var sBtn = $('ep-add-site-btn');
            if (sBtn) sBtn.addEventListener('click', function () { assignEntity('site', $('ep-add-site').value); });
            var dBtn = $('ep-add-device-btn');
            if (dBtn) dBtn.addEventListener('click', function () { assignEntity('device', $('ep-add-device').value); });
        }).catch(function (err) { AC.showError('Failed to load assignments: ' + err.message); });
    }

    function assignEntity(kind, idRaw) {
        var id = parseInt(idRaw, 10);
        if (!id) return;
        var url = API + '/' + (kind === 'site' ? 'sites' : 'devices') + '/' + id + '/event-profile';
        // Move-confirm: if the entity already carries a DIFFERENT profile,
        // never steal silently.
        AC.apiFetch(API + '/' + (kind === 'site' ? 'sites' : 'devices') + '/' + id + '/alert-config')
            .catch(function () { return { data: null }; })
            .then(function (res) {
                var cur = res.data && res.data.event_profile_id;
                if (cur && cur !== currentId) {
                    // Raw names — AC.confirm renders via textContent (esc() here
                    // would double-escape "R&D" into "R&amp;D").
                    var from = profileById(cur);
                    return AC.confirm('This ' + kind + ' currently uses profile “' + (from ? from.name : ('#' + cur)) + '”. Move it to “' + ((profileById(currentId) || {}).name || '') + '”?',
                        { title: 'Move ' + kind + '?', confirmLabel: 'Move' });
                }
                return true;
            })
            .then(function (ok) {
                if (!ok) return;
                AC.apiFetch(url, { method: 'PUT', body: { profile_id: currentId } }).then(function () {
                    AC.showSuccess('Assigned');
                    loadProfiles().then(function () { renderDetailHeader(); renderAssignments(); });
                }).catch(function (err) { AC.showError('Assign failed: ' + err.message); });
            });
    }

    function unassignEntity(kind, id) {
        var url = API + '/' + (kind === 'site' ? 'sites' : 'devices') + '/' + id + '/event-profile';
        AC.apiFetch(url, { method: 'PUT', body: { profile_id: null } }).then(function () {
            AC.showSuccess('Unassigned');
            loadProfiles().then(function () { renderDetailHeader(); renderAssignments(); });
        }).catch(function (err) { AC.showError('Unassign failed: ' + err.message); });
    }

    // ---- State C: effective view -------------------------------------------

    function showEffective() {
        setHash('#effective');
        setView('effective');
        var body = $('ep-effective-body');
        Promise.all([
            AC.apiFetch(API + '/devices').catch(function () { return { data: [] }; }),
            AC.apiFetch(API + '/sites').catch(function () { return { data: [] }; })
        ]).then(function (r) {
            allDevices = r[0].data || [];
            allSites = r[1].data || [];
            body.innerHTML =
                '<div class="flex items-center" style="gap:10px;flex-wrap:wrap;margin-bottom:14px">' +
                '<button class="btn secondary sm" data-action="ep-back">← Profiles</button>' +
                '<h2 class="text-xl font-bold font-outfit" style="margin:0">Effective coverage</h2></div>' +
                '<p class="text-xs" style="color:var(--fwmon-text-faint);margin:0 0 12px">Pick a device or site to see exactly which alert types fire there and which profile layer decided each one.</p>' +
                '<div class="form-row" style="max-width:640px"><div class="form-group"><label for="ep-eff-device">Device</label>' +
                '<select id="ep-eff-device"><option value="">— pick a device —</option>' +
                allDevices.map(function (d) { return '<option value="' + d.id + '">' + esc(d.name) + '</option>'; }).join('') + '</select></div>' +
                '<div class="form-group"><label for="ep-eff-site">…or site</label>' +
                '<select id="ep-eff-site"><option value="">— pick a site —</option>' +
                allSites.map(function (s) { return '<option value="' + s.id + '">' + esc(s.name) + '</option>'; }).join('') + '</select></div></div>' +
                '<div id="ep-eff-result"></div>';
            var dSel = $('ep-eff-device'), sSel = $('ep-eff-site');
            dSel.addEventListener('change', function () { if (dSel.value) { sSel.value = ''; loadEffective('device_id=' + dSel.value); } });
            sSel.addEventListener('change', function () { if (sSel.value) { dSel.value = ''; loadEffective('site_id=' + sSel.value); } });
        });
    }

    function loadEffective(q) {
        var out = $('ep-eff-result');
        out.innerHTML = '<div style="color:var(--fwmon-text-faint);padding:12px">Resolving…</div>';
        AC.apiFetch(API + '/event-config/effective?' + q).then(function (res) {
            var d = res.data || {};
            var chain = (d.chain || []).map(function (l) {
                return '<span class="ep-layer-badge ' + esc(l.layer) + '">' + esc(l.layer.toUpperCase()) + '</span> ' +
                    '<a href="#profile-' + l.profile_id + '/toggles" data-ep-openprofile="' + l.profile_id + '" style="margin-right:14px">' + esc(l.profile_name || ('#' + l.profile_id)) + '</a>';
            }).join('<span style="color:var(--fwmon-text-faint);margin-right:14px">→</span>');
            var famRows = {};
            (d.toggles || []).forEach(function (t) {
                (famRows[t.family] = famRows[t.family] || []).push(t);
            });
            var togglesHTML = Object.keys(famRows).map(function (fam) {
                return '<div class="ep-matrix-group-head" style="cursor:default"><span>' + esc(fam) + '</span></div>' +
                    famRows[fam].map(function (t) {
                        var src = t.decided_by === 'implicit' ? 'On — nothing overrides it' :
                            ((t.enabled ? 'On' : 'Off') + ' — decided by the ' + t.decided_by + ' layer');
                        return '<div class="ep-matrix-row"><span class="badge">' + esc(t.alert_type) + '</span>' +
                            '<span class="ep-row-hint' + (t.decided_by !== 'implicit' ? ' is-override' : '') + '">' + esc(src) + '</span>' +
                            '<span style="margin-left:auto;font-family:var(--fwmon-font-mono);font-size:0.75rem;color:' +
                            (t.enabled ? 'var(--fwmon-series-1)' : 'var(--fwmon-sig-crit)') + '">' + (t.enabled ? 'ON' : 'OFF') + '</span></div>';
                    }).join('');
            }).join('');
            var rulesHTML = (d.rules || []).length
                ? '<div class="table-wrap" style="overflow-x:auto"><table class="data-table"><thead><tr><th>#</th><th>Layer</th><th>Rule</th><th>Source</th><th>Action</th><th>Priority</th><th>Expires</th></tr></thead><tbody>' +
                d.rules.map(function (r, i) {
                    return '<tr><td>' + (i + 1) + '</td><td><span class="ep-layer-badge ' + esc(r.layer) + '">' + esc(r.layer.toUpperCase()) + '</span></td>' +
                        '<td>' + esc(r.name) + '</td><td>' + esc(r.source) + '</td><td>' + esc(r.action) + '</td><td>' + esc(r.priority) + '</td>' +
                        '<td>' + (r.expires_at ? '⏱ ' + esc(r.expires_at) : '—') + '</td></tr>';
                }).join('') + '</tbody></table></div>'
                : '<div style="color:var(--fwmon-text-faint);padding:8px 4px">No match rules apply to this scope.</div>';
            out.innerHTML =
                '<div style="margin:10px 0 16px"><span style="color:var(--fwmon-text-faint);font-size:0.8rem;margin-right:10px">Chain:</span>' + chain + '</div>' +
                '<h3 style="font-size:0.9rem;margin:14px 0 4px">Alert type toggles</h3>' + togglesHTML +
                '<h3 style="font-size:0.9rem;margin:18px 0 4px">Match rules that apply (evaluation order)</h3>' + rulesHTML;
        }).catch(function (err) { out.innerHTML = ''; AC.showError('Effective lookup failed: ' + err.message); });
    }

    // ---- profile modal (create / rename / clone) ---------------------------

    function openProfileModal(mode, id) {
        var p = id ? profileById(id) : null;
        $('event-profile-mode').value = mode;
        $('event-profile-id').value = id || '';
        $('event-profile-modal-title').textContent =
            mode === 'edit' ? 'Edit Profile' : (mode === 'clone' ? 'Clone “' + (p ? p.name : '') + '”' : 'Create Event Profile');
        $('ep-name').value = mode === 'edit' && p ? p.name : (mode === 'clone' && p ? p.name + ' Copy' : '');
        $('ep-description').value = mode === 'edit' && p ? (p.description || '') : '';
        var nameInput = $('ep-name');
        nameInput.disabled = !!(mode === 'edit' && p && p.is_default);
        nameInput.title = nameInput.disabled ? 'The Default profile cannot be renamed' : '';
        AC.openModal('event-profile-modal');
    }

    function submitProfileModal(e) {
        e.preventDefault();
        var mode = $('event-profile-mode').value;
        var id = parseInt($('event-profile-id').value, 10) || 0;
        var body = { name: $('ep-name').value.trim(), description: $('ep-description').value.trim() };
        var req;
        if (mode === 'edit') req = AC.apiFetch(API + '/event-rule-profiles/' + id, { method: 'PUT', body: body });
        else if (mode === 'clone') req = AC.apiFetch(API + '/event-rule-profiles/' + id + '/clone', { method: 'POST', body: { name: body.name } });
        else req = AC.apiFetch(API + '/event-rule-profiles', { method: 'POST', body: body });
        req.then(function (res) {
            AC.closeModal('event-profile-modal');
            AC.showSuccess(mode === 'edit' ? 'Profile updated' : (mode === 'clone' ? 'Profile cloned' : 'Profile created'));
            loadProfiles().then(function () {
                var target = (mode !== 'edit' && res && res.data && res.data.id) ? res.data.id : (currentId && $('ep-detail-view').style.display !== 'none' ? currentId : 0);
                if (mode === 'edit' && $('ep-detail-view').style.display !== 'none') { renderDetailHeader(); renderGrid(); return; }
                if (target) showDetail(target, 'toggles'); else { renderStats(); renderGrid(); }
            });
        }).catch(function (err) { AC.showError('Save failed: ' + err.message); });
    }

    function deleteProfile(id) {
        var p = profileById(id);
        if (!p) return;
        var c = p.counts || {};
        AC.confirm('Delete profile “' + p.name + '”? Its ' + (c.rule_count || 0) + ' rule(s) move to Default; ' +
            (c.site_count || 0) + ' site(s) and ' + (c.device_count || 0) + ' device(s) fall back to inheriting.',
            { title: 'Delete profile?', confirmLabel: 'Delete', danger: true }).then(function (ok) {
            if (!ok) return;
            AC.apiFetch(API + '/event-rule-profiles/' + id, { method: 'DELETE' }).then(function () {
                AC.showSuccess('Profile deleted');
                if (currentId === id) showGrid();
                else loadProfiles().then(function () { renderStats(); renderGrid(); });
            }).catch(function (err) { AC.showError('Delete failed: ' + err.message); });
        });
    }

    // ---- wiring ------------------------------------------------------------

    function wire() {
        var createBtn = $('ep-create-btn');
        if (createBtn) createBtn.addEventListener('click', function () { openProfileModal('create'); });
        var effBtn = $('ep-effective-btn');
        if (effBtn) effBtn.addEventListener('click', showEffective);
        var form = $('event-profile-form');
        if (form) form.addEventListener('submit', submitProfileModal);
        document.querySelectorAll('[data-ep-close]').forEach(function (b) {
            b.addEventListener('click', function () { AC.closeModal('event-profile-modal'); });
        });
        var filter = $('ep-matrix-filter');
        if (filter) filter.addEventListener('input', renderMatrix);
        var saveBtn = $('ep-save-toggles-btn');
        if (saveBtn) saveBtn.addEventListener('click', saveToggles);
        var discardBtn = $('ep-discard-btn');
        if (discardBtn) discardBtn.addEventListener('click', function () { workToggles = Object.assign({}, baseToggles); renderMatrix(); });
        var tabs = $('ep-tabs');
        if (tabs) tabs.addEventListener('click', function (ev) {
            var t = ev.target.closest('[data-ep-tab]');
            if (t) selectTab(t.getAttribute('data-ep-tab'));
        });

        // Page-scoped hashchange: deep links / manual hash edits re-route, but
        // ONLY while this page is active (the #alert/<id> handler owns its own
        // pattern; ours never matches it).
        window.addEventListener('hashchange', function () {
            if (!pageActive()) return;
            routeFromHash();
        });

        // Delegated actions across all three views.
        var page = $('page-event-rules');
        if (page) page.addEventListener('click', function (ev) {
            var seg = ev.target.closest('[data-ep-seg]');
            if (seg) { setToggle(seg.getAttribute('data-ep-type'), seg.getAttribute('data-ep-seg')); return; }
            var bulk = ev.target.closest('[data-ep-bulk]');
            if (bulk) { bulkSet(bulk.getAttribute('data-ep-fam'), bulk.getAttribute('data-ep-bulk')); return; }
            var head = ev.target.closest('.ep-matrix-group-head');
            if (head && !ev.target.closest('.ep-group-bulk')) {
                var fam = head.getAttribute('data-ep-group');
                if (fam) { collapsed[fam] = !collapsed[fam]; renderMatrix(); }
                return;
            }
            var chipX = ev.target.closest('[data-ep-unassign]');
            if (chipX) { unassignEntity(chipX.getAttribute('data-ep-unassign'), parseInt(chipX.getAttribute('data-id'), 10)); return; }
            var rf = ev.target.closest('[data-ep-rulefilter]');
            if (rf) { rulesFilter = rf.getAttribute('data-ep-rulefilter'); renderRulesTab(); return; }
            var openProf = ev.target.closest('[data-ep-openprofile]');
            if (openProf) { ev.preventDefault(); showDetail(parseInt(openProf.getAttribute('data-ep-openprofile'), 10), 'toggles'); return; }
            var act = ev.target.closest('[data-action]');
            if (!act) return;
            var action = act.getAttribute('data-action');
            var id = parseInt(act.getAttribute('data-id') || '0', 10);
            if (action === 'ep-open') showDetail(id, 'toggles');
            else if (action === 'ep-back') { confirmDiscard().then(function (ok) { if (ok) { workToggles = Object.assign({}, baseToggles); showGrid(); } }); }
            else if (action === 'ep-edit') openProfileModal('edit', id);
            else if (action === 'ep-clone') openProfileModal('clone', id);
            else if (action === 'ep-delete') deleteProfile(id);
        });
    }

    window.FwmonEventProfiles = {
        init: init,
        // getProfiles feeds the rule builder's profile select + entity modals.
        getProfiles: function () { return profiles; }
    };
})();
