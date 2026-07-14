/* admin-event-rules.js — NOC Event-Rule Builder (Phase 2, v0.11.51).
 *
 * UI for the vendor-aware alert/suppress rule engine shipped in v0.11.49.
 * Lists rules, and provides a builder modal with an AND/OR condition widget and
 * a live "Preview" tester that runs a candidate rule against recent syslog
 * before saving. All backend routes are admin-only; the server enforces, and
 * non-admins see a graceful placeholder rather than a broken page.
 *
 * Mirrors the conventions of admin-threatintel.js / the Alert Policies page:
 * AdminCommon.apiFetch (auto CSRF/JSON, returns {success,data}), escapeHtml,
 * openModal/closeModal, confirm, showError/showSuccess.
 */
(function () {
    'use strict';
    var AC = window.AdminCommon;
    var API = '/admin/api';

    // validVendors mirrors the server set (handlers.go). vendor_scope filters
    // which devices a rule applies to; only fortigate/opnsense/pfsense extract
    // structured fields today (others fall back to base fields).
    var VENDORS = ['fortigate', 'opnsense', 'pfsense', 'paloalto', 'cisco_asa', 'sonicwall', 'firewalla', 'generic'];
    var OPS = ['eq', 'neq', 'contains', 'not_contains', 'regex', 'gt', 'lt', 'in', 'exists'];
    var OP_SET = OPS.reduce(function (m, o) { m[o] = 1; return m; }, {});
    var GROUP_OPS = { and: 1, or: 1 };
    // Common FortiGate fields offered as datalist suggestions (free-text still allowed).
    var FIELD_HINTS = ['subtype', 'level', 'logid', 'logdesc', 'action', 'srcintf', 'dstintf',
        'srcip', 'dstip', 'srcport', 'dstport', 'user', 'service', 'severity', 'facility', 'app_name', 'message'];
    // Default state-rule dampening (mirrors the server seed + defaults).
    var STATE_DEFAULT_MIN_UP_MIN = 60; // 3600s
    var STATE_DEFAULT_DAILY_CAP = 1;

    // The datalist a condition field should suggest from, by current source.
    function fieldHintsId() {
        var s = $('er-source').value;
        if (s === 'state') return 'er-state-field-hints';
        if (s === 'metric') return 'er-metric-field-hints';
        if (s === 'spike') return 'er-spike-field-hints';
        if (s === 'trap') return 'er-trap-field-hints';
        if (s === 'flow_security') return 'er-flowsec-field-hints';
        return 'er-field-hints';
    }

    var rules = [];
    var devices = [];
    var sites = [];
    var policies = [];
    var wired = false;
    // When a rule is created from an sFlow-security alert, the alert id to ack once
    // the rule saves (the rule only drops the source from the next cycle, so the
    // open alert would otherwise linger). Cleared after each open/save.
    var pendingAckAlertId = null;

    function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }
    function $(id) { return document.getElementById(id); }

    // ---- load + render ---------------------------------------------------

    function init() {
        if (!wired) { wire(); wired = true; }
        // A "Create rule from alert" click on the Alerts page stashes a one-shot
        // prefill and navigates here; open the editor once the device/site/rule
        // lists are loaded (else a device-scoped suppress would save fleet-wide).
        var pending = takePendingPrefill();
        Promise.all([loadLists(), loadRules()]).then(function () {
            if (pending) openFromPrefill(pending);
        });
    }

    // takePendingPrefill reads + clears the one-shot handoff from the Alerts page.
    function takePendingPrefill() {
        var raw;
        try { raw = sessionStorage.getItem('fwmon_rule_prefill'); } catch (e) { return null; }
        if (!raw) return null;
        try { sessionStorage.removeItem('fwmon_rule_prefill'); } catch (e) { /* ignore */ }
        try { return JSON.parse(raw); } catch (e) { return null; }
    }

    // openFromPrefill opens the editor for a suggested rule (or the existing rule
    // when "customize" targeted one), verifying the device/site scope actually took.
    function openFromPrefill(pending) {
        if (pending.editId) { openRuleModal(pending.editId); return; }
        var pf = pending.rule || {};
        pf.action = pending.action || 'suppress';
        pf.enabled = true;
        pf.name = pf.suggested_name || pf.name || '';
        // The suggested name says "Suppress …"; relabel for the customize path.
        if (pf.action === 'alert' && pf.name.indexOf('Suppress ') === 0) {
            pf.name = 'Customize ' + pf.name.slice('Suppress '.length);
        }
        openRuleModal(null, pf);
        if (pf.device_id && String($('er-device').value) !== String(pf.device_id)) {
            AC.showError('Could not pre-select the device for this rule — set the scope manually before saving.');
        } else if (pf.site_id && String($('er-site').value) !== String(pf.site_id)) {
            AC.showError('Could not pre-select the site for this rule — set the scope manually before saving.');
        }
    }

    function loadLists() {
        return Promise.all([
            AC.apiFetch(API + '/devices').catch(function () { return { data: [] }; }),
            AC.apiFetch(API + '/sites').catch(function () { return { data: [] }; }),
            AC.apiFetch(API + '/alert-policies').catch(function () { return { data: [] }; })
        ]).then(function (r) {
            devices = r[0].data || [];
            sites = r[1].data || [];
            policies = r[2].data || [];
        });
    }

    function loadRules() {
        return AC.apiFetch(API + '/event-rules').then(function (res) {
            rules = res.data || [];
            renderStats();
            renderTable();
        }).catch(function (err) {
            // Admin-only API: operator/viewer get 403 — show a placeholder, not a
            // broken page (no dead ends).
            var role = (AC && AC.sessionRole) || '';
            if (/role|forbidden|allow this action/i.test(err.message) || (role && role !== 'admin')) {
                renderPlaceholder();
            } else {
                AC.showError('Failed to load event rules: ' + err.message);
            }
        });
    }

    function renderPlaceholder() {
        var grid = $('event-rules-table-wrap');
        if (grid) {
            grid.innerHTML = '<div class="empty-state" style="padding:32px;text-align:center;color:var(--fwmon-text-faint)">' +
                'Admin role required to manage event rules.</div>';
        }
        ['er-stat-total', 'er-stat-enabled', 'er-stat-suppress', 'er-stat-hits'].forEach(function (id) {
            if ($(id)) $(id).textContent = '--';
        });
    }

    function renderStats() {
        var enabled = 0, suppress = 0, hits = 0;
        rules.forEach(function (r) {
            if (r.enabled) enabled++;
            if (r.action === 'suppress') suppress++;
            hits += (r.hit_count || 0);
        });
        if ($('er-stat-total')) $('er-stat-total').textContent = rules.length;
        if ($('er-stat-enabled')) $('er-stat-enabled').textContent = enabled;
        if ($('er-stat-suppress')) $('er-stat-suppress').textContent = suppress;
        if ($('er-stat-hits')) $('er-stat-hits').textContent = hits.toLocaleString();
    }

    function matchSummary(r) {
        if (!r.match_json) return '<span style="color:var(--fwmon-text-faint)">any</span>';
        try {
            var t = JSON.parse(r.match_json);
            return esc(summarizeNode(t));
        } catch (e) { return '<span style="color:var(--fwmon-sig-warn)">invalid</span>'; }
    }
    function summarizeNode(n) {
        if (!n || !n.op) return '';
        if (n.op === 'and' || n.op === 'or') {
            return '(' + (n.conditions || []).map(summarizeNode).join(' ' + n.op.toUpperCase() + ' ') + ')';
        }
        if (n.op === 'exists') return n.field + ' exists';
        if (n.op === 'in') return n.field + ' in [' + (n.values || []).join(',') + ']';
        return n.field + ' ' + n.op + ' ' + (n.value == null ? '' : n.value);
    }

    // expiresText renders a temporary rule's remaining window ("in 3h"/"in 2d"),
    // an "expired" badge for one not yet pruned, or "—" for a permanent rule.
    function expiresText(r) {
        if (!r.expires_at) return '<span style="color:var(--fwmon-text-faint)">—</span>';
        var ms = new Date(r.expires_at).getTime() - Date.now();
        if (ms <= 0) return '<span class="badge" style="background:var(--fwmon-card-bg);color:var(--fwmon-text-faint)">expired</span>';
        var h = Math.round(ms / 3600000);
        var label = h >= 48 ? Math.round(h / 24) + 'd' : (h >= 1 ? h + 'h' : Math.max(1, Math.round(ms / 60000)) + 'm');
        return '<span class="badge" title="' + esc(r.expires_at) + '">in ' + label + '</span>';
    }

    function renderTable() {
        var wrap = $('event-rules-table-wrap');
        if (!wrap) return;
        if (!rules.length) {
            wrap.innerHTML = '<div class="empty-state" style="padding:32px;text-align:center;color:var(--fwmon-text-faint)">' +
                'No event rules yet. Click “+ Create Rule”.</div>';
            return;
        }
        var rows = rules.map(function (r) {
            var actionBadge = r.action === 'suppress'
                ? '<span class="badge" style="background:var(--fwmon-card-bg);color:var(--fwmon-text-faint)">suppress</span>'
                : '<span class="badge">alert</span>';
            var sevText = r.severity ? esc(r.severity) : '<span style="color:var(--fwmon-text-faint)">default</span>';
            var seedBadge = (r.seed_version > 0) ? ' <span class="badge" title="Shipped default rule" style="background:var(--fwmon-accent-bg);color:var(--fwmon-accent)">default</span>' : '';
            var toggle = '<label class="toggle-switch"><input type="checkbox" data-er-toggle="' + r.id + '"' + (r.enabled ? ' checked' : '') + '><span class="toggle-slider"></span></label>';
            return '<tr>' +
                '<td>' + esc(r.priority) + '</td>' +
                '<td>' + esc(r.name) + seedBadge + '</td>' +
                '<td>' + esc(r.source) + '</td>' +
                '<td>' + (r.vendor_scope ? esc(r.vendor_scope) : '<span style="color:var(--fwmon-text-faint)">any</span>') + '</td>' +
                '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + (r.match_json ? esc(r.match_json) : '') + '">' + matchSummary(r) + '</td>' +
                '<td>' + actionBadge + '</td>' +
                '<td>' + sevText + '</td>' +
                '<td>' + expiresText(r) + '</td>' +
                '<td>' + toggle + '</td>' +
                '<td>' + (r.hit_count || 0).toLocaleString() + '</td>' +
                '<td style="white-space:nowrap">' +
                '<button class="btn secondary sm" data-er-edit="' + r.id + '" data-min-role="admin">Edit</button> ' +
                '<button class="btn danger sm" data-er-delete="' + r.id + '" data-min-role="admin">Delete</button>' +
                '</td></tr>';
        }).join('');
        wrap.innerHTML = '<div class="table-wrap" style="overflow-x:auto"><table class="data-table">' +
            '<thead><tr><th>Pri</th><th>Name</th><th>Source</th><th>Vendor</th><th>Match</th><th>Action</th><th>Severity</th><th>Expires</th><th>Enabled</th><th>Hits</th><th></th></tr></thead>' +
            '<tbody>' + rows + '</tbody></table></div>';
    }

    // ---- modal ------------------------------------------------------------

    function fillSelect(sel, items, anyLabel, valueKey, labelKey) {
        if (!sel) return;
        var html = '<option value="">' + anyLabel + '</option>';
        items.forEach(function (it) {
            html += '<option value="' + esc(it[valueKey]) + '">' + esc(it[labelKey]) + '</option>';
        });
        sel.innerHTML = html;
    }

    // expiresHoursFor returns the value for the "expires in hours" input: a
    // prefill's suggested hours (create-from-alert), or an existing rule's
    // remaining hours (edit), or blank (permanent / fresh rule).
    function expiresHoursFor(r, isEdit) {
        if (!r) return '';
        if (!isEdit && r.expires_hours) return r.expires_hours;
        if (isEdit && r.expires_at) {
            var ms = new Date(r.expires_at).getTime() - Date.now();
            if (ms > 0) return Math.ceil(ms / 3600000);
        }
        return '';
    }

    function openRuleModal(id, prefill) {
        // Edit → load from the in-memory list; Create → blank, unless a prefill
        // object (same shape as a rule) is passed from the "create from alert" flow.
        var r = id ? rules.find(function (x) { return x.id === id; }) : (prefill || null);
        if (id && !r) { AC.showError('That rule no longer exists.'); return; } // deleted between suggest + open
        var isEdit = !!id;
        $('event-rule-modal-title').textContent = isEdit ? 'Edit Event Rule' : (prefill ? 'New Event Rule (from alert)' : 'Create Event Rule');
        $('event-rule-id').value = isEdit ? r.id : ''; // MUST be empty for prefill → POST, not PUT /undefined
        $('er-name').value = r ? r.name : '';
        $('er-description').value = r ? (r.description || '') : '';
        $('er-enabled').checked = r ? !!r.enabled : true;
        $('er-priority').value = r ? r.priority : 100;
        $('er-source').value = r ? (r.source || 'syslog') : 'syslog';

        fillSelect($('er-vendor'), VENDORS.map(function (v) { return { v: v, n: v }; }), 'Any vendor', 'v', 'n');
        $('er-vendor').value = r ? (r.vendor_scope || '') : '';
        fillSelect($('er-device'), devices, 'Any device', 'id', 'name');
        $('er-device').value = r && r.device_id ? r.device_id : '';
        fillSelect($('er-site'), sites, 'Any site', 'id', 'name');
        $('er-site').value = r && r.site_id ? r.site_id : '';
        fillSelect($('er-policy'), policies, 'Device default policy', 'id', 'name');
        $('er-policy').value = r && r.policy_id ? r.policy_id : '';

        $('er-action').value = r ? (r.action || 'alert') : 'alert';
        $('er-severity').value = r ? (r.severity || '') : '';
        $('er-alert-type').value = r ? (r.alert_type || '') : '';
        $('er-group-by').value = r ? (r.group_by || '') : '';
        $('er-cooldown').value = r && r.cooldown_minutes ? r.cooldown_minutes : '';

        // Temporary-rule expiry. A prefill from a "Suppress source" alert carries
        // expires_hours (default 24); an existing rule shows its remaining hours.
        $('er-expires').value = expiresHoursFor(r, isEdit);
        // Ack-on-create handoff (F3): the alert this rule was built from, to ack on save.
        pendingAckAlertId = (!isEdit && prefill && prefill.ack_alert_id) ? prefill.ack_alert_id : null;

        // Dampening (state rules): parse the blob into minutes + cap, defaulting to
        // the shipped values so a fresh state rule pre-fills sensible numbers.
        loadDampenFromRule(r);
        // Threshold (metric rules): parse mode + threshold/clear/k.
        loadMetricFromRule(r);
        loadSpikeFromRule(r);

        // conditions: parse match_json into rows, or advanced raw for nested trees
        $('er-advanced-toggle').checked = false;
        $('er-raw-json').value = '';
        setAdvanced(false);
        loadConditionsFromRule(r);
        onSourceChange();
        clearPreview();
        AC.openModal('event-rule-modal');
    }

    // loadDampenFromRule fills the minutes/cap inputs from a rule's dampen_json.
    // New state rules (or non-state rules) fall back to the shipped defaults.
    function loadDampenFromRule(r) {
        var minMin = STATE_DEFAULT_MIN_UP_MIN, cap = STATE_DEFAULT_DAILY_CAP;
        if (r && r.dampen_json) {
            try {
                var d = JSON.parse(r.dampen_json);
                if (typeof d.min_up_seconds === 'number') minMin = Math.round(d.min_up_seconds / 60);
                if (typeof d.daily_cap === 'number') cap = d.daily_cap;
            } catch (e) { /* keep defaults on a malformed blob */ }
        }
        $('er-min-up').value = minMin;
        $('er-daily-cap').value = cap;
    }

    // collectDampen serializes the dampening inputs to the state dampen_json blob.
    function collectDampen() {
        var minMin = parseInt($('er-min-up').value, 10);
        if (isNaN(minMin) || minMin < 0) minMin = STATE_DEFAULT_MIN_UP_MIN;
        var cap = parseInt($('er-daily-cap').value, 10);
        if (isNaN(cap) || cap < 0) cap = STATE_DEFAULT_DAILY_CAP;
        return JSON.stringify({ refire_mode: 'episode', min_up_seconds: minMin * 60, daily_cap: cap });
    }

    // loadMetricFromRule fills the metric threshold inputs from a rule's
    // dampen_json {mode,threshold,clear_threshold,zscore_k}. Blank threshold =
    // inherit the Settings→Alerts / policy / device value.
    function loadMetricFromRule(r) {
        var mode = 'static', th = '', clr = '', k = '';
        if (r && r.dampen_json) {
            try {
                var d = JSON.parse(r.dampen_json);
                if (d.mode === 'zscore' || d.mode === 'static') mode = d.mode;
                if (typeof d.threshold === 'number' && d.threshold > 0) th = d.threshold;
                if (typeof d.clear_threshold === 'number' && d.clear_threshold > 0) clr = d.clear_threshold;
                if (typeof d.zscore_k === 'number' && d.zscore_k > 0) k = d.zscore_k;
            } catch (e) { /* keep defaults on a malformed blob */ }
        }
        $('er-metric-mode').value = mode;
        $('er-metric-threshold').value = th;
        $('er-metric-clear').value = clr;
        $('er-metric-k').value = k;
    }

    // collectMetricDampen serializes the metric threshold inputs. Blank numeric
    // fields are OMITTED (0 would read as "inherit"/"default" — we keep them
    // absent so an empty threshold genuinely inherits the resolved value).
    function collectMetricDampen() {
        var out = { mode: $('er-metric-mode').value || 'static' };
        var th = parseFloat($('er-metric-threshold').value);
        if (!isNaN(th) && th > 0) out.threshold = th;
        var clr = parseFloat($('er-metric-clear').value);
        if (!isNaN(clr) && clr > 0) out.clear_threshold = clr;
        if (out.mode === 'zscore') {
            var k = parseFloat($('er-metric-k').value);
            if (!isNaN(k) && k > 0) out.zscore_k = k;
        }
        return JSON.stringify(out);
    }

    // loadSpikeFromRule fills the spike inputs from a rule's dampen_json
    // {stddev_k, min_duration_minutes}. Blank = the shipped defaults.
    function loadSpikeFromRule(r) {
        var k = '', dur = '';
        if (r && r.dampen_json) {
            try {
                var d = JSON.parse(r.dampen_json);
                if (typeof d.stddev_k === 'number' && d.stddev_k > 0) k = d.stddev_k;
                if (typeof d.min_duration_minutes === 'number' && d.min_duration_minutes > 0) dur = d.min_duration_minutes;
            } catch (e) { /* keep blanks on a malformed blob */ }
        }
        $('er-spike-k').value = k;
        $('er-spike-duration').value = dur;
    }

    // collectSpikeDampen serializes the spike inputs. Blank fields are omitted so
    // they inherit the detector defaults (k=3, sustain=15m).
    function collectSpikeDampen() {
        var out = {};
        var k = parseFloat($('er-spike-k').value);
        if (!isNaN(k) && k > 0) out.stddev_k = k;
        var dur = parseInt($('er-spike-duration').value, 10);
        if (!isNaN(dur) && dur > 0) out.min_duration_minutes = dur;
        return JSON.stringify(out);
    }

    // dampenForSource returns the dampen_json for the current source ('' for
    // sources that don't use it, e.g. trap/syslog/flow).
    function dampenForSource() {
        var s = $('er-source').value;
        if (s === 'state') return collectDampen();
        if (s === 'metric') return collectMetricDampen();
        if (s === 'spike') return collectSpikeDampen();
        return '';
    }

    function loadConditionsFromRule(r) {
        var cont = $('er-conditions');
        cont.innerHTML = '';
        $('er-combinator').value = 'and';
        if (!r || !r.match_json) { addConditionRow(); return; }
        var t;
        try { t = JSON.parse(r.match_json); } catch (e) { t = null; }
        if (!t) { addConditionRow(); return; }
        // A simple single-group (and/or of leaves) or a bare leaf maps to rows;
        // anything nested drops into the raw-JSON escape hatch.
        if (t.op === 'and' || t.op === 'or') {
            var flat = (t.conditions || []).every(function (c) { return c.op !== 'and' && c.op !== 'or'; });
            if (flat) {
                $('er-combinator').value = t.op;
                (t.conditions || []).forEach(addConditionRow);
                if (!t.conditions || !t.conditions.length) addConditionRow();
                return;
            }
            // nested → advanced
            $('er-advanced-toggle').checked = true;
            setAdvanced(true);
            $('er-raw-json').value = JSON.stringify(t, null, 2);
            return;
        }
        // bare leaf
        addConditionRow(t);
    }

    function addConditionRow(cond) {
        var cont = $('er-conditions');
        var row = document.createElement('div');
        row.className = 'er-cond-row form-row';
        row.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:6px';
        var opts = OPS.map(function (o) { return '<option value="' + o + '"' + (cond && cond.op === o ? ' selected' : '') + '>' + o + '</option>'; }).join('');
        var val = cond ? (cond.op === 'in' ? (cond.values || []).join(', ') : (cond.value == null ? '' : cond.value)) : '';
        row.innerHTML =
            '<input class="er-cond-field" list="' + fieldHintsId() + '" placeholder="field" value="' + esc(cond ? cond.field : '') + '" style="flex:1">' +
            '<select class="er-cond-op" style="flex:0 0 130px">' + opts + '</select>' +
            '<input class="er-cond-value" placeholder="value" value="' + esc(val) + '" style="flex:1">' +
            '<button type="button" class="btn danger sm er-cond-del" title="Remove">×</button>';
        cont.appendChild(row);
        var opSel = row.querySelector('.er-cond-op');
        var valInput = row.querySelector('.er-cond-value');
        function syncVal() { valInput.style.display = (opSel.value === 'exists') ? 'none' : ''; if (opSel.value === 'in') valInput.placeholder = 'a, b, c'; else valInput.placeholder = 'value'; }
        opSel.addEventListener('change', syncVal); syncVal();
        row.querySelector('.er-cond-del').addEventListener('click', function () { row.remove(); });
    }

    function setAdvanced(on) {
        $('er-conditions-visual').style.display = on ? 'none' : '';
        $('er-conditions-raw').style.display = on ? '' : 'none';
    }

    // Build the match_json STRING from the visual rows or the raw textarea.
    // Returns { json: string, error: string|null }. json === '' means no
    // conditions (match-all) — callers decide whether that's allowed.
    function collectMatch() {
        if ($('er-advanced-toggle').checked) {
            var raw = $('er-raw-json').value.trim();
            if (!raw) return { json: '', error: null };
            var parsed;
            try { parsed = JSON.parse(raw); } catch (e) { return { json: '', error: 'Invalid JSON: ' + e.message }; }
            var verr = validateNode(parsed);
            if (verr) return { json: '', error: verr };
            return { json: JSON.stringify(parsed), error: null };
        }
        var conds = [];
        var rowsEls = $('er-conditions').querySelectorAll('.er-cond-row');
        for (var i = 0; i < rowsEls.length; i++) {
            var row = rowsEls[i];
            var field = row.querySelector('.er-cond-field').value.trim();
            var op = row.querySelector('.er-cond-op').value;
            var value = row.querySelector('.er-cond-value').value;
            if (op === 'exists') { if (field) conds.push({ op: 'exists', field: field }); continue; }
            if (!field) continue;
            if (op === 'in') {
                var values = value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
                conds.push({ op: 'in', field: field, values: values });
            } else {
                if ((op === 'gt' || op === 'lt') && value.trim() !== '' && isNaN(parseFloat(value))) {
                    return { json: '', error: 'Operator "' + op + '" needs a numeric value (field "' + field + '")' };
                }
                conds.push({ op: op, field: field, value: value });
            }
        }
        if (!conds.length) return { json: '', error: null };
        var combinator = $('er-combinator').value;
        var tree = conds.length === 1 ? conds[0] : { op: combinator, conditions: conds };
        return { json: JSON.stringify(tree), error: null };
    }

    // validateNode mirrors the server compiler's expectations: known ops, valid
    // regex. Prevents a silently-never-matching rule from the raw-JSON path.
    function validateNode(n) {
        if (!n || typeof n !== 'object' || !n.op) return 'Each node needs an "op"';
        if (GROUP_OPS[n.op]) {
            if (!Array.isArray(n.conditions)) return '"' + n.op + '" needs a conditions array';
            for (var i = 0; i < n.conditions.length; i++) { var e = validateNode(n.conditions[i]); if (e) return e; }
            return null;
        }
        if (!OP_SET[n.op]) return 'Unknown operator "' + n.op + '"';
        if (n.op !== 'exists' && !n.field) return 'Operator "' + n.op + '" needs a field';
        if (n.op === 'regex') { try { new RegExp(n.value); } catch (e) { return 'Invalid regex: ' + e.message; } }
        return null;
    }

    function onActionChange() {
        var isAlert = $('er-action').value !== 'suppress';
        $('er-alert-fields').style.display = isAlert ? '' : 'none';
        // Dampening/threshold/spike panels only apply to an ALERT rule (a suppress
        // rule mutes, so there's nothing to dampen).
        var src = $('er-source').value;
        $('er-dampen-section').style.display = (src === 'state' && isAlert) ? '' : 'none';
        $('er-metric-section').style.display = (src === 'metric' && isAlert) ? '' : 'none';
        $('er-spike-section').style.display = (src === 'spike' && isAlert) ? '' : 'none';
    }

    // onMetricModeChange shows the Z-score K field only in zscore mode.
    function onMetricModeChange() {
        $('er-metric-k-group').style.display = ($('er-metric-mode').value === 'zscore') ? '' : 'none';
    }

    // onSourceChange re-scopes the editor to the selected source: state rules get
    // the dampening panel + state field hints; metric rules get the threshold
    // panel + metric field hints. Both hide the syslog preview (which tests stored
    // logs, meaningless for live state/metric events) in favor of a note.
    function onSourceChange() {
        var src = $('er-source').value;
        var isState = src === 'state', isMetric = src === 'metric', isSpike = src === 'spike', isTrap = src === 'trap', isFlowSec = src === 'flow_security';
        // Swap the field-hint datalist on every open condition row + the dedup field.
        var list = fieldHintsId();
        document.querySelectorAll('#er-conditions .er-cond-field').forEach(function (el) { el.setAttribute('list', list); });
        var gb = $('er-group-by'); if (gb) gb.setAttribute('list', list);
        // Preview vs source-specific note. State/metric/spike/trap/flow_security all
        // evaluate live telemetry, not stored logs, so the syslog preview is
        // meaningless for them.
        var noPreview = isState || isMetric || isSpike || isTrap || isFlowSec;
        $('er-preview-btn').style.display = noPreview ? 'none' : '';
        $('er-preview-result').style.display = noPreview ? 'none' : '';
        $('er-state-preview-note').style.display = isState ? '' : 'none';
        $('er-metric-preview-note').style.display = isMetric ? '' : 'none';
        $('er-spike-preview-note').style.display = isSpike ? '' : 'none';
        $('er-trap-preview-note').style.display = isTrap ? '' : 'none';
        $('er-flowsec-preview-note').style.display = isFlowSec ? '' : 'none';
        if (noPreview) { $('er-preview-samples').style.display = 'none'; }
        // Spike rules ignore the per-rule cooldown (the detector paces episodes), so
        // hide that field for spike to avoid a dead knob.
        var cd = $('er-cooldown');
        if (cd) { var cg = cd.closest('.form-group'); if (cg) cg.style.display = isSpike ? 'none' : ''; }
        onMetricModeChange();
        onActionChange();
    }

    // ---- preview ----------------------------------------------------------

    function clearPreview() {
        $('er-preview-result').textContent = '';
        $('er-preview-samples').style.display = 'none';
        $('er-preview-samples-list').innerHTML = '';
    }

    function previewRule() {
        var m = collectMatch();
        if (m.error) { AC.showError(m.error); return; }
        if (!m.json) { AC.showError('Add at least one condition before previewing.'); return; }
        var btn = $('er-preview-btn'); btn.disabled = true; btn.textContent = 'Testing…';
        AC.apiFetch(API + '/event-rules/test', {
            method: 'POST',
            body: { match_json: m.json, vendor_scope: $('er-vendor').value || '', limit: 5000 }
        }).then(function (res) {
            var d = res.data || {};
            var pct = ((d.rate || 0) * 100).toFixed(1);
            $('er-preview-result').textContent = 'Scanned ' + (d.scanned || 0) + ' recent messages, matched ' + (d.matched || 0) + ' (' + pct + '%). ' + (d.note || '');
            var list = d.samples || [];
            $('er-preview-samples').style.display = list.length ? '' : 'none';
            $('er-preview-samples-list').innerHTML = list.map(function (s) {
                return '<div style="margin-bottom:4px;word-break:break-word">' + esc(s) + '</div>';
            }).join('');
        }).catch(function (err) {
            AC.showError('Preview failed: ' + err.message);
        }).finally(function () { btn.disabled = false; btn.textContent = 'Preview matches'; });
    }

    // ---- submit / toggle / delete ----------------------------------------

    function submitForm(e) {
        e.preventDefault();
        var m = collectMatch();
        if (m.error) { AC.showError(m.error); return; }
        var action = $('er-action').value || 'alert';
        if (!m.json) {
            // empty match = match-all; block for alert, hard-confirm never allowed for suppress
            AC.showError('Add at least one condition (a rule with no conditions would match every message).');
            return;
        }
        var proceed = Promise.resolve(true);
        if (action === 'suppress') {
            proceed = AC.confirm('This SUPPRESS rule will silence every matching alert. Run Preview first to confirm the scope. Continue?', { title: 'Create suppress rule?', confirmLabel: 'Create', danger: true });
        }
        proceed.then(function (ok) {
            if (!ok) return;
            var id = $('event-rule-id').value;
            var body = {
                name: $('er-name').value.trim(),
                description: $('er-description').value.trim(),
                enabled: $('er-enabled').checked,
                priority: (function () { var p = parseInt($('er-priority').value, 10); return isNaN(p) ? 100 : p; })(), // NOT `|| 100`: a suggested priority 0 must stay 0, not jump to 100
                source: $('er-source').value || 'syslog',
                vendor_scope: $('er-vendor').value || '',
                device_id: $('er-device').value ? parseInt($('er-device').value, 10) : null,
                site_id: $('er-site').value ? parseInt($('er-site').value, 10) : null,
                match_json: m.json,
                action: action,
                alert_type: $('er-alert-type').value || '',
                severity: $('er-severity').value || '',
                group_by: $('er-group-by').value.trim(),
                cooldown_minutes: $('er-cooldown').value ? parseInt($('er-cooldown').value, 10) : null,
                policy_id: $('er-policy').value ? parseInt($('er-policy').value, 10) : null,
                dampen_json: dampenForSource(),
                expires_at: (function () {
                    var h = parseInt($('er-expires').value, 10);
                    return (!isNaN(h) && h > 0) ? new Date(Date.now() + h * 3600000).toISOString() : null;
                })()
            };
            var url = id ? (API + '/event-rules/' + id) : (API + '/event-rules');
            var ackId = pendingAckAlertId; // capture before the async save
            AC.apiFetch(url, { method: id ? 'PUT' : 'POST', body: body }).then(function () {
                AC.closeModal('event-rule-modal');
                AC.showSuccess(id ? 'Rule updated' : 'Rule created');
                // Ack the originating alert (F3): the rule only drops the source next
                // cycle, so the open alert would otherwise linger. Best-effort.
                if (!id && ackId) {
                    AC.apiFetch(API + '/alerts/' + ackId + '/acknowledge', { method: 'POST', body: { notes: 'Suppressed via Event Rule' } }).catch(function () { });
                }
                pendingAckAlertId = null;
                loadRules();
            }).catch(function (err) { AC.showError('Save failed: ' + err.message); });
        });
    }

    function toggleEnabled(id, checkbox) {
        var r = rules.find(function (x) { return x.id === id; });
        if (!r) return;
        var next = checkbox.checked;
        var doIt = Promise.resolve(true);
        if (!next && r.seed_version > 0) {
            doIt = AC.confirm('“' + r.name + '” is a shipped default rule. Disabling it may stop baseline alerting. Continue?', { title: 'Disable default rule?', confirmLabel: 'Disable', danger: true });
        }
        doIt.then(function (ok) {
            if (!ok) { checkbox.checked = r.enabled; return; }
            // PUT the FULL object (the handler Selects all editable columns).
            var body = Object.assign({}, r, { enabled: next });
            AC.apiFetch(API + '/event-rules/' + id, { method: 'PUT', body: body }).then(function () {
                r.enabled = next; renderStats();
                AC.showSuccess(next ? 'Rule enabled' : 'Rule disabled');
            }).catch(function (err) { checkbox.checked = r.enabled; AC.showError('Update failed: ' + err.message); });
        });
    }

    function deleteRule(id) {
        var r = rules.find(function (x) { return x.id === id; });
        if (!r) return;
        var msg = r.seed_version > 0
            ? '“' + r.name + '” is a shipped default rule and will NOT be re-created. Deleting it permanently removes this default. Continue?'
            : 'Delete rule “' + r.name + '”?';
        AC.confirm(msg, { title: 'Delete rule?', confirmLabel: 'Delete', danger: true }).then(function (ok) {
            if (!ok) return;
            AC.apiFetch(API + '/event-rules/' + id, { method: 'DELETE' }).then(function () {
                AC.showSuccess('Rule deleted');
                loadRules();
            }).catch(function (err) { AC.showError('Delete failed: ' + err.message); });
        });
    }

    // ---- wiring -----------------------------------------------------------

    function wire() {
        var create = $('er-create-btn');
        if (create) create.addEventListener('click', function () { openRuleModal(null); });
        var form = $('event-rule-form');
        if (form) form.addEventListener('submit', submitForm);
        var addCond = $('er-add-condition');
        if (addCond) addCond.addEventListener('click', function () { addConditionRow(); });
        var actionSel = $('er-action');
        if (actionSel) actionSel.addEventListener('change', onActionChange);
        var sourceSel = $('er-source');
        if (sourceSel) sourceSel.addEventListener('change', onSourceChange);
        var metricMode = $('er-metric-mode');
        if (metricMode) metricMode.addEventListener('change', onMetricModeChange);
        var previewBtn = $('er-preview-btn');
        if (previewBtn) previewBtn.addEventListener('click', previewRule);
        var advToggle = $('er-advanced-toggle');
        if (advToggle) advToggle.addEventListener('change', function () { setAdvanced(advToggle.checked); });
        // modal close buttons
        document.querySelectorAll('[data-er-close]').forEach(function (b) {
            b.addEventListener('click', function () { AC.closeModal('event-rule-modal'); });
        });
        // table action delegation
        var wrap = $('event-rules-table-wrap');
        if (wrap) {
            wrap.addEventListener('click', function (ev) {
                var t = ev.target.closest('[data-er-edit],[data-er-delete]');
                if (!t) return;
                if (t.hasAttribute('data-er-edit')) openRuleModal(parseInt(t.getAttribute('data-er-edit'), 10));
                else deleteRule(parseInt(t.getAttribute('data-er-delete'), 10));
            });
            wrap.addEventListener('change', function (ev) {
                var t = ev.target.closest('[data-er-toggle]');
                if (t) toggleEnabled(parseInt(t.getAttribute('data-er-toggle'), 10), t);
            });
        }
    }

    window.FwmonEventRules = { init: init };
})();
