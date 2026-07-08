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

    var rules = [];
    var devices = [];
    var sites = [];
    var policies = [];
    var wired = false;

    function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }
    function $(id) { return document.getElementById(id); }

    // ---- load + render ---------------------------------------------------

    function init() {
        if (!wired) { wire(); wired = true; }
        loadLists();
        loadRules();
    }

    function loadLists() {
        Promise.all([
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
        AC.apiFetch(API + '/event-rules').then(function (res) {
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
                '<td>' + toggle + '</td>' +
                '<td>' + (r.hit_count || 0).toLocaleString() + '</td>' +
                '<td style="white-space:nowrap">' +
                '<button class="btn secondary sm" data-er-edit="' + r.id + '" data-min-role="admin">Edit</button> ' +
                '<button class="btn danger sm" data-er-delete="' + r.id + '" data-min-role="admin">Delete</button>' +
                '</td></tr>';
        }).join('');
        wrap.innerHTML = '<div class="table-wrap" style="overflow-x:auto"><table class="data-table">' +
            '<thead><tr><th>Pri</th><th>Name</th><th>Source</th><th>Vendor</th><th>Match</th><th>Action</th><th>Severity</th><th>Enabled</th><th>Hits</th><th></th></tr></thead>' +
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

    function openRuleModal(id) {
        var r = id ? rules.find(function (x) { return x.id === id; }) : null;
        $('event-rule-modal-title').textContent = r ? 'Edit Event Rule' : 'Create Event Rule';
        $('event-rule-id').value = r ? r.id : '';
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

        // conditions: parse match_json into rows, or advanced raw for nested trees
        $('er-advanced-toggle').checked = false;
        $('er-raw-json').value = '';
        setAdvanced(false);
        loadConditionsFromRule(r);
        onActionChange();
        clearPreview();
        AC.openModal('event-rule-modal');
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
            '<input class="er-cond-field" list="er-field-hints" placeholder="field" value="' + esc(cond ? cond.field : '') + '" style="flex:1">' +
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
                priority: parseInt($('er-priority').value, 10) || 100,
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
                policy_id: $('er-policy').value ? parseInt($('er-policy').value, 10) : null
            };
            var url = id ? (API + '/event-rules/' + id) : (API + '/event-rules');
            AC.apiFetch(url, { method: id ? 'PUT' : 'POST', body: body }).then(function () {
                AC.closeModal('event-rule-modal');
                AC.showSuccess(id ? 'Rule updated' : 'Rule created');
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
