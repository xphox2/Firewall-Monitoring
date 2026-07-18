// admin-alerting.js — the Alerting hub (v0.11.87).
// One surface for the alert-threshold hierarchy: edit global defaults, then see
// everywhere they're overridden (site / device / notification profile / event
// rule). Reads the read-only /alert-config/overview endpoint; edits global via
// the existing POST /api/settings; drills into the 5a device/site modals via
// their existing document-level data-actions.
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var wired = false;

    var GLOBAL_FIELDS = {
        cpu_threshold: 'alerting-g-cpu',
        memory_threshold: 'alerting-g-memory',
        disk_threshold: 'alerting-g-disk',
        session_threshold: 'alerting-g-sessions',
        spike_stddev_threshold: 'alerting-g-spike-stddev',
        spike_min_duration_minutes: 'alerting-g-spike-min',
        telemetry_stale_minutes: 'alerting-g-telemetry-stale'
    };

    var METRIC_LABEL = {
        CPU_HIGH: 'CPU', MEMORY_HIGH: 'Memory', DISK_HIGH: 'Disk', SESSIONS_HIGH: 'Sessions'
    };
    var SCOPE_LABEL = { device: 'Device', site: 'Site', policy: 'Profile', rule: 'Event Rule', event_profile: 'Event Profile' };

    function el(id) { return document.getElementById(id); }

    function fmtValue(alertType, v) {
        if (v == null) return '';
        if (alertType === 'SESSIONS_HIGH') return Number(v).toLocaleString();
        return (Math.round(Number(v) * 100) / 100) + (METRIC_LABEL[alertType] ? '%' : '');
    }

    function load() {
        AC.apiFetch(API_BASE + '/alert-config/overview').then(function(resp) {
            var d = resp && resp.data ? resp.data : {};
            populateGlobal(d.global || {});
            renderOverrides(d.overrides || []);
        }).catch(function(e) {
            fwmonLog.error('[Alerting] load failed:', e);
            AC.showError('Failed to load alerting config: ' + e.message);
        });
    }

    function populateGlobal(g) {
        Object.keys(GLOBAL_FIELDS).forEach(function(key) {
            var input = el(GLOBAL_FIELDS[key]);
            if (input && g[key] != null) input.value = g[key];
        });
        var spikeEnabled = el('alerting-g-spike-enabled');
        if (spikeEnabled) spikeEnabled.checked = g.spike_alert_enabled === true;

        // Read-only for non-admins (values visible, editing gated). Gate on the
        // session promise, not the sync AC.sessionRole — /me and this overview
        // race, and reading sessionRole before /me resolves would wrongly disable
        // the inputs for a real admin (the Save button un-hides via CSS anyway).
        AC.whenMe().then(function(me) {
            var isAdmin = me && me.role === 'admin';
            Object.keys(GLOBAL_FIELDS).forEach(function(key) {
                var input = el(GLOBAL_FIELDS[key]);
                if (input) input.disabled = !isAdmin;
            });
            if (spikeEnabled) spikeEnabled.disabled = !isAdmin;
        });
    }

    function renderOverrides(rows) {
        var wrap = el('alerting-overrides');
        if (!wrap) return;
        if (!rows.length) {
            wrap.innerHTML = '<p style="color:var(--fwmon-text-mute);font-size:0.85rem;margin:0;">No threshold overrides — global defaults apply everywhere.</p>';
            return;
        }
        // Stable, readable order: group by scope (device→site→profile→rule), then name.
        var scopeOrder = { device: 0, site: 1, policy: 2, rule: 3 };
        rows = rows.slice().sort(function(a, b) {
            var sa = scopeOrder[a.scope] != null ? scopeOrder[a.scope] : 9;
            var sb = scopeOrder[b.scope] != null ? scopeOrder[b.scope] : 9;
            if (sa !== sb) return sa - sb;
            return (a.scope_name || '').localeCompare(b.scope_name || '');
        });
        var body = rows.map(function(r) {
            var scope = SCOPE_LABEL[r.scope] || r.scope;
            var metric, value, note = '';
            if (r.kind === 'disabled') {
                // Device rows = the master off-switch; event_profile rows (v48)
                // = one alert type toggled Off by a profile.
                var what = (r.scope === 'event_profile' && r.alert_type)
                    ? (r.alert_type + ' toggled off')
                    : 'All alerts disabled';
                metric = '<span style="color:var(--fwmon-danger,#f85149);">' + AC.escapeHtml(what) + '</span>';
                value = '—';
            } else if (r.kind === 'custom') {
                metric = 'Custom metric rule';
                value = fmtValue('', r.value);
            } else {
                metric = METRIC_LABEL[r.alert_type] || r.alert_type;
                value = fmtValue(r.alert_type, r.value);
                if (r.shadowed_by_rule) note = '<span style="color:var(--fwmon-accent,#58a6ff);font-size:0.72rem;">overridden by an event rule</span>';
            }
            var action = editControl(r);
            return '<tr>' +
                '<td>' + AC.escapeHtml(scope) + '</td>' +
                '<td>' + AC.escapeHtml(r.scope_name || ('#' + r.scope_id)) + '</td>' +
                '<td>' + metric + '</td>' +
                '<td class="num">' + AC.escapeHtml(String(value)) + '</td>' +
                '<td>' + note + '</td>' +
                '<td style="text-align:right;">' + action + '</td>' +
                '</tr>';
        }).join('');
        wrap.innerHTML = '<div style="overflow-x:auto;"><table class="fwmon-table">' +
            '<thead><tr><th>Scope</th><th>Name</th><th>Metric</th><th>Value</th><th></th><th></th></tr></thead>' +
            '<tbody>' + body + '</tbody></table></div>';
    }

    // editControl returns the drill-in for a row. Device/site rows reuse the 5a
    // modals via their existing document-level data-actions (no window exports);
    // profile/rule rows link to their pages.
    function editControl(r) {
        if (r.scope === 'device') {
            return '<button class="btn sm secondary" data-action="device-alert-config" data-min-role="operator" data-id="' + r.scope_id + '">Edit</button>';
        }
        if (r.scope === 'site') {
            return '<button class="btn sm secondary" data-action="site-alert-config" data-min-role="operator" data-id="' + r.scope_id + '">Edit</button>';
        }
        if (r.scope === 'policy') {
            return '<a class="btn sm secondary" href="/admin/alert-policies">Open</a>';
        }
        return '<a class="btn sm secondary" href="/admin/event-rules">Open</a>';
    }

    function saveGlobal() {
        var settings = [];
        function pushNum(key, category) {
            var input = el(GLOBAL_FIELDS[key]);
            if (input) settings.push({ key: key, value: input.value, category: category, type: 'string' });
        }
        pushNum('cpu_threshold', 'alerts');
        pushNum('memory_threshold', 'alerts');
        pushNum('disk_threshold', 'alerts');
        pushNum('session_threshold', 'alerts');
        var spikeEnabled = el('alerting-g-spike-enabled');
        if (spikeEnabled) settings.push({ key: 'spike_alert_enabled', value: String(spikeEnabled.checked), category: 'spike', type: 'bool' });
        pushNum('spike_stddev_threshold', 'spike');
        pushNum('spike_min_duration_minutes', 'spike');
        pushNum('telemetry_stale_minutes', 'alerts');

        AC.apiFetch(API_BASE + '/settings', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings)
        }).then(function() {
            AC.showSuccess('Global alert defaults saved');
            load(); // reflects the save (server refreshes the alert cache immediately)
        }).catch(function(e) {
            AC.showError('Failed to save defaults: ' + e.message);
        });
    }

    function init() {
        if (!wired) {
            AC.delegateEvent('click', { 'alerting-save-global': function() { saveGlobal(); } });
            wired = true;
        }
        load();
    }

    window.FwmonAlerting = { init: init };
})();
