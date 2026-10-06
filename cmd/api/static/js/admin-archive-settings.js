// admin-archive-settings.js — the raw archive's settings on Settings →
// Retention (A-10). Every ARCHIVE_* key can be set here; a value set here wins
// over the environment, which stays the default ("revert to env default"
// removes the admin value). GET /archive/settings fills the form, Test
// connection (POST /archive/settings/test) runs the bucket preflight with the
// form's values without saving, Save (POST /archive/settings) re-verifies the
// password (+ 2FA code) and is audit-logged with the field names only.
//
// The secret access key is write-only: the server never returns it; the form
// shows whether it is set and the key ID's (not the secret's) last four
// characters.
//
// CSP: no inline handlers — one click and one input listener on the card,
// dispatching on data-arch-action. Exposed as window.FwmonArchiveSettings;
// admin-main.js calls render() from loadSettings (admins only).
(function () {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var esc = AC.escapeHtml;

    var SECTIONS = [
        { id: 'connection', title: 'Connection', hint: 'Any S3-compatible service (Backblaze B2, AWS S3, MinIO). Use a key restricted to this bucket and prefix, without delete rights.' },
        { id: 'streams', title: 'Streams', hint: 'An enabled stream is exported, uploaded, read back and verified; its raw rows are then deleted only once verified. Enabling runs the bucket preflight and checks the staging directory before it saves.' },
        { id: 'object_lock', title: 'Object Lock', hint: 'Retention applied to every object written. The bucket must have Object Lock enabled (Test connection checks it).' },
        { id: 'schedule', title: 'Schedule', hint: 'Pacing and the monthly seal. The defaults suit most installs.' },
        { id: 'advanced', title: 'Advanced', hint: 'Lab and self-hosted endpoints only.' }
    ];

    var LABELS = {
        ARCHIVE_SYSLOG_ENABLED: ['Archive raw syslog', ''],
        ARCHIVE_FLOWS_ENABLED: ['Archive flows', 'sFlow, NetFlow and the sFlow interface counters.'],
        ARCHIVE_STAGING_DIR: ['Staging directory', 'Absolute path on a volume with at least 2 GiB free (a day of compressed syslog). In Docker, a mounted volume.'],
        ARCHIVE_S3_ENDPOINT: ['Endpoint', 'https://host only, no path, e.g. https://s3.example.com (your provider documents its S3 endpoint).'],
        ARCHIVE_S3_REGION: ['Region', 'The bucket’s region as the provider names it, e.g. region-1.'],
        ARCHIVE_S3_BUCKET: ['Bucket', ''],
        ARCHIVE_S3_PREFIX: ['Prefix', 'Every object key starts with it, e.g. fwmon/site-a'],
        ARCHIVE_S3_PATH_STYLE: ['Path-style addressing', 'On for B2 and MinIO.'],
        ARCHIVE_S3_ACCESS_KEY_ID: ['Access key ID', ''],
        ARCHIVE_S3_SECRET_ACCESS_KEY: ['Secret access key', 'Write-only: stored encrypted, never shown again.'],
        ARCHIVE_OBJECT_LOCK_MODE: ['Mode', 'GOVERNANCE is recommended; COMPLIANCE cannot be shortened by anyone.'],
        ARCHIVE_OBJECT_LOCK_DAYS: ['Retention days', '0 turns the per-object retention off (max 3000).'],
        ARCHIVE_WINDOW: ['Syslog export window (UTC)', 'HH:MM-HH:MM, may wrap midnight. Blank: any time. Flows always run.'],
        ARCHIVE_MIN_AGE_HOURS: ['Minimum age before export (hours)', '1-168'],
        ARCHIVE_SEAL_GRACE_HOURS: ['Seal grace (hours after a month ends)', '6-168'],
        ARCHIVE_SEAL_REVERIFY: ['Seal re-check', 'head checks size and ETag; full reads every object back.'],
        ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC: ['Syslog read rate (rows/s)', '100-100000'],
        ARCHIVE_FLOW_RATE_ROWS_PER_SEC: ['Flow read rate (rows/s)', '100-100000'],
        ARCHIVE_ALLOW_HTTP: ['Allow an http:// endpoint', 'Credentials travel unencrypted. Lab only.'],
        ARCHIVE_ALLOW_PRIVATE_ENDPOINT: ['Allow a private or loopback endpoint', 'For a self-hosted MinIO, Garage or SeaweedFS on your network.']
    };

    var SELECTS = {
        ARCHIVE_OBJECT_LOCK_MODE: [['', '(none)'], ['GOVERNANCE', 'GOVERNANCE'], ['COMPLIANCE', 'COMPLIANCE']],
        ARCHIVE_SEAL_REVERIFY: [['head', 'head'], ['full', 'full']]
    };

    var SOURCE_BADGE = {
        ui: ['info', 'set here'],
        env: ['online', 'environment'],
        'default': ['', 'default']
    };

    var view = null;         // the last GET
    var revert = {};         // key → true: revert to the environment on save
    var onSaved = null;      // callback after a save (refresh the status card)
    var bound = false;

    function host() { return document.getElementById('settings-archive-config'); }

    // norm is a value as its form control holds it (the server accepts the
    // lock mode in any case and stores the seal re-check in lower case).
    function norm(f, v) {
        v = v == null ? '' : String(v);
        if (f.key === 'ARCHIVE_OBJECT_LOCK_MODE') return v.toUpperCase();
        if (f.key === 'ARCHIVE_SEAL_REVERIFY') return v.toLowerCase();
        return v;
    }

    function fieldByKey(key) {
        return (view && view.fields || []).filter(function (f) { return f.key === key; })[0];
    }

    function inputHtml(f) {
        var id = 'arch-' + f.key.toLowerCase();
        var locked = f.location && view.location_locked;
        var dis = locked ? ' disabled' : '';
        if (f.kind === 'bool') {
            return '<input type="checkbox" id="' + id + '" data-arch-key="' + f.key + '"' + (f.value === 'true' ? ' checked' : '') + dis + '>';
        }
        if (SELECTS[f.key]) {
            var cur = norm(f, f.value);
            return '<select id="' + id + '" data-arch-key="' + f.key + '"' + dis + '>' + SELECTS[f.key].map(function (o) {
                return '<option value="' + esc(o[0]) + '"' + (o[0] === cur ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
            }).join('') + '</select>';
        }
        if (f.kind === 'secret') {
            var ph = f.set ? 'set (key ID ends in ' + (f.hint || '…') + '); type to replace' : 'not set';
            return '<input type="password" id="' + id + '" data-arch-key="' + f.key + '" value="" autocomplete="new-password" placeholder="' + esc(ph) + '">';
        }
        var type = f.kind === 'int' ? 'number' : 'text';
        return '<input type="' + type + '" id="' + id + '" data-arch-key="' + f.key + '" value="' + esc(f.value) + '" autocomplete="off"' + dis + '>';
    }

    function sourceHtml(f) {
        if (revert[f.key]) return '<span class="badge warning">reverts to the environment on save</span>';
        var b = SOURCE_BADGE[f.source] || SOURCE_BADGE['default'];
        var out = '<span class="badge ' + b[0] + '">' + b[1] + '</span>';
        if (f.source === 'ui' && !(f.location && view.location_locked)) {
            var envText = f.kind === 'secret' ? 'the environment’s key, if it sets one' : (f.env_value === '' ? 'blank' : f.env_value);
            out += ' <button type="button" class="btn sm secondary" data-arch-action="revert" data-key="' + f.key + '">' +
                (f.kind === 'secret' ? 'Clear (use the environment’s)' : 'Revert to env default') + '</button>' +
                ' <span class="field-hint">environment / default: ' + esc(envText) + '</span>';
        }
        return out;
    }

    function fieldHtml(f) {
        var l = LABELS[f.key] || [f.key, ''];
        var id = 'arch-' + f.key.toLowerCase();
        var hint = l[1];
        if (f.location && view.location_locked) hint = 'Fixed: the archive already holds objects here (see docs/OPERATIONS.md, moving the bucket). ' + hint;
        var head = f.kind === 'bool'
            ? '<div class="toggle-row">' + inputHtml(f) + '<label for="' + id + '">' + esc(l[0]) + '</label></div>'
            : '<label for="' + id + '">' + esc(l[0]) + ' <code>' + f.key + '</code></label>' + inputHtml(f);
        return '<div class="setting-item archive-setting" data-arch-field="' + f.key + '">' + head +
            (f.kind === 'bool' ? '<div class="field-hint"><code>' + f.key + '</code>' + (hint ? ' — ' + esc(hint) : '') + '</div>'
                : (hint ? '<div class="field-hint">' + esc(hint) + '</div>' : '')) +
            '<div class="archive-setting-source">' + sourceHtml(f) + '</div></div>';
    }

    function renderForm() {
        var el = host();
        if (!el || !view) return;
        var html = '';
        if (view.problem) {
            html += '<p class="archive-settings-problem" role="alert">The configuration in effect is refused: ' + esc(view.problem) + '</p>';
        }
        if (view.location_locked) {
            html += '<p class="field-hint">The archive holds chunks, so the endpoint, bucket and prefix are fixed here.</p>';
        }
        SECTIONS.forEach(function (s) {
            var fields = view.fields.filter(function (f) { return f.section === s.id; });
            var body = '<p class="field-hint">' + esc(s.hint) + '</p><div class="settings-grid">' + fields.map(fieldHtml).join('') + '</div>';
            if (s.id === 'advanced') {
                html += '<details class="archive-settings-section"><summary>' + esc(s.title) + '</summary>' + body + '</details>';
            } else {
                html += '<fieldset class="archive-settings-section"><legend>' + esc(s.title) + '</legend>' + body + '</fieldset>';
            }
        });
        html += '<div class="archive-settings-actions">' +
            '<button type="button" class="btn secondary" data-arch-action="test">Test connection</button>' +
            '<button type="button" class="btn secondary" data-arch-action="discard">Discard</button>' +
            '<button type="button" class="btn" data-arch-action="save">Save archive settings</button></div>' +
            '<div id="archive-settings-result" class="archive-settings-result" role="status" aria-live="polite"></div>';
        el.innerHTML = html;
    }

    function showResult(ok, lines) {
        var el = document.getElementById('archive-settings-result');
        if (!el) return;
        el.className = 'archive-settings-result ' + (ok ? 'is-ok' : 'is-bad');
        el.innerHTML = lines.filter(Boolean).map(function (l) { return '<p>' + esc(l) + '</p>'; }).join('');
    }

    // draft is what the form changes: {set, revert}.
    function draft() {
        var set = {}, rev = [];
        (view.fields || []).forEach(function (f) {
            if (revert[f.key]) { rev.push(f.key); return; }
            var input = document.querySelector('[data-arch-key="' + f.key + '"]');
            if (!input || input.disabled) return;
            if (f.kind === 'secret') {
                if (input.value !== '') set[f.key] = input.value;
                return;
            }
            var v = f.kind === 'bool' ? String(input.checked) : input.value.trim();
            if (v !== norm(f, f.value)) set[f.key] = v;
        });
        return { set: set, revert: rev };
    }

    function boolAfter(key, d) {
        if (d.set[key] != null) return d.set[key] === 'true';
        if (d.revert.indexOf(key) >= 0) return fieldByKey(key).env_value === 'true';
        return fieldByKey(key).value === 'true';
    }

    function load() {
        return AC.apiFetch(API_BASE + '/archive/settings').then(function (res) {
            view = (res && res.data) || null;
            revert = {};
            renderForm();
        });
    }

    function test() {
        var d = draft();
        showResult(true, ['Testing the connection…']);
        AC.apiFetch(API_BASE + '/archive/settings/test', { method: 'POST', body: JSON.stringify(d) }).then(function (res) {
            var r = (res && res.data) || {};
            showResult(!!r.ok, [(r.ok ? 'Connection OK. ' : 'Connection failed: ') + (r.message || ''), r.staging]);
        }).catch(function (e) {
            showResult(false, ['Test failed: ' + ((e && e.message) || e)]);
        });
    }

    function save() {
        var d = draft();
        var keys = Object.keys(d.set).concat(d.revert);
        if (!keys.length) { AC.showError('Nothing changed'); return; }
        var notes = [];
        [['ARCHIVE_SYSLOG_ENABLED', 'syslog'], ['ARCHIVE_FLOWS_ENABLED', 'flows']].forEach(function (s) {
            var before = fieldByKey(s[0]).value === 'true', after = boolAfter(s[0], d);
            if (before && !after) {
                notes.push('Turning ' + s[1] + ' OFF: its raw rows are then deleted without waiting for the archive, and every month until it is switched back on is sealed partial.');
            } else if (!before && after) {
                notes.push('Turning ' + s[1] + ' ON: the server runs the bucket preflight and checks the staging directory before it saves.');
            }
        });
        var me = AC.sessionMe;
        var totpOn = me ? !!me.totp_enabled : null;
        var fields = [{ name: 'password', label: 'Current password', type: 'password', autocomplete: 'current-password', required: true }];
        if (totpOn !== false) {
            fields.push({ name: 'totp_code', label: totpOn ? 'Authenticator code' : 'Authenticator code (if 2FA is on)',
                type: 'text', autocomplete: 'one-time-code', inputmode: 'numeric', maxLength: 32, required: !!totpOn });
        }
        AC.promptFields('Save ' + keys.length + ' archive setting' + (keys.length === 1 ? '' : 's') + ' (' + keys.join(', ') + ')? ' +
            notes.join(' ') + ' The poller applies the change within a minute, without a restart.', {
            title: 'Save archive settings', confirmLabel: 'Save', fields: fields
        }).then(function (v) {
            if (!v) return null;
            var body = { set: d.set, revert: d.revert, password: v.password, totp_code: (v.totp_code || '').trim() };
            return AC.apiFetch(API_BASE + '/archive/settings', { method: 'POST', body: JSON.stringify(body) }).then(function (res) {
                var r = (res && res.data) || {};
                view = r.settings || view;
                revert = {};
                renderForm();
                showResult(true, [r.message].concat(r.warnings || []));
                AC.showSuccess('Archive settings saved');
                if (onSaved) onSaved();
            });
        }).catch(function (e) {
            var msg = String((e && e.message) || e);
            showResult(false, [/^Not saved:/.test(msg) ? msg : 'Not saved: ' + msg]);
        });
    }

    function bind() {
        var el = host();
        if (!el || bound) return;
        bound = true;
        el.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-arch-action]');
            if (!btn || !el.contains(btn)) return;
            switch (btn.dataset.archAction) {
            case 'revert': {
                var f = fieldByKey(btn.dataset.key);
                if (!f) return;
                revert[f.key] = true;
                var input = document.querySelector('[data-arch-key="' + f.key + '"]');
                if (input) {
                    if (f.kind === 'bool') input.checked = f.env_value === 'true';
                    else if (f.kind !== 'secret') input.value = norm(f, f.env_value);
                    else input.value = '';
                }
                var src = el.querySelector('[data-arch-field="' + f.key + '"] .archive-setting-source');
                if (src) src.innerHTML = sourceHtml(f);
                break;
            }
            case 'test': test(); break;
            case 'save': save(); break;
            case 'discard': load(); break;
            }
        });
        // Editing a field after "revert" keeps the edit instead.
        el.addEventListener('input', function (e) {
            var key = e.target && e.target.dataset && e.target.dataset.archKey;
            if (key && revert[key]) {
                delete revert[key];
                var src = el.querySelector('[data-arch-field="' + key + '"] .archive-setting-source');
                if (src) src.innerHTML = sourceHtml(fieldByKey(key));
            }
        });
    }

    function render(opts) {
        var el = host();
        if (!el) return;
        onSaved = (opts && opts.onSaved) || onSaved;
        AC.whenMe().then(function (me) {
            if (!me || me.role !== 'admin') return null;
            bind();
            return load();
        }).catch(function (e) {
            if (window.fwmonLog) window.fwmonLog.warn('[Settings] archive settings load failed', e);
            el.innerHTML = '<p class="field-hint">Archive settings unavailable.</p>';
        });
    }

    window.FwmonArchiveSettings = { render: render };
})();
