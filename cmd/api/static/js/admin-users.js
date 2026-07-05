/* User management (RBAC, P0-1) — renders the Users card on the settings page.
 * The card is hidden until the shared identity (AdminCommon.whenMe, see
 * admin-common.js) confirms the session is role=admin; the server enforces
 * the same via the adminOnlyRoutes map, so this gating is purely cosmetic. */
(function () {
    'use strict';

    function boot() {
        var AC = window.AdminCommon;
        if (!AC) { return; } // load order guard; admin-common.js is first

        var API_BASE = AC.API_BASE;
        var card = document.getElementById('card-users');
        if (!card) { return; }

        var me = null;

        function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }

        function roleSelect(u) {
            var roles = ['viewer', 'operator', 'admin'];
            var opts = roles.map(function (r) {
                return '<option value="' + r + '"' + (u.role === r ? ' selected' : '') + '>' + r + '</option>';
            }).join('');
            return '<select data-action="user-role" data-id="' + u.id + '">' + opts + '</select>';
        }

        function renderUsers(users) {
            var rows = users.map(function (u) {
                var self = me && u.id === me.id;
                var status = u.disabled
                    ? '<span style="color:var(--fwmon-crit,#f85149)">disabled</span>'
                    : (u.must_change_password ? '<span style="color:var(--fwmon-warn,#d29922)">pw change pending</span>' : 'active');
                return '<tr>' +
                    '<td>' + esc(u.username) + (self ? ' <span style="color:var(--fwmon-text-faint)">(you)</span>' : '') + '</td>' +
                    '<td>' + (self ? esc(u.role) : roleSelect(u)) + '</td>' +
                    '<td>' + status + '</td>' +
                    '<td>' + (u.totp_enabled ? '<span style="color:var(--fwmon-sig-ok,#36c98a)">on</span>' : '<span style="color:var(--fwmon-text-faint)">off</span>') + '</td>' +
                    '<td style="white-space:nowrap">' +
                        (self ? '' :
                            '<button class="btn secondary" data-action="user-toggle-disabled" data-id="' + u.id + '" data-disabled="' + (!u.disabled) + '">' + (u.disabled ? 'Enable' : 'Disable') + '</button> ' +
                            '<button class="btn secondary" data-action="user-reset-password" data-id="' + u.id + '" data-name="' + esc(u.username) + '">Reset PW</button> ' +
                            (u.totp_enabled ? '<button class="btn secondary" data-action="user-reset-2fa" data-id="' + u.id + '" data-name="' + esc(u.username) + '">Reset 2FA</button> ' : '') +
                            '<button class="btn danger" data-action="user-delete" data-id="' + u.id + '" data-name="' + esc(u.username) + '">Delete</button>') +
                    '</td></tr>';
            }).join('');
            document.getElementById('users-table').innerHTML =
                '<table class="data-table"><thead><tr>' +
                '<th>Username</th><th>Role</th><th>Status</th><th>2FA</th><th>Actions</th>' +
                '</tr></thead><tbody>' + rows + '</tbody></table>';
        }

        function loadUsers() {
            return AC.apiFetch(API_BASE + '/users').then(function (res) {
                renderUsers((res && res.data) || []);
            }).catch(function () {
                AC.showError('Failed to load users');
            });
        }

        function showTempPassword(username, pw) {
            // Shown once — the server stores only the hash. Rendered inline so
            // the admin can copy it before it disappears on the next re-render.
            document.getElementById('user-temp-password').innerHTML =
                '<div class="card" style="border-color:var(--fwmon-warn,#d29922)">' +
                'Temporary password for <strong>' + esc(username) + '</strong> (shown once, must be changed at first login): ' +
                '<code style="user-select:all">' + esc(pw) + '</code></div>';
        }

        var actions = {
            'create-user': function () {
                var name = document.getElementById('new-user-name').value.trim();
                var role = document.getElementById('new-user-role').value;
                if (name.length < 3) { AC.showError('Username must be at least 3 characters'); return; }
                AC.apiFetch(API_BASE + '/users', { method: 'POST', body: { username: name, role: role } })
                    .then(function (res) {
                        document.getElementById('new-user-name').value = '';
                        showTempPassword(res.data.user.username, res.data.temp_password);
                        AC.showSuccess('User created');
                        loadUsers();
                    })
                    .catch(function (err) { AC.showError((err && err.message) || 'Failed to create user'); });
            },
            'user-role': function (el) {
                AC.apiFetch(API_BASE + '/users/' + el.dataset.id, { method: 'PUT', body: { role: el.value } })
                    .then(function () { AC.showSuccess('Role updated (their sessions are revoked)'); loadUsers(); })
                    .catch(function (err) { AC.showError((err && err.message) || 'Failed to update role'); loadUsers(); });
            },
            'user-toggle-disabled': function (el) {
                AC.apiFetch(API_BASE + '/users/' + el.dataset.id, { method: 'PUT', body: { disabled: el.dataset.disabled === 'true' } })
                    .then(function () { AC.showSuccess('User updated'); loadUsers(); })
                    .catch(function (err) { AC.showError((err && err.message) || 'Failed to update user'); });
            },
            // v0.11.19: AC.confirm is Promise-based ({danger} opts, resolves
            // true/false). These four actions passed a CALLBACK as the second
            // argument, which confirmModal never invokes — the dialog showed,
            // Confirm clicked, and nothing happened.
            'user-reset-password': function (el) {
                AC.confirm('Reset the password for "' + el.dataset.name + '"? Their sessions will be revoked.', { danger: true, confirmLabel: 'Reset password' }).then(function (ok) {
                    if (!ok) { return; }
                    AC.apiFetch(API_BASE + '/users/' + el.dataset.id + '/reset-password', { method: 'POST' })
                        .then(function (res) {
                            showTempPassword(el.dataset.name, res.data.temp_password);
                            loadUsers();
                        })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to reset password'); });
                });
            },
            'user-reset-2fa': function (el) {
                AC.confirm('Reset 2FA for "' + el.dataset.name + '"? They will log in with password only until they re-enroll.', { danger: true, confirmLabel: 'Reset 2FA' }).then(function (ok) {
                    if (!ok) { return; }
                    AC.apiFetch(API_BASE + '/users/' + el.dataset.id + '/reset-2fa', { method: 'POST' })
                        .then(function () { AC.showSuccess('2FA reset'); loadUsers(); })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to reset 2FA'); });
                });
            },
            'user-delete': function (el) {
                AC.confirm('Delete user "' + el.dataset.name + '"? This cannot be undone.', { danger: true, confirmLabel: 'Delete user' }).then(function (ok) {
                    if (!ok) { return; }
                    AC.apiFetch(API_BASE + '/users/' + el.dataset.id, { method: 'DELETE' })
                        .then(function () { AC.showSuccess('User deleted'); loadUsers(); })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to delete user'); });
                });
            }
        };

        card.addEventListener('click', function (e) {
            var el = e.target.closest('[data-action]');
            if (!el || !actions[el.dataset.action] || el.tagName === 'SELECT') { return; }
            actions[el.dataset.action](el);
        });
        card.addEventListener('change', function (e) {
            var el = e.target.closest('select[data-action="user-role"]');
            if (el) { actions['user-role'](el); }
        });

        /* ---- API tokens card (P0-2) — same admin-only gating ---- */
        var tokensCard = document.getElementById('card-tokens');

        function renderTokens(toks) {
            var rows = toks.map(function (t) {
                var status = t.revoked_at ? 'revoked'
                    : (t.expires_at && new Date(t.expires_at) < new Date()) ? 'expired' : 'active';
                return '<tr>' +
                    '<td>' + esc(t.name) + '</td>' +
                    '<td><code>' + esc(t.prefix) + '…</code></td>' +
                    '<td>' + esc(t.scope) + '</td>' +
                    '<td>' + status + '</td>' +
                    '<td>' + (t.last_used_at ? new Date(t.last_used_at).toLocaleString() : 'never') + '</td>' +
                    '<td>' + (t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'never') + '</td>' +
                    '<td>' + (t.revoked_at ? '' :
                        '<button class="btn danger" data-action="revoke-token" data-id="' + t.id + '" data-name="' + esc(t.name) + '">Revoke</button>') +
                    '</td></tr>';
            }).join('');
            document.getElementById('tokens-table').innerHTML =
                '<table class="data-table"><thead><tr>' +
                '<th>Name</th><th>Token</th><th>Scope</th><th>Status</th><th>Last used</th><th>Expires</th><th></th>' +
                '</tr></thead><tbody>' + (rows || '<tr><td colspan="7" style="color:var(--fwmon-text-faint)">No tokens yet</td></tr>') + '</tbody></table>';
        }

        function loadTokens() {
            return AC.apiFetch(API_BASE + '/tokens').then(function (res) {
                renderTokens((res && res.data) || []);
            }).catch(function () { AC.showError('Failed to load API tokens'); });
        }

        var tokenActions = {
            'create-token': function () {
                var name = document.getElementById('new-token-name').value.trim();
                var scope = document.getElementById('new-token-scope').value;
                var days = parseInt(document.getElementById('new-token-expiry').value, 10) || 0;
                if (name.length < 3) { AC.showError('Token name must be at least 3 characters'); return; }
                AC.apiFetch(API_BASE + '/tokens', { method: 'POST', body: { name: name, scope: scope, expires_in_days: days } })
                    .then(function (res) {
                        document.getElementById('new-token-name').value = '';
                        document.getElementById('token-plaintext').innerHTML =
                            '<div class="card" style="border-color:var(--fwmon-warn,#d29922)">' +
                            'Token <strong>' + esc(name) + '</strong> (shown once — copy it now): ' +
                            '<code style="user-select:all">' + esc(res.data.token) + '</code></div>';
                        AC.showSuccess('Token created');
                        loadTokens();
                    })
                    .catch(function (err) { AC.showError((err && err.message) || 'Failed to create token'); });
            },
            'revoke-token': function (el) {
                AC.confirm('Revoke token "' + el.dataset.name + '"? Anything using it stops working immediately.', { danger: true, confirmLabel: 'Revoke token' }).then(function (ok) {
                    if (!ok) { return; }
                    AC.apiFetch(API_BASE + '/tokens/' + el.dataset.id, { method: 'DELETE' })
                        .then(function () { AC.showSuccess('Token revoked'); loadTokens(); })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to revoke token'); });
                });
            }
        };

        if (tokensCard) {
            tokensCard.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action]');
                if (el && tokenActions[el.dataset.action]) { tokenActions[el.dataset.action](el); }
            });
        }

        /* The 2FA card + enrollment flow moved to admin-profile.js
           (FwmonProfile) with the v0.11.16 profile page. The /me fetch,
           role stamping, sidebar badge, and role events moved to
           admin-common.js (AC.whenMe, LC-18) so EVERY admin page —
           including the standalone ones that never load this module —
           stamps <html data-role>. This module only gates the admin-only
           users/tokens cards off the shared identity. */

        AC.whenMe().then(function (resolved) {
            me = resolved;
            if (me && me.role === 'admin') {
                card.style.display = '';
                loadUsers();
                if (tokensCard) {
                    tokensCard.style.display = '';
                    loadTokens();
                }
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
