/* User management (RBAC, P0-1) — renders the Users card on the settings page.
 * The card is hidden until GET /admin/api/me confirms the session is
 * role=admin; the server enforces the same via the adminOnlyRoutes map, so
 * this gating is purely cosmetic. The session's role is also published as
 * AdminCommon.sessionRole for other modules to gate UI on. */
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
            'user-reset-password': function (el) {
                AC.confirm('Reset the password for "' + el.dataset.name + '"? Their sessions will be revoked.', function () {
                    AC.apiFetch(API_BASE + '/users/' + el.dataset.id + '/reset-password', { method: 'POST' })
                        .then(function (res) {
                            showTempPassword(el.dataset.name, res.data.temp_password);
                            loadUsers();
                        })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to reset password'); });
                });
            },
            'user-reset-2fa': function (el) {
                AC.confirm('Reset 2FA for "' + el.dataset.name + '"? They will log in with password only until they re-enroll.', function () {
                    AC.apiFetch(API_BASE + '/users/' + el.dataset.id + '/reset-2fa', { method: 'POST' })
                        .then(function () { AC.showSuccess('2FA reset'); loadUsers(); })
                        .catch(function (err) { AC.showError((err && err.message) || 'Failed to reset 2FA'); });
                });
            },
            'user-delete': function (el) {
                AC.confirm('Delete user "' + el.dataset.name + '"? This cannot be undone.', function () {
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
                AC.confirm('Revoke token "' + el.dataset.name + '"? Anything using it stops working immediately.', function () {
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

        /* ---- Two-factor authentication card (P0-3) — every role, own account ---- */
        var twofaCard = document.getElementById('card-2fa');

        function render2FA() {
            if (!twofaCard || !me) { return; }
            var status = document.getElementById('twofa-status');
            var flow = document.getElementById('twofa-flow');
            if (me.totp_enabled) {
                status.innerHTML = '<span style="color:var(--fwmon-sig-ok,#36c98a)">✓ Two-factor authentication is enabled.</span>';
                flow.innerHTML =
                    '<div class="form-row" style="align-items:flex-end;">' +
                    '<div class="form-group"><label for="twofa-disable-pw">Password</label><input type="password" id="twofa-disable-pw" autocomplete="current-password"></div>' +
                    '<div class="form-group"><label for="twofa-disable-code">Code (or recovery code)</label><input type="text" id="twofa-disable-code" autocomplete="one-time-code"></div>' +
                    '<div class="form-group"><button class="btn danger" data-action="twofa-disable">Disable 2FA</button></div>' +
                    '</div>';
            } else {
                status.innerHTML = '<span style="color:var(--fwmon-text-faint)">Two-factor authentication is off.</span>';
                flow.innerHTML =
                    '<div class="form-row" style="align-items:flex-end;">' +
                    '<div class="form-group"><label for="twofa-setup-pw">Confirm your password to begin</label><input type="password" id="twofa-setup-pw" autocomplete="current-password"></div>' +
                    '<div class="form-group"><button class="btn" data-action="twofa-setup">Set Up 2FA</button></div>' +
                    '</div>';
            }
        }

        function render2FAVerifyStep(secret, url) {
            document.getElementById('twofa-flow').innerHTML =
                '<div class="card" style="border-color:var(--fwmon-warn,#d29922)">' +
                '<p style="margin-bottom:8px;">Add this key to your authenticator app (manual entry), then confirm with a code:</p>' +
                '<p>Secret: <code style="user-select:all">' + esc(secret) + '</code></p>' +
                '<p style="margin-top:4px; word-break:break-all;">URI: <code style="user-select:all; font-size:0.78rem;">' + esc(url) + '</code></p>' +
                '</div>' +
                '<div class="form-row" style="align-items:flex-end; margin-top:10px;">' +
                '<div class="form-group"><label for="twofa-verify-code">6-digit code</label><input type="text" id="twofa-verify-code" inputmode="numeric" autocomplete="one-time-code"></div>' +
                '<div class="form-group"><button class="btn" data-action="twofa-verify">Verify &amp; Enable</button></div>' +
                '</div>';
            document.getElementById('twofa-verify-code').focus();
        }

        var twofaActions = {
            'twofa-setup': function () {
                var pw = document.getElementById('twofa-setup-pw').value;
                if (!pw) { AC.showError('Enter your password first'); return; }
                AC.apiFetch(API_BASE + '/2fa/setup', { method: 'POST', body: { password: pw } })
                    .then(function (res) { render2FAVerifyStep(res.data.secret, res.data.otpauth_url); })
                    .catch(function (err) { AC.showError((err && err.message) || 'Setup failed'); });
            },
            'twofa-verify': function () {
                var code = document.getElementById('twofa-verify-code').value.trim();
                if (!code) { AC.showError('Enter the code from your app'); return; }
                AC.apiFetch(API_BASE + '/2fa/verify', { method: 'POST', body: { code: code } })
                    .then(function (res) {
                        var codes = (res.data.recovery_codes || []).map(function (c) {
                            return '<code style="user-select:all">' + esc(c) + '</code>';
                        }).join(' &nbsp; ');
                        document.getElementById('twofa-status').innerHTML =
                            '<span style="color:var(--fwmon-sig-ok,#36c98a)">✓ Enabled.</span>';
                        document.getElementById('twofa-flow').innerHTML =
                            '<div class="card" style="border-color:var(--fwmon-warn,#d29922)">' +
                            '<p style="margin-bottom:8px;"><strong>Recovery codes</strong> (shown once — store them somewhere safe):</p>' +
                            '<p style="line-height:2">' + codes + '</p>' +
                            '<p style="margin-top:8px; color:var(--fwmon-text-faint)">Your sessions were revoked — you\'ll be asked to log in again with your new code.</p>' +
                            '</div>';
                    })
                    .catch(function (err) { AC.showError((err && err.message) || 'Verification failed'); });
            },
            'twofa-disable': function () {
                var pw = document.getElementById('twofa-disable-pw').value;
                var code = document.getElementById('twofa-disable-code').value.trim();
                if (!pw || !code) { AC.showError('Password and a code are required'); return; }
                AC.apiFetch(API_BASE + '/2fa/disable', { method: 'POST', body: { password: pw, code: code } })
                    .then(function () {
                        me.totp_enabled = false;
                        AC.showSuccess('Two-factor authentication disabled');
                        render2FA();
                    })
                    .catch(function (err) { AC.showError((err && err.message) || 'Disable failed'); });
            }
        };

        if (twofaCard) {
            twofaCard.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action]');
                if (el && twofaActions[el.dataset.action]) { twofaActions[el.dataset.action](el); }
            });
        }

        AC.apiFetch(API_BASE + '/me').then(function (res) {
            me = (res && res.data) || null;
            AC.sessionRole = me ? me.role : null;
            render2FA();
            if (me && me.role === 'admin') {
                card.style.display = '';
                loadUsers();
                if (tokensCard) {
                    tokensCard.style.display = '';
                    loadTokens();
                }
            }
        }).catch(function () { /* leave the cards hidden */ });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
