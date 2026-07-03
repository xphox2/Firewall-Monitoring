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
                    '<td style="white-space:nowrap">' +
                        (self ? '' :
                            '<button class="btn secondary" data-action="user-toggle-disabled" data-id="' + u.id + '" data-disabled="' + (!u.disabled) + '">' + (u.disabled ? 'Enable' : 'Disable') + '</button> ' +
                            '<button class="btn secondary" data-action="user-reset-password" data-id="' + u.id + '" data-name="' + esc(u.username) + '">Reset PW</button> ' +
                            '<button class="btn danger" data-action="user-delete" data-id="' + u.id + '" data-name="' + esc(u.username) + '">Delete</button>') +
                    '</td></tr>';
            }).join('');
            document.getElementById('users-table').innerHTML =
                '<table class="data-table"><thead><tr>' +
                '<th>Username</th><th>Role</th><th>Status</th><th>Actions</th>' +
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

        AC.apiFetch(API_BASE + '/me').then(function (res) {
            me = (res && res.data) || null;
            AC.sessionRole = me ? me.role : null;
            if (me && me.role === 'admin') {
                card.style.display = '';
                loadUsers();
            }
        }).catch(function () { /* leave the card hidden */ });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
