// admin-login.js — Login page logic
(function() {
    'use strict';

    var API_BASE = '/api';

    // completeLogin is the one success path for password, TOTP and passkey
    // sign-in. The redirect is always /admin: a must_change_password account
    // is then stopped by the server-side gate and the SPA's forced-change
    // modal, exactly as for a password login. When the server reports
    // passkeys added since the last acknowledgement (passkey_notices), the
    // user sees them first and chooses to review or continue.
    function completeLogin(payload) {
        // v0.11.17: a fresh login resets the MFA-wizard "offered this
        // session" flag, so "Not now" really means "ask me again next
        // login" (sessionStorage outlives a logout in the same tab —
        // without this the prompt only returned when the tab closed).
        try { sessionStorage.removeItem('fwmon:mfa-wizard-offered'); } catch (err) { /* ignore */ }
        var notices = payload && Array.isArray(payload.passkey_notices) ? payload.passkey_notices : [];
        if (notices.length === 0) {
            window.location.href = '/admin';
            return;
        }
        showPasskeyNotices(notices);
    }

    function showPasskeyNotices(notices) {
        var list = document.getElementById('passkey-notice-list');
        list.textContent = '';
        notices.forEach(function(n) {
            var li = document.createElement('li');
            var when = n && n.created_at ? new Date(n.created_at) : null;
            // Passkey names are user-controlled: textContent only.
            li.textContent = '"' + String((n && n.name) || 'Passkey') + '"' +
                (when && !isNaN(when.getTime()) ? ' — added ' + when.toLocaleString() : '');
            list.appendChild(li);
        });
        ['login-form', 'totp-form', 'passkey-section', 'error', 'back-link'].forEach(function(id) {
            var el = document.getElementById(id);
            if (el) { el.classList.add('hidden'); }
        });
        document.getElementById('passkey-notice').classList.remove('hidden');
        document.getElementById('passkey-notice-continue').focus();
    }

    function showError(msg) {
        var errorDiv = document.getElementById('error');
        errorDiv.textContent = msg;
        errorDiv.classList.remove('hidden');
    }

    function postJSON(url, body) {
        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(body || {})
        }).then(function(response) { return response.json(); });
    }

    // Passkey sign-in. The button exists in the markup but stays hidden
    // unless FwmonPasskey.usable() confirms the server config (enabled +
    // this origin listed), WebAuthn support and a secure context. Every
    // failure shows ONE generic message; a cancelled browser prompt is
    // silent. The password form is never touched.
    //
    // User gesture (Safari/WebKit): navigator.credentials.get() must run
    // inside the click, not after an awaited fetch, or WebKit refuses it
    // with NotAllowedError. So the begin options are PREFETCHED when the
    // button appears (and again after each attempt, or when older than
    // PREFETCH_MAX_AGE_MS — the server ceremony lives 5 minutes), and the
    // click handler calls get() synchronously. Only when no fresh options
    // are at hand does it fall back to fetch-then-get; a NotAllowedError on
    // that path is reported as a blocked prompt instead of staying silent.
    var PASSKEY_FAILED = 'Passkey sign-in failed. Try again, or sign in with your password.';
    var PASSKEY_BLOCKED = 'Your browser blocked the passkey prompt — click "Sign in with a passkey" to try again.';
    var PREFETCH_MAX_AGE_MS = 4 * 60 * 1000;
    function setupPasskeyLogin() {
        var PK = window.FwmonPasskey;
        var section = document.getElementById('passkey-section');
        var btn = document.getElementById('passkey-btn');
        if (!PK || !section || !btn) { return; }

        // At most one begin in flight: each begin replaces the webauthn_login
        // ceremony cookie, so the options used must come from the LAST begin.
        var prefetched = null;   // { publicKey, at }
        var inflight = null;     // Promise<{publicKey, at}|null>
        function fetchOptions() {
            if (inflight) { return inflight; }
            inflight = postJSON(API_BASE + '/auth/passkey/login/begin', {})
                .then(function(begin) {
                    if (!begin || !begin.success || !begin.data || !begin.data.publicKey) { return null; }
                    prefetched = { publicKey: begin.data.publicKey, at: Date.now() };
                    return prefetched;
                })
                .catch(function() { return null; })
                .finally(function() { inflight = null; });
            return inflight;
        }
        function takeFresh() {
            var p = prefetched;
            prefetched = null;
            if (!inflight && p && Date.now() - p.at < PREFETCH_MAX_AGE_MS) { return p; }
            return null;
        }

        function callGet(publicKey) {
            try {
                return navigator.credentials.get({ publicKey: PK.requestOptions(publicKey) });
            } catch (e) {
                return Promise.reject(e);
            }
        }

        function finish(credPromise, viaGesture) {
            return credPromise
                .then(function(cred) {
                    if (!cred) { throw new Error('no credential'); }
                    return postJSON(API_BASE + '/auth/passkey/login/finish', PK.assertionJSON(cred));
                })
                .then(function(fin) {
                    if (fin && fin.success) {
                        completeLogin(fin.data);
                        return true;
                    }
                    showError(PASSKEY_FAILED);
                    return false;
                })
                .catch(function(err) {
                    if (PK.isCancel(err)) {
                        // Inside a direct click this is the user dismissing
                        // the prompt: stay silent. After an awaited fetch it
                        // may be the browser refusing a non-gesture call.
                        if (!viaGesture) { showError(PASSKEY_BLOCKED); }
                        return false;
                    }
                    showError(PASSKEY_FAILED);
                    return false;
                });
        }

        PK.getConfig().then(function(cfg) {
            if (!PK.usable(cfg)) { return; }
            section.classList.remove('hidden');
            fetchOptions();
            btn.addEventListener('click', function() {
                if (btn.disabled) { return; }
                var fresh = takeFresh();
                var attempt;
                if (fresh) {
                    // Gesture path: get() is the first thing the click does.
                    attempt = finish(callGet(fresh.publicKey), true);
                } else {
                    attempt = fetchOptions().then(function(opts) {
                        prefetched = null;
                        if (!opts) { showError(PASSKEY_FAILED); return false; }
                        return finish(callGet(opts.publicKey), false);
                    });
                }
                btn.disabled = true;
                btn.textContent = 'Waiting for passkey...';
                document.getElementById('error').classList.add('hidden');
                attempt.then(function(ok) {
                    if (ok) { return; }
                    btn.disabled = false;
                    btn.textContent = 'Sign in with a passkey';
                    fetchOptions(); // fresh options for the next click
                });
            });
        });
    }
    setupPasskeyLogin();

    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();

        var username = document.getElementById('username').value;
        var password = document.getElementById('password').value;
        var btn = document.getElementById('login-btn');
        var errorDiv = document.getElementById('error');

        btn.disabled = true;
        btn.textContent = 'Logging in...';
        // v0.10.232: was using errorDiv.style.display = 'block'/'none' which
        // worked only because inline style (specificity 1,0,0,0) beats the
        // .hidden class on the element (markup at login.html:15). Same trap
        // that hid the connection-detail tabs (v0.10.230) and the IRC SASL
        // fields (v0.10.231) — refactoring to style.display = '' would
        // silently break the error banner. Toggle .hidden directly so the
        // markup and JS use the same source of truth.
        errorDiv.classList.add('hidden');

        fetch(API_BASE + '/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password })
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (data.success && data.data && data.data.totp_required) {
                // 2FA second step (P0-3): swap to the code form. The server
                // holds a 5-minute pending_2fa cookie; the password form is
                // done.
                document.getElementById('login-form').classList.add('hidden');
                document.getElementById('totp-form').classList.remove('hidden');
                document.getElementById('totp-code').focus();
            } else if (data.success) {
                completeLogin(data.data);
            } else {
                errorDiv.textContent = data.error || 'Invalid credentials';
                errorDiv.classList.remove('hidden');
            }
        })
        .catch(function() {
            errorDiv.textContent = 'Connection error. Please try again.';
            errorDiv.classList.remove('hidden');
        })
        .finally(function() {
            btn.disabled = false;
            btn.textContent = 'Login';
        });
    });

    document.getElementById('totp-form').addEventListener('submit', function(e) {
        e.preventDefault();

        var code = document.getElementById('totp-code').value.trim();
        var btn = document.getElementById('totp-btn');
        var errorDiv = document.getElementById('error');

        btn.disabled = true;
        btn.textContent = 'Verifying...';
        errorDiv.classList.add('hidden');

        fetch(API_BASE + '/auth/totp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (data.success) {
                completeLogin(data.data);
            } else {
                errorDiv.textContent = data.error || 'Invalid code';
                errorDiv.classList.remove('hidden');
                document.getElementById('totp-code').value = '';
                document.getElementById('totp-code').focus();
            }
        })
        .catch(function() {
            errorDiv.textContent = 'Connection error. Please try again.';
            errorDiv.classList.remove('hidden');
        })
        .finally(function() {
            btn.disabled = false;
            btn.textContent = 'Verify';
        });
    });
})();
