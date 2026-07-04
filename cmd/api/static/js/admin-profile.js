/* Profile page + MFA onboarding wizard (v0.11.16) — window.FwmonProfile.
 *
 * Owns: the /admin/profile page rendering (identity card, 2FA-off banner),
 * the self-service 2FA flow (moved here from admin-users.js so there is ONE
 * enrollment UX), and the login-time MFA onboarding wizard.
 *
 * The wizard is offered at most once per tab-session to accounts with 2FA
 * off that haven't declined ("Don't ask me again" persists server-side via
 * POST /admin/api/me/mfa-decline). It never fights the forced-password-change
 * modal: that gate 403s /admin/api/me, so `me` doesn't resolve at all.
 *
 * Security-critical invariants:
 *  - The recovery-codes step makes NO API calls (the verify step revoked all
 *    sessions; a fetch would 401-redirect and destroy the once-only codes).
 *  - ESC / close is swallowed on the codes step until the user confirms
 *    they saved the codes (capture listener registered before AC.openModal's,
 *    so stopImmediatePropagation pre-empts the shared modal ESC handler).
 *  - Abandoning at any earlier step is safe: TOTP stays off, the pending
 *    secret is inert, and relaunching mints a fresh one.
 */
(function () {
    'use strict';

    var AC = null;
    var API_BASE = '';
    var me = null;
    var state = { step: null, secret: '', otpauthUrl: '', qrPng: '', codes: [], codesSaved: false, offerDecline: true, busy: false };
    var bound = false;
    var escGuard = null;
    var unloadGuard = null;

    // The codes/done steps run on a revoked session by design. Three guards
    // keep the once-only recovery codes on screen until the user has them:
    // the auth-redirect hold (admin-common.js honors it on 401), a browser
    // leave-warning, and a confirm button that stays disabled until the codes
    // were actually copied or downloaded.
    function holdSession(on) {
        window.__fwmonAuthRedirectHold = on || undefined;
        if (on && !unloadGuard) {
            unloadGuard = function (ev) {
                ev.preventDefault();
                ev.returnValue = '';
            };
            window.addEventListener('beforeunload', unloadGuard);
        } else if (!on && unloadGuard) {
            window.removeEventListener('beforeunload', unloadGuard);
            unloadGuard = null;
        }
    }

    function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }
    function $(id) { return document.getElementById(id); }

    /* ---------------- Profile page ---------------- */

    function renderIdentity() {
        if (!me) { return; }
        if ($('profile-username')) { $('profile-username').textContent = me.username || '—'; }
        if ($('profile-role')) { $('profile-role').textContent = me.role || '—'; }
        if ($('profile-created')) {
            $('profile-created').textContent = me.created_at ? new Date(me.created_at).toLocaleDateString() : '—';
        }
        if ($('profile-email')) { $('profile-email').value = me.email || ''; }
        if ($('profile-fullname')) { $('profile-fullname').value = me.full_name || ''; }
        var banner = $('profile-mfa-banner');
        if (banner) { banner.hidden = !!me.totp_enabled; }
    }

    function render2FA() {
        var status = $('twofa-status');
        var flow = $('twofa-flow');
        if (!status || !flow || !me) { return; }
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
                '<button class="btn" data-action="mfa-wizard-launch">Enable two-factor authentication</button>';
        }
    }

    function initPage() {
        var title = $('page-title');
        if (title) { title.textContent = 'Your Profile'; }
        if (me) {
            renderIdentity();
            render2FA();
        } else if (AC.sessionMe) {
            me = AC.sessionMe;
            renderIdentity();
            render2FA();
        }
        // else: the fwmon:me-resolved listener renders when /me lands.
    }

    function saveProfile(btn) {
        var email = ($('profile-email') ? $('profile-email').value : '').trim();
        var fullName = ($('profile-fullname') ? $('profile-fullname').value : '').trim();
        btn.disabled = true;
        AC.apiFetch(API_BASE + '/me', { method: 'PUT', body: { email: email, full_name: fullName } })
            .then(function () {
                AC.showSuccess('Profile updated');
                if (me) { me.email = email; me.full_name = fullName; }
                if (AC.sessionMe) { AC.sessionMe.email = email; AC.sessionMe.full_name = fullName; }
            })
            .catch(function (err) { AC.showError((err && err.message) || 'Failed to update profile'); })
            .finally(function () { btn.disabled = false; });
    }

    /* ---------------- Wizard ---------------- */

    var DOT_STEPS = ['intro', 'password', 'scan', 'verify', 'codes', 'done'];

    function renderDots() {
        var dots = $('mfa-wizard-dots');
        if (!dots) { return; }
        var idx = DOT_STEPS.indexOf(state.step === 'decline' ? 'intro' : state.step);
        dots.innerHTML = DOT_STEPS.map(function (_, i) {
            return '<span' + (i <= idx ? ' class="on"' : '') + '></span>';
        }).join('');
    }

    function setStep(step, bodyHtml, footerHtml) {
        state.step = step;
        renderDots();
        $('mfa-wizard-body').innerHTML =
            '<div class="mfa-wizard-error" id="mfa-wizard-error"></div>' + bodyHtml;
        $('mfa-wizard-footer').innerHTML = footerHtml;
        // Move focus to the step heading so screen readers announce progress.
        var h = $('mfa-wizard-body').querySelector('h3');
        if (h) { h.setAttribute('tabindex', '-1'); try { h.focus(); } catch (e) { /* ignore */ } }
    }

    function showError(msg) {
        var el = $('mfa-wizard-error');
        if (el) { el.textContent = msg || ''; }
    }

    function stepIntro() {
        setStep('intro',
            '<h3>Add a second lock to your account</h3>' +
            '<p>A password alone can be phished or guessed. Two-factor authentication adds a 6-digit code from your phone, so a stolen password is not enough to get in.</p>' +
            '<p>Setup takes about two minutes, and you can stop at any point.</p>',
            (state.offerDecline
                ? '<button class="mfa-wizard-quiet" data-action="mfa-w-decline-open">Don’t ask me again</button>'
                : '') +
            '<button class="btn secondary" data-action="mfa-w-notnow">Not now</button>' +
            '<button class="btn" data-action="mfa-w-start">Set up two-factor</button>');
    }

    function stepDecline() {
        setStep('decline',
            '<h3>Turn off these reminders?</h3>' +
            '<p>Without two-factor authentication, anyone who learns your password can sign in as you — including to acknowledge alerts and change monitoring settings.</p>' +
            '<label class="mfa-wizard-check"><input type="checkbox" id="mfa-w-risk-check">' +
            'I understand the risk and don’t want two-factor authentication</label>' +
            '<p style="font-size:0.8rem;">You can enable it any time from your Profile page.</p>',
            '<button class="btn secondary" data-action="mfa-w-back">Back</button>' +
            '<button class="btn danger" data-action="mfa-w-decline-confirm">Turn off these reminders</button>');
    }

    function stepPassword() {
        setStep('password',
            '<h3>First, confirm it’s you</h3>' +
            '<p>Enter your password to start the setup.</p>' +
            '<div class="form-group"><label for="mfa-w-password">Password</label>' +
            '<input type="password" id="mfa-w-password" autocomplete="current-password"></div>',
            '<button class="btn secondary" data-action="mfa-w-notnow">Cancel</button>' +
            '<button class="btn" data-action="mfa-w-setup">Continue</button>');
        var pw = $('mfa-w-password');
        pw.focus();
        pw.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { actions['mfa-w-setup'](); }
        });
    }

    function stepScan() {
        var qr = state.qrPng
            ? '<div class="mfa-qr-wrap"><img alt="QR code for your authenticator app" src="data:image/png;base64,' + state.qrPng + '"></div>'
            : '';
        setStep('scan',
            '<h3>Add the key to your authenticator app</h3>' +
            qr +
            '<p style="text-align:center; margin-bottom:8px;">Scan the code with any authenticator app (Google Authenticator, Authy, 1Password…).</p>' +
            '<p style="text-align:center;"><a class="btn secondary" style="min-height:44px; display:inline-flex; align-items:center;" href="' + esc(state.otpauthUrl) + '">On this phone? Open your authenticator app</a></p>' +
            '<details style="margin-bottom:12px;"><summary style="cursor:pointer; color:var(--fwmon-text-faint); font-size:0.85rem;">Can’t scan? Enter the key manually</summary>' +
            '<div class="mfa-secret-box" style="margin-top:8px;">' + esc(state.secret) + '</div>' +
            '<button class="btn secondary" style="margin-top:8px;" data-action="mfa-w-copy-secret">Copy key</button>' +
            '</details>',
            '<button class="btn secondary" data-action="mfa-w-notnow">Cancel</button>' +
            '<button class="btn" data-action="mfa-w-to-verify">I’ve added it — next</button>');
    }

    function stepVerify() {
        setStep('verify',
            '<h3>Enter the 6-digit code</h3>' +
            '<p>Type the code your authenticator app shows right now.</p>' +
            '<div class="form-group"><input class="mfa-code-input" type="text" id="mfa-w-code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" aria-label="6-digit code"></div>',
            '<button class="btn secondary" data-action="mfa-w-back-scan">Back</button>' +
            '<button class="btn" id="mfa-w-verify-btn" data-action="mfa-w-verify">Verify &amp; enable</button>');
        var input = $('mfa-w-code');
        input.focus();
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { actions['mfa-w-verify'](); }
        });
    }

    function stepCodes() {
        state.codesSaved = false;
        holdSession(true);
        var grid = state.codes.map(function (c) { return '<code>' + esc(c) + '</code>'; }).join('');
        setStep('codes',
            '<h3>Save your recovery codes</h3>' +
            '<p>Each code signs you in once if you lose your authenticator. <strong>They are shown only now.</strong></p>' +
            '<div class="mfa-recovery-grid">' + grid + '</div>' +
            '<p style="display:flex; gap:8px; flex-wrap:wrap;">' +
            '<button class="btn secondary" data-action="mfa-w-copy-codes">Copy all</button>' +
            '<button class="btn secondary" data-action="mfa-w-download-codes">Download .txt</button>' +
            '</p>' +
            '<p id="mfa-w-codes-hint" style="font-size:0.8rem; color:var(--fwmon-text-faint);">Copy or download your codes to continue.</p>',
            '<button class="btn" id="mfa-w-codes-saved-btn" data-action="mfa-w-codes-saved" disabled>I’ve saved my recovery codes</button>');
    }

    // Called after a successful copy/download: unlocks the confirm button.
    function markCodesSaved() {
        state.codesSaved = true;
        var btn = $('mfa-w-codes-saved-btn');
        if (btn) { btn.disabled = false; }
        var hint = $('mfa-w-codes-hint');
        if (hint) { hint.textContent = 'Codes saved — double-check they’re really there, then continue.'; }
    }

    function stepDone() {
        setStep('done',
            '<h3>Two-factor authentication is on ✓</h3>' +
            '<p>For security, your sessions were signed out. Sign in again with your password and a code from your app.</p>',
            '<button class="btn" data-action="mfa-w-login">Continue to sign in</button>');
    }

    function copyText(text, okMsg, onSuccess) {
        var done = function () {
            AC.showSuccess(okMsg);
            if (onSuccess) { onSuccess(); }
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () {
                AC.showError('Copy failed — select the text manually');
            });
        } else {
            AC.showError('Copy not available — select the text manually');
        }
    }

    function launchWizard(opts) {
        opts = opts || {};
        state = { step: null, secret: '', otpauthUrl: '', qrPng: '', codes: [], offerDecline: opts.offerDecline !== false, busy: false };
        // Swallow ESC on the codes step BEFORE AC.openModal registers its own
        // capture handler — registration order decides who runs first.
        if (!escGuard) {
            escGuard = function (ev) {
                if (ev.key !== 'Escape') { return; }
                if (state.step === 'codes') {
                    ev.preventDefault();
                    ev.stopImmediatePropagation();
                    showError('Save your recovery codes first — they are shown only once.');
                } else if (state.step === 'done') {
                    // The session is revoked; closing the dialog would strand
                    // the user on a dead page. ESC = the intended exit.
                    ev.preventDefault();
                    ev.stopImmediatePropagation();
                    actions['mfa-w-login']();
                }
            };
            document.addEventListener('keydown', escGuard, true);
        }
        stepIntro();
        AC.openModal('mfa-wizard-modal');
    }

    function closeWizard() {
        AC.closeModal('mfa-wizard-modal');
        holdSession(false);
        if (escGuard) {
            document.removeEventListener('keydown', escGuard, true);
            escGuard = null;
        }
    }

    var actions = {
        'mfa-wizard-launch': function () { launchWizard({ offerDecline: false }); },
        'mfa-wizard-close': function () {
            if (state.step === 'codes') {
                showError('Save your recovery codes first — they are shown only once.');
                return;
            }
            if (state.step === 'done') { actions['mfa-w-login'](); return; }
            closeWizard();
        },
        'mfa-w-notnow': function () { closeWizard(); },
        'mfa-w-back': function () { stepIntro(); },
        'mfa-w-back-scan': function () { stepScan(); },
        'mfa-w-start': function () { stepPassword(); },
        'mfa-w-decline-open': function () { stepDecline(); },
        'mfa-w-decline-confirm': function () {
            var check = $('mfa-w-risk-check');
            if (!check || !check.checked) {
                showError('Tick the checkbox to confirm you accept the risk.');
                return;
            }
            if (state.busy) { return; }
            state.busy = true;
            AC.apiFetch(API_BASE + '/me/mfa-decline', { method: 'POST', body: { acknowledge_risk: true } })
                .then(function () {
                    if (me) { me.mfa_prompt_dismissed = true; }
                    if (AC.sessionMe) { AC.sessionMe.mfa_prompt_dismissed = true; }
                    AC.showSuccess('Okay — you can enable two-factor any time from your Profile.');
                    closeWizard();
                })
                .catch(function (err) { showError((err && err.message) || 'Connection failed — try again'); })
                .finally(function () { state.busy = false; });
        },
        'mfa-w-setup': function () {
            var pw = $('mfa-w-password') ? $('mfa-w-password').value : '';
            if (!pw) { showError('Enter your password first.'); return; }
            if (state.busy) { return; }
            state.busy = true;
            AC.apiFetch(API_BASE + '/2fa/setup', { method: 'POST', body: { password: pw } })
                .then(function (res) {
                    state.secret = res.data.secret;
                    state.otpauthUrl = res.data.otpauth_url;
                    state.qrPng = res.data.qr_png || '';
                    stepScan();
                })
                .catch(function (err) { showError((err && err.message) || 'Connection failed — try again'); })
                .finally(function () { state.busy = false; });
        },
        'mfa-w-to-verify': function () { stepVerify(); },
        'mfa-w-copy-secret': function () { copyText(state.secret, 'Key copied'); },
        'mfa-w-verify': function () {
            var code = $('mfa-w-code') ? $('mfa-w-code').value.trim() : '';
            if (!code) { showError('Enter the code from your app.'); return; }
            if (state.busy) { return; }
            state.busy = true;
            var btn = $('mfa-w-verify-btn');
            if (btn) { btn.disabled = true; }
            AC.apiFetch(API_BASE + '/2fa/verify', { method: 'POST', body: { code: code } })
                .then(function (res) {
                    state.codes = (res.data && res.data.recovery_codes) || [];
                    if (me) { me.totp_enabled = true; }
                    if (AC.sessionMe) { AC.sessionMe.totp_enabled = true; }
                    stepCodes();
                })
                .catch(function (err) {
                    var msg = (err && err.message) || 'Verification failed';
                    if (/too many|locked/i.test(msg)) {
                        msg = 'Too many attempts — wait 15 minutes. Your setup is saved; relaunch from your Profile page.';
                    } else {
                        msg += ' — check the code and that your phone’s clock is set automatically.';
                    }
                    showError(msg);
                    var input = $('mfa-w-code');
                    if (input) { input.value = ''; input.focus(); }
                })
                .finally(function () {
                    state.busy = false;
                    if (btn) { btn.disabled = false; }
                });
        },
        'mfa-w-copy-codes': function () { copyText(state.codes.join('\n'), 'Recovery codes copied', markCodesSaved); },
        'mfa-w-download-codes': function () {
            // Pure client-side: the session is already revoked at this step.
            var blob = new Blob([
                'Firewall-Mon recovery codes for ' + ((me && me.username) || 'your account') + '\n' +
                'Each code works once. Keep this file somewhere safe.\n\n' +
                state.codes.join('\n') + '\n'
            ], { type: 'text/plain' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'firewall-mon-recovery-codes.txt';
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
            markCodesSaved();
        },
        'mfa-w-codes-saved': function () {
            if (!state.codesSaved) {
                showError('Copy or download your codes first — they are shown only once.');
                return;
            }
            stepDone();
        },
        'mfa-w-login': function () {
            // Drop the guards BEFORE navigating, or our own beforeunload
            // prompt would second-guess the deliberate exit.
            holdSession(false);
            window.location.href = '/admin/login';
        },

        /* Profile page actions */
        'profile-save': function (el) { saveProfile(el); },
        'twofa-disable': function () {
            var pw = $('twofa-disable-pw') ? $('twofa-disable-pw').value : '';
            var code = $('twofa-disable-code') ? $('twofa-disable-code').value.trim() : '';
            if (!pw || !code) { AC.showError('Password and a code are required'); return; }
            AC.apiFetch(API_BASE + '/2fa/disable', { method: 'POST', body: { password: pw, code: code } })
                .then(function () {
                    if (me) { me.totp_enabled = false; }
                    if (AC.sessionMe) { AC.sessionMe.totp_enabled = false; }
                    AC.showSuccess('Two-factor authentication disabled');
                    renderIdentity();
                    render2FA();
                })
                .catch(function (err) { AC.showError((err && err.message) || 'Disable failed'); });
        }
    };

    function bindOnce() {
        if (bound) { return; }
        bound = true;
        [document.getElementById('page-profile'), document.getElementById('mfa-wizard-modal')]
            .forEach(function (root) {
                if (!root) { return; }
                root.addEventListener('click', function (e) {
                    var el = e.target.closest('[data-action]');
                    if (el && actions[el.dataset.action]) {
                        if (el.tagName === 'A' && el.getAttribute('href') && el.getAttribute('href').indexOf('otpauth:') === 0) {
                            return; // let the authenticator deep link navigate
                        }
                        e.preventDefault();
                        actions[el.dataset.action](el);
                    }
                });
            });

        document.addEventListener('fwmon:me-resolved', function (ev) {
            me = ev.detail || me;
            var page = document.getElementById('page-profile');
            if (page && page.classList.contains('active')) {
                renderIdentity();
                render2FA();
            }
            maybeOfferWizard();
        });
    }

    function maybeOfferWizard() {
        if (!me) { return; }
        if (me.totp_enabled || me.mfa_prompt_dismissed || me.must_change_password) { return; }
        if (sessionStorage.getItem('fwmon:mfa-wizard-offered')) { return; }
        sessionStorage.setItem('fwmon:mfa-wizard-offered', '1');
        launchWizard({ offerDecline: true });
    }

    function boot() {
        AC = window.AdminCommon;
        if (!AC || !document.getElementById('page-profile')) { return; }
        API_BASE = AC.API_BASE;
        bindOnce();
        if (AC.sessionMe) {
            me = AC.sessionMe;
            maybeOfferWizard();
        }
    }

    window.FwmonProfile = {
        initPage: initPage,
        launchWizard: launchWizard
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
