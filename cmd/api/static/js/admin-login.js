// admin-login.js — Login page logic
(function() {
    'use strict';

    var API_BASE = '/api';

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
                window.location.href = '/admin';
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
                window.location.href = '/admin';
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
