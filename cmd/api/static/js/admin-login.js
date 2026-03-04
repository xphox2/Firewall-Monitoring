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
        errorDiv.style.display = 'none';

        fetch(API_BASE + '/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password })
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (data.success) {
                window.location.href = '/admin';
            } else {
                errorDiv.textContent = data.error || 'Invalid credentials';
                errorDiv.style.display = 'block';
            }
        })
        ['catch'](function() {
            errorDiv.textContent = 'Connection error. Please try again.';
            errorDiv.style.display = 'block';
        })
        ['finally'](function() {
            btn.disabled = false;
            btn.textContent = 'Login';
        });
    });
})();
