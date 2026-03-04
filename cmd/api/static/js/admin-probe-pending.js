// admin-probe-pending.js — Pending probe approvals page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var pendingProbes = [];

    function loadProbes() {
        Promise.all([
            AC.apiFetch(API_BASE + '/probes/pending'),
            AC.apiFetch(API_BASE + '/probes')
        ]).then(function(results) {
            pendingProbes = (results[0] && results[0].data) || [];
            renderPending();
        })['catch'](function(err) {
            AC.showError('Failed to load: ' + err.message);
        });
    }

    function renderPending() {
        var container = document.getElementById('pending-container');

        if (pendingProbes.length === 0) {
            container.innerHTML = '<div class="card"><div class="empty">No pending probe requests. All probes have been processed.</div></div>';
            return;
        }

        var html = '';
        for (var i = 0; i < pendingProbes.length; i++) {
            var p = pendingProbes[i];
            html += '<div class="probe-card">' +
                '<div class="probe-header">' +
                '<span class="probe-name">' + AC.escapeHtml(p.name) + '</span>' +
                '<span class="badge pending">Pending</span>' +
                '</div>' +
                '<div class="probe-details">' +
                '<div><span>Listen:</span> ' + AC.escapeHtml(p.listen_address || '') + ':' + (p.listen_port || '') + '</div>' +
                '<div><span>Created:</span> ' + (p.created_at ? new Date(p.created_at).toLocaleString() : 'N/A') + '</div>' +
                '</div>' +
                '<div class="probe-actions">' +
                '<button class="btn sm" data-action="approve-probe" data-id="' + p.id + '">Approve</button>' +
                '<button class="btn sm danger" data-action="show-reject-modal" data-id="' + p.id + '">Reject</button>' +
                '</div>' +
                '</div>';
        }
        container.innerHTML = '<div class="card"><h2>Pending Requests (' + pendingProbes.length + ')</h2></div>' + html;
    }

    function approveProbe(id) {
        if (!confirm('Approve this probe?')) return;

        AC.apiFetch(API_BASE + '/probes/' + id + '/approve', {
            method: 'POST',
            body: { notes: 'Approved via admin panel' }
        }).then(function() {
            AC.showSuccess('Probe approved');
            loadProbes();
        })['catch'](function(err) {
            AC.showError('Error: ' + err.message);
        });
    }

    function showRejectModal(id) {
        document.getElementById('reject-probe-id').value = id;
        document.getElementById('reject-reason').value = '';
        document.getElementById('reject-modal').classList.add('active');
    }

    function closeRejectModal() {
        document.getElementById('reject-modal').classList.remove('active');
    }

    function submitReject(e) {
        e.preventDefault();
        var id = parseInt(document.getElementById('reject-probe-id').value);
        var reason = document.getElementById('reject-reason').value;

        AC.apiFetch(API_BASE + '/probes/' + id + '/reject', {
            method: 'POST',
            body: { reason: reason }
        }).then(function() {
            closeRejectModal();
            AC.showSuccess('Probe rejected');
            loadProbes();
        })['catch'](function(err) {
            AC.showError('Error: ' + err.message);
        });
    }

    // Event delegation
    AC.delegateEvent('click', {
        'approve-probe': function(el) { approveProbe(parseInt(el.dataset.id)); },
        'show-reject-modal': function(el) { showRejectModal(parseInt(el.dataset.id)); },
        'close-reject-modal': function() { closeRejectModal(); },
        'logout': function() { AC.doLogout(); }
    });

    // Form submit
    document.getElementById('reject-form').addEventListener('submit', submitReject);

    // Init
    AC.fetchCsrfToken().then(function() {
        loadProbes();
    });
})();
