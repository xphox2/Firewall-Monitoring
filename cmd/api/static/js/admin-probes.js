// admin-probes.js — Probe management page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var currentProbes = [];
    var currentSites = [];
    var currentDeployProbe = null;

    function loadProbes() {
        AC.apiFetch(API_BASE + '/probes').then(function(result) {
            currentProbes = result.data || [];
            renderProbes(currentProbes);
        })['catch'](function(err) {
            AC.showError('Failed to load probes: ' + err.message);
        });
    }

    function loadSites() {
        return AC.apiFetch(API_BASE + '/sites').then(function(result) {
            currentSites = result.data || [];
            populateSiteSelect();
        })['catch'](function(err) {
            console.error('Failed to load sites:', err);
        });
    }

    function populateSiteSelect() {
        var select = document.getElementById('probe-site');
        select.innerHTML = '<option value="">Select a site</option>' +
            currentSites.map(function(s) {
                return '<option value="' + s.id + '">' + AC.escapeHtml(s.name) + '</option>';
            }).join('');
    }

    function getServerUrl() {
        return window.location.origin;
    }

    function renderProbes(probes) {
        var tbody = document.querySelector('#probes-table tbody');
        if (probes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading">No probes configured</td></tr>';
            return;
        }
        tbody.innerHTML = probes.map(function(p) {
            var approvalStatus = p.approval_status || 'pending';
            var lastSeen = p.last_seen && p.last_seen !== '0001-01-01T00:00:00Z'
                ? new Date(p.last_seen).toLocaleString() : 'Never';
            var html = '<tr>' +
                '<td><strong>' + AC.escapeHtml(p.name) + '</strong>' +
                (p.description ? '<br><span class="info-text">' + AC.escapeHtml(p.description) + '</span>' : '') +
                '</td>' +
                '<td>' + AC.escapeHtml(p.site ? p.site.name : '-') + '</td>' +
                '<td><span class="badge ' + AC.escapeHtml(p.status) + '">' + AC.escapeHtml(p.status || 'offline').toUpperCase() + '</span></td>' +
                '<td><span class="badge ' + AC.escapeHtml(approvalStatus) + '">' + AC.escapeHtml(approvalStatus).toUpperCase() + '</span></td>' +
                '<td>' + lastSeen + '</td>' +
                '<td class="actions">' +
                '<button class="btn sm info" data-action="deploy-info" data-id="' + p.id + '">Deploy Info</button>';
            if (approvalStatus === 'pending') {
                html += '<button class="btn sm" data-action="approve-probe" data-id="' + p.id + '">Approve</button>' +
                    '<button class="btn sm danger" data-action="reject-probe" data-id="' + p.id + '">Reject</button>';
            }
            html += '<button class="btn sm secondary" data-action="edit-probe" data-id="' + p.id + '">Edit</button>' +
                '<button class="btn sm danger" data-action="delete-probe" data-id="' + p.id + '">Delete</button>' +
                '</td></tr>';
            return html;
        }).join('');
    }

    function showAddModal() {
        document.getElementById('probe-modal').classList.add('active');
        document.getElementById('probe-modal-title').textContent = 'Add Probe';
        document.getElementById('probe-form').reset();
        document.getElementById('probe-id').value = '';
        loadSites();
    }

    function closeProbeModal() {
        document.getElementById('probe-modal').classList.remove('active');
    }

    function editProbe(id) {
        var probe = null;
        for (var i = 0; i < currentProbes.length; i++) {
            if (currentProbes[i].id === id) {
                probe = currentProbes[i];
                break;
            }
        }
        if (!probe) return;

        loadSites().then(function() {
            document.getElementById('probe-modal').classList.add('active');
            document.getElementById('probe-modal-title').textContent = 'Edit Probe';
            document.getElementById('probe-id').value = probe.id;
            document.getElementById('probe-name').value = probe.name;
            document.getElementById('probe-site').value = probe.site_id || '';
            document.getElementById('probe-description').value = probe.description || '';
        });
    }

    function saveProbe(e) {
        e.preventDefault();
        var id = document.getElementById('probe-id').value;
        var data = {
            name: document.getElementById('probe-name').value,
            site_id: parseInt(document.getElementById('probe-site').value),
            description: document.getElementById('probe-description').value,
            enabled: true
        };

        var method = id ? 'PUT' : 'POST';
        var url = id ? API_BASE + '/probes/' + id : API_BASE + '/probes';

        AC.apiFetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(function(result) {
            closeProbeModal();
            loadProbes();

            if (!id && result && result.data) {
                // New probe created — show deploy instructions immediately
                showDeployInfoForProbe(result.data);
                AC.showSuccess('Probe created — copy the deploy instructions below');
            } else {
                AC.showSuccess(id ? 'Probe updated' : 'Probe created');
            }
        })['catch'](function(err) {
            AC.showError('Error saving probe: ' + err.message);
        });
    }

    function showDeployInfoForProbe(probe) {
        currentDeployProbe = probe;
        document.getElementById('deploy-probe-id').value = probe.id;

        var key = probe.registration_key || '(no key — click Regenerate Key)';
        document.getElementById('deploy-key').textContent = key;

        var serverUrl = getServerUrl();
        var envContent = 'PROBE_NAME=' + probe.name +
            '\nPROBE_SITE_ID=' + (probe.site_id || 0) +
            '\nPROBE_REGISTRATION_KEY=' + (probe.registration_key || 'MISSING') +
            '\nPROBE_SERVER_URL=' + serverUrl;

        var envBlock = document.getElementById('deploy-env');
        envBlock.innerHTML = '<button class="copy-btn" data-action="copy-env">Copy</button>' +
            AC.escapeHtml(envContent);

        document.getElementById('deploy-modal').classList.add('active');
    }

    function showDeployInfo(id) {
        var probe = null;
        for (var i = 0; i < currentProbes.length; i++) {
            if (currentProbes[i].id === id) {
                probe = currentProbes[i];
                break;
            }
        }
        if (!probe) return;

        AC.apiFetch(API_BASE + '/probes/' + id).then(function(result) {
            if (result && result.data) {
                showDeployInfoForProbe(result.data);
            }
        })['catch'](function(err) {
            AC.showError('Failed to load probe details: ' + err.message);
        });
    }

    function closeDeployModal() {
        document.getElementById('deploy-modal').classList.remove('active');
        currentDeployProbe = null;
    }

    function copyDeployKey() {
        var key = document.getElementById('deploy-key').textContent;
        if (key && key.charAt(0) !== '(') {
            navigator.clipboard.writeText(key);
            AC.showSuccess('Key copied to clipboard');
        }
    }

    function copyEnvBlock() {
        var envBlock = document.getElementById('deploy-env');
        var text = envBlock.textContent.replace('Copy', '').trim();
        navigator.clipboard.writeText(text);
        AC.showSuccess('Environment variables copied to clipboard');
    }

    function regenerateKey() {
        var probeId = document.getElementById('deploy-probe-id').value;
        if (!probeId) return;

        if (!confirm('Regenerate the registration key? The old key will stop working immediately.')) return;

        AC.apiFetch(API_BASE + '/probes/' + probeId + '/regenerate-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(function(result) {
            if (result && result.data) {
                var newKey = result.data.registration_key;
                document.getElementById('deploy-key').textContent = newKey;

                if (currentDeployProbe) {
                    currentDeployProbe.registration_key = newKey;
                    var serverUrl = getServerUrl();
                    var envContent = 'PROBE_NAME=' + currentDeployProbe.name +
                        '\nPROBE_SITE_ID=' + (currentDeployProbe.site_id || 0) +
                        '\nPROBE_REGISTRATION_KEY=' + newKey +
                        '\nPROBE_SERVER_URL=' + serverUrl;
                    var envBlock = document.getElementById('deploy-env');
                    envBlock.innerHTML = '<button class="copy-btn" data-action="copy-env">Copy</button>' +
                        AC.escapeHtml(envContent);
                }

                AC.showSuccess('Registration key regenerated');
                loadProbes();
            }
        })['catch'](function(err) {
            AC.showError('Error regenerating key: ' + err.message);
        });
    }

    function deleteProbe(id) {
        if (!confirm('Delete this probe?')) return;
        AC.apiFetch(API_BASE + '/probes/' + id, { method: 'DELETE' }).then(function() {
            loadProbes();
            AC.showSuccess('Probe deleted');
        })['catch'](function(err) {
            AC.showError('Error deleting probe: ' + err.message);
        });
    }

    function approveProbe(id) {
        AC.apiFetch(API_BASE + '/probes/' + id + '/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: '' })
        }).then(function() {
            loadProbes();
            AC.showSuccess('Probe approved');
        })['catch'](function(err) {
            AC.showError('Error approving probe: ' + err.message);
        });
    }

    function rejectProbe(id) {
        var reason = prompt('Enter rejection reason:');
        if (!reason) return;
        AC.apiFetch(API_BASE + '/probes/' + id + '/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason })
        }).then(function() {
            loadProbes();
            AC.showSuccess('Probe rejected');
        })['catch'](function(err) {
            AC.showError('Error rejecting probe: ' + err.message);
        });
    }

    function filterProbes(filter) {
        document.querySelectorAll('.filter-tab').forEach(function(t) {
            t.classList.remove('active');
        });
        document.querySelector('.filter-tab[data-filter="' + filter + '"]').classList.add('active');
        if (filter === 'all') {
            renderProbes(currentProbes);
        } else {
            renderProbes(currentProbes.filter(function(p) {
                return (p.approval_status || 'pending') === filter;
            }));
        }
    }

    // Event delegation
    AC.delegateEvent('click', {
        'logout': function() { AC.doLogout(); },
        'show-add-modal': function() { showAddModal(); },
        'close-probe-modal': function() { closeProbeModal(); },
        'close-deploy-modal': function() { closeDeployModal(); },
        'edit-probe': function(el) { editProbe(parseInt(el.dataset.id)); },
        'delete-probe': function(el) { deleteProbe(parseInt(el.dataset.id)); },
        'deploy-info': function(el) { showDeployInfo(parseInt(el.dataset.id)); },
        'approve-probe': function(el) { approveProbe(parseInt(el.dataset.id)); },
        'reject-probe': function(el) { rejectProbe(parseInt(el.dataset.id)); },
        'copy-deploy-key': function() { copyDeployKey(); },
        'regenerate-key': function() { regenerateKey(); },
        'copy-env': function() { copyEnvBlock(); },
        'filter-probes': function(el) { filterProbes(el.dataset.filter); }
    });

    // Form submit
    document.getElementById('probe-form').addEventListener('submit', saveProbe);

    // Init
    AC.fetchCsrfToken().then(function() {
        loadProbes();
    });
})();
