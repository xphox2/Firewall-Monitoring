// admin-probes.js — Probe management page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var currentProbes = [];
    var currentSites = [];
    var currentDeployProbe = null;
    var probeStatsMap = {};

    function loadProbes() {
        AC.apiFetch(API_BASE + '/probes').then(function(result) {
            currentProbes = result.data || [];
            renderProbes(currentProbes);
            loadProbeSummaryStats();
        }).catch(function(err) {
            AC.showError('Failed to load probes: ' + err.message);
        });
    }

    function loadProbeSummaryStats() {
        // "Data Totals (All Probes)" is an orphan-safe running total: it counts
        // ALL telemetry regardless of which probe collected it (or whether that
        // probe still exists), so the numbers never drop when a probe is
        // decommissioned or deleted. See GET /api/probes/stats/global.
        function renderSummary(t) {
            function card(icon, accent, label, total, lastHr) {
                return '<div class="stat-card ' + accent + '">' +
                    '<div class="stat-icon">' + icon + '</div>' +
                    '<div class="stat-content">' +
                        '<div class="stat-label">' + label + '</div>' +
                        '<div class="stat-value">' + (total || 0).toLocaleString() + '</div>' +
                        '<div style="font-size:0.72rem;color:var(--fwmon-text-faint);margin-top:4px;">+' + (lastHr || 0).toLocaleString() + ' last hr</div>' +
                    '</div>' +
                '</div>';
            }
            document.getElementById('probe-summary-stats').innerHTML =
                card('📄', 'accent-blue', 'Syslog', t.syslog, t.syslog_last_hour) +
                card('⚡', 'accent-green', 'Traps', t.traps, t.traps_last_hour) +
                card('🔄', 'accent-blue', 'Flows', t.flows, t.flows_last_hour) +
                card('📶', 'accent-green', 'Pings', t.pings, t.pings_last_hour);
        }

        AC.apiFetch(API_BASE + '/probes/stats/global').then(function(r) {
            renderSummary((r && r.data) ? r.data : {});
        }).catch(function() {
            renderSummary({});
        });

        // Per-probe stats power the individual probe cards. AUDIT-064: one
        // batched request instead of N round-trips. Decommissioned probes are
        // excluded here (their card isn't shown) but still counted in the totals
        // above via the orphan-safe global endpoint.
        var statProbes = currentProbes.filter(function(p) { return p.approval_status === 'approved' && !p.decommissioned_at; });
        var ids = statProbes.map(function(p) { return p.id; });
        if (ids.length === 0) { return; }
        AC.apiFetch(API_BASE + '/probes/stats?ids=' + ids.join(',')).then(function(r) {
            probeStatsMap = {};
            (r && r.data ? r.data : []).forEach(function(d) { probeStatsMap[d.probe_id] = d; });
            renderProbes(currentProbes);
        }).catch(function() {});
    }

    function loadSites() {
        return AC.apiFetch(API_BASE + '/sites').then(function(result) {
            currentSites = result.data || [];
            populateSiteSelect();
        }).catch(function(err) {
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
        var grid = document.getElementById('probes-grid');
        if (!grid) return;
        if (probes.length === 0) {
            grid.innerHTML = '<div class="col-span-full card text-center p-8 text-[#8b949e]">No probes configured</div>';
            return;
        }
        grid.innerHTML = probes.map(function(p) {
            var approvalStatus = p.approval_status || 'pending';
            var lastSeen = p.last_seen && p.last_seen !== '0001-01-01T00:00:00Z'
                ? AC.formatDate(p.last_seen) : 'Never';
            
            var statusBadge = '';
            if (p.status === 'online' || p.status === 'up') {
                statusBadge = '<span class="badge online">ONLINE</span>';
            } else if (p.status === 'offline' || p.status === 'down') {
                statusBadge = '<span class="badge offline">OFFLINE</span>';
            } else {
                statusBadge = '<span class="badge unknown">' + (p.status || 'OFFLINE').toUpperCase() + '</span>';
            }

            var isDecommissioned = !!p.decommissioned_at;
            var approvalBadge = '';
            if (isDecommissioned) {
                approvalBadge = '<span class="badge unknown" title="Retired — data preserved, hidden from active lists">DECOMMISSIONED</span>';
            } else if (approvalStatus === 'approved') {
                approvalBadge = '<span class="badge approved">APPROVED</span>';
            } else if (approvalStatus === 'rejected') {
                approvalBadge = '<span class="badge rejected">REJECTED</span>';
            } else {
                approvalBadge = '<span class="badge pending">PENDING</span>';
            }

            var stats = probeStatsMap[p.id];
            var statsHtml = '';
            if (stats && approvalStatus === 'approved') {
                statsHtml = '<div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:6px;margin:12px 0;background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:8px;">' +
                    '<div style="text-align:center;">' +
                        '<div style="font-size:0.58rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.3px;">Logs</div>' +
                        '<div style="font-size:0.78rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + (stats.syslog || 0).toLocaleString() + '</div>' +
                    '</div>' +
                    '<div style="text-align:center;">' +
                        '<div style="font-size:0.58rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.3px;">Traps</div>' +
                        '<div style="font-size:0.78rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + (stats.traps || 0).toLocaleString() + '</div>' +
                    '</div>' +
                    '<div style="text-align:center;">' +
                        '<div style="font-size:0.58rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.3px;">Flows</div>' +
                        '<div style="font-size:0.78rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + (stats.flows || 0).toLocaleString() + '</div>' +
                    '</div>' +
                    '<div style="text-align:center;">' +
                        '<div style="font-size:0.58rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.3px;">Pings</div>' +
                        '<div style="font-size:0.78rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + (stats.pings || 0).toLocaleString() + '</div>' +
                    '</div>' +
                '</div>';
            } else {
                statsHtml = '<div style="height:12px;"></div>';
            }

            var desc = p.description ? AC.escapeHtml(p.description) : '<span style="color:var(--fwmon-text-mute);font-style:italic">No description provided</span>';

            // Decommissioned probes only offer Restore (no Deploy/Edit). Active
            // probes that ever collected (approved) are retired via Decommission,
            // which preserves their data; only never-used pending/rejected probes
            // expose a hard Delete.
            var buttons;
            if (isDecommissioned) {
                buttons = '<button class="btn sm" data-action="recommission-probe" data-min-role="operator" data-id="' + p.id + '">Restore</button>';
            } else {
                buttons = '<button class="btn sm secondary" data-action="deploy-info" data-id="' + p.id + '">Deploy Info</button>';
                if (approvalStatus === 'pending') {
                    buttons += '<button class="btn sm" data-action="approve-probe" data-min-role="operator" data-id="' + p.id + '">Approve</button>' +
                        '<button class="btn sm danger" data-action="reject-probe" data-min-role="operator" data-id="' + p.id + '">Reject</button>';
                }
                buttons += '<button class="btn sm secondary" data-action="edit-probe" data-min-role="operator" data-id="' + p.id + '">Edit</button>';
                if (approvalStatus === 'approved') {
                    buttons += '<button class="btn sm danger" data-action="decommission-probe" data-min-role="operator" data-id="' + p.id + '">Decommission</button>';
                } else {
                    buttons += '<button class="btn sm danger" data-action="delete-probe" data-min-role="operator" data-id="' + p.id + '">Delete</button>';
                }
            }

            return '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:250px;padding:20px;">' +
                '<div>' +
                    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">' +
                        '<h3 style="font-size:1.05rem;font-weight:600;color:var(--fwmon-text);margin:0;font-family:\'Outfit\',sans-serif;">' + AC.escapeHtml(p.name) + '</h3>' +
                        '<div style="display:flex;gap:4px;">' + statusBadge + approvalBadge + '</div>' +
                    '</div>' +
                    '<div style="font-size:0.8rem;color:var(--fwmon-text-faint);margin-bottom:14px;min-height:36px;line-height:1.4;">' + desc + '</div>' +
                    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:10px;">' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.5px;margin-bottom:2px;">Site</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:var(--fwmon-text-dim);">' + AC.escapeHtml(p.site ? p.site.name : '-') + '</span>' +
                        '</div>' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.5px;margin-bottom:2px;">Last Seen</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + lastSeen + '</span>' +
                        '</div>' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.5px;margin-bottom:2px;">Version</span>' +
                            // "unknown" rather than a blank or a guess: it means a
                            // collector too old to report its build, which is a real
                            // answer and the one worth being able to see.
                            '<span style="font-size:0.8rem;font-weight:600;color:' +
                                (p.agent_version ? 'var(--fwmon-text-dim)' : 'var(--fwmon-text-mute)') +
                                ';font-family:var(--fwmon-font-mono);">' +
                                AC.escapeHtml(p.agent_version || 'unknown') + '</span>' +
                        '</div>' +
                    '</div>' +
                    statsHtml +
                '</div>' +
                '<div style="display:flex;justify-content:flex-end;gap:6px;border-top:1px solid var(--fwmon-border);padding-top:12px;flex-wrap:wrap;">' +
                    buttons +
                '</div>' +
            '</div>';
        }).join('');
    }

    function showAddModal() {
        AC.openModal('probe-modal');
        document.getElementById('probe-modal-title').textContent = 'Add Probe';
        document.getElementById('probe-form').reset();
        document.getElementById('probe-id').value = '';
        loadSites();
    }

    function closeProbeModal() {
        AC.closeModal('probe-modal');
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
            AC.openModal('probe-modal');
            document.getElementById('probe-modal-title').textContent = 'Edit Probe';
            document.getElementById('probe-id').value = probe.id;
            document.getElementById('probe-name').value = probe.name;
            document.getElementById('probe-site').value = probe.site_id || '';
            document.getElementById('probe-description').value = probe.description || '';
            document.getElementById('probe-tftp-server-ip').value = probe.tftp_server_ip || '';
        });
    }

    function saveProbe(e) {
        e.preventDefault();
        var id = document.getElementById('probe-id').value;
        var data = {
            name: document.getElementById('probe-name').value,
            site_id: parseInt(document.getElementById('probe-site').value),
            description: document.getElementById('probe-description').value,
            tftp_server_ip: document.getElementById('probe-tftp-server-ip').value.trim(),
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
        }).catch(function(err) {
            AC.showError('Error saving probe: ' + err.message);
        });
    }

    // realKey filters out the server's redaction mask: after the create-time
    // show-once reveal (LC-16), every GET returns '********' for a probe with
    // a key — which is truthy, so without this the deploy modal rendered the
    // mask as if it were a copyable key.
    function realKey(k) {
        return (k && k !== '********') ? k : '';
    }

    function showDeployInfoForProbe(probe) {
        currentDeployProbe = probe;
        document.getElementById('deploy-probe-id').value = probe.id;

        var key = realKey(probe.registration_key) ||
            '(key shown once at creation — an admin can issue a new one with Regenerate Key)';
        document.getElementById('deploy-key').textContent = key;

        var serverUrl = getServerUrl();
        var envContent = 'PROBE_NAME=' + probe.name +
            '\nPROBE_SITE_ID=' + (probe.site_id || 0) +
            '\nPROBE_REGISTRATION_KEY=' + (realKey(probe.registration_key) || 'MISSING') +
            '\nPROBE_SERVER_URL=' + serverUrl;

        var envBlock = document.getElementById('deploy-env');
        envBlock.innerHTML = '<button class="copy-btn" data-action="copy-env">Copy</button>' +
            AC.escapeHtml(envContent);

        AC.openModal('deploy-modal');
    }

    function showDeployInfo(id) {
        var probe = null;
        for (var i = 0; i < currentProbes.length; i++) {
            if (currentProbes[i].id === id) {
                probe = currentProbes[i];
                break;
            }
        }
        if (!probe) {
            AC.showError('Probe not found');
            return;
        }

        AC.fetchCsrfToken().then(function() {
            return AC.apiFetch(API_BASE + '/probes/' + id);
        }).then(function(result) {
            if (result && result.data) {
                showDeployInfoForProbe(result.data);
            }
        }).catch(function(err) {
            AC.showError('Failed to load probe details: ' + err.message);
        });
    }

    function closeDeployModal() {
        AC.closeModal('deploy-modal');
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

        AC.confirm('Regenerate the registration key? The old key will stop working immediately.', {
            title: 'Regenerate key?',
            confirmLabel: 'Regenerate',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;

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
            }).catch(function(err) {
                AC.showError('Error regenerating key: ' + err.message);
            });
        });
    }

    function deleteProbe(id) {
        AC.confirm('Delete this probe?', {
            title: 'Delete probe?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            AC.apiFetch(API_BASE + '/probes/' + id, { method: 'DELETE' }).then(function() {
                loadProbes();
                AC.showSuccess('Probe deleted');
            }).catch(function(err) {
                AC.showError('Error deleting probe: ' + err.message);
            });
        });
    }

    // Decommission retires a replaced probe WITHOUT deleting any data — the
    // probe's telemetry stays counted in the running totals; it's just hidden
    // from the active lists. This is the right action for an in-service probe.
    function decommissionProbe(id) {
        AC.confirm('Decommission this probe? Its historical data is kept and still counts toward the totals — the probe is just retired and hidden from the active list. Reassign its devices to the replacement probe first.', {
            title: 'Decommission probe?',
            confirmLabel: 'Decommission',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            AC.apiFetch(API_BASE + '/probes/' + id + '/decommission', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            }).then(function() {
                loadProbes();
                AC.showSuccess('Probe decommissioned (data preserved)');
            }).catch(function(err) {
                AC.showError('Error decommissioning probe: ' + err.message);
            });
        });
    }

    function recommissionProbe(id) {
        AC.apiFetch(API_BASE + '/probes/' + id + '/recommission', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(function() {
            loadProbes();
            AC.showSuccess('Probe restored');
        }).catch(function(err) {
            AC.showError('Error restoring probe: ' + err.message);
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
        }).catch(function(err) {
            AC.showError('Error approving probe: ' + err.message);
        });
    }

    // AUDIT-051: reject now uses the styled #reject-modal instead of the
    // native window.prompt() (lessons.md: AdminCommon modals are the standard).
    function rejectProbe(id) {
        document.getElementById('reject-probe-id').value = id;
        document.getElementById('reject-reason').value = '';
        AC.openModal('reject-modal');
    }

    function closeRejectModal() {
        AC.closeModal('reject-modal');
    }

    function submitReject(e) {
        e.preventDefault();
        var id = parseInt(document.getElementById('reject-probe-id').value, 10);
        var reason = document.getElementById('reject-reason').value.trim();
        if (!reason) return;
        AC.apiFetch(API_BASE + '/probes/' + id + '/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason })
        }).then(function() {
            closeRejectModal();
            loadProbes();
            AC.showSuccess('Probe rejected');
        }).catch(function(err) {
            AC.showError('Error rejecting probe: ' + err.message);
        });
    }

    function filterProbes(filter) {
        document.querySelectorAll('.filter-tab').forEach(function(t) {
            t.classList.remove('active');
        });
        var tab = document.querySelector('.filter-tab[data-filter="' + filter + '"]');
        if (tab) tab.classList.add('active');
        if (filter === 'decommissioned') {
            renderProbes(currentProbes.filter(function(p) { return !!p.decommissioned_at; }));
            return;
        }
        // Decommissioned probes are hidden from the active tabs (all/pending/
        // approved/rejected) — they live under their own tab. Their data still
        // counts in the totals via the orphan-safe global endpoint.
        var active = currentProbes.filter(function(p) { return !p.decommissioned_at; });
        if (filter === 'all') {
            renderProbes(active);
        } else {
            renderProbes(active.filter(function(p) {
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
        'decommission-probe': function(el) { decommissionProbe(parseInt(el.dataset.id)); },
        'recommission-probe': function(el) { recommissionProbe(parseInt(el.dataset.id)); },
        'deploy-info': function(el) { showDeployInfo(parseInt(el.dataset.id)); },
        'approve-probe': function(el) { approveProbe(parseInt(el.dataset.id)); },
        'reject-probe': function(el) { rejectProbe(parseInt(el.dataset.id)); },
        'close-reject-modal': function() { closeRejectModal(); },
        'copy-deploy-key': function() { copyDeployKey(); },
        'regenerate-key': function() { regenerateKey(); },
        'copy-env': function() { copyEnvBlock(); },
        'filter-probes': function(el) { filterProbes(el.dataset.filter); }
    });

    // Form submit
    document.getElementById('probe-form').addEventListener('submit', saveProbe);
    document.getElementById('reject-form').addEventListener('submit', submitReject); // AUDIT-051

    // Init — the SPA calls this when the Probes page is shown (admin-main.js
    // loadPageData). The event-delegation and form-submit wiring above runs
    // once at module load; only the data fetch is deferred so we don't hit
    // /api/probes while the operator is on another page.
    window.FwmonProbes = { init: function () {
        AC.fetchCsrfToken().then(function () { loadProbes(); });
    } };
})();
