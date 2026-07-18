// admin-sites.js — Site management page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var sites = [];
    var editingId = null;

    function loadSites() {
        AC.apiFetch(API_BASE + '/sites').then(function(result) {
            sites = (result.data || []).sort(function(a, b) {
                return (a.name || '').localeCompare(b.name || '');
            });
            renderSites();
        }).catch(function(err) {
            console.error('[Sites] Error loading sites:', err);
            AC.showError('Failed to load sites: ' + err.message);
        });
    }

    function renderSites() {
        var container = document.getElementById('sites-container');
        if (sites.length === 0) {
            container.innerHTML = '<div class="col-span-full card text-center p-8 text-[#8b949e]">No sites configured. Click "+ Add Site" to create one.</div>';
            return;
        }

        var html = '';
        for (var i = 0; i < sites.length; i++) {
            var site = sites[i];
            
            var desc = site.description ? AC.escapeHtml(site.description) : '<span style="color:var(--fwmon-text-mute);font-style:italic">No description provided</span>';
            
            html += '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:245px;padding:20px;">' +
                '<div>' +
                    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">' +
                        '<h3 style="font-size:1.05rem;font-weight:600;color:var(--fwmon-text);margin:0;font-family:\'Outfit\',sans-serif;">' + AC.escapeHtml(site.name) + '</h3>' +
                        (site.country ? '<span class="badge info">' + AC.escapeHtml(site.country).toUpperCase() + '</span>' : '') +
                    '</div>' +
                    '<div style="font-size:0.8rem;color:var(--fwmon-text-faint);margin-bottom:14px;min-height:36px;line-height:1.4;">' + desc + '</div>' +
                    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:10px;">' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.5px;margin-bottom:2px;">Region</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:var(--fwmon-text-dim);">' + AC.escapeHtml(site.region || 'N/A') + '</span>' +
                        '</div>' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:var(--fwmon-text-mute);letter-spacing:0.5px;margin-bottom:2px;">Timezone</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:var(--fwmon-text-dim);font-family:var(--fwmon-font-mono);">' + AC.escapeHtml(site.timezone || 'N/A') + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div style="font-size:0.75rem;color:var(--fwmon-text-faint);margin-bottom:8px;">' +
                        '<span style="color:var(--fwmon-text-mute);font-weight:500;">Address:</span> ' + AC.escapeHtml(site.address || 'N/A') +
                    '</div>' +
                '</div>' +
                '<div style="display:flex;justify-content:flex-end;gap:6px;border-top:1px solid var(--fwmon-border);padding-top:12px;">' +
                    '<button class="btn sm secondary" data-action="site-alert-config" data-min-role="operator" data-id="' + site.id + '">Alert overrides</button> ' +
                    '<button class="btn sm secondary" data-action="edit-site" data-min-role="operator" data-id="' + site.id + '">Edit</button> ' +
                    '<button class="btn sm danger" data-action="delete-site" data-min-role="operator" data-id="' + site.id + '">Delete</button>' +
                '</div>' +
                '</div>';
        }
        container.innerHTML = html;
    }

    function showAddModal() {
        editingId = null;
        document.getElementById('modal-title').textContent = 'Add Site';
        document.getElementById('site-form').reset();
        document.getElementById('site-id').value = '';
        document.getElementById('csrf-token').value = AC.getCsrfToken();
        AC.openModal('site-modal');
    }

    function editSite(id) {
        var site = null;
        for (var i = 0; i < sites.length; i++) {
            if (sites[i].id === id) {
                site = sites[i];
                break;
            }
        }
        if (!site) return;

        editingId = id;
        document.getElementById('modal-title').textContent = 'Edit Site';
        document.getElementById('site-id').value = id;
        document.getElementById('site-name').value = site.name || '';
        document.getElementById('site-region').value = site.region || '';
        document.getElementById('site-country').value = site.country || '';
        document.getElementById('site-address').value = site.address || '';
        document.getElementById('site-timezone').value = site.timezone || '';
        document.getElementById('site-description').value = site.description || '';
        document.getElementById('csrf-token').value = AC.getCsrfToken();
        AC.openModal('site-modal');
    }

    function closeModal() {
        AC.closeModal('site-modal');
    }

    function saveSite(e) {
        e.preventDefault();

        var data = {
            name: document.getElementById('site-name').value,
            region: document.getElementById('site-region').value,
            country: document.getElementById('site-country').value,
            address: document.getElementById('site-address').value,
            timezone: document.getElementById('site-timezone').value,
            description: document.getElementById('site-description').value
        };

        var url = API_BASE + '/sites';
        var method = 'POST';

        if (editingId) {
            url += '/' + editingId;
            method = 'PUT';
        }

        AC.apiFetch(url, { method: method, body: data }).then(function() {
            closeModal();
            AC.showSuccess(editingId ? 'Site updated' : 'Site created');
            loadSites();
        }).catch(function(err) {
            console.error('[Sites] Save error:', err);
            AC.showError('Error saving site: ' + err.message);
        });
    }

    function deleteSite(id) {
        AC.confirm('Are you sure you want to delete this site?', {
            title: 'Delete site?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            AC.apiFetch(API_BASE + '/sites/' + id, { method: 'DELETE' }).then(function() {
                AC.showSuccess('Site deleted');
                loadSites();
            }).catch(function(err) {
                AC.showError('Error deleting site: ' + err.message);
            });
        });
    }

    // ---- Site Alert Config Modal (Phase 5a) ----
    function siteName(id) {
        for (var i = 0; i < sites.length; i++) { if (sites[i].id === id) return sites[i].name; }
        return '';
    }

    function showSiteAlertModal(id) {
        var nm = siteName(id);
        document.getElementById('site-alert-modal-title').textContent = nm ? 'Alert Configuration: ' + nm : 'Site Alert Configuration';
        document.getElementById('site-alert-site-id').value = id;
        ['cpu', 'memory', 'disk', 'sessions', 'cooldown', 'storm'].forEach(function(f) {
            document.getElementById('site-alert-' + f).value = '';
        });
        var policySelect = document.getElementById('site-alert-policy');
        policySelect.innerHTML = '<option value="">— Inherit from global default —</option>';
        var epSelect = document.getElementById('site-event-profile');
        if (epSelect) epSelect.innerHTML = '<option value="">— Inherit from Default —</option>';

        Promise.all([
            AC.apiFetch(API_BASE + '/sites/' + id + '/alert-config'),
            AC.apiFetch(API_BASE + '/alert-policies'),
            AC.apiFetch(API_BASE + '/event-rule-profiles').catch(function() { return { data: [] }; })
        ]).then(function(results) {
            var cfgResp = results[0], polResp = results[1], profResp = results[2];
            if (polResp && polResp.data) {
                polResp.data.forEach(function(p) {
                    var opt = document.createElement('option');
                    opt.value = p.id; opt.textContent = p.name;
                    policySelect.appendChild(opt);
                });
            }
            // Event profiles (v48): Default is the implicit fallback, so only
            // non-default profiles are explicit choices.
            if (epSelect && profResp && profResp.data) {
                profResp.data.forEach(function(p) {
                    if (p.is_default) return;
                    var opt = document.createElement('option');
                    opt.value = p.id; opt.textContent = p.name;
                    epSelect.appendChild(opt);
                });
            }
            if (cfgResp && cfgResp.data) {
                var cfg = cfgResp.data;
                if (cfg.policy_id) policySelect.value = cfg.policy_id;
                if (epSelect && cfg.event_profile_id) epSelect.value = cfg.event_profile_id;
                if (cfg.cpu_threshold) document.getElementById('site-alert-cpu').value = cfg.cpu_threshold;
                if (cfg.memory_threshold) document.getElementById('site-alert-memory').value = cfg.memory_threshold;
                if (cfg.disk_threshold) document.getElementById('site-alert-disk').value = cfg.disk_threshold;
                if (cfg.session_threshold) document.getElementById('site-alert-sessions').value = cfg.session_threshold;
                if (cfg.cooldown_minutes) document.getElementById('site-alert-cooldown').value = cfg.cooldown_minutes;
                if (cfg.storm_sources != null) document.getElementById('site-alert-storm').value = cfg.storm_sources;
            }
            AC.openModal('site-alert-modal');
            AC.renderAlertInheritanceHints({ siteId: id }, 'site', {
                CPU_HIGH: 'site-eff-cpu', MEMORY_HIGH: 'site-eff-memory',
                DISK_HIGH: 'site-eff-disk', SESSIONS_HIGH: 'site-eff-sessions'
            });
        }).catch(function(e) {
            console.error('[Sites] Failed to load site alert config:', e);
            AC.showError('Failed to load site alert config: ' + e.message);
        });
    }

    function closeSiteAlertModal() { AC.closeModal('site-alert-modal'); }

    function resetSiteAlertConfig() {
        var id = document.getElementById('site-alert-site-id').value;
        if (!id) return;
        AC.confirm('Reset alert configuration to defaults? This removes all overrides for this site.', {
            title: 'Reset site alert config?', confirmLabel: 'Reset', danger: true,
        }).then(function(ok) {
            if (!ok) return;
            AC.apiFetch(API_BASE + '/sites/' + id + '/alert-config', { method: 'DELETE' }).then(function() {
                closeSiteAlertModal();
                AC.showSuccess('Site alert config reset to defaults');
            }).catch(function(e) {
                AC.showError('Reset failed: ' + e.message);
            });
        });
    }

    function saveSiteAlertConfig(e) {
        e.preventDefault();
        var id = document.getElementById('site-alert-site-id').value;
        if (!id) return;
        function num(f, isInt) {
            var v = document.getElementById('site-alert-' + f).value;
            if (v === '') return 0;
            return isInt ? parseInt(v) : parseFloat(v);
        }
        var policyVal = document.getElementById('site-alert-policy').value;
        var stormRaw = document.getElementById('site-alert-storm').value;
        var data = {
            site_id: parseInt(id),
            policy_id: policyVal ? parseInt(policyVal) : null,
            cpu_threshold: num('cpu'),
            memory_threshold: num('memory'),
            disk_threshold: num('disk'),
            session_threshold: num('sessions', true),
            cooldown_minutes: num('cooldown', true),
            // Tri-state: blank = inherit (null), a number (incl. 0) = explicit.
            storm_sources: stormRaw === '' ? null : parseInt(stormRaw)
        };
        // v48: the Event Profile assignment rides its own column-targeted
        // endpoint (the alert-config PUT preserves it on omit).
        var epSel = document.getElementById('site-event-profile');
        var epBody = { profile_id: (epSel && epSel.value) ? parseInt(epSel.value, 10) : null };
        AC.apiFetch(API_BASE + '/sites/' + id + '/alert-config', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: data
        }).then(function() {
            return AC.apiFetch(API_BASE + '/sites/' + id + '/event-profile', {
                method: 'PUT', body: { profile_id: epBody.profile_id }
            }).catch(function(e) { AC.showError('Event profile assignment failed: ' + e.message); });
        }).then(function() {
            closeSiteAlertModal();
            AC.showSuccess('Site alert config saved');
        }).catch(function(err) {
            AC.showError('Error saving site alert config: ' + err.message);
        });
    }

    // Event delegation
    AC.delegateEvent('click', {
        'show-add-modal': function() { showAddModal(); },
        'edit-site': function(el) { editSite(parseInt(el.dataset.id)); },
        'delete-site': function(el) { deleteSite(parseInt(el.dataset.id)); },
        'site-alert-config': function(el) { showSiteAlertModal(parseInt(el.dataset.id)); },
        'close-site-alert-modal': function() { closeSiteAlertModal(); },
        'reset-site-alert-config': function() { resetSiteAlertConfig(); },
        'close-modal': function() { closeModal(); },
        'logout': function() { AC.doLogout(); }
    });

    // Form submit
    document.getElementById('site-form').addEventListener('submit', saveSite);
    var siteAlertForm = document.getElementById('site-alert-form');
    if (siteAlertForm) siteAlertForm.addEventListener('submit', saveSiteAlertConfig);

    // Init — the SPA calls this when the Sites page is shown (admin-main.js
    // loadPageData). Event/form wiring above runs once at module load; only
    // the data fetch is deferred.
    window.FwmonSites = { init: function () {
        AC.fetchCsrfToken().then(function () { loadSites(); });
    } };
})();
