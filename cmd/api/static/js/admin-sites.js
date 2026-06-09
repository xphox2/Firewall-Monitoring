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
            
            var desc = site.description ? AC.escapeHtml(site.description) : '<span style="color:#475569;font-style:italic">No description provided</span>';
            
            html += '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:245px;padding:20px;">' +
                '<div>' +
                    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">' +
                        '<h3 style="font-size:1.05rem;font-weight:600;color:#f8fafc;margin:0;font-family:\'Outfit\',sans-serif;">' + AC.escapeHtml(site.name) + '</h3>' +
                        (site.country ? '<span class="badge info">' + AC.escapeHtml(site.country).toUpperCase() + '</span>' : '') +
                    '</div>' +
                    '<div style="font-size:0.8rem;color:#94a3b8;margin-bottom:14px;min-height:36px;line-height:1.4;">' + desc + '</div>' +
                    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);border-radius:8px;padding:10px;">' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;margin-bottom:2px;">Region</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:#e2e8f0;">' + AC.escapeHtml(site.region || 'N/A') + '</span>' +
                        '</div>' +
                        '<div style="display:flex;flex-direction:column;">' +
                            '<span style="font-size:0.6rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;margin-bottom:2px;">Timezone</span>' +
                            '<span style="font-size:0.8rem;font-weight:600;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + AC.escapeHtml(site.timezone || 'N/A') + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div style="font-size:0.75rem;color:#8b949e;margin-bottom:8px;">' +
                        '<span style="color:#64748b;font-weight:500;">Address:</span> ' + AC.escapeHtml(site.address || 'N/A') +
                    '</div>' +
                '</div>' +
                '<div style="display:flex;justify-content:flex-end;gap:6px;border-top:1px solid rgba(255,255,255,0.05);padding-top:12px;">' +
                    '<button class="btn sm secondary" data-action="edit-site" data-id="' + site.id + '">Edit</button> ' +
                    '<button class="btn sm danger" data-action="delete-site" data-id="' + site.id + '">Delete</button>' +
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

    // Event delegation
    AC.delegateEvent('click', {
        'show-add-modal': function() { showAddModal(); },
        'edit-site': function(el) { editSite(parseInt(el.dataset.id)); },
        'delete-site': function(el) { deleteSite(parseInt(el.dataset.id)); },
        'close-modal': function() { closeModal(); },
        'logout': function() { AC.doLogout(); }
    });

    // Form submit
    document.getElementById('site-form').addEventListener('submit', saveSite);

    // Init
    AC.fetchCsrfToken().then(function() {
        loadSites();
    });
})();
