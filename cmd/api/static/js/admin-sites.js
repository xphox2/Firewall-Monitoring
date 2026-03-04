// admin-sites.js — Site management page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var sites = [];
    var editingId = null;

    function loadSites() {
        AC.apiFetch(API_BASE + '/sites').then(function(result) {
            sites = result.data || [];
            renderSites();
        })['catch'](function(err) {
            console.error('[Sites] Error loading sites:', err);
            AC.showError('Failed to load sites: ' + err.message);
        });
    }

    function renderSites() {
        var container = document.getElementById('sites-container');
        if (sites.length === 0) {
            container.innerHTML = '<div class="empty">No sites configured. Click "Add Site" to create one.</div>';
            return;
        }

        var html = '';
        for (var i = 0; i < sites.length; i++) {
            var site = sites[i];
            html += '<div class="site-card">' +
                '<h3>' + AC.escapeHtml(site.name) + '</h3>' +
                '<div class="site-info">' +
                '<div><span>Region:</span> ' + AC.escapeHtml(site.region || 'N/A') + '</div>' +
                '<div><span>Country:</span> ' + AC.escapeHtml(site.country || 'N/A') + '</div>' +
                '<div><span>Timezone:</span> ' + AC.escapeHtml(site.timezone || 'N/A') + '</div>' +
                '<div><span>Address:</span> ' + AC.escapeHtml(site.address || 'N/A') + '</div>' +
                '</div>' +
                '<div style="margin-top:15px;">' +
                '<button class="btn sm" data-action="edit-site" data-id="' + site.id + '">Edit</button> ' +
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
        document.getElementById('site-modal').classList.add('active');
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
        document.getElementById('site-modal').classList.add('active');
    }

    function closeModal() {
        document.getElementById('site-modal').classList.remove('active');
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
        })['catch'](function(err) {
            console.error('[Sites] Save error:', err);
            AC.showError('Error saving site: ' + err.message);
        });
    }

    function deleteSite(id) {
        if (!confirm('Are you sure you want to delete this site?')) return;

        AC.apiFetch(API_BASE + '/sites/' + id, { method: 'DELETE' }).then(function() {
            AC.showSuccess('Site deleted');
            loadSites();
        })['catch'](function(err) {
            AC.showError('Error deleting site: ' + err.message);
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
