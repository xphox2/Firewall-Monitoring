// admin-network.js — Network diagram page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var currentDevices = [];
    var currentConnections = [];
    var currentSites = [];
    var selectedNode = null;

    // Connection type -> visual style mapping
    function getConnStyle(type) {
        var styles = {
            ipsec:    { color: '#58a6ff', dash: null, width: '2' },
            ssl:      { color: '#d29922', dash: null, width: '2' },
            vxlan:    { color: '#8957e5', dash: '8,4', width: '2' },
            l2vlan:   { color: '#39d4e0', dash: null, width: '2' },
            l3ipvlan: { color: '#da7de8', dash: '12,4', width: '2' },
            gre:      { color: '#b392f0', dash: null, width: '2' },
            wan:      { color: '#f0883e', dash: null, width: '2' },
            lag:      { color: '#d29922', dash: null, width: '4' },
            tunnel:   { color: '#8b949e', dash: null, width: '2' }
        };
        return styles[type] || styles.tunnel;
    }

    function loadData() {
        Promise.all([
            AC.apiFetch(API_BASE + '/devices'),
            AC.apiFetch(API_BASE + '/connections'),
            AC.apiFetch(API_BASE + '/sites')
        ]).then(function(results) {
            currentDevices = (results[0] && results[0].data) || [];
            currentConnections = (results[1] && results[1].data) || [];
            currentSites = (results[2] && results[2].data) || [];
            renderNetworkDiagram();
            renderConnectionsTable();
        })['catch'](function(err) {
            AC.showError('Failed to load data: ' + err.message);
        });
    }

    function renderNetworkDiagram() {
        var svg = document.getElementById('network-svg');
        svg.innerHTML = '';

        if (currentDevices.length === 0) {
            svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#8b949e">No devices to display</text>';
            return;
        }

        var container = document.getElementById('network-container');
        var width = container.clientWidth || 800;
        var height = 500;

        var siteGroups = {};
        var i, d;
        for (i = 0; i < currentDevices.length; i++) {
            d = currentDevices[i];
            var siteId = d.site_id || 0;
            if (!siteGroups[siteId]) siteGroups[siteId] = [];
            siteGroups[siteId].push(d);
        }

        var sitePositions = {};
        var siteIds = Object.keys(siteGroups);
        var siteCount = siteIds.length;

        for (i = 0; i < siteIds.length; i++) {
            var angle = (2 * Math.PI * i) / siteCount - Math.PI / 2;
            var radius = Math.min(width, height) / 3;
            var centerX = width / 2 + radius * Math.cos(angle);
            var centerY = height / 2 + radius * Math.sin(angle);
            sitePositions[siteIds[i]] = { x: centerX, y: centerY };
        }

        var defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');

        var markerDefs = [
            { id: 'arrow-up', fill: '#3fb150' },
            { id: 'arrow-down', fill: '#f85149' },
            { id: 'arrow-unknown', fill: '#8b949e' }
        ];

        for (i = 0; i < markerDefs.length; i++) {
            var marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
            marker.setAttribute('id', markerDefs[i].id);
            marker.setAttribute('markerWidth', '10');
            marker.setAttribute('markerHeight', '10');
            marker.setAttribute('refX', '9');
            marker.setAttribute('refY', '3');
            marker.setAttribute('orient', 'auto');
            marker.setAttribute('markerUnits', 'strokeWidth');
            marker.innerHTML = '<path d="M0,0 L0,6 L9,3 z" fill="' + markerDefs[i].fill + '" />';
            defs.appendChild(marker);
        }

        svg.appendChild(defs);

        // Draw connection lines
        for (i = 0; i < currentConnections.length; i++) {
            var conn = currentConnections[i];
            var srcIdx = -1;
            var dstIdx = -1;
            for (var j = 0; j < currentDevices.length; j++) {
                if (currentDevices[j].id === conn.source_device_id) srcIdx = j;
                if (currentDevices[j].id === conn.dest_device_id) dstIdx = j;
            }

            if (srcIdx >= 0 && dstIdx >= 0) {
                var srcSiteId = currentDevices[srcIdx].site_id || 0;
                var dstSiteId = currentDevices[dstIdx].site_id || 0;

                var srcPos = sitePositions[srcSiteId] || { x: width / 2, y: height / 2 };
                var dstPos = sitePositions[dstSiteId] || { x: width / 2, y: height / 2 };

                var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', srcPos.x);
                line.setAttribute('y1', srcPos.y);
                line.setAttribute('x2', dstPos.x);
                line.setAttribute('y2', dstPos.y);

                var connStyle = getConnStyle(conn.connection_type);
                var isDown = conn.status === 'down';
                var baseColor = connStyle.color || '#8b949e';
                line.setAttribute('stroke', isDown ? '#484f58' : baseColor);
                line.setAttribute('opacity', isDown ? '0.5' : '1');
                if (connStyle.dash) line.setAttribute('stroke-dasharray', connStyle.dash);
                line.setAttribute('stroke-width', connStyle.width || '2');
                line.setAttribute('marker-end', 'url(#arrow-' + conn.status + ')');
                line.style.cursor = 'pointer';
                line.addEventListener('click', (function(c) {
                    return function() { showConnectionDetails(c); };
                })(conn));
                svg.appendChild(line);
            }
        }

        // Draw site groups with devices
        var siteIdKeys = Object.keys(siteGroups);
        for (i = 0; i < siteIdKeys.length; i++) {
            var currentSiteId = siteIdKeys[i];
            var devices = siteGroups[currentSiteId];
            var pos = sitePositions[currentSiteId] || { x: width / 2, y: height / 2 };
            var site = null;
            for (var s = 0; s < currentSites.length; s++) {
                if (currentSites[s].id === parseInt(currentSiteId)) {
                    site = currentSites[s];
                    break;
                }
            }

            var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('transform', 'translate(' + (pos.x - 70) + ', ' + (pos.y - 40) + ')');

            var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('width', '140');
            rect.setAttribute('height', String(30 + devices.length * 35));
            rect.setAttribute('rx', '8');
            rect.setAttribute('fill', '#161b22');
            rect.setAttribute('stroke', '#30363d');
            rect.setAttribute('stroke-width', '2');
            rect.style.cursor = 'pointer';
            rect.addEventListener('click', (function(st) {
                return function() { if (st) showSiteDetails(st); };
            })(site));
            g.appendChild(rect);

            var title = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            title.setAttribute('x', '70');
            title.setAttribute('y', '20');
            title.setAttribute('text-anchor', 'middle');
            title.setAttribute('fill', '#fff');
            title.setAttribute('font-weight', '600');
            title.textContent = site ? site.name : 'Unassigned';
            g.appendChild(title);

            for (var idx = 0; idx < devices.length; idx++) {
                var device = devices[idx];
                var fwY = 35 + idx * 35;

                var fwRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                fwRect.setAttribute('x', '10');
                fwRect.setAttribute('y', fwY);
                fwRect.setAttribute('width', '120');
                fwRect.setAttribute('height', '28');
                fwRect.setAttribute('rx', '4');
                fwRect.setAttribute('fill', '#21262d');
                fwRect.setAttribute('stroke',
                    device.status === 'online' ? '#3fb150' :
                    device.status === 'offline' ? '#f85149' : '#30363d');
                fwRect.setAttribute('stroke-width', '1');
                fwRect.style.cursor = 'pointer';
                fwRect.addEventListener('click', (function(dev) {
                    return function(e) { e.stopPropagation(); showDeviceDetails(dev); };
                })(device));
                g.appendChild(fwRect);

                var fwName = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                fwName.setAttribute('x', '15');
                fwName.setAttribute('y', fwY + 18);
                fwName.setAttribute('fill', '#fff');
                fwName.setAttribute('font-size', '12');
                fwName.textContent = device.name.substring(0, 12);
                g.appendChild(fwName);
            }

            svg.appendChild(g);
        }
    }

    function matchMethodBadge(method, autoDetected) {
        if (!autoDetected) return '<span style="color:#8b949e;font-size:0.75rem;">Manual</span>';
        var badges = {
            'ip_match': '<span class="badge" style="background:#484f58;font-size:0.65rem;padding:1px 5px;">IP Match</span>',
            'interface_ip': '<span class="badge" style="background:#1f6feb;font-size:0.65rem;padding:1px 5px;">WAN IP</span>',
            'bidirectional': '<span class="badge" style="background:#238636;font-size:0.65rem;padding:1px 5px;">Bidirectional</span>',
            'vxlan_name': '<span class="badge" style="background:#8957e5;font-size:0.65rem;padding:1px 5px;">VXLAN</span>',
            'tunnel_name': '<span class="badge" style="background:#d29922;font-size:0.65rem;padding:1px 5px;">Tunnel Name</span>',
            'tunnel_indirect': '<span class="badge" style="background:#f0883e;font-size:0.65rem;padding:1px 5px;">Indirect</span>',
            'manual': '<span style="color:#8b949e;font-size:0.75rem;">Manual</span>'
        };
        return badges[method] || badges['ip_match'];
    }

    function renderConnectionsTable() {
        var tbody = document.querySelector('#connections-table tbody');
        if (currentConnections.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No connections configured</td></tr>';
            return;
        }

        var html = '';
        for (var i = 0; i < currentConnections.length; i++) {
            var c = currentConnections[i];
            html += '<tr>' +
                '<td>' + AC.escapeHtml(c.name) + '</td>' +
                '<td>' + (AC.escapeHtml(c.source_device && c.source_device.name) || 'DEV-' + c.source_device_id) + '</td>' +
                '<td>' + (AC.escapeHtml(c.dest_device && c.dest_device.name) || 'DEV-' + c.dest_device_id) + '</td>' +
                '<td><span class="type-badge ' + AC.escapeHtml(c.connection_type) + '">' + AC.escapeHtml(c.connection_type || 'ipsec').toUpperCase() + '</span></td>' +
                '<td><span class="badge ' + AC.escapeHtml(c.status) + '">' + AC.escapeHtml(c.status || 'unknown').toUpperCase() + '</span></td>' +
                '<td>' + matchMethodBadge(c.match_method, c.auto_detected) + '</td>' +
                '<td>' +
                '<button class="btn sm secondary" data-action="edit-connection" data-id="' + c.id + '">Edit</button> ' +
                '<button class="btn sm danger" data-action="delete-connection" data-id="' + c.id + '">Delete</button>' +
                '</td>' +
                '</tr>';
        }
        tbody.innerHTML = html;
    }

    function showDeviceDetails(device) {
        selectedNode = device;
        document.getElementById('details-title').textContent = 'Device Details';
        document.getElementById('details-content').innerHTML =
            '<div class="connection-info">' +
            '<h4>' + AC.escapeHtml(device.name) + '</h4>' +
            '<p><strong>IP:</strong> ' + AC.escapeHtml(device.ip_address) + '</p>' +
            '<p><strong>Status:</strong> <span class="badge ' + device.status + '">' + (device.status || 'unknown') + '</span></p>' +
            '<p><strong>Location:</strong> ' + (AC.escapeHtml(device.location) || '-') + '</p>' +
            '<p><strong>Site:</strong> ' + ((device.site && device.site.name) || 'Unassigned') + '</p>' +
            '<p><strong>Last Polled:</strong> ' + (device.last_polled ? new Date(device.last_polled).toLocaleString() : 'Never') + '</p>' +
            '</div>' +
            '<button class="btn sm secondary" data-action="go-to-devices">Go to Devices</button>';
        document.getElementById('details-panel').classList.add('open');
    }

    function showConnectionDetails(conn) {
        document.getElementById('details-title').textContent = 'Connection Details';
        document.getElementById('details-content').innerHTML =
            '<div class="connection-info">' +
            '<h4>' + AC.escapeHtml(conn.name) + '</h4>' +
            '<p><strong>Type:</strong> <span class="type-badge ' + conn.connection_type + '">' + AC.escapeHtml(conn.connection_type || 'ipsec').toUpperCase() + '</span></p>' +
            '<p><strong>Status:</strong> <span class="badge ' + conn.status + '">' + AC.escapeHtml(conn.status || 'unknown').toUpperCase() + '</span></p>' +
            '<p><strong>Source:</strong> ' + (AC.escapeHtml(conn.source_device && conn.source_device.name) || 'DEV-' + conn.source_device_id) + '</p>' +
            '<p><strong>Destination:</strong> ' + (AC.escapeHtml(conn.dest_device && conn.dest_device.name) || 'DEV-' + conn.dest_device_id) + '</p>' +
            '<p><strong>Discovery:</strong> ' + matchMethodBadge(conn.match_method, conn.auto_detected) + '</p>' +
            (conn.tunnel_names ? '<p><strong>Tunnels:</strong> ' + AC.escapeHtml(conn.tunnel_names) + '</p>' : '') +
            '<p><strong>Latency:</strong> ' + (conn.latency ? conn.latency + 'ms' : '-') + '</p>' +
            '<p><strong>Last Check:</strong> ' + (conn.last_check ? new Date(conn.last_check).toLocaleString() : 'Never') + '</p>' +
            (conn.notes ? '<p><strong>Notes:</strong> ' + AC.escapeHtml(conn.notes) + '</p>' : '') +
            '</div>' +
            '<a href="/admin/connections/' + conn.id + '" class="btn sm" style="margin-bottom:8px;display:inline-block;text-decoration:none;">View Full Details &rarr;</a> ' +
            '<button class="btn sm danger" data-action="delete-connection" data-id="' + conn.id + '">Delete Connection</button>';
        document.getElementById('details-panel').classList.add('open');
    }

    function showSiteDetails(site) {
        var siteDevices = [];
        for (var i = 0; i < currentDevices.length; i++) {
            if (currentDevices[i].site_id === site.id) siteDevices.push(currentDevices[i]);
        }
        document.getElementById('details-title').textContent = 'Site Details';
        document.getElementById('details-content').innerHTML =
            '<div class="connection-info">' +
            '<h4>' + AC.escapeHtml(site.name) + '</h4>' +
            '<p><strong>Region:</strong> ' + (AC.escapeHtml(site.region) || '-') + '</p>' +
            '<p><strong>Country:</strong> ' + (AC.escapeHtml(site.country) || '-') + '</p>' +
            '<p><strong>Timezone:</strong> ' + (AC.escapeHtml(site.timezone) || '-') + '</p>' +
            '<p><strong>Devices:</strong> ' + siteDevices.length + '</p>' +
            '<p><strong>Address:</strong> ' + (AC.escapeHtml(site.address) || '-') + '</p>' +
            '</div>' +
            '<button class="btn sm secondary" data-action="go-to-sites">Go to Sites</button>';
        document.getElementById('details-panel').classList.add('open');
    }

    function closeDetailsPanel() {
        document.getElementById('details-panel').classList.remove('open');
        selectedNode = null;
    }

    function populateDeviceSelects() {
        var sourceSel = document.getElementById('connection-source');
        var destSel = document.getElementById('connection-dest');
        var options = '';
        for (var i = 0; i < currentDevices.length; i++) {
            var d = currentDevices[i];
            options += '<option value="' + d.id + '">' + AC.escapeHtml(d.name) + ' (' + AC.escapeHtml(d.ip_address) + ')</option>';
        }
        sourceSel.innerHTML = options;
        destSel.innerHTML = options;
    }

    function showAddConnectionModal() {
        if (currentDevices.length < 2) {
            alert('You need at least 2 devices to create a connection');
            return;
        }
        document.getElementById('connection-modal').classList.add('active');
        document.getElementById('connection-form').reset();
        document.getElementById('connection-id').value = '';
        populateDeviceSelects();
    }

    function editConnection(id) {
        var conn = null;
        for (var i = 0; i < currentConnections.length; i++) {
            if (currentConnections[i].id === id) {
                conn = currentConnections[i];
                break;
            }
        }
        if (!conn) return;

        document.getElementById('connection-modal').classList.add('active');
        document.getElementById('connection-id').value = conn.id;
        document.getElementById('connection-name').value = conn.name;
        document.getElementById('connection-type').value = conn.connection_type || 'ipsec';
        document.getElementById('connection-notes').value = conn.notes || '';
        populateDeviceSelects();
        document.getElementById('connection-source').value = conn.source_device_id;
        document.getElementById('connection-dest').value = conn.dest_device_id;
    }

    function closeConnectionModal() {
        document.getElementById('connection-modal').classList.remove('active');
    }

    function saveConnection(e) {
        e.preventDefault();
        var id = document.getElementById('connection-id').value;
        var data = {
            name: document.getElementById('connection-name').value,
            source_device_id: parseInt(document.getElementById('connection-source').value),
            dest_device_id: parseInt(document.getElementById('connection-dest').value),
            connection_type: document.getElementById('connection-type').value,
            notes: document.getElementById('connection-notes').value
        };

        if (data.source_device_id === data.dest_device_id) {
            alert('Source and destination cannot be the same');
            return;
        }

        var method = id ? 'PUT' : 'POST';
        var url = id ? API_BASE + '/connections/' + id : API_BASE + '/connections';
        AC.apiFetch(url, { method: method, body: data }).then(function() {
            closeConnectionModal();
            loadData();
            AC.showSuccess(id ? 'Connection updated' : 'Connection created');
        })['catch'](function(err) {
            AC.showError('Error saving connection: ' + err.message);
        });
    }

    function deleteConnection(id) {
        if (!confirm('Delete this connection?')) return;
        AC.apiFetch(API_BASE + '/connections/' + id, { method: 'DELETE' }).then(function() {
            loadData();
            closeDetailsPanel();
            AC.showSuccess('Connection deleted');
        })['catch'](function(err) {
            AC.showError('Error deleting connection: ' + err.message);
        });
    }

    // Event delegation
    AC.delegateEvent('click', {
        'logout': function() { AC.doLogout(); },
        'show-add-connection': function() { showAddConnectionModal(); },
        'close-connection-modal': function() { closeConnectionModal(); },
        'close-details-panel': function() { closeDetailsPanel(); },
        'edit-connection': function(el) { editConnection(parseInt(el.dataset.id)); },
        'delete-connection': function(el) { deleteConnection(parseInt(el.dataset.id)); },
        'go-to-devices': function() { window.location.href = '/admin/devices'; },
        'go-to-sites': function() { window.location.href = '/admin/sites'; }
    });

    // Form submit
    document.getElementById('connection-form').addEventListener('submit', saveConnection);

    // Window resize
    window.addEventListener('resize', function() {
        renderNetworkDiagram();
    });

    // Init
    AC.fetchCsrfToken().then(function() {
        loadData();
    });
})();
