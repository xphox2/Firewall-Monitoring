// public-dashboard.js — Public dashboard page logic
(function() {
    'use strict';

    var API_BASE = '/api';
    var refreshTimer;
    var displaySettings = {};
    var currentDeviceId = null;
    var interfaceHistory = {};

    function escapeHtml(str) {
        if (!str) return '';
        var s = String(str);
        return s.replace(/[&<>"']/g, function(c) {
            return {'&':'&amp;','<':'&gt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
        });
    }

    document.getElementById('footer-year').textContent = new Date().getFullYear();

    function fetchDisplaySettings() {
        fetch(API_BASE + '/public/display-settings')
            .then(function(response) {
                if (!response.ok) return;
                return response.json();
            })
            .then(function(data) {
                if (data && data.success && data.data) {
                    displaySettings = data.data;
                    applyDisplaySettings();
                }
            })
            ['catch'](function(error) {
                console.error('Error fetching display settings:', error);
            });
    }

    function applyDisplaySettings() {
        var mapping = {
            'public_show_hostname': 'status-banner',
            'public_show_uptime': 'card-uptime',
            'public_show_cpu': 'card-cpu',
            'public_show_memory': 'card-memory',
            'public_show_sessions': 'card-sessions',
            'public_show_interfaces': 'card-interfaces',
            'public_show_bandwidth': 'card-bandwidth',
            'public_show_vpn': 'card-vpn',
            'public_show_connections': 'card-connections'
        };

        for (var key in mapping) {
            var el = document.getElementById(mapping[key]);
            if (el && displaySettings[key] === 'false') {
                el.classList.add('hidden');
            } else if (el) {
                el.classList.remove('hidden');
            }
        }

        var interval = parseInt(displaySettings['public_refresh_interval']) || 30;
        if (refreshTimer) clearInterval(refreshTimer);
        refreshTimer = setInterval(function() { 
            fetchDashboard(); 
            fetchInterfaces();
            if (displaySettings['public_show_bandwidth'] === 'true') fetchBandwidth();
            if (displaySettings['public_show_vpn'] === 'true') fetchVPN();
            if (displaySettings['public_show_connections'] === 'true') fetchConnections();
        }, interval * 1000);
    }

    function fetchDevices() {
        return fetch(API_BASE + '/public/devices')
            .then(function(response) {
                if (!response.ok) return;
                return response.json();
            })
            .then(function(data) {
                if (!data || !data.success || !data.data || data.data.length <= 1) return;

                var select = document.getElementById('device-select');
                select.innerHTML = data.data.map(function(d) {
                    return '<option value="' + d.id + '">' + escapeHtml(d.name) + ' (' + escapeHtml(d.status) + ')</option>';
                }).join('');

                if (!currentDeviceId && data.data.length > 0) {
                    currentDeviceId = data.data[0].id;
                }
                select.value = currentDeviceId;
                document.getElementById('device-selector').style.display = 'block';
            })
            ['catch'](function(e) { console.error('Error fetching devices:', e); });
    }

    document.getElementById('device-select').addEventListener('change', function() {
        currentDeviceId = this.value;
        interfaceHistory = {};
        fetchDashboard();
        fetchInterfaces();
        if (displaySettings['public_show_bandwidth'] === 'true') fetchBandwidth();
        if (displaySettings['public_show_vpn'] === 'true') fetchVPN();
        if (displaySettings['public_show_connections'] === 'true') fetchConnections();
    });

    function fetchDashboard() {
        var url = API_BASE + '/public/dashboard';
        if (currentDeviceId) url += '?device_id=' + currentDeviceId;
        fetch(url)
            .then(function(response) {
                if (!response.ok) throw new Error('Failed to fetch data');
                return response.json();
            })
            .then(function(data) {
                if (!data.success) throw new Error(data.error || 'Failed to fetch data');
                updateDashboard(data.data);
            })
            ['catch'](function(error) {
                console.error('Error:', error);
                document.getElementById('connection-status').textContent = 'Offline';
                document.getElementById('status-banner').className = 'status-banner offline';
            });
    }

    function fetchInterfaces() {
        var url = API_BASE + '/public/interfaces';
        if (currentDeviceId) url += '?device_id=' + currentDeviceId;
        fetch(url)
            .then(function(response) {
                if (!response.ok) return;
                return response.json();
            })
            .then(function(data) {
                if (data && data.success) {
                    updateInterfaces(data.data);
                    if (displaySettings['public_show_bandwidth'] === 'true') {
                        updateBandwidthCharts(data.data);
                    }
                }
            })
            ['catch'](function(error) {
                console.error('Error fetching interfaces:', error);
            });
    }

    function fetchBandwidth() {
        fetch(API_BASE + '/public/interfaces' + (currentDeviceId ? '?device_id=' + currentDeviceId : ''))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data && data.success) updateBandwidthCharts(data.data);
            })
            ['catch'](function(e) { console.error('Bandwidth error:', e); });
    }

    function fetchVPN() {
        fetch(API_BASE + '/public/vpn' + (currentDeviceId ? '?device_id=' + currentDeviceId : ''))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data && data.success) updateVPN(data.data);
            })
            ['catch'](function(e) { console.error('VPN error:', e); });
    }

    function fetchConnections() {
        fetch(API_BASE + '/public/connections')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data && data.success) updateConnections(data.data);
            })
            ['catch'](function(e) { console.error('Connections error:', e); });
    }

    function updateDashboard(d) {
        var nameLabel = document.getElementById('device-name-label');
        nameLabel.textContent = d.device_name ? d.device_name + ' - ' : '';
        document.getElementById('hostname').textContent = d.hostname || 'Firewall';
        document.getElementById('connection-status').textContent = 'Online';
        document.getElementById('status-banner').className = 'status-banner online';
        document.getElementById('uptime').textContent = d.uptime || '--';
        document.getElementById('cpu').textContent = d.cpu ? d.cpu.toFixed(1) : '--';
        document.getElementById('memory').textContent = d.memory ? d.memory.toFixed(1) : '--';
        document.getElementById('sessions').textContent = formatNumber(d.sessions) || '--';

        updateProgressBar('cpu-bar', d.cpu);
        updateProgressBar('memory-bar', d.memory);
    }

    function updateInterfaces(interfaces) {
        var container = document.getElementById('interfaces');
        if (!interfaces || interfaces.length === 0) {
            container.innerHTML = '<div class="loading">No interfaces found</div>';
            return;
        }
        
        var selectedIfaces = displaySettings['public_bandwidth_interfaces'];
        var selectedArray = selectedIfaces ? selectedIfaces.split(',') : [];
        var ifacesToShow = selectedArray.length > 0 
            ? interfaces.filter(function(i) { return selectedArray.indexOf(i.name) !== -1 || selectedArray.indexOf('Interface ' + i.index) !== -1; })
            : interfaces;
        
        container.innerHTML = ifacesToShow.map(function(iface) {
            return '<div class="interface-card">' +
                '<div class="name">' + (escapeHtml(iface.name) || 'Interface ' + iface.index) + '</div>' +
                '<span class="status ' + escapeHtml(iface.status) + '">' + escapeHtml(iface.status).toUpperCase() + '</span>' +
                '<div class="interface-stats"><div>' +
                '<div>&darr; ' + formatBytes(iface.in_bytes) + '</div>' +
                '<div>&uarr; ' + formatBytes(iface.out_bytes) + '</div>' +
                '</div><div style="text-align: right;">' +
                '<div>' + formatSpeed(iface.speed) + '</div>' +
                '<div>' + (iface.in_errors + iface.out_errors) + ' errors</div>' +
                '</div></div></div>';
        }).join('');
    }

    function updateBandwidthCharts(interfaces) {
        var container = document.getElementById('bandwidth-charts');
        if (!interfaces || interfaces.length === 0) {
            container.innerHTML = '<div class="loading">No interface data</div>';
            return;
        }

        var selectedIfaces = displaySettings['public_bandwidth_interfaces'];
        var selectedArray = selectedIfaces ? selectedIfaces.split(',') : [];
        var ifacesToShow = selectedArray.length > 0 
            ? interfaces.filter(function(i) { return selectedArray.indexOf(i.name) !== -1 || selectedArray.indexOf('Interface ' + i.index) !== -1; })
            : interfaces.slice(0, 4);

        container.innerHTML = ifacesToShow.map(function(iface) {
            var rxPercent = Math.min(100, (iface.in_bytes / (iface.speed || 1000000000)) * 100);
            var txPercent = Math.min(100, (iface.out_bytes / (iface.speed || 1000000000)) * 100);
            return '<div class="bandwidth-chart">' +
                '<div class="chart-header">' +
                '<div class="interface-name">' + escapeHtml(iface.name || 'Interface ' + iface.index) + '</div>' +
                '<div class="bandwidth-values">' +
                '<span>&darr; ' + formatBytes(iface.in_bytes) + '/s</span>' +
                '<span>&uarr; ' + formatBytes(iface.out_bytes) + '/s</span>' +
                '</div></div>' +
                '<div class="bandwidth-bar-container">' +
                '<div class="bandwidth-bar-wrapper">' +
                '<label>RX</label>' +
                '<div class="bandwidth-bar">' +
                '<div class="bar-fill rx" style="width: ' + rxPercent + '%"></div>' +
                '<span class="bar-value">' + rxPercent.toFixed(1) + '%</span>' +
                '</div></div>' +
                '<div class="bandwidth-bar-wrapper">' +
                '<label>TX</label>' +
                '<div class="bandwidth-bar">' +
                '<div class="bar-fill tx" style="width: ' + txPercent + '%"></div>' +
                '<span class="bar-value">' + txPercent.toFixed(1) + '%</span>' +
                '</div></div></div></div>';
        }).join('');
    }

    function updateVPN(tunnels) {
        var container = document.getElementById('vpn-tunnels');
        if (!tunnels || tunnels.length === 0) {
            container.innerHTML = '<div class="loading">No VPN tunnels found</div>';
            return;
        }

        var selectedTunnels = displaySettings['public_vpn_tunnels'];
        var selectedArray = selectedTunnels ? selectedTunnels.split(',') : [];
        var tunnelsToShow = selectedArray.length > 0 
            ? tunnels.filter(function(t) { return selectedArray.indexOf(t.tunnel_name) !== -1; })
            : tunnels;

        container.innerHTML = tunnelsToShow.map(function(tunnel) {
            return '<div class="vpn-card">' +
                '<div class="tunnel-name">' + escapeHtml(tunnel.tunnel_name) + '</div>' +
                '<div class="tunnel-info">Type: ' + escapeHtml(tunnel.tunnel_type || 'IPSec') + '</div>' +
                '<div class="tunnel-info">Remote: ' + escapeHtml(tunnel.remote_ip || 'N/A') + '</div>' +
                '<span class="status ' + escapeHtml(tunnel.status) + '">' + escapeHtml(tunnel.status || 'unknown').toUpperCase() + '</span>' +
                '</div>';
        }).join('');
    }

    function updateConnections(connections) {
        var container = document.getElementById('connections-map');
        if (!connections || connections.length === 0) {
            container.innerHTML = '<div class="loading">No connections configured</div>';
            return;
        }

        var devices = {};
        var maxX = 0, maxY = 0;
        connections.forEach(function(c) {
            if (c.source && !devices[c.source]) {
                var x = Math.random() * 60 + 20;
                var y = Math.random() * 60 + 20;
                devices[c.source] = { x: x, y: y, name: c.source };
                maxX = Math.max(maxX, x);
                maxY = Math.max(maxY, y);
            }
            if (c.dest && !devices[c.dest]) {
                var x = Math.random() * 60 + 20;
                var y = Math.random() * 60 + 20;
                devices[c.dest] = { x: x, y: y, name: c.dest };
                maxX = Math.max(maxX, x);
                maxY = Math.max(maxY, y);
            }
        });

        var scale = Math.max(maxX, maxY) > 80 ? 80 / Math.max(maxX, maxY) : 1;
        
        var nodesHtml = Object.keys(devices).map(function(key) {
            var d = devices[key];
            return '<div class="connection-node" style="left: ' + (d.x * scale) + '%; top: ' + (d.y * scale) + '%;">' +
                '<div class="node-name">' + escapeHtml(d.name) + '</div></div>';
        }).join('');

        var linesHtml = connections.map(function(c) {
            var src = devices[c.source];
            var dst = devices[c.dest];
            if (!src || !dst) return '';
            
            var x1 = src.x * scale;
            var y1 = src.y * scale;
            var x2 = dst.x * scale;
            var y2 = dst.y * scale;
            var length = Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2));
            var angle = Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI;
            
            return '<div class="connection-line ' + escapeHtml(c.status || 'unknown') + '" ' +
                'style="left: ' + x1 + '%; top: ' + y1 + '%; width: ' + length + '%; transform: rotate(' + angle + 'deg);"></div>';
        }).join('');

        container.innerHTML = linesHtml + nodesHtml;
    }

    function updateProgressBar(id, value) {
        var bar = document.getElementById(id);
        if (!bar || value === undefined) return;
        bar.style.width = Math.min(value, 100) + '%';
        bar.className = 'fill';
        if (value >= 80) bar.classList.add('high');
        else if (value >= 60) bar.classList.add('medium');
        else bar.classList.add('low');
    }

    function formatNumber(num) {
        if (num === null || num === undefined) return '--';
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function formatBytes(bytes) {
        if (!bytes) return '0 B';
        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
    }

    function formatSpeed(speed) {
        if (!speed) return 'Unknown';
        if (speed >= 1000000000) return (speed / 1000000000).toFixed(0) + ' Gbps';
        if (speed >= 1000000) return (speed / 1000000).toFixed(0) + ' Mbps';
        return (speed / 1000).toFixed(0) + ' Kbps';
    }

    fetchDisplaySettings();
    fetchDevices().then(function() {
        fetchDashboard();
        fetchInterfaces();
        if (displaySettings['public_show_bandwidth'] === 'true') fetchBandwidth();
        if (displaySettings['public_show_vpn'] === 'true') fetchVPN();
        if (displaySettings['public_show_connections'] === 'true') fetchConnections();
    });
    if (!refreshTimer) {
        refreshTimer = setInterval(function() { 
            fetchDashboard(); 
            fetchInterfaces();
            if (displaySettings['public_show_bandwidth'] === 'true') fetchBandwidth();
            if (displaySettings['public_show_vpn'] === 'true') fetchVPN();
            if (displaySettings['public_show_connections'] === 'true') fetchConnections();
        }, 30000);
    }
})();
