// public-dashboard.js — Public dashboard page logic
(function() {
    'use strict';

    var API_BASE = '/api';
    var refreshTimer;
    var displaySettings = {};
    var currentDeviceId = null;

    function escapeHtml(str) {
        if (!str) return '';
        var s = String(str);
        return s.replace(/[&<>"']/g, function(c) {
            return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
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
            'public_show_interfaces': 'card-interfaces'
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
        refreshTimer = setInterval(function() { fetchDashboard(); fetchInterfaces(); }, interval * 1000);
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

    // Bind onchange via JS instead of inline
    document.getElementById('device-select').addEventListener('change', function() {
        currentDeviceId = this.value;
        fetchDashboard();
        fetchInterfaces();
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
                if (data && data.success) updateInterfaces(data.data);
            })
            ['catch'](function(error) {
                console.error('Error fetching interfaces:', error);
            });
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
        container.innerHTML = interfaces.map(function(iface) {
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
    });
    if (!refreshTimer) {
        refreshTimer = setInterval(function() { fetchDashboard(); fetchInterfaces(); }, 30000);
    }
})();
