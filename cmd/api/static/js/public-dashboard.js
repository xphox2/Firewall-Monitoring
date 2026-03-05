// public-dashboard.js — Public dashboard page logic
(function() {
    'use strict';

    var API_BASE = '/api';
    var refreshTimer;
    var displaySettings = {};
    var allDevices = [];
    var allInterfaces = {};
    var publicInterfaces = {};
    var currentIfaceKey = null;
    var bandwidthChart = null;
    var chartOptions = { view: 'rate', range: '1h' };

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
            .then(function(response) { if (!response.ok) return; return response.json(); })
            .then(function(data) {
                if (data && data.success && data.data) {
                    displaySettings = data.data;
                    try {
                        publicInterfaces = JSON.parse(displaySettings['public_interfaces'] || '{}');
                    } catch(e) { publicInterfaces = {}; }
                    applyDisplaySettings();
                }
            })['catch'](function(e) { console.error('Error fetching display settings:', e); });
    }

    function applyDisplaySettings() {
        var mapping = {
            'public_show_hostname': 'card-devices',
            'public_show_uptime': 'card-devices',
            'public_show_cpu': 'card-devices',
            'public_show_memory': 'card-devices',
            'public_show_sessions': 'card-devices',
            'public_show_interfaces': 'card-interfaces',
            'public_show_bandwidth': 'card-bandwidth',
            'public_show_vpn': 'card-vpn',
            'public_show_connections': 'card-connections'
        };

        document.getElementById('card-devices').classList.remove('hidden');
        
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
            loadAllData(); 
        }, interval * 1000);
    }

    function loadAllData() {
        fetchAllDevices().then(function() {
            if (displaySettings['public_show_interfaces'] !== 'false') fetchAllInterfaces();
            if (displaySettings['public_show_bandwidth'] !== 'false') fetchBandwidth();
            if (displaySettings['public_show_vpn'] !== 'false') fetchAllVPN();
            if (displaySettings['public_show_connections'] !== 'false') fetchConnections();
        });
    }

    function fetchAllDevices() {
        fetch(API_BASE + '/public/devices')
            .then(function(response) { if (!response.ok) return []; return response.json(); })
            .then(function(data) {
                if (!data || !data.success || !data.data) return;
                allDevices = data.data;
                loadAllDeviceData();
            })['catch'](function(e) { console.error('Error fetching devices:', e); });
    }

    function loadAllDeviceData() {
        var promises = allDevices.map(function(device) {
            return fetch(API_BASE + '/public/dashboard?device_id=' + device.id)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    device.statusData = data.success ? data.data : null;
                })['catch'](function() { device.statusData = null; });
        });

        Promise.all(promises).then(function() {
            renderDevicesTable();
        });
    }

    function renderDevicesTable() {
        var tbody = document.getElementById('devices-body');
        if (!allDevices.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading">No devices configured</td></tr>';
            return;
        }

        tbody.innerHTML = allDevices.map(function(device) {
            var d = device.statusData || {};
            var statusClass = d.hostname ? 'online' : 'offline';
            var uptime = d.uptime || '--';
            var cpu = d.cpu || 0;
            var memory = d.memory || 0;
            var sessions = d.sessions != null ? formatNumber(d.sessions) : '--';

            var cpuBar = getProgressBar(cpu);
            var memBar = getProgressBar(memory);

            return '<tr>' +
                '<td><div class="device-name">' + escapeHtml(device.name) + '</div></td>' +
                '<td><span class="device-status ' + statusClass + '">' + statusClass.toUpperCase() + '</span></td>' +
                '<td><div class="metric-value" style="font-size:1rem;">' + uptime + '</div></td>' +
                '<td><div class="metric-value">' + (cpu ? cpu.toFixed(1) : '--') + '%</div><div class="metric-bar"><div class="fill ' + cpuBar + '" style="width:' + Math.min(cpu, 100) + '%"></div></div></td>' +
                '<td><div class="metric-value">' + (memory ? memory.toFixed(1) : '--') + '%</div><div class="metric-bar"><div class="fill ' + memBar + '" style="width:' + Math.min(memory, 100) + '%"></div></div></td>' +
                '<td><div class="metric-value" style="font-size:1rem;">' + sessions + '</div></td>' +
                '</tr>';
        }).join('');
    }

    function getProgressBar(value) {
        if (value >= 80) return 'high';
        if (value >= 60) return 'medium';
        return 'low';
    }

    function fetchAllInterfaces() {
        var promises = allDevices.map(function(device) {
            return fetch(API_BASE + '/public/interfaces?device_id=' + device.id)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data && data.success && data.data) {
                        allInterfaces[device.id] = data.data;
                    }
                })['catch'](function() {});
        });

        Promise.all(promises).then(function() {
            renderPublicInterfaces();
        });
    }

    function renderPublicInterfaces() {
        var container = document.getElementById('interfaces');
        var interfaces = [];

        allDevices.forEach(function(device) {
            var deviceIfaces = allInterfaces[device.id] || [];
            var pubIfaces = publicInterfaces[device.id] || [];
            
            deviceIfaces.forEach(function(iface) {
                if (pubIfaces.length === 0 || pubIfaces.indexOf(iface.name) !== -1) {
                    interfaces.push({
                        deviceId: device.id,
                        deviceName: device.name,
                        name: iface.name,
                        status: iface.status,
                        in_bytes: iface.in_bytes,
                        out_bytes: iface.out_bytes,
                        speed: iface.speed
                    });
                }
            });
        });

        if (!interfaces.length) {
            container.innerHTML = '<div class="loading">No public interfaces configured</div>';
            return;
        }

        container.innerHTML = interfaces.map(function(iface) {
            return '<div class="interface-card">' +
                '<div class="header">' +
                '<div class="name">' + escapeHtml(iface.name) + '</div>' +
                '<span class="status ' + escapeHtml(iface.status) + '">' + escapeHtml(iface.status).toUpperCase() + '</span>' +
                '</div>' +
                '<div class="device">' + escapeHtml(iface.deviceName) + '</div>' +
                '<div class="stats">' +
                '<div>&darr; ' + formatBytes(iface.in_bytes) + '</div>' +
                '<div>&uarr; ' + formatBytes(iface.out_bytes) + '</div>' +
                '</div></div>';
        }).join('');
    }

    function fetchBandwidth() {
        var pubIfaces = [];
        
        allDevices.forEach(function(device) {
            var ifaces = publicInterfaces[device.id] || [];
            if (ifaces.length > 0) {
                ifaces.forEach(function(name) {
                    pubIfaces.push({ deviceId: device.id, deviceName: device.name, name: name });
                });
            }
        });

        if (pubIfaces.length === 0) {
            document.getElementById('bandwidth-charts').innerHTML = '<div class="loading">No public interfaces configured for bandwidth charts</div>';
            return;
        }

        var controls = document.getElementById('bandwidth-controls');
        controls.style.display = 'flex';

        var select = document.getElementById('bandwidth-interface-select');
        select.innerHTML = pubIfaces.map(function(i) {
            return '<option value="' + i.deviceId + '|' + escapeHtml(i.name) + '">' + escapeHtml(i.deviceName) + ' - ' + escapeHtml(i.name) + '</option>';
        }).join('');

                select.onchange = function() {
                    loadBandwidthChart();
                };

                document.getElementById('bandwidth-view-select').onchange = function() {
                    chartOptions.view = this.value;
                    loadBandwidthChart();
                };

                document.getElementById('bandwidth-range-select').onchange = function() {
                    chartOptions.range = this.value;
                    loadBandwidthChart();
                };

                currentIfaceKey = pubIfaces[0].deviceId + '|' + pubIfaces[0].name;
                loadBandwidthChart();
    }

    function loadBandwidthChart() {
        if (!currentIfaceKey) return;
        
        var parts = currentIfaceKey.split('|');
        var deviceId = parts[0];
        var ifaceName = parts[1];

        fetch(API_BASE + '/public/interfaces?device_id=' + deviceId)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data || !data.success) return;
                var found = data.data.find(function(i) { return i.name === ifaceName; });
                if (found) {
                    var url = API_BASE + '/public/interfaces/chart?device_id=' + deviceId + '&index=' + found.index + '&view=' + chartOptions.view + '&range=' + chartOptions.range;
                    fetch(url)
                        .then(function(r) { return r.json(); })
                        .then(function(chartData) {
                            if (chartData && chartData.success) {
                                renderBandwidthChart(chartData.data, ifaceName);
                            }
                        })['catch'](function() {});
                }
            })['catch'](function() {});
    }

    function renderBandwidthChart(data, ifaceName) {
        var container = document.getElementById('bandwidth-charts');
        
        var latestRx = data.rx_rate ? data.rx_rate[data.rx_rate.length - 1] : 0;
        var latestTx = data.tx_rate ? data.tx_rate[data.tx_rate.length - 1] : 0;
        var totalRx = data.rx_total ? data.rx_total[data.rx_total.length - 1] : 0;
        var totalTx = data.tx_total ? data.tx_total[data.tx_total.length - 1] : 0;

        var statsHtml = '';
        if (chartOptions.view === 'rate') {
            statsHtml = '<div class="stat rx"><span>&darr; ' + latestRx.toFixed(2) + ' Mbps</span></div>' +
                        '<div class="stat tx"><span>&uarr; ' + latestTx.toFixed(2) + ' Mbps</span></div>';
        } else if (chartOptions.view === 'total') {
            statsHtml = '<div class="stat rx"><span>&darr; ' + formatBytes(totalRx) + '</span></div>' +
                        '<div class="stat tx"><span>&uarr; ' + formatBytes(totalTx) + '</span></div>';
        } else {
            statsHtml = '<div class="stat rx"><span>&darr; ' + latestRx.toFixed(2) + ' Mbps</span> (' + formatBytes(totalRx) + ')</div>' +
                        '<div class="stat tx"><span>&uarr; ' + latestTx.toFixed(2) + ' Mbps</span> (' + formatBytes(totalTx) + ')</div>';
        }

        container.innerHTML = '<div class="chart-card">' +
            '<h3>' + escapeHtml(ifaceName) + '</h3>' +
            '<div class="current-stats">' + statsHtml + '</div>' +
            '<div class="chart-container"><canvas id="bandwidth-chart-canvas"></canvas></div>' +
            '</div>';

        var ctx = document.getElementById('bandwidth-chart-canvas').getContext('2d');
        
        if (bandwidthChart) {
            bandwidthChart.destroy();
        }

        var datasets = [];
        
        if (chartOptions.view === 'rate' || chartOptions.view === 'mix') {
            datasets.push({
                label: 'RX (Mbps)',
                data: data.rx_rate,
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
            datasets.push({
                label: 'TX (Mbps)',
                data: data.tx_rate,
                borderColor: '#ff9500',
                backgroundColor: 'rgba(255, 149, 0, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
        }
        
        if (chartOptions.view === 'total') {
            datasets.push({
                label: 'RX (Bytes)',
                data: data.rx_total,
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
            datasets.push({
                label: 'TX (Bytes)',
                data: data.tx_total,
                borderColor: '#ff9500',
                backgroundColor: 'rgba(255, 149, 0, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
        }

        bandwidthChart = new Chart(ctx, {
            type: 'line',
            data: { labels: data.labels, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { intersect: false, mode: 'index' },
                plugins: { legend: { display: chartOptions.view === 'mix', labels: { color: '#fff' } } },
                scales: {
                    x: { display: true, grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: 'rgba(255,255,255,0.6)', maxTicksLimit: 12 } },
                    y: { 
                        display: chartOptions.view !== 'total',
                        grid: { color: 'rgba(255,255,255,0.1)' }, 
                        ticks: { color: 'rgba(255,255,255,0.6)', callback: function(v) { return v + ' Mbps'; } },
                        title: { display: chartOptions.view !== 'total', text: 'Mbps', color: 'rgba(255,255,255,0.6)' }
                    },
                    y1: {
                        display: chartOptions.view === 'total',
                        position: 'right',
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: 'rgba(255,255,255,0.6)', callback: function(v) { return formatBytes(v); } },
                        title: { display: chartOptions.view === 'total', text: 'Bytes', color: 'rgba(255,255,255,0.6)' }
                    }
                }
            }
        });
    }

    function fetchAllVPN() {
        var promises = allDevices.map(function(device) {
            return fetch(API_BASE + '/public/vpn?device_id=' + device.id)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data && data.success && data.data) {
                        data.data.forEach(function(t) { t._deviceName = device.name; });
                        return data.data;
                    }
                    return [];
                })['catch'](function() { return []; });
        });

        Promise.all(promises).then(function(results) {
            var tunnels = results.reduce(function(acc, arr) { return acc.concat(arr); }, []);
            renderVPN(tunnels);
        });
    }

    function renderVPN(tunnels) {
        var container = document.getElementById('vpn-tunnels');
        if (!tunnels || tunnels.length === 0) {
            container.innerHTML = '<div class="loading">No VPN tunnels found</div>';
            return;
        }

        container.innerHTML = tunnels.map(function(tunnel) {
            return '<div class="vpn-card">' +
                '<div class="tunnel-name">' + escapeHtml(tunnel.tunnel_name) + '</div>' +
                '<div class="tunnel-info">' + escapeHtml(tunnel._deviceName) + '</div>' +
                '<div class="tunnel-info">Type: ' + escapeHtml(tunnel.tunnel_type || 'IPSec') + '</div>' +
                '<div class="tunnel-info">Remote: ' + escapeHtml(tunnel.remote_ip || 'N/A') + '</div>' +
                '<span class="status ' + escapeHtml(tunnel.status) + '">' + escapeHtml(tunnel.status || 'unknown').toUpperCase() + '</span>' +
                '</div>';
        }).join('');
    }

    function fetchConnections() {
        fetch(API_BASE + '/public/connections')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data && data.success) renderConnections(data.data);
            })['catch'](function(e) { console.error('Connections error:', e); });
    }

    function renderConnections(connections) {
        var container = document.getElementById('connections-map');
        if (!connections || connections.length === 0) {
            container.innerHTML = '<div class="loading">No connections configured</div>';
            return;
        }

        var devices = {};
        connections.forEach(function(c) {
            if (c.source && !devices[c.source]) {
                devices[c.source] = { x: Math.random() * 60 + 20, y: Math.random() * 60 + 20, name: c.source };
            }
            if (c.dest && !devices[c.dest]) {
                devices[c.dest] = { x: Math.random() * 60 + 20, y: Math.random() * 60 + 20, name: c.dest };
            }
        });

        var nodesHtml = Object.keys(devices).map(function(key) {
            var d = devices[key];
            return '<div class="connection-node" style="left: ' + d.x + '%; top: ' + d.y + '%;">' +
                '<div class="node-name">' + escapeHtml(d.name) + '</div></div>';
        }).join('');

        var linesHtml = connections.map(function(c) {
            var src = devices[c.source];
            var dst = devices[c.dest];
            if (!src || !dst) return '';
            var length = Math.sqrt(Math.pow(dst.x - src.x, 2) + Math.pow(dst.y - src.y, 2));
            var angle = Math.atan2(dst.y - src.y, dst.x - src.x) * 180 / Math.PI;
            return '<div class="connection-line ' + escapeHtml(c.status || 'unknown') + '" ' +
                'style="left: ' + src.x + '%; top: ' + src.y + '%; width: ' + length + '%; transform: rotate(' + angle + 'deg);"></div>';
        }).join('');

        container.innerHTML = linesHtml + nodesHtml;
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

    fetchDisplaySettings();
    loadAllData();
})();
