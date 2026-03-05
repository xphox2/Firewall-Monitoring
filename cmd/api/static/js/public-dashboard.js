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
    var bandwidthCharts = {}; // Store chart instances per interface index
    var chartOptions = { view: 'rate', range: '1h' };

    function escapeHtml(str) {
        if (!str) return '';
        var s = String(str);
        return s.replace(/[&<>"']/g, function(c) {
            return {'&':'&amp;','<':'&gt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
        });
    }

    document.getElementById('footer-year').textContent = new Date().getFullYear();

    fetchDisplaySettings().then(function() {
        loadAllData();
    });

    function fetchDisplaySettings() {
        return fetch(API_BASE + '/public/display-settings')
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

        applyBandwidthLayout();
        setupAdminControls();
    }

    function applyBandwidthLayout() {
        var layout = displaySettings['public_bandwidth_layout'] || 'grid';
        var height = parseInt(displaySettings['public_bandwidth_height']) || 400;
        
        var grid = document.getElementById('bandwidth-charts');
        if (grid) {
            grid.classList.remove('layout-grid', 'layout-full');
            grid.classList.add('layout-' + layout);
        }

        var containers = document.querySelectorAll('.chart-container');
        containers.forEach(function(c) {
            c.style.height = height + 'px';
        });
    }

    function setupAdminControls() {
        var isAdmin = displaySettings['is_admin'] === true || displaySettings['is_admin'] === 'true';
        var adminControls = document.getElementById('admin-bandwidth-controls');
        
        if (!isAdmin || !adminControls) return;

        adminControls.classList.remove('hidden');

        var layoutSelect = document.getElementById('admin-layout-select');
        var heightSelect = document.getElementById('admin-height-select');
        var saveBtn = document.getElementById('save-layout-btn');
        var saveStatus = document.getElementById('layout-save-status');

        if (layoutSelect) {
            layoutSelect.value = displaySettings['public_bandwidth_layout'] || 'grid';
        }
        if (heightSelect) {
            heightSelect.value = displaySettings['public_bandwidth_height'] || '400';
        }

        if (saveBtn) {
            saveBtn.addEventListener('click', function() {
                var newLayout = layoutSelect.value;
                var newHeight = heightSelect.value;

                fetch(API_BASE + '/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        settings: [
                            { key: 'public_bandwidth_layout', value: newLayout, category: 'display', type: 'string' },
                            { key: 'public_bandwidth_height', value: newHeight, category: 'display', type: 'string' }
                        ]
                    })
                })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data && data.success) {
                        displaySettings['public_bandwidth_layout'] = newLayout;
                        displaySettings['public_bandwidth_height'] = newHeight;
                        applyBandwidthLayout();
                        saveStatus.classList.remove('hidden');
                        setTimeout(function() {
                            saveStatus.classList.add('hidden');
                        }, 2000);
                    }
                })['catch'](function(e) {
                    console.error('Error saving layout:', e);
                });
            });
        }
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
        return fetch(API_BASE + '/public/devices')
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
        if (!tbody) return;
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
        if (!container) return;
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
            var bc = document.getElementById('bandwidth-charts');
            if (bc) bc.innerHTML = '<div class="loading">No public interfaces configured for bandwidth charts</div>';
            return;
        }

        var viewSelect = document.getElementById('bandwidth-view-select');
        if (viewSelect) {
            viewSelect.onchange = function() {
                destroyAllCharts();
                chartOptions.view = this.value;
                renderAllBandwidthCharts();
            };
        }

        var rangeSelect = document.getElementById('bandwidth-range-select');
        if (rangeSelect) {
            rangeSelect.onchange = function() {
                destroyAllCharts();
                chartOptions.range = this.value;
                renderAllBandwidthCharts();
            };
        }

        renderAllBandwidthCharts(pubIfaces);
    }

    function destroyAllCharts() {
        for (var key in bandwidthCharts) {
            if (bandwidthCharts[key]) {
                bandwidthCharts[key].destroy();
            }
        }
        bandwidthCharts = {};
    }

    function renderAllBandwidthCharts(pubIfaces) {
        if (!pubIfaces) {
            pubIfaces = [];
            allDevices.forEach(function(device) {
                var ifaces = publicInterfaces[device.id] || [];
                ifaces.forEach(function(name) {
                    pubIfaces.push({ deviceId: device.id, deviceName: device.name, name: name });
                });
            });
        }

        var container = document.getElementById('bandwidth-charts');
        if (!container) return;

        var chartHtml = pubIfaces.map(function(iface, idx) {
            return '<div class="chart-card" id="chart-card-' + idx + '">' +
                '<div class="chart-header">' +
                '<h3>' + escapeHtml(iface.deviceName) + ' - ' + escapeHtml(iface.name) + '</h3>' +
                '<button class="collapse-btn" onclick="document.getElementById(\'chart-card-' + idx + '\').classList.toggle(\'collapsed\')">−</button>' +
                '</div>' +
                '<div class="current-stats" id="stats-' + idx + '"><span class="loading">Loading...</span></div>' +
                '<div class="chart-container"><canvas id="chart-canvas-' + idx + '"></canvas></div>' +
                '</div>';
        }).join('');

        container.innerHTML = chartHtml;

        pubIfaces.forEach(function(iface, idx) {
            loadBandwidthChartForIface(iface, idx);
        });
    }

    function loadBandwidthChartForIface(iface, chartIdx) {
        fetch(API_BASE + '/public/interfaces?device_id=' + iface.deviceId)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data || !data.success) return;
                var found = data.data.find(function(i) { return i.name === iface.name; });
                if (found) {
                    var url = API_BASE + '/public/interfaces/chart?device_id=' + iface.deviceId + '&index=' + found.index + '&view=' + chartOptions.view + '&range=' + chartOptions.range;
                    fetch(url)
                        .then(function(r) { return r.json(); })
                        .then(function(chartData) {
                            if (chartData && chartData.success) {
                                renderSingleBandwidthChart(chartData.data, iface, chartIdx);
                            }
                        })['catch'](function() {});
                }
            })['catch'](function() {});
    }

    function renderSingleBandwidthChart(data, iface, chartIdx) {
        // Ensure arrays exist and convert to numbers
        var rxRateArr = Array.isArray(data.rx_rate) ? data.rx_rate.map(Number) : [];
        var txRateArr = Array.isArray(data.tx_rate) ? data.tx_rate.map(Number) : [];
        var rxTotalArr = Array.isArray(data.rx_total) ? data.rx_total.map(Number) : [];
        var txTotalArr = Array.isArray(data.tx_total) ? data.tx_total.map(Number) : [];
        
        var latestRx = rxRateArr.length > 0 ? rxRateArr[rxRateArr.length - 1] : 0;
        var latestTx = txRateArr.length > 0 ? txRateArr[txRateArr.length - 1] : 0;
        
        // Calculate totals from cumulative counter values (last - first)
        var totalRx = 0;
        var totalTx = 0;
        if (rxTotalArr.length > 1 && txTotalArr.length > 1) {
            var firstRx = rxTotalArr[0];
            var lastRxVal = rxTotalArr[rxTotalArr.length - 1];
            var firstTxVal = txTotalArr[0];
            var lastTxVal = txTotalArr[txTotalArr.length - 1];
            totalRx = lastRxVal - firstRx;
            totalTx = lastTxVal - firstTxVal;
            if (totalRx < 0) totalRx = lastRxVal;
            if (totalTx < 0) totalTx = lastTxVal;
        }

        var device = allDevices.find(function(d) { return d.id === iface.deviceId; });
        var wanSpeed = device && device.wan_speed_mbps ? device.wan_speed_mbps : 1000;
        var usePercentage = wanSpeed > 0;

        var statsEl = document.getElementById('stats-' + chartIdx);
        if (statsEl) {
            var rxPercent = usePercentage ? ((latestRx / wanSpeed) * 100).toFixed(1) : null;
            var txPercent = usePercentage ? ((latestTx / wanSpeed) * 100).toFixed(1) : null;

            // Force to number
            var displayTotalRx = Number(totalRx) || 0;
            var displayTotalTx = Number(totalTx) || 0;

            if (chartOptions.view === 'rate') {
                var html = '<div class="stat rx"><span>&darr; ' + (latestRx || 0).toFixed(2) + ' Mbps</span>';
                if (rxPercent) html += ' <span class="percent">(' + rxPercent + '%)</span>';
                html += '</div><div class="stat tx"><span>&uarr; ' + (latestTx || 0).toFixed(2) + ' Mbps</span>';
                if (txPercent) html += ' <span class="percent">(' + txPercent + '%)</span>';
                html += '</div>';
                statsEl.innerHTML = html;
            } else if (chartOptions.view === 'total') {
                statsEl.innerHTML = '<div class="stat rx"><span>&darr; ' + formatBytes(displayTotalRx) + '</span></div>' +
                    '<div class="stat tx"><span>&uarr; ' + formatBytes(displayTotalTx) + '</span></div>';
            } else {
                statsEl.innerHTML = '<div class="stat rx"><span>&darr; ' + (latestRx || 0).toFixed(2) + ' Mbps</span> (' + formatBytes(displayTotalRx) + ')' +
                    (rxPercent ? ' <span class="percent">(' + rxPercent + '%)</span>' : '') + '</div>' +
                    '<div class="stat tx"><span>&uarr; ' + (latestTx || 0).toFixed(2) + ' Mbps</span> (' + formatBytes(displayTotalTx) + ')' +
                    (txPercent ? ' <span class="percent">(' + txPercent + '%)</span>' : '') + '</div>';
            }
        }

        var canvasEl = document.getElementById('chart-canvas-' + chartIdx);
        if (!canvasEl) return;
        var ctx = canvasEl.getContext('2d');

        var datasets = [];
        
        // Rate view and Mix view show throughput (Mbps)
        if (chartOptions.view === 'rate' || chartOptions.view === 'mix') {
            datasets.push({
                label: 'RX (Mbps)',
                data: data.rx_rate,
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y'
            });
            datasets.push({
                label: 'TX (Mbps)',
                data: data.tx_rate,
                borderColor: '#ff9500',
                backgroundColor: 'rgba(255, 149, 0, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y'
            });
        }
        
        // Mix view also shows total bytes on secondary axis
        if (chartOptions.view === 'mix') {
            datasets.push({
                label: 'RX Total (GB)',
                data: data.rx_total.map(function(v) { return v / 1024 / 1024 / 1024; }),
                borderColor: '#00cc66',
                backgroundColor: 'transparent',
                borderDash: [5, 5],
                fill: false,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y1'
            });
            datasets.push({
                label: 'TX Total (GB)',
                data: data.tx_total.map(function(v) { return v / 1024 / 1024 / 1024; }),
                borderColor: '#cc7700',
                backgroundColor: 'transparent',
                borderDash: [5, 5],
                fill: false,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y1'
            });
        }
        
        // Total view shows cumulative bytes transferred during period
        if (chartOptions.view === 'total') {
            var firstRx = data.rx_total.length > 0 ? data.rx_total[0] : 0;
            var firstTx = data.tx_total.length > 0 ? data.tx_total[0] : 0;
            // Convert to cumulative transferred (delta from first value)
            var cumulativeRx = data.rx_total.map(function(v) { return Math.max(0, v - firstRx); });
            var cumulativeTx = data.tx_total.map(function(v) { return Math.max(0, v - firstTx); });
            datasets.push({
                label: 'RX Transferred',
                data: cumulativeRx,
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
            datasets.push({
                label: 'TX Transferred',
                data: cumulativeTx,
                borderColor: '#ff9500',
                backgroundColor: 'rgba(255, 149, 0, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            });
        }

        var chartKey = iface.deviceId + '-' + iface.name;
        var existingChart = bandwidthCharts[chartKey];

        if (existingChart) {
            existingChart.data.labels = data.labels;
            existingChart.data.datasets = datasets;
            existingChart.update('none');
        } else {
            bandwidthCharts[chartKey] = new Chart(ctx, {
                type: 'line',
                data: { labels: data.labels, datasets: datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 0 },
                    interaction: { intersect: false, mode: 'index' },
                    plugins: { legend: { display: chartOptions.view === 'mix', labels: { color: '#fff' } } },
                    scales: {
                        x: { display: true, grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: 'rgba(255,255,255,0.6)', maxTicksLimit: 8 } },
                        y: { 
                            display: chartOptions.view !== 'total',
                            position: 'left',
                            grid: { color: 'rgba(255,255,255,0.1)' }, 
                            ticks: { color: 'rgba(255,255,255,0.6)', callback: function(v) { return v + ' Mbps'; } },
                            title: { display: chartOptions.view !== 'total', text: 'Mbps', color: 'rgba(255,255,255,0.6)' }
                        },
                        y1: {
                            display: chartOptions.view === 'total' || chartOptions.view === 'mix',
                            position: 'right',
                            grid: { display: false },
                            ticks: { color: 'rgba(255,255,255,0.6)', callback: function(v) { 
                                if (chartOptions.view === 'total') return formatBytes(v);
                                return v.toFixed(2) + ' GB';
                            }},
                            title: { display: chartOptions.view === 'total' || chartOptions.view === 'mix', text: chartOptions.view === 'total' ? 'Bytes' : 'Total GB', color: 'rgba(255,255,255,0.6)' }
                        }
                    }
                }
            });
        }
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
        if (!container) return;
        if (!tunnels || tunnels.length === 0) {
            if (container) container.innerHTML = '<div class="loading">No VPN tunnels found</div>';
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
        if (!container) return;
        if (!connections || connections.length === 0) {
            if (container) container.innerHTML = '<div class="loading">No connections configured</div>';
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
        if (bytes == null || bytes === 0) return '0 B';
        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
    }
})();
