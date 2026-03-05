// admin-device-detail.js — Device detail page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;

    var deviceData = null;
    var allInterfaces = [];
    var currentFilter = 'all';
    var expandedIfIndex = null;
    var ifaceCharts = {};
    var currentChartRange = '24h';
    var statusHistoryChart = null;
    var publicInterfaces = {}; // {"iface1":true,"iface2":true}

    var deviceId = window.location.pathname.split('/').pop();

    window.togglePublicIface = function(ifaceName, isPublic) {
        if (!publicInterfaces[deviceId]) publicInterfaces[deviceId] = [];
        var idx = publicInterfaces[deviceId].indexOf(ifaceName);
        if (isPublic && idx === -1) {
            publicInterfaces[deviceId].push(ifaceName);
        } else if (!isPublic && idx !== -1) {
            publicInterfaces[deviceId].splice(idx, 1);
        }
        
        var payload = [{ key: 'public_interfaces', value: JSON.stringify(publicInterfaces), category: 'display', type: 'string' }];
        fetch('/admin/api/settings', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': AC.getCsrfToken() },
            body: JSON.stringify(payload)
        }).then(function(resp) {
            if (resp.ok) {
                console.log('Saved public interface:', ifaceName, isPublic);
            } else {
                console.error('Failed to save');
            }
        });
    };

    function loadPublicInterfaces() {
        fetch('/admin/api/display-settings', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (result && result.data && result.data.public_interfaces) {
                    try {
                        publicInterfaces = JSON.parse(result.data.public_interfaces);
                        if (!publicInterfaces[deviceId]) publicInterfaces[deviceId] = [];
                    } catch(e) { publicInterfaces = {}; }
                }
            })['catch'](function() {});
    }

    function isPublicIface(iface) {
        var list = publicInterfaces[deviceId] || [];
        return list.indexOf(iface.name) !== -1;
    }

    function savePublicInterface(ifaceName, isPublic) {
        if (!publicInterfaces[deviceId]) publicInterfaces[deviceId] = [];
        var idx = publicInterfaces[deviceId].indexOf(ifaceName);
        if (isPublic && idx === -1) {
            publicInterfaces[deviceId].push(ifaceName);
        } else if (!isPublic && idx !== -1) {
            publicInterfaces[deviceId].splice(idx, 1);
        }
        
        var payload = [{ key: 'public_interfaces', value: JSON.stringify(publicInterfaces), category: 'display', type: 'string' }];
        fetch('/admin/api/settings', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': AC.getCsrfToken() },
            body: JSON.stringify(payload)
        }).then(function(resp) {
            if (!resp.ok) {
                console.error('Failed to save public interface settings');
            }
        })['catch'](function(err) { 
            console.error('Error saving public interface:', err); 
        });
    }

    function loadDevice() {
        fetch('/admin/api/devices/' + deviceId + '/detail', { credentials: 'same-origin' })
            .then(function(resp) {
                if (resp.status === 401) { window.location.href = '/admin/login'; return Promise.reject(new Error('Not authenticated')); }
                if (!resp.ok) throw new Error('Failed to load device');
                return resp.json();
            })
            .then(function(result) {
                if (!result.success) throw new Error(result.error || 'Failed to load');
                deviceData = result.data;
                renderDevice();
            })
            ['catch'](function(e) {
                if (e.message === 'Not authenticated') return;
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = e.message;
            });
    }

    function renderDevice() {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('content').style.display = 'block';

        var dev = deviceData.device;
        document.getElementById('deviceName').textContent = dev.name || dev.hostname || 'Unknown';
        document.title = (dev.name || 'Device') + ' - Firewall Monitor';

        var statusBadge = document.getElementById('deviceStatus');
        statusBadge.textContent = dev.status || 'unknown';
        statusBadge.className = 'badge ' + (dev.status || 'unknown');

        document.getElementById('deviceIP').textContent = dev.ip_address + ':' + dev.snmp_port;
        document.getElementById('deviceProbe').textContent = dev.probe ? 'Probe: ' + dev.probe.name : '';
        document.getElementById('deviceSite').textContent = dev.site ? 'Site: ' + dev.site.name : '';
        document.getElementById('devicePolled').textContent = dev.last_polled ? 'Last polled: ' + formatTime(dev.last_polled) : '';

        renderSystemStatus();
        renderInterfaces();
        renderVPN();
        renderSensors();
        renderProcessors();
        renderAlerts();
        renderPing();
        renderHA();
        renderSecurity();
        renderSDWAN();
        renderLicenses();
    }

    function renderSystemStatus() {
        var ss = deviceData.system_status;
        if (!ss) {
            document.getElementById('systemStats').insertAdjacentHTML('beforeend',
                '<div class="empty" style="grid-column:1/-1;text-align:center;padding:1.5rem 0">Awaiting data from probe\u2026</div>');
            return;
        }

        createGauge('cpuGauge', ss.cpu_usage, getGaugeColor(ss.cpu_usage));
        document.getElementById('cpuValue').textContent = ss.cpu_usage.toFixed(1) + '%';

        createGauge('memGauge', ss.memory_usage, getGaugeColor(ss.memory_usage));
        document.getElementById('memValue').textContent = ss.memory_usage.toFixed(1) + '%';

        if (ss.disk_usage === 0 && ss.disk_total === 0) {
            createGauge('diskGauge', 0, '#484f58');
            document.getElementById('diskValue').textContent = 'N/A';
        } else {
            createGauge('diskGauge', ss.disk_usage, getGaugeColor(ss.disk_usage));
            document.getElementById('diskValue').textContent = ss.disk_usage.toFixed(1) + '%';
        }

        document.getElementById('sessionCount').textContent = ss.session_count ? ss.session_count.toLocaleString() : '0';
        document.getElementById('uptimeValue').textContent = formatUptime(ss.uptime);
        document.getElementById('firmwareValue').textContent = ss.version || '-';

        // Extended status cards
        var extGrid = document.getElementById('extendedStats');
        var showExt = false;

        if (ss.session_rate_1 || ss.session_rate_10 || ss.session_rate_30 || ss.session_rate_60) {
            document.getElementById('cardSessionRate').style.display = '';
            document.getElementById('sessionRateValue').textContent =
                '1m: ' + ss.session_rate_1 + '  10m: ' + ss.session_rate_10 + '  30m: ' + ss.session_rate_30 + '  60m: ' + ss.session_rate_60;
            showExt = true;
        }
        if (ss.session_count_6) {
            document.getElementById('cardIPv6').style.display = '';
            document.getElementById('ipv6SessionValue').textContent = ss.session_count_6.toLocaleString();
            showExt = true;
        }
        if (ss.sslvpn_users || ss.sslvpn_tunnels) {
            document.getElementById('cardSSLVPN').style.display = '';
            document.getElementById('sslvpnValue').textContent = (ss.sslvpn_users || 0) + ' users / ' + (ss.sslvpn_tunnels || 0) + ' tunnels';
            showExt = true;
        }
        if (ss.av_version) {
            document.getElementById('cardAVSig').style.display = '';
            document.getElementById('avSigValue').textContent = ss.av_version;
            showExt = true;
        }
        if (ss.ips_version) {
            document.getElementById('cardIPSSig').style.display = '';
            document.getElementById('ipsSigValue').textContent = ss.ips_version;
            showExt = true;
        }
        if (showExt) extGrid.style.display = '';

        loadStatusHistoryChart();
    }

    function loadStatusHistoryChart() {
        fetch('/admin/api/devices/' + deviceId + '/status-history?hours=24', {
            credentials: 'include'
        })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (!result.success) return;

                var sysData = (result.data && result.data.system_status) || [];
                var pingData = (result.data && result.data.ping_history) || [];
                if (!sysData.length && !pingData.length) return;

                var labels = sysData.map(function(s) {
                    var d = new Date(s.timestamp);
                    return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
                });
                var cpuData = sysData.map(function(s) { return s.cpu_usage; });
                var memData = sysData.map(function(s) { return s.memory_usage; });
                var diskData = sysData.map(function(s) { return s.disk_usage; });

                // Build latency dataset aligned to system_status timestamps
                var latencyData = [];
                if (pingData.length && sysData.length) {
                    var pi = 0;
                    for (var si = 0; si < sysData.length; si++) {
                        var sysTime = new Date(sysData[si].timestamp).getTime();
                        var bestIdx = -1, bestDist = Infinity;
                        while (pi < pingData.length && new Date(pingData[pi].timestamp).getTime() <= sysTime + 120000) {
                            var dist = Math.abs(new Date(pingData[pi].timestamp).getTime() - sysTime);
                            if (dist < bestDist) { bestDist = dist; bestIdx = pi; }
                            pi++;
                        }
                        if (bestIdx >= 0) pi = bestIdx;
                        latencyData.push(bestIdx >= 0 && bestDist < 120000 && pingData[bestIdx].success ? pingData[bestIdx].latency : null);
                    }
                }

                var datasets = [
                    { label: 'CPU %', data: cpuData, borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.05)', fill: true, tension: 0.3, pointRadius: 0, yAxisID: 'y' },
                    { label: 'Memory %', data: memData, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.05)', fill: true, tension: 0.3, pointRadius: 0, yAxisID: 'y' },
                    { label: 'Disk %', data: diskData, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.05)', fill: true, tension: 0.3, pointRadius: 0, yAxisID: 'y' }
                ];

                var scales = {
                    x: { ticks: { color: '#484f58', font: { size: 10 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                    y: { position: 'left', min: 0, max: 100, ticks: { color: '#484f58', font: { size: 10 } }, grid: { color: '#21262d' } }
                };

                if (latencyData.some(function(v) { return v !== null; })) {
                    datasets.push({
                        label: 'Latency (ms)',
                        data: latencyData,
                        borderColor: '#d29922',
                        backgroundColor: 'rgba(210,153,34,0.05)',
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                        borderDash: [4, 2],
                        yAxisID: 'y1'
                    });
                    scales.y1 = {
                        position: 'right',
                        min: 0,
                        title: { display: true, text: 'ms', color: '#d29922', font: { size: 10 } },
                        ticks: { color: '#d29922', font: { size: 10 } },
                        grid: { drawOnChartArea: false }
                    };
                }

                var ctx = document.getElementById('status-history-chart');
                if (!ctx) return;
                if (statusHistoryChart) statusHistoryChart.destroy();
                statusHistoryChart = new Chart(ctx, {
                    type: 'line',
                    data: { labels: labels, datasets: datasets },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#8b949e', boxWidth: 12, padding: 8, font: { size: 11 } } } },
                        scales: scales
                    }
                });
            })
            ['catch'](function(e) { console.error('Failed to load status history chart:', e); });
    }

    function createGauge(containerId, value, color) {
        var container = document.getElementById(containerId);
        var radius = 32;
        var circumference = 2 * Math.PI * radius;
        var offset = circumference - (Math.min(value, 100) / 100) * circumference;

        container.innerHTML =
            '<svg width="80" height="80" viewBox="0 0 80 80">' +
                '<circle class="gauge-bg" cx="40" cy="40" r="' + radius + '" />' +
                '<circle class="gauge-fill" cx="40" cy="40" r="' + radius + '"' +
                    ' stroke="' + color + '"' +
                    ' stroke-dasharray="' + circumference + '"' +
                    ' stroke-dashoffset="' + offset + '" />' +
            '</svg>' +
            '<div class="gauge-text">' + Math.round(value) + '%</div>';
    }

    function getGaugeColor(value) {
        if (value >= 90) return '#f85149';
        if (value >= 70) return '#d29922';
        return '#3fb950';
    }

    function renderInterfaces() {
        allInterfaces = deviceData.interfaces || [];
        var upCount = allInterfaces.filter(function(i) { return i.status === 'up'; }).length;
        var downCount = allInterfaces.filter(function(i) { return i.status === 'down'; }).length;
        document.getElementById('ifaceSummary').textContent =
            allInterfaces.length + ' total, ' + upCount + ' up, ' + downCount + ' down';

        // Build dynamic filter buttons
        var filtersDiv = document.getElementById('ifaceFilters');
        var typeCounts = {};
        allInterfaces.forEach(function(i) {
            var tn = i.type_name || 'other';
            typeCounts[tn] = (typeCounts[tn] || 0) + 1;
        });

        var btns = '<button class="filter-btn' + (currentFilter === 'all' ? ' active' : '') + '" data-action="filter-ifaces" data-filter="all">All (' + allInterfaces.length + ')</button>';
        btns += '<button class="filter-btn' + (currentFilter === 'up' ? ' active' : '') + '" data-action="filter-ifaces" data-filter="up">Up (' + upCount + ')</button>';
        btns += '<button class="filter-btn' + (currentFilter === 'down' ? ' active' : '') + '" data-action="filter-ifaces" data-filter="down">Down (' + downCount + ')</button>';

        var sortedTypes = Object.keys(typeCounts).sort();
        for (var ti = 0; ti < sortedTypes.length; ti++) {
            var tn = sortedTypes[ti];
            var label = tn.charAt(0).toUpperCase() + tn.slice(1);
            btns += '<button class="filter-btn' + (currentFilter === tn ? ' active' : '') + '" data-action="filter-ifaces" data-filter="' + esc(tn) + '">' + esc(label) + ' (' + typeCounts[tn] + ')</button>';
        }
        filtersDiv.innerHTML = btns;

        filterIfaces(currentFilter);
    }

    function filterIfaces(filter) {
        currentFilter = filter;
        document.querySelectorAll('#ifaceFilters .filter-btn').forEach(function(btn) {
            btn.classList.toggle('active', btn.getAttribute('data-filter') === filter);
        });

        var filtered = allInterfaces;
        if (filter === 'up') filtered = allInterfaces.filter(function(i) { return i.status === 'up'; });
        else if (filter === 'down') filtered = allInterfaces.filter(function(i) { return i.status === 'down'; });
        else if (filter !== 'all') filtered = allInterfaces.filter(function(i) { return (i.type_name || 'other') === filter; });

        var body = document.getElementById('ifaceBody');
        var empty = document.getElementById('ifaceEmpty');

        if (filtered.length === 0) {
            body.innerHTML = '';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';

        // Sort: up first, then by name
        filtered.sort(function(a, b) {
            if (a.status === 'up' && b.status !== 'up') return -1;
            if (a.status !== 'up' && b.status === 'up') return 1;
            return (a.name || '').localeCompare(b.name || '');
        });

        var html = '';
        for (var fi = 0; fi < filtered.length; fi++) {
            var iface = filtered[fi];
            var typeBadge = getTypeBadge(iface);
            var isExpanded = expandedIfIndex === iface.index;
            html += '<tr class="clickable" data-action="toggle-expand" data-index="' + iface.index + '">' +
                '<td><strong>' + esc(iface.name) + '</strong></td>' +
                '<td>' + esc(iface.alias || '') + '</td>' +
                '<td>' + typeBadge + '</td>' +
                '<td>' + formatSpeed(iface) + '</td>' +
                '<td><span class="badge ' + iface.status + '">' + iface.status + '</span></td>' +
                '<td><span class="badge ' + iface.admin_status + '">' + (iface.admin_status || '-') + '</span></td>' +
                '<td>' + formatBytes(iface.in_bytes) + '</td>' +
                '<td>' + formatBytes(iface.out_bytes) + '</td>' +
                '<td>' + ((iface.in_errors || 0) + (iface.out_errors || 0)) + '</td>' +
                '<td>' + (iface.mtu || '-') + '</td>' +
                '<td style="font-family:monospace;font-size:0.78rem">' + esc(iface.mac_address || '-') + '</td>' +
                '<td><input type="checkbox" ' + (isPublicIface(iface) ? 'checked ' : '') + 'onclick="window.togglePublicIface(\'' + esc(iface.name) + '\', this.checked)"></td>' +
                '</tr>';

            if (isExpanded) {
                var ranges = ['24h', '7d', '30d', '90d'];
                var rangeBtns = '';
                for (var ri = 0; ri < ranges.length; ri++) {
                    var r = ranges[ri];
                    rangeBtns += '<button class="chart-range-btn' + (currentChartRange === r ? ' active' : '') + '" data-action="load-iface-chart" data-index="' + iface.index + '" data-range="' + r + '">' + r + '</button>';
                }
                html += '<tr class="expand-row"><td colspan="11">' +
                    '<div class="expand-content">' +
                        '<div class="detail-grid">' +
                            '<div class="detail-item"><span class="label">Index</span><span class="value">' + iface.index + '</span></div>' +
                            '<div class="detail-item"><span class="label">Type ID</span><span class="value">' + iface.type + ' (' + (iface.type_name || 'unknown') + ')</span></div>' +
                            '<div class="detail-item"><span class="label">VLAN ID</span><span class="value">' + (iface.vlan_id || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">High Speed</span><span class="value">' + (iface.high_speed ? iface.high_speed + ' Mbps' : '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Description</span><span class="value">' + esc(iface.description || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">In Bytes</span><span class="value">' + formatBytes(iface.in_bytes) + '</span></div>' +
                            '<div class="detail-item"><span class="label">Out Bytes</span><span class="value">' + formatBytes(iface.out_bytes) + '</span></div>' +
                            '<div class="detail-item"><span class="label">In Packets</span><span class="value">' + (iface.in_packets || 0).toLocaleString() + '</span></div>' +
                            '<div class="detail-item"><span class="label">Out Packets</span><span class="value">' + (iface.out_packets || 0).toLocaleString() + '</span></div>' +
                            '<div class="detail-item"><span class="label">In Errors</span><span class="value">' + (iface.in_errors || 0).toLocaleString() + '</span></div>' +
                            '<div class="detail-item"><span class="label">Out Errors</span><span class="value">' + (iface.out_errors || 0).toLocaleString() + '</span></div>' +
                            '<div class="detail-item"><span class="label">In Discards</span><span class="value">' + (iface.in_discards || 0).toLocaleString() + '</span></div>' +
                            '<div class="detail-item"><span class="label">Out Discards</span><span class="value">' + (iface.out_discards || 0).toLocaleString() + '</span></div>' +
                        '</div>' +
                        '<div class="chart-range-btns">' + rangeBtns + '</div>' +
                        '<div class="iface-chart-container" id="chart-container-' + iface.index + '">' +
                            '<canvas id="canvas-' + iface.index + '"></canvas>' +
                        '</div>' +
                    '</div>' +
                '</td></tr>';
            }
        }
        body.innerHTML = html;

        if (expandedIfIndex !== null) {
            loadInterfaceChart(expandedIfIndex, currentChartRange);
        }
    }

    function toggleExpand(ifIndex) {
        expandedIfIndex = expandedIfIndex === ifIndex ? null : ifIndex;
        filterIfaces(currentFilter);
    }

    function loadInterfaceChart(ifIndex, range) {
        currentChartRange = range;
        // Update active button styling
        document.querySelectorAll('.chart-range-btn').forEach(function(btn) {
            btn.classList.toggle('active', btn.textContent === range);
        });

        var canvas = document.getElementById('canvas-' + ifIndex);
        if (!canvas) return;

        // Destroy previous chart instance
        if (ifaceCharts[ifIndex]) {
            ifaceCharts[ifIndex].destroy();
            delete ifaceCharts[ifIndex];
        }

        fetch('/admin/api/devices/' + deviceId + '/interfaces/' + ifIndex + '/chart?range=' + range, { credentials: 'same-origin' })
            .then(function(resp) {
                if (!resp.ok) return Promise.reject(new Error('Failed'));
                return resp.json();
            })
            .then(function(result) {
                if (!result.success || !result.data || result.data.length < 2) {
                    var ctx2 = canvas.getContext('2d');
                    ctx2.fillStyle = '#484f58';
                    ctx2.font = '11px sans-serif';
                    ctx2.fillText('Not enough history data', 10, 30);
                    return;
                }

                var data = result.data;
                var labels = data.map(function(d) {
                    var b = d.bucket;
                    if (range === '90d') return b.substring(5);
                    if (range === '30d' || range === '7d') return b.substring(5, 13);
                    return b.substring(11, 16);
                });

                ifaceCharts[ifIndex] = new Chart(canvas, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            { label: 'In Bytes', data: data.map(function(d) { return d.in_bytes; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                            { label: 'Out Bytes', data: data.map(function(d) { return d.out_bytes; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
                        scales: {
                            x: { ticks: { color: '#484f58', font: { size: 9 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                            y: { ticks: { color: '#484f58', font: { size: 9 }, callback: function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } }
                        }
                    }
                });
            })
            ['catch'](function(e) { console.error('Failed to load interface chart:', e); });
    }

    function getTypeBadge(iface) {
        var tn = iface.type_name || '';
        if (tn === 'vxlan') return '<span class="badge vxlan">VXLAN</span>';
        if (tn === 'tunnel') return '<span class="badge tunnel">Tunnel</span>';
        if (tn === 'lag') return '<span class="badge lag">LAG</span>';
        if (tn === 'loopback') return '<span class="badge unknown">Loop</span>';
        if (tn === 'ethernet') return '<span class="badge online">Eth</span>';
        if (tn) return '<span class="badge unknown">' + esc(tn) + '</span>';
        return '<span style="color:#484f58">' + iface.type + '</span>';
    }

    function renderVPN() {
        var vpn = deviceData.vpn_status || [];
        var body = document.getElementById('vpnBody');
        var empty = document.getElementById('vpnEmpty');

        if (vpn.length === 0) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = vpn.map(function(v) {
            return '<tr>' +
                '<td>' + esc(v.phase1_name || v.tunnel_name) + '</td>' +
                '<td><strong>' + esc(v.tunnel_name) + '</strong></td>' +
                '<td>' + getTunnelTypeBadge(v.tunnel_type) + '</td>' +
                '<td>' + esc(v.remote_ip) + '</td>' +
                '<td><span class="badge ' + v.status + '">' + v.status + '</span></td>' +
                '<td><code style="color:#58a6ff;font-size:0.8rem;">' + esc(v.local_subnet || '-') + '</code></td>' +
                '<td><code style="color:#3fb950;font-size:0.8rem;">' + esc(v.remote_subnet || '-') + '</code></td>' +
                '<td>' + formatBytes(v.bytes_in) + '</td>' +
                '<td>' + formatBytes(v.bytes_out) + '</td>' +
                '<td>' + formatVpnUptime(v.tunnel_uptime) + '</td>' +
            '</tr>';
        }).join('');

        // Update tab label with count
        var upCount = vpn.filter(function(v) { return v.status === 'up'; }).length;
        var vpnTab = document.querySelector('[data-tab="vpn"]');
        if (vpnTab) vpnTab.textContent = 'VPN Tunnels (' + upCount + '/' + vpn.length + ')';
    }

    function renderSensors() {
        var sensors = deviceData.hardware_sensors || [];
        var body = document.getElementById('sensorBody');
        var empty = document.getElementById('sensorEmpty');

        if (sensors.length === 0) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = sensors.map(function(s) {
            return '<tr>' +
                '<td>' + esc(s.name) + '</td>' +
                '<td><strong>' + s.value + '</strong></td>' +
                '<td>' + esc(s.unit || '') + '</td>' +
                '<td><span class="badge ' + (s.status === 'alarm' ? 'critical' : 'online') + '">' + s.status + '</span></td>' +
            '</tr>';
        }).join('');
    }

    function renderProcessors() {
        var procs = deviceData.processor_stats || [];
        var container = document.getElementById('procBars');
        var empty = document.getElementById('procEmpty');
        var summary = document.getElementById('procSummary');

        if (procs.length === 0) { container.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        var avg = procs.reduce(function(s, p) { return s + p.usage; }, 0) / procs.length;
        summary.textContent = procs.length + ' cores, avg ' + avg.toFixed(1) + '%';

        // Update tab label
        var procTab = document.querySelector('[data-tab="processors"]');
        if (procTab) procTab.textContent = 'Processors (' + procs.length + ')';

        container.innerHTML = procs.map(function(p) {
            var color = getGaugeColor(p.usage);
            var width = Math.min(p.usage, 100);
            return '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 14px;display:flex;align-items:center;gap:12px">' +
                '<span style="color:#8b949e;font-size:0.78rem;min-width:60px">Core ' + p.index + '</span>' +
                '<div style="flex:1;background:#21262d;border-radius:3px;height:16px;overflow:hidden">' +
                    '<div style="width:' + width + '%;height:100%;background:' + color + ';border-radius:3px;transition:width 0.3s"></div>' +
                '</div>' +
                '<span style="color:#e6edf3;font-size:0.82rem;font-weight:600;min-width:45px;text-align:right">' + p.usage.toFixed(0) + '%</span>' +
            '</div>';
        }).join('');
    }

    function renderAlerts() {
        var alerts = deviceData.recent_alerts || [];
        var body = document.getElementById('alertBody');
        var empty = document.getElementById('alertEmpty');

        if (alerts.length === 0) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = alerts.map(function(a) {
            return '<tr>' +
                '<td style="white-space:nowrap">' + formatTime(a.timestamp) + '</td>' +
                '<td>' + esc(a.alert_type) + '</td>' +
                '<td><span class="badge ' + a.severity + '">' + a.severity + '</span></td>' +
                '<td>' + esc(a.message) + '</td>' +
            '</tr>';
        }).join('');
    }

    function renderPing() {
        var pings = deviceData.ping_stats || [];
        var body = document.getElementById('pingBody');
        var empty = document.getElementById('pingEmpty');

        if (pings.length === 0) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = pings.map(function(p) {
            return '<tr>' +
                '<td>' + esc(p.target_ip) + '</td>' +
                '<td>' + (p.min_latency ? p.min_latency.toFixed(2) + ' ms' : '-') + '</td>' +
                '<td>' + (p.avg_latency ? p.avg_latency.toFixed(2) + ' ms' : '-') + '</td>' +
                '<td>' + (p.max_latency ? p.max_latency.toFixed(2) + ' ms' : '-') + '</td>' +
                '<td>' + (p.packet_loss != null ? p.packet_loss.toFixed(1) + '%' : '-') + '</td>' +
                '<td>' + (p.samples || 0) + '</td>' +
            '</tr>';
        }).join('');
    }

    function getTunnelTypeBadge(type) {
        if (!type) return '<span style="color:#484f58">-</span>';
        var colors = { 'ipsec': '#58a6ff', 'ipsec-dialup': '#d29922', 'sslvpn': '#3fb950' };
        var color = colors[type] || '#8b949e';
        return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44">' + esc(type) + '</span>';
    }

    function renderHA() {
        var ha = deviceData.ha_status || [];
        var body = document.getElementById('haBody');
        var empty = document.getElementById('haEmpty');
        var header = document.getElementById('haHeader');

        if (!ha.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        var mode = ha[0].system_mode || 'unknown';
        var group = ha[0].group_name || '';
        header.textContent = 'Mode: ' + mode + (group ? ' \u2014 ' + group : '');

        body.innerHTML = ha.map(function(m) {
            var cpuColor = getGaugeColor(m.cpu_usage);
            var memColor = getGaugeColor(m.memory_usage);
            var isMaster = m.member_serial === m.master_serial;
            var syncColor = m.sync_status === 'synchronized' ? '#3fb950' : m.sync_status === 'unsynchronized' ? '#f85149' : '#d29922';
            return '<tr>' +
                '<td style="font-family:monospace;font-size:0.8rem">' + esc(m.member_serial) + '</td>' +
                '<td><strong>' + esc(m.member_hostname || '-') + '</strong></td>' +
                '<td style="color:' + cpuColor + ';font-weight:600">' + m.cpu_usage.toFixed(1) + '%</td>' +
                '<td style="color:' + memColor + ';font-weight:600">' + m.memory_usage.toFixed(1) + '%</td>' +
                '<td>' + (m.network_usage ? (m.network_usage / 1000).toFixed(1) : '0') + '</td>' +
                '<td>' + (m.session_count || 0).toLocaleString() + '</td>' +
                '<td><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:' + syncColor + '22;color:' + syncColor + ';border:1px solid ' + syncColor + '44">' + esc(m.sync_status || 'unknown') + '</span></td>' +
                '<td>' + (isMaster ? '<span class="badge online">Primary</span>' : '<span class="badge unknown">Secondary</span>') + '</td>' +
            '</tr>';
        }).join('');

        var haTab = document.querySelector('[data-tab="ha"]');
        if (haTab) haTab.textContent = 'HA Cluster (' + ha.length + ')';
    }

    function renderSecurity() {
        var sec = deviceData.security_stats;
        var content = document.getElementById('securityContent');
        var empty = document.getElementById('securityEmpty');

        if (!sec) { content.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        content.innerHTML =
            '<h3 style="color:#c9d1d9;font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px">Antivirus</h3>' +
            '<div class="stat-grid">' +
                '<div class="stat-card"><div class="stat-label">Detected</div><div class="stat-value">' + (sec.av_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Blocked</div><div class="stat-value">' + (sec.av_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">HTTP Detected</div><div class="stat-value">' + (sec.av_http_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">SMTP Detected</div><div class="stat-value">' + (sec.av_smtp_detected || 0).toLocaleString() + '</div></div>' +
            '</div>' +
            '<h3 style="color:#c9d1d9;font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px">Intrusion Prevention</h3>' +
            '<div class="stat-grid">' +
                '<div class="stat-card"><div class="stat-label">Detected</div><div class="stat-value">' + (sec.ips_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Blocked</div><div class="stat-value">' + (sec.ips_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Critical</div><div class="stat-value" style="color:#f85149">' + (sec.ips_critical || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">High</div><div class="stat-value" style="color:#d29922">' + (sec.ips_high || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Medium</div><div class="stat-value" style="color:#e3b341">' + (sec.ips_medium || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Low</div><div class="stat-value" style="color:#58a6ff">' + (sec.ips_low || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Info</div><div class="stat-value" style="color:#8b949e">' + (sec.ips_info || 0).toLocaleString() + '</div></div>' +
            '</div>' +
            '<h3 style="color:#c9d1d9;font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px">Web Filter</h3>' +
            '<div class="stat-grid">' +
                '<div class="stat-card"><div class="stat-label">HTTP Blocked</div><div class="stat-value">' + (sec.wf_http_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">HTTPS Blocked</div><div class="stat-value">' + (sec.wf_https_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">URL Blocked</div><div class="stat-value">' + (sec.wf_url_blocked || 0).toLocaleString() + '</div></div>' +
            '</div>';
    }

    function renderSDWAN() {
        var sdwan = deviceData.sdwan_health || [];
        var body = document.getElementById('sdwanBody');
        var empty = document.getElementById('sdwanEmpty');

        if (!sdwan.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = sdwan.map(function(d) {
            var stateColor = d.state === 'alive' ? '#3fb950' : d.state === 'dead' ? '#f85149' : '#d29922';
            var latColor = d.latency > 200 ? '#f85149' : d.latency > 100 ? '#d29922' : '#c9d1d9';
            var lossColor = d.packet_loss > 5 ? '#f85149' : d.packet_loss > 1 ? '#d29922' : '#c9d1d9';
            return '<tr>' +
                '<td><strong>' + esc(d.name) + '</strong></td>' +
                '<td>' + esc(d.interface) + '</td>' +
                '<td><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:' + stateColor + '22;color:' + stateColor + ';border:1px solid ' + stateColor + '44">' + esc(d.state || 'unknown') + '</span></td>' +
                '<td style="color:' + latColor + '">' + (d.latency != null ? d.latency.toFixed(1) : '-') + '</td>' +
                '<td style="color:' + lossColor + '">' + (d.packet_loss != null ? d.packet_loss.toFixed(2) : '-') + '</td>' +
                '<td>' + (d.packet_send || 0).toLocaleString() + '</td>' +
                '<td>' + (d.packet_recv || 0).toLocaleString() + '</td>' +
            '</tr>';
        }).join('');

        var sdwanTab = document.querySelector('[data-tab="sdwan"]');
        if (sdwanTab) sdwanTab.textContent = 'SD-WAN (' + sdwan.length + ')';
    }

    function renderLicenses() {
        var lics = deviceData.license_info || [];
        var body = document.getElementById('licenseBody');
        var empty = document.getElementById('licenseEmpty');

        if (!lics.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';

        body.innerHTML = lics.map(function(l) {
            var expiryStyle = '';
            if (l.expiry_date && l.expiry_date !== 'N/A' && l.expiry_date !== '') {
                var exp = new Date(l.expiry_date);
                if (!isNaN(exp.getTime())) {
                    var now = new Date();
                    var daysLeft = (exp - now) / 86400000;
                    if (daysLeft < 0) expiryStyle = 'color:#f85149;font-weight:600';
                    else if (daysLeft < 30) expiryStyle = 'color:#d29922;font-weight:600';
                    else expiryStyle = 'color:#3fb950';
                }
            }
            return '<tr>' +
                '<td>' + esc(l.description) + '</td>' +
                '<td style="' + expiryStyle + '">' + esc(l.expiry_date || 'N/A') + '</td>' +
            '</tr>';
        }).join('');

        var licTab = document.querySelector('[data-tab="licenses"]');
        if (licTab) licTab.textContent = 'Licenses (' + lics.length + ')';
    }

    function switchTab(name) {
        document.querySelectorAll('.section-tab').forEach(function(t) { t.classList.remove('active'); });
        document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
        var tab = document.querySelector('[data-tab="' + name + '"]');
        if (tab) tab.classList.add('active');
        var content = document.getElementById('tab-' + name);
        if (content) content.classList.add('active');
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        var val = bytes;
        while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
        return val.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    function formatVpnUptime(hundredths) {
        if (!hundredths) return '-';
        var secs = Math.floor(hundredths / 100);
        var d = Math.floor(secs / 86400);
        var h = Math.floor((secs % 86400) / 3600);
        var m = Math.floor((secs % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }

    function formatSpeed(iface) {
        if (iface.high_speed && iface.high_speed > 0) {
            if (iface.high_speed >= 1000) return (iface.high_speed / 1000).toFixed(0) + ' Gbps';
            return iface.high_speed + ' Mbps';
        }
        if (iface.speed) {
            var mbps = iface.speed / 1000000;
            if (mbps >= 1000) return (mbps / 1000).toFixed(0) + ' Gbps';
            if (mbps >= 1) return mbps.toFixed(0) + ' Mbps';
            return iface.speed + ' bps';
        }
        return '-';
    }

    function formatUptime(seconds) {
        if (!seconds) return '-';
        var totalSec = Math.floor(seconds / 100);
        var days = Math.floor(totalSec / 86400);
        var hours = Math.floor((totalSec % 86400) / 3600);
        var mins = Math.floor((totalSec % 3600) / 60);
        if (days > 0) return days + 'd ' + hours + 'h';
        if (hours > 0) return hours + 'h ' + mins + 'm';
        return mins + 'm';
    }

    function formatTime(ts) {
        if (!ts) return '-';
        var d = new Date(ts);
        if (isNaN(d.getTime())) return '-';
        var now = new Date();
        var diff = (now - d) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function esc(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Register all delegated event handlers
    AC.delegateEvent('click', {
        'logout': function() {
            AC.doLogout();
        },
        'switch-tab': function(el) {
            switchTab(el.dataset.tab);
        },
        'filter-ifaces': function(el) {
            filterIfaces(el.dataset.filter);
        },
        'toggle-expand': function(el) {
            toggleExpand(parseInt(el.dataset.index, 10));
        },
        'load-iface-chart': function(el, e) {
            e.stopPropagation();
            loadInterfaceChart(parseInt(el.dataset.index, 10), el.dataset.range);
        }
    });

    // Auto-refresh every 60 seconds
    setInterval(loadDevice, 60000);

    // Initial load — wait for CSRF token fetch then load
    AC.fetchCsrfToken().then(function() {
        return loadPublicInterfaces();
    }).then(function() {
        loadDevice();
    });
})();
