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
    var statusHistoryPromise = null;
    var publicInterfaces = {}; // {"iface1":true,"iface2":true}

    var deviceId = window.location.pathname.split('/').pop();
    if (!deviceId || deviceId === 'detail') {
        deviceId = null;
    }

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
                // saved successfully
            } else {
                console.error('Failed to save, status:', resp.status);
            }
        })['catch'](function(err) { 
            console.error('Error saving:', err); 
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
        renderConfigHistory();
        renderProcessMonitor();
        renderInterfaceErrors();
    }

    function renderSystemStatus() {
        var ss = deviceData.system_status;
        if (!ss) {
            document.getElementById('systemStats').insertAdjacentHTML('beforeend',
                '<div class="empty" style="grid-column:1/-1;text-align:center;padding:1.5rem 0">Awaiting data from probe\u2026</div>');
            return;
        }

        createGauge('cpuGauge', ss.cpu_usage, getGaugeColor(ss.cpu_usage));
        createGauge('memGauge', ss.memory_usage, getGaugeColor(ss.memory_usage));

        if (ss.disk_usage === 0 && ss.disk_total === 0) {
            createGauge('diskGauge', 0, '#484f58');
        } else {
            createGauge('diskGauge', ss.disk_usage, getGaugeColor(ss.disk_usage));
        }

        document.getElementById('sessionCount').textContent = ss.session_count ? ss.session_count.toLocaleString() : '0';
        document.getElementById('uptimeValue').textContent = formatUptime(ss.uptime);

        // Extended status cards
        var extGrid = document.getElementById('extendedStats');
        var showExt = false;

        if (ss.version) {
            document.getElementById('firmwareValue').textContent = ss.version;
            document.getElementById('cardFirmware').style.display = '';
            showExt = true;
        }

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
        loadNetworkThroughputChart();
        loadCPUBreakdownChart();
    }

    function loadStatusHistoryChart() {
        if (!statusHistoryPromise) {
            statusHistoryPromise = fetch('/admin/api/devices/' + deviceId + '/status-history?hours=24', {
                credentials: 'include'
            }).then(function(resp) { return resp.json(); });
        }
        statusHistoryPromise.then(function(result) {
            if (!result.success) return;

            var sysData = (result.data && result.data.system_status) || [];
            var pingData = (result.data && result.data.ping_history) || [];
            if (!sysData.length && !pingData.length) return;

            var labels = sysData.map(function(s) {
                var d = new Date(s.timestamp);
                var tz = AC.getTimezone();
                return d.toLocaleString('en-US', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
            });
            var cpuData = sysData.map(function(s) { return s.cpu_usage; });
            var memData = sysData.map(function(s) { return s.memory_usage; });
            var diskData = sysData.map(function(s) { return s.disk_usage; });

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
            })['catch'](function(e) { console.error('Failed to load status history chart:', e); });
    }

    var networkThroughputChart = null;
    var currentNetworkThroughputRange = '24h';
    var statusHistoryCache = {};

    var networkThroughputRangeChangeHandler = function() {
        loadNetworkThroughputChart(this.value);
    };

    function loadNetworkThroughputChart(range) {
        if (!range) range = currentNetworkThroughputRange;
        currentNetworkThroughputRange = range;

        // Update select dropdown
        var ntSelect = document.getElementById('network-throughput-range');
        if (ntSelect) ntSelect.value = range;

        // Convert range to hours for API
        var hoursMap = { '0.25': 0.25, '0.5': 0.5, '1': 1, '6': 6, '12': 12, '24': 24, '168': 168, '720': 720, '2160': 2160, '8760': 8760 };
        var hours = hoursMap[range] || 24;

        // Check cache first
        var cacheKey = range;
        var section = document.getElementById('network-throughput-section');
        if (!section) return;

        if (statusHistoryCache[cacheKey]) {
            renderNetworkThroughputChart(statusHistoryCache[cacheKey], range);
            return;
        }

        section.innerHTML = '<div class="flex justify-between items-center mb-3"><h3 class="text-[0.85rem] text-[#8b949e] font-medium">Network Throughput</h3><select class="chart-range-select" id="network-throughput-range"><option value="0.25">15m</option><option value="0.5">30m</option><option value="1">1h</option><option value="6">6h</option><option value="12">12h</option><option value="24" selected>24h</option><option value="168">1w</option><option value="720">1m</option><option value="2160">3m</option><option value="8760">1y</option></select></div><canvas id="network-throughput-chart"></canvas><div class="loading">Loading...</div>';
        var sel = document.getElementById('network-throughput-range');
        sel.value = range;
        sel.removeEventListener('change', networkThroughputRangeChangeHandler);
        sel.addEventListener('change', networkThroughputRangeChangeHandler);

        fetch('/admin/api/devices/' + deviceId + '/status-history?hours=' + hours, {
            credentials: 'include'
        }).then(function(resp) { return resp.json(); })
        .then(function(result) {
            if (!result.success) return;
            var sysData = (result.data && result.data.system_status) || [];
            statusHistoryCache[cacheKey] = sysData;
            renderNetworkThroughputChart(sysData, range);
        })['catch'](function(e) { console.error('Failed to load network throughput chart:', e); });
    }

    function renderNetworkThroughputChart(sysData, range) {
        if (!sysData || !sysData.length) return;

        var hasNetworkData = sysData.some(function(s) { return s.network_in_kbps > 0 || s.network_out_kbps > 0; });
        var section = document.getElementById('network-throughput-section');
        if (!section) return;

        if (!hasNetworkData) {
            section.innerHTML = '<div class="flex justify-between items-center mb-3"><h3 class="text-[0.85rem] text-[#8b949e] font-medium">Network Throughput</h3><select class="chart-range-select" id="network-throughput-range"><option value="0.25">15m</option><option value="0.5">30m</option><option value="1">1h</option><option value="6">6h</option><option value="12">12h</option><option value="24" selected>24h</option><option value="168">1w</option><option value="720">1m</option><option value="2160">3m</option><option value="8760">1y</option></select></div><div class="text-[#8b949e] text-center p-4">No network throughput data available</div>';
            var sel = document.getElementById('network-throughput-range');
            sel.value = range;
            sel.removeEventListener('change', networkThroughputRangeChangeHandler);
            sel.addEventListener('change', networkThroughputRangeChangeHandler);
            return;
        }

        var showDate = range === '168' || range === '720' || range === '2160';
        var labels = sysData.map(function(s) {
            var d = new Date(s.timestamp);
            var tz = AC.getTimezone();
            if (showDate) {
                return d.toLocaleString('en-US', { timeZone: tz, month: 'short', day: 'numeric' });
            }
            return d.toLocaleString('en-US', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
        });
        var netInData = sysData.map(function(s) { return s.network_in_kbps || 0; });
        var netOutData = sysData.map(function(s) { return s.network_out_kbps || 0; });

        section.innerHTML = '<div class="flex justify-between items-center mb-3"><h3 class="text-[0.85rem] text-[#8b949e] font-medium">Network Throughput</h3><select class="chart-range-select" id="network-throughput-range"><option value="0.25">15m</option><option value="0.5">30m</option><option value="1">1h</option><option value="6">6h</option><option value="12">12h</option><option value="24" selected>24h</option><option value="168">1w</option><option value="720">1m</option><option value="2160">3m</option><option value="8760">1y</option></select></div><canvas id="network-throughput-chart"></canvas>';
        var sel = document.getElementById('network-throughput-range');
        sel.value = range;
        sel.removeEventListener('change', networkThroughputRangeChangeHandler);
        sel.addEventListener('change', networkThroughputRangeChangeHandler);

        var ctx = document.getElementById('network-throughput-chart');
        if (!ctx) return;
        if (networkThroughputChart) networkThroughputChart.destroy();
        networkThroughputChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    { label: 'In (kbps)', data: netInData, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.1)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                    { label: 'Out (kbps)', data: netOutData, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: { duration: 0 },
                plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
                scales: {
                    x: { ticks: { color: '#484f58', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                    y: { min: 0, ticks: { color: '#484f58', font: { size: 11 }, callback: function(v) { return v + ' kbps'; } }, grid: { color: '#21262d' } }
                }
            }
        });
    }

    var cpuBreakdownChart = null;
    function loadCPUBreakdownChart() {
        if (!statusHistoryPromise) {
            statusHistoryPromise = fetch('/admin/api/devices/' + deviceId + '/status-history?hours=24', {
                credentials: 'include'
            }).then(function(resp) { return resp.json(); });
        }
        statusHistoryPromise.then(function(result) {
            if (!result.success) return;
            var sysData = (result.data && result.data.system_status) || [];
            if (!sysData.length) return;

            var hasBreakdown = sysData.some(function(s) { return s.cpu_user > 0 || s.cpu_system > 0 || s.cpu_idle > 0; });
            var section = document.getElementById('cpu-breakdown-section');
            if (!section) return;

            if (!hasBreakdown) {
                section.style.display = 'none';
                return;
            }
            section.style.display = 'block';

            var labels = sysData.map(function(s) {
                var d = new Date(s.timestamp);
                var tz = AC.getTimezone();
                return d.toLocaleString('en-US', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
            });

            var ctx = document.getElementById('cpu-breakdown-chart');
            if (!ctx) return;
            if (cpuBreakdownChart) cpuBreakdownChart.destroy();
            cpuBreakdownChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        { label: 'User', data: sysData.map(function(s) { return s.cpu_user || 0; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'System', data: sysData.map(function(s) { return s.cpu_system || 0; }), borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'Nice', data: sysData.map(function(s) { return s.cpu_nice || 0; }), borderColor: '#d29922', backgroundColor: 'rgba(210,153,34,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'IOWait', data: sysData.map(function(s) { return s.cpu_iowait || 0; }), borderColor: '#bc8cff', backgroundColor: 'rgba(188,140,255,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'IRQ', data: sysData.map(function(s) { return s.cpu_irq || 0; }), borderColor: '#ff7b72', backgroundColor: 'rgba(255,123,114,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'SoftIRQ', data: sysData.map(function(s) { return s.cpu_softirq || 0; }), borderColor: '#39d4e0', backgroundColor: 'rgba(57,212,224,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 },
                        { label: 'Idle', data: sysData.map(function(s) { return s.cpu_idle || 0; }), borderColor: '#484f58', backgroundColor: 'rgba(72,79,88,0.3)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1 }
                    ]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 6, font: { size: 10 } } } },
                    scales: {
                        x: { ticks: { color: '#484f58', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                        y: { min: 0, max: 100, stacked: false, ticks: { color: '#484f58', font: { size: 11 }, callback: function(v) { return v + '%'; } }, grid: { color: '#21262d' } }
                    }
                }
            });
        })['catch'](function(e) { console.error('Failed to load CPU breakdown chart:', e); });
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
                    ctx2.clearRect(0, 0, canvas.width, canvas.height);
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
                            x: { ticks: { color: '#484f58', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                            y: { ticks: { color: '#484f58', font: { size: 11 }, callback: function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } }
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
            var hasTraffic = (v.bytes_in > 0) || (v.bytes_out > 0);
            var state = v.state || (v.status === 'up' ? 'active' : 'inactive');
            var stateClass = (state === 'active' && hasTraffic) ? 'active' : (state === 'active' ? 'up' : 'inactive');
            var stateLabel = (state === 'active' && hasTraffic) ? 'Online' : state;
            return '<tr>' +
                '<td>' + esc(v.phase1_name || v.tunnel_name) + '</td>' +
                '<td><strong>' + esc(v.tunnel_name) + '</strong></td>' +
                '<td>' + getTunnelTypeBadge(v.tunnel_type) + '</td>' +
                '<td style="color:#8b949e;font-size:0.8rem;">' + esc(v.interface_name || '-') + '</td>' +
                '<td>' + esc(v.remote_ip) + '</td>' +
                '<td style="color:#8b949e;font-size:0.78rem;">' + esc(v.mode || '-') + '</td>' +
                '<td><span class="badge ' + v.status + '">' + v.status + '</span></td>' +
                '<td><span class="badge ' + stateClass + '">' + stateLabel + '</span></td>' +
                '<td><code style="color:#58a6ff;font-size:0.8rem;">' + esc(v.local_subnet || '-') + '</code></td>' +
                '<td><code style="color:#3fb950;font-size:0.8rem;">' + esc(v.remote_subnet || '-') + '</code></td>' +
                '<td>' + formatBytes(v.bytes_in) + '</td>' +
                '<td>' + formatBytes(v.bytes_out) + '</td>' +
                '<td>' + formatVpnUptime(v.tunnel_uptime) + '</td>' +
            '</tr>';
        }).join('');

        // Update tab label with count
        var upCount = vpn.filter(function(v) { return v.status === 'up'; }).length;
        var onlineCount = vpn.filter(function(v) { var hasTraffic = (v.bytes_in > 0) || (v.bytes_out > 0); var state = v.state || (v.status === 'up' ? 'active' : 'inactive'); return state === 'active' && hasTraffic; }).length;
        var vpnTab = document.querySelector('[data-tab="vpn"]');
        if (vpnTab) vpnTab.textContent = 'VPN Tunnels (' + onlineCount + '/' + upCount + ' online/up)';
    }

    function renderSensors() {
        var sensors = deviceData.hardware_sensors || [];
        var container = document.getElementById('sensorCards');
        var empty = document.getElementById('sensorEmpty');
        var summary = document.getElementById('sensorSummary');

        if (sensors.length === 0) { container.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';
        summary.textContent = sensors.length + ' sensors';

        container.innerHTML = sensors.map(function(s) {
            var isAlarm = s.status && s.status.toLowerCase() === 'alarm';
            var statusClass = isAlarm ? 'alarm' : 'normal';
            var borderColor = isAlarm ? '#f85149' : '#30363d';
            var icon = getSensorIcon(s.name, s.unit);

            return '<div style="background:#0d1117;border:1px solid ' + borderColor + ';border-radius:8px;padding:14px;">' +
                '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">' +
                    '<div style="width:36px;height:36px;background:#161b22;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#8b949e;font-size:1.2rem;">' + icon + '</div>' +
                    '<div style="flex:1;min-width:0;">' +
                        '<div style="color:#e6edf3;font-size:0.85rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="' + esc(s.name) + '">' + esc(s.name) + '</div>' +
                        '<div style="color:#8b949e;font-size:0.72rem;text-transform:uppercase;">' + esc(s.unit || '') + '</div>' +
                    '</div>' +
                '</div>' +
                '<div style="display:flex;justify-content:space-between;align-items:flex-end;">' +
                    '<div style="color:#e6edf3;font-size:1.4rem;font-weight:700;">' + s.value.toFixed(1) + '</div>' +
                    '<div style="display:flex;align-items:center;gap:6px;">' +
                        '<span style="width:8px;height:8px;border-radius:50%;background:' + (isAlarm ? '#f85149' : '#3fb950') + ';"></span>' +
                        '<span style="color:' + (isAlarm ? '#f85149' : '#8b949e') + ';font-size:0.75rem;text-transform:uppercase;">' + esc(s.status || 'unknown') + '</span>' +
                    '</div>' +
                '</div>' +
            '</div>';
        }).join('');
    }

    function getSensorIcon(name, unit) {
        if (!name) return '?';
        var n = name.toLowerCase();
        var u = (unit || '').toLowerCase();

        if (u === 'c' || n.includes('temp') || n.includes('temperature')) return '🌡';
        if (n.includes('fan') || n.includes('speed')) return '🌀';
        if (u === 'v' || n.includes('volt') || n.includes('voltage')) return '⚡';
        if (u === 'rpm') return '🔄';
        if (n.includes('power') || n.includes('psu')) return '🔌';
        if (n.includes('current') || u === 'a') return '📊';
        return '📋';
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
                '<td>' + (p.min_latency != null ? p.min_latency.toFixed(2) + ' ms' : '-') + '</td>' +
                '<td>' + (p.avg_latency != null ? p.avg_latency.toFixed(2) + ' ms' : '-') + '</td>' +
                '<td>' + (p.max_latency != null ? p.max_latency.toFixed(2) + ' ms' : '-') + '</td>' +
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
        var container = document.getElementById('licenseCards');
        var empty = document.getElementById('licenseEmpty');
        var summary = document.getElementById('licenseSummary');

        if (!lics.length) { container.innerHTML = ''; empty.style.display = 'block'; return; }
        empty.style.display = 'none';
        summary.textContent = lics.length + ' licenses';

        container.innerHTML = lics.map(function(l) {
            var statusColor = '#8b949e';
            var statusBg = 'rgba(139,148,158,0.15)';
            var isLicensed = l.status && (l.status.toLowerCase() === 'licensed' || l.status.toLowerCase() === 'registered');
            if (isLicensed) { statusColor = '#3fb950'; statusBg = 'rgba(63,185,80,0.15)'; }
            else if (l.status && l.status.toLowerCase() === 'expired') { statusColor = '#f85149'; statusBg = 'rgba(248,81,73,0.15)'; }
            else if (l.status && l.status.toLowerCase() === 'no_license') { statusColor = '#d29922'; statusBg = 'rgba(210,153,34,0.15)'; }

            var expiryInfo = '';
            if (l.expiry_date && l.expiry_date !== 'N/A' && l.expiry_date !== '') {
                var exp = new Date(l.expiry_date);
                if (!isNaN(exp.getTime())) {
                    var now = new Date();
                    var daysLeft = Math.ceil((exp - now) / 86400000);
                    var expiryColor = '#8b949e';
                    if (daysLeft < 0) { expiryColor = '#f85149'; expiryInfo = 'Expired ' + Math.abs(daysLeft) + ' days ago'; }
                    else if (daysLeft < 30) { expiryColor = '#d29922'; expiryInfo = 'Expires in ' + daysLeft + ' days'; }
                    else { expiryColor = '#3fb950'; expiryInfo = 'Expires ' + l.expiry_date; }
                    expiryInfo = '<div style="color:' + expiryColor + ';font-size:0.75rem;margin-top:4px;">' + expiryInfo + '</div>';
                } else {
                    expiryInfo = '<div style="color:#8b949e;font-size:0.75rem;margin-top:4px;">Expires: ' + esc(l.expiry_date) + '</div>';
                }
            }

            var icon = getLicenseIcon(l.description);

            return '<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;">' +
                '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;">' +
                    '<div style="width:40px;height:40px;background:' + statusBg + ';border-radius:8px;display:flex;align-items:center;justify-content:center;color:' + statusColor + ';font-size:1.3rem;">' + icon + '</div>' +
                    '<div style="flex:1;min-width:0;">' +
                        '<div style="color:#e6edf3;font-size:0.9rem;font-weight:600;margin-bottom:2px;">' + esc(l.description || 'Unknown') + '</div>' +
                        '<div style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.7rem;font-weight:600;text-transform:uppercase;background:' + statusBg + ';color:' + statusColor + ';">' + esc(l.status || 'unknown') + '</div>' +
                    '</div>' +
                '</div>' +
                expiryInfo +
                (l.details ? '<div style="color:#8b949e;font-size:0.72rem;margin-top:6px;line-height:1.4;">' + esc(l.details) + '</div>' : '') +
            '</div>';
        }).join('');

        var licTab = document.querySelector('[data-tab="licenses"]');
        if (licTab) licTab.textContent = 'Licenses (' + lics.length + ')';
    }

    function getLicenseIcon(description) {
        if (!description) return '📋';
        var d = description.toLowerCase();
        if (d.includes('antivirus') || d.includes('av')) return '🦠';
        if (d.includes('ips') || d.includes('intrusion')) return '🛡';
        if (d.includes('web')) return '🌐';
        if (d.includes('email') || d.includes('mail')) return '📧';
        if (d.includes('forticare') || d.includes('support')) return '🎧';
        if (d.includes('fortiguard')) return '🛡';
        if (d.includes('cloud')) return '☁️';
        if (d.includes('sd-wan')) return '🌍';
        if (d.includes('vdom')) return '📦';
        return '📋';
    }

    var configRevisions = [];
    var configCompareSelection = { from: null, to: null };

    function renderConfigHistory() {
        fetch('/admin/api/devices/' + deviceId + '/config-history', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                var revs = (result.success && result.data && result.data.revisions) ? result.data.revisions : [];
                configRevisions = revs;
                var body = document.getElementById('configBody');
                var empty = document.getElementById('configEmpty');
                var summary = document.getElementById('configSummary');

                if (!revs.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
                empty.style.display = 'none';
                summary.textContent = revs.length + ' revision(s)';

                // Default radio selection: from = second-newest, to = newest (what users want most often).
                if (configCompareSelection.from === null && revs.length >= 2) {
                    configCompareSelection.from = revs[1].id;
                    configCompareSelection.to = revs[0].id;
                }

                body.innerHTML = revs.map(function(r, i) {
                    var isCurrent = i === 0 ? ' <span class="badge" style="background:#238636;padding:2px 6px;border-radius:4px;font-size:0.7rem;margin-left:6px">Current</span>' : '';
                    var fromChecked = configCompareSelection.from === r.id ? ' checked' : '';
                    var toChecked = configCompareSelection.to === r.id ? ' checked' : '';
                    var trigger = r.trigger_source || 'poll';
                    var triggerColor = trigger === 'syslog' ? '#3fb950' : (trigger === 'manual' ? '#d29922' : '#58a6ff');
                    var quality = r.backup_quality || 'full';
                    var qualityColor = quality === 'masked' ? '#f85149' : (quality === 'unknown' ? '#8b949e' : '#3fb950');
                    var normHash = r.normalized_checksum || '-';
                    if (normHash !== '-' && normHash.length > 12) normHash = normHash.substring(0, 12) + '…';
                    return '<tr>' +
                        '<td><input type="radio" name="cfgFrom" value="' + r.id + '" data-action="cfg-compare-from"' + fromChecked + '></td>' +
                        '<td><input type="radio" name="cfgTo"   value="' + r.id + '" data-action="cfg-compare-to"' + toChecked + '></td>' +
                        '<td style="white-space:nowrap">' + formatTime(r.timestamp) + isCurrent + '</td>' +
                        '<td><span class="badge" style="background:rgba(0,0,0,0.3);color:' + triggerColor + ';padding:2px 6px;border-radius:4px;font-size:0.72rem">' + esc(trigger) + '</span></td>' +
                        '<td><span class="badge" style="background:rgba(0,0,0,0.3);color:' + qualityColor + ';padding:2px 6px;border-radius:4px;font-size:0.72rem">' + esc(quality) + '</span></td>' +
                        '<td><code style="color:#58a6ff;font-size:0.75rem" title="' + esc(r.normalized_checksum || '') + '">' + esc(normHash) + '</code></td>' +
                        '<td>' + formatBytes(r.length) + '</td>' +
                        '<td>' +
                        '<button class="btn secondary text-[0.78rem] mr-1" onclick="viewConfigRevision(' + r.id + ')">View</button>' +
                        '<button class="btn secondary text-[0.78rem] mr-1" onclick="downloadConfigRevision(' + r.id + ')">Download</button>' +
                        '<button class="btn secondary text-[0.78rem]" onclick="deleteConfigRevision(' + r.id + ')" style="color:#f85149">Delete</button>' +
                        '</td>' +
                    '</tr>';
                }).join('');

                updateConfigCompareButton();
            })['catch'](function(e) { console.error('Failed to load config history:', e); });
    }

    function updateConfigCompareButton() {
        var btn = document.getElementById('configCompareBtn');
        var hint = document.getElementById('configCompareHint');
        if (!btn) return;
        var ok = configCompareSelection.from !== null
              && configCompareSelection.to !== null
              && configCompareSelection.from !== configCompareSelection.to;
        btn.disabled = !ok;
        if (ok) {
            hint.textContent = 'Comparing rev #' + configCompareSelection.from + ' → rev #' + configCompareSelection.to;
        } else if (configCompareSelection.from !== null && configCompareSelection.from === configCompareSelection.to) {
            hint.textContent = 'From and To are the same — pick different revisions.';
        } else {
            hint.textContent = 'Pick two revisions to compare (radio columns).';
        }
    }

    document.addEventListener('change', function(e) {
        var t = e.target;
        if (!t || !t.dataset) return;
        if (t.dataset.action === 'cfg-compare-from') {
            configCompareSelection.from = parseInt(t.value, 10);
            updateConfigCompareButton();
        } else if (t.dataset.action === 'cfg-compare-to') {
            configCompareSelection.to = parseInt(t.value, 10);
            updateConfigCompareButton();
        }
    });

    document.addEventListener('click', function(e) {
        var t = e.target;
        if (!t) return;
        if (t.id === 'configCompareBtn' && !t.disabled) {
            openConfigDiff(configCompareSelection.from, configCompareSelection.to);
        }
        if (t.dataset && t.dataset.action === 'close-config-diff') {
            var modal = document.getElementById('config-diff-modal');
            if (modal) modal.classList.remove('active');
        }
    });

    function openConfigDiff(fromID, toID) {
        var url = '/admin/api/devices/' + deviceId + '/config-history/diff?from=' + fromID + '&to=' + toID;
        fetch(url, { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(result) {
                if (!result.success || !result.data) {
                    alert('Diff failed: ' + (result.error || 'unknown'));
                    return;
                }
                renderConfigDiff(result.data);
            })['catch'](function(e) { console.error('config diff failed:', e); });
    }

    function renderConfigDiff(data) {
        var modal = document.getElementById('config-diff-modal');
        var meta  = document.getElementById('config-diff-meta');
        var body  = document.getElementById('config-diff-body');
        if (!modal || !meta || !body) {
            console.error('config-diff-modal: required DOM elements missing', { modal: !!modal, meta: !!meta, body: !!body });
            return;
        }

        // Show the modal FIRST. If diff rendering throws, the user at least
        // sees an error in the modal body instead of a frozen-looking page.
        modal.classList.remove('hidden');
        modal.classList.add('active');
        body.innerHTML = '<div style="padding:20px;color:#8b949e">Computing diff…</div>';

        try {
            var fromRev = data && data.from || {};
            var toRev   = data && data.to   || {};

            meta.innerHTML = '<span style="color:#f85149">From #' + esc(String(fromRev.id || '?')) + '</span> ' + formatTime(fromRev.timestamp) +
                ' (' + esc(fromRev.trigger_source || 'poll') + ', ' + esc(fromRev.backup_quality || 'full') + ')' +
                ' &nbsp;→&nbsp; <span style="color:#3fb950">To #' + esc(String(toRev.id || '?')) + '</span> ' + formatTime(toRev.timestamp) +
                ' (' + esc(toRev.trigger_source || 'poll') + ', ' + esc(toRev.backup_quality || 'full') + ')';

            // Compile vendor-aware volatile-line patterns (server sends them
            // as RE2 strings; we translate to JS RegExp). Crucially we add
            // the `g` flag so .replace() catches every match, not just the
            // first — without it only one ENC line per pattern got masked
            // and the rest leaked into the diff as "changes".
            var patterns = (data && data.volatile_patterns || []).map(function(p) {
                try {
                    var src = p.regex || '';
                    var jsFlags = 'g';
                    var flagMatch = src.match(/^\(\?([a-z]+)\)/);
                    if (flagMatch) {
                        if (flagMatch[1].indexOf('m') !== -1) jsFlags += 'm';
                        if (flagMatch[1].indexOf('s') !== -1) jsFlags += 's';
                        src = src.substring(flagMatch[0].length);
                    }
                    return { name: p.name || '?', regex: new RegExp(src, jsFlags) };
                } catch (e) {
                    console.warn('skipping invalid volatile pattern', p, e);
                    return null;
                }
            }).filter(function(x) { return x; });

            var fromText = fromRev.config_text || '';
            var toText   = toRev.config_text   || '';

            var maskedFrom = maskVolatile(fromText, patterns);
            var maskedTo   = maskVolatile(toText,   patterns);

            body.innerHTML = computeMaskedDiff(maskedFrom, maskedTo);
        } catch (err) {
            console.error('Diff render failed:', err, 'data:', data);
            body.innerHTML = '<div style="color:#f85149;padding:20px;font-family:sans-serif">' +
                '<strong>Failed to render diff.</strong><br>' +
                esc(String(err && err.message || err)) + '<br><br>' +
                '<span style="color:#8b949e;font-size:0.85rem">Open browser dev tools (F12) → Console for details.</span>' +
                '</div>';
        }
    }

    function maskVolatile(text, patterns) {
        var masked = text;
        patterns.forEach(function(p) {
            // p.regex carries the `g` flag so replace() catches every match.
            masked = masked.replace(p.regex, function(m) {
                return '__VOLATILE__' + p.name + '__' + Math.floor(m.length) + '__';
            });
        });
        return masked;
    }

    function computeMaskedDiff(from, to) {
        var fromLines = from.split('\n');
        var toLines   = to.split('\n');
        var maxLen = Math.max(fromLines.length, toLines.length);

        // Hard cap to avoid hanging the browser on pathologically large
        // configs. 10 000 lines = ~50–80 KB rendered HTML, plenty for any
        // real FortiGate config.
        var MAX_LINES = 10000;
        var truncated = maxLen > MAX_LINES;
        if (truncated) maxLen = MAX_LINES;

        // Build via an array + join (O(n)) rather than `+=` (O(n²) on some
        // engines). Matters for 5 000+ line diffs.
        var parts = [];

        for (var i = 0; i < maxLen; i++) {
            var l1 = i < fromLines.length ? fromLines[i] : null;
            var l2 = i < toLines.length   ? toLines[i]   : null;

            var l1Volatile = l1 !== null && l1.indexOf('__VOLATILE__') !== -1;
            var l2Volatile = l2 !== null && l2.indexOf('__VOLATILE__') !== -1;

            // If either side has a volatile marker on this line, render one
            // grey "(volatile: name)" row and skip the red/green emit. The
            // two sides should be aligned because we masked both texts with
            // the same patterns.
            if (l1Volatile || l2Volatile) {
                var marker = l1Volatile ? l1 : l2;
                var nm = marker.match(/__VOLATILE__([^_]+)__/);
                var name = nm ? nm[1] : '?';
                parts.push('<div style="background:#21262d;color:#8b949e;padding:1px 8px"> &nbsp; <em>(volatile: ' + esc(name) + ')</em></div>');
                continue;
            }
            if (l1 === l2) {
                parts.push('<div style="padding:1px 8px;color:#c9d1d9">' + esc(l1 || '') + '</div>');
            } else {
                if (l1 !== null) {
                    parts.push('<div style="background:rgba(248,81,73,0.15);color:#ff7b72;padding:1px 8px">- ' + esc(l1) + '</div>');
                }
                if (l2 !== null) {
                    parts.push('<div style="background:rgba(63,185,80,0.15);color:#3fb950;padding:1px 8px">+ ' + esc(l2) + '</div>');
                }
            }
        }
        if (truncated) {
            parts.push('<div style="background:#21262d;color:#d2992a;padding:8px;text-align:center">' +
                '… diff truncated at ' + MAX_LINES + ' lines for browser performance. Download both revisions to compare offline.</div>');
        }
        if (parts.length === 0) return '<div style="color:#8b949e;padding:20px">No differences found</div>';
        return parts.join('');
    }

    window.viewConfigRevision = function(revId) {
        fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId + '/view', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (!result.success || !result.data || !result.data.revision) return;
                var rev = result.data.revision;
                showConfigModal('Configuration Revision', rev.config_text, rev.timestamp, rev.checksum);
            })['catch'](function(e) { console.error('Failed to view config:', e); });
    };

    window.diffConfigRevisions = function(revId1, revId2) {
        Promise.all([
            fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId1 + '/view', { credentials: 'same-origin' }).then(function(r) { return r.json(); }),
            fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId2 + '/view', { credentials: 'same-origin' }).then(function(r) { return r.json(); })
        ]).then(function(results) {
            if (!results[0].success || !results[0].data || !results[1].success || !results[1].data) return;
            var rev1 = results[0].data.revision;
            var rev2 = results[1].data.revision;
            showDiffModal('Configuration Diff', rev1.config_text, rev2.config_text, rev1.timestamp, rev2.timestamp);
        })['catch'](function(e) { console.error('Failed to load diff:', e); });
    };

    function showConfigModal(title, configText, timestamp, checksum) {
        var modal = document.getElementById('config-modal') || createConfigModal();
        modal.querySelector('.modal-header h2').textContent = title;
        var content = modal.querySelector('.config-modal-body');
        content.innerHTML = '<div class="config-meta mb-3 text-[0.82rem] text-[#8b949e]">' +
            '<span>Timestamp: ' + formatTime(timestamp) + '</span>' +
            '<span class="ml-4">Checksum: ' + esc(checksum || '-') + '</span></div>' +
            '<pre class="config-text bg-[#0d1117] border border-[#30363d] rounded p-4 overflow-auto" style="max-height:60vh;white-space:pre-wrap;font-size:0.8rem">' + esc(configText || '') + '</pre>';
        modal.classList.add('active');
    }

    function showDiffModal(title, text1, text2, ts1, ts2) {
        var modal = document.getElementById('config-modal') || createConfigModal();
        modal.querySelector('.modal-header h2').textContent = title;
        var content = modal.querySelector('.config-modal-body');
        var diffHtml = computeDiff(text1 || '', text2 || '');
        content.innerHTML = '<div class="config-meta mb-3 text-[0.82rem] text-[#8b949e] flex justify-between">' +
            '<div><span class="text-[#f85149]">Older:</span> ' + formatTime(ts1) + '</div>' +
            '<div><span class="text-[#3fb950]">Newer:</span> ' + formatTime(ts2) + '</div></div>' +
            '<div class="diff-container bg-[#0d1117] border border-[#30363d] rounded p-4 overflow-auto" style="max-height:60vh;white-space:pre-wrap;font-size:0.8rem">' + diffHtml + '</div>';
        modal.classList.add('active');
    }

    function computeDiff(text1, text2) {
        var lines1 = text1.split('\n');
        var lines2 = text2.split('\n');
        var result = [];
        var maxLen = Math.max(lines1.length, lines2.length);
        for (var i = 0; i < maxLen; i++) {
            var l1 = lines1[i] || '';
            var l2 = lines2[i] || '';
            if (l1 === l2) {
                result.push({ type: 'unchanged', text: l1 });
            } else {
                result.push({ type: 'removed', text: l1 });
                result.push({ type: 'added', text: l2 });
            }
        }
        var html = '';
        result.forEach(function(line) {
            var cls = '';
            var prefix = ' ';
            if (line.type === 'removed') { cls = 'diff-removed'; prefix = '-'; }
            else if (line.type === 'added') { cls = 'diff-added'; prefix = '+'; }
            html += '<div class="' + cls + '" style="padding:2px 8px;">' + prefix + ' ' + esc(line.text) + '</div>';
        });
        return html || '<div class="text-[#8b949e] p-4">No differences found</div>';
    }

    function createConfigModal() {
        var modal = document.createElement('div');
        modal.id = 'config-modal';
        modal.className = 'modal';
        modal.innerHTML = '<div class="modal-content" style="width:95vw;max-width:1400px;">' +
            '<div class="modal-header">' +
            '<h2>Configuration</h2>' +
            '<button class="modal-close" onclick="this.closest(\'.modal\').classList.remove(\'active\')">&times;</button>' +
            '</div>' +
            '<div class="config-modal-body" style="max-height:75vh;overflow-y:auto;"></div>' +
            '<div class="modal-footer">' +
            '<button type="button" class="btn secondary" onclick="this.closest(\'.modal\').classList.remove(\'active\')">Close</button>' +
            '</div></div>';
        document.body.appendChild(modal);
        var style = document.createElement('style');
        style.textContent = '.diff-removed{background:rgba(248,81,73,0.15);color:#ff7b72;}.diff-added{background:rgba(63,185,80,0.15);color:#3fb950;}';
        document.head.appendChild(style);
        return modal;
    }

    window.downloadConfigRevision = function(revId) {
        fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId, { credentials: 'same-origin' })
            .then(function(resp) { return resp.text(); })
            .then(function(text) {
                var blob = new Blob([text], { type: 'text/plain' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'config_' + deviceId + '_' + revId + '.txt';
                a.click();
                URL.revokeObjectURL(url);
            })['catch'](function(e) { console.error('Failed to download config:', e); });
    };

    window.deleteConfigRevision = function(revId) {
        if (!confirm('Delete this configuration revision?')) return;
        fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': AC.getCsrfToken() }
        }).then(function(resp) { return resp.json(); })
        .then(function(result) {
            if (result.success) renderConfigHistory();
            else alert('Failed to delete: ' + (result.error || 'Unknown error'));
        })['catch'](function(e) { console.error('Failed to delete config:', e); });
    };

    var procSshChart = null;
    function renderProcessMonitor() {
        var rangeSelect = document.getElementById('proc-ssh-range');
        if (!rangeSelect) return;

        rangeSelect.addEventListener('change', function() {
            loadProcessMonitorData(this.value);
        });
        loadProcessMonitorData(rangeSelect.value);
    }

    function loadProcessMonitorData(hours) {
        fetch('/admin/api/devices/' + deviceId + '/process-history?hours=' + hours + '&limit=500', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (!result.success || !result.data || !result.data.process_stats || !result.data.process_stats.length) {
                    document.getElementById('procSshEmpty').style.display = 'block';
                    document.getElementById('proc-ssh-chart').style.display = 'none';
                    return;
                }
                document.getElementById('procSshEmpty').style.display = 'none';
                document.getElementById('proc-ssh-chart').style.display = 'block';
                document.getElementById('procSshSummary').textContent = result.data.process_stats.length + ' snapshots';

                var stats = result.data.process_stats;
                var topProcs = {};
                stats.forEach(function(snap) {
                    (snap.processes || []).slice(0, 5).forEach(function(p) {
                        if (!topProcs[p.name]) topProcs[p.name] = [];
                        topProcs[p.name].push({ ts: snap.timestamp, cpu: p.cpu });
                    });
                });

                var procNames = Object.keys(topProcs).slice(0, 6);
                if (!procNames.length) return;

                var colors = ['#58a6ff', '#3fb950', '#f85149', '#d29922', '#bc8cff', '#ff7b72'];
                var datasets = procNames.map(function(name, idx) {
                    return {
                        label: name,
                        data: topProcs[name].map(function(d) { return d.cpu; }),
                        borderColor: colors[idx % colors.length],
                        backgroundColor: colors[idx % colors.length] + '22',
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0
                    };
                });

                var labels = topProcs[procNames[0]].map(function(d) {
                    return new Date(d.ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
                });

                var canvas = document.getElementById('proc-ssh-chart');
                if (procSshChart) procSshChart.destroy();
                procSshChart = new Chart(canvas, {
                    type: 'line',
                    data: { labels: labels, datasets: datasets },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 6, font: { size: 10 } } } },
                        scales: {
                            x: { ticks: { color: '#484f58', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                            y: { min: 0, ticks: { color: '#484f58', font: { size: 11 }, callback: function(v) { return v + '%'; } }, grid: { color: '#21262d' } }
                        }
                    }
                });
            })['catch'](function(e) { console.error('Failed to load process monitor:', e); });
    }

    var ifaceErrChart = null;
    function renderInterfaceErrors() {
        var ifaceSelect = document.getElementById('iface-err-interface');
        var rangeSelect = document.getElementById('iface-err-range');
        if (!ifaceSelect || !rangeSelect) return;

        ifaceSelect.addEventListener('change', function() { loadInterfaceErrorsData(rangeSelect.value, this.value); });
        rangeSelect.addEventListener('change', function() { loadInterfaceErrorsData(this.value, ifaceSelect.value); });
        loadInterfaceErrorsData(rangeSelect.value, ifaceSelect.value);
    }

    function loadInterfaceErrorsData(hours, ifaceFilter) {
        var url = '/admin/api/devices/' + deviceId + '/interface-errors?hours=' + hours + '&limit=500';
        if (ifaceFilter) url += '&interface=' + encodeURIComponent(ifaceFilter);

        fetch(url, { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (!result.success || !result.data || !result.data.interface_errors || !result.data.interface_errors.length) {
                    document.getElementById('ifaceErrEmpty').style.display = 'block';
                    document.getElementById('iface-err-chart').style.display = 'none';
                    return;
                }
                document.getElementById('ifaceErrEmpty').style.display = 'none';
                document.getElementById('iface-err-chart').style.display = 'block';
                document.getElementById('ifaceErrSummary').textContent = result.data.interface_errors.length + ' data points';

                var errs = result.data.interface_errors;
                var byIface = {};
                errs.forEach(function(e) {
                    if (!byIface[e.interface]) byIface[e.interface] = [];
                    byIface[e.interface].push(e);
                });

                var ifaceNames = Object.keys(byIface);
                var colors = ['#58a6ff', '#3fb950', '#f85149', '#d29922', '#bc8cff', '#ff7b72'];
                var datasets = ifaceNames.map(function(name, idx) {
                    var color = colors[idx % colors.length];
                    return {
                        label: name + ' In',
                        data: byIface[name].map(function(e) { return e.in_errors; }),
                        borderColor: color,
                        backgroundColor: color + '22',
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0
                    };
                });

                var labels = byIface[ifaceNames[0]].map(function(e) {
                    return new Date(e.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
                });

                var canvas = document.getElementById('iface-err-chart');
                if (ifaceErrChart) ifaceErrChart.destroy();
                ifaceErrChart = new Chart(canvas, {
                    type: 'line',
                    data: { labels: labels, datasets: datasets },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 6, font: { size: 10 } } } },
                        scales: {
                            x: { ticks: { color: '#484f58', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                            y: { min: 0, ticks: { color: '#484f58', font: { size: 11 } }, grid: { color: '#21262d' } }
                        }
                    }
                });
            })['catch'](function(e) { console.error('Failed to load interface errors:', e); });
    }

    function switchTab(name) {
        document.querySelectorAll('.tab-item').forEach(function(t) { t.classList.remove('active'); });
        document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
        var tab = document.querySelector('.tab-item[data-tab="' + name + '"]');
        if (tab) tab.classList.add('active');
        var content = document.getElementById('tab-' + name);
        if (content) content.classList.add('active');
    }

    function formatBytes(bytes) {
        if (bytes == null || bytes === 0) return '0 B';
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
        return window.AdminCommon.formatDateShort(ts);
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
        },
        'load-network-throughput': function(el, e) {
            e.stopPropagation();
            loadNetworkThroughputChart(el.dataset.range);
        }
    });

    // Network throughput range select dropdown
    var ntRangeSelect = document.getElementById('network-throughput-range');
    if (ntRangeSelect) {
        ntRangeSelect.addEventListener('change', function() {
            loadNetworkThroughputChart(this.value);
        });
    }

    // Auto-refresh every 60 seconds
    setInterval(loadDevice, 60000);

    // Initial load — wait for CSRF token fetch then load
    AC.fetchCsrfToken().then(function() {
        return loadPublicInterfaces();
    }).then(function() {
        loadDevice();
    });
})();
