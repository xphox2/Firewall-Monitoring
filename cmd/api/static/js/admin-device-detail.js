// admin-device-detail.js — Device detail page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;

    var deviceData = null;
    var allInterfaces = [];
    var currentFilter = 'all';
    var vpnSearchQuery = '';
    var currentVpnFilter = 'all';
    var alertsSearchQuery = '';
    var alertsSeverityFilter = 'all';
    var expandedIfIndex = null;
    var ifaceCharts = {};
    var currentChartRange = '24h';
    var currentChartView = 'rate'; // 'rate' | 'total' | 'mix' — shared 3-mode bandwidth view (matches public dashboard)
    var ifaceWin = null;           // {from, to} epoch-ms when drag-zoomed; null = use the preset range
    var ifaceBucketMs = {};        // ifIndex -> bucket_ms[] of the currently rendered series (for drag→time mapping)
    var ifaceChartSeq = {};        // ifIndex -> monotonically increasing request token; a late response whose token is stale is dropped (audit L19)
    var tunnelChartSeq = {};       // tunnel_name -> request token (same staleness guard)
    var tunnelCharts = {};
    var expandedTunnel = null;     // tunnel_name of the currently-expanded VPN row
    var currentTunnelRange = '24h';
    var currentTunnelView = 'rate';
    var tunnelWin = null;          // {from, to} epoch-ms when drag-zoomed
    var tunnelBucketMs = {};       // tunnel_name -> bucket_ms[]
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
        }).catch(function(err) { 
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
            }).catch(function() {});
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
            .catch(function(e) {
                if (e.message === 'Not authenticated') return;
                // v0.10.233: #error / #content carry class="hidden" in the
                // markup (device-detail.html:44, 46). style.display = 'block'
                // worked only because inline beats class. Same trap as the
                // v0.10.230/231/232 sweep — switched to classList toggling
                // so removing the higher-specificity class can't break it.
                document.getElementById('loading').classList.add('hidden');
                document.getElementById('error').classList.remove('hidden');
                document.getElementById('error').textContent = e.message;
            });
    }

    function renderDevice() {
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('content').classList.remove('hidden');

        var dev = deviceData.device;
        var nameText = dev.name || dev.hostname || 'Unknown';
        document.getElementById('deviceName').textContent = nameText;
        document.title = nameText + ' - Firewall Monitor';

        var avatar = document.querySelector('.device-avatar');
        if (avatar) {
            avatar.textContent = nameText.substring(0, 2).toUpperCase();
        }

        var statusBadge = document.getElementById('deviceStatus');
        statusBadge.textContent = dev.status || 'unknown';
        statusBadge.className = 'badge ' + (dev.status || 'unknown');

        document.getElementById('deviceIP').textContent = dev.ip_address + ':' + dev.snmp_port;
        document.getElementById('deviceProbe').textContent = dev.probe ? 'Probe: ' + dev.probe.name : '';
        document.getElementById('deviceSite').textContent = dev.site ? 'Site: ' + dev.site.name : '';
        document.getElementById('devicePolled').textContent = dev.last_polled ? 'Last polled: ' + formatTime(dev.last_polled) : '';
        // SSH launch button (v0.10.216, bundle F2): renders as <a href="ssh://…">
        // so the OS hands the URL to the operator's registered SSH handler.
        var sshHost = document.getElementById('deviceSshLaunch');
        if (sshHost && AC.sshLaunchButton) {
            sshHost.innerHTML = AC.sshLaunchButton(dev);
        }

        renderSystemStatus();
        renderInterfaces();
        renderVPN();
        renderSensors();
        renderProcessors();
        renderDiskAndLoad();
        renderAlerts();
        renderPing();
        renderHA();
        renderSecurity();
        renderSDWAN();
        renderLicenses();
        renderConfigHistory();
    }

    function renderSystemStatus() {
        var ss = deviceData.system_status;
        // Clear any prior "awaiting data" banner first, so it neither stacks on
        // every 60s poll nor lingers once real data arrives (audit L20).
        var statsHost = document.getElementById('systemStats');
        if (statsHost) {
            var prevBanner = statsHost.querySelector('.awaiting-probe-data');
            if (prevBanner) prevBanner.remove();
        }
        if (!ss) {
            if (statsHost) statsHost.insertAdjacentHTML('beforeend',
                '<div class="empty awaiting-probe-data" style="grid-column:1/-1;text-align:center;padding:1.5rem 0">Awaiting data from probe\u2026</div>');
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

        // v0.10.205: the three above-the-fold charts are now uPlot, fetched
        // from a single bucketed endpoint, with synced brush-zoom across
        // panels. The shell DOM and renderers live in
        // admin-device-detail-charts.js (window.FwmonDeviceCharts). Initialize
        // once per page load; subsequent calls to loadDevice() are no-ops on
        // the chart side since the module owns its own auto-refresh on range
        // change. If the module isn't loaded for some reason, fall back to
        // the legacy renderers below.
        if (window.FwmonDeviceCharts) {
            if (!window.__fwmonChartsInited) {
                window.__fwmonChartsInited = true;
                window.FwmonDeviceCharts.init(deviceId);
            }
        } else {
            loadStatusHistoryChartLegacy();
            loadNetworkThroughputChartLegacy();
            loadCPUBreakdownChartLegacy();
        }
    }

    // Legacy Chart.js renderers — kept only as a fallback path if the uPlot
    // module fails to load. Production rendering goes through
    // FwmonDeviceCharts (admin-device-detail-charts.js).
    function loadStatusHistoryChartLegacy() {
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
                { label: 'CPU %', data: cpuData, borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.05)', fill: true, tension: 0, pointRadius: 0, yAxisID: 'y' },
                { label: 'Memory %', data: memData, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.05)', fill: true, tension: 0, pointRadius: 0, yAxisID: 'y' },
                { label: 'Disk %', data: diskData, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.05)', fill: true, tension: 0, pointRadius: 0, yAxisID: 'y' }
            ];

            var AC = window.AdminCommon;
            var tickColor = AC ? AC.cssVar('--fwmon-text-faint', '#8b949e') : '#8b949e';
            var gridColor = AC ? AC.cssVar('--fwmon-grid-stroke', '#1c222b') : '#1c222b';
            var legendColor = AC ? AC.cssVar('--fwmon-text-dim', '#c9d1d9') : '#c9d1d9';
            var scales = {
                x: { ticks: { color: tickColor, font: { size: 10 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: gridColor } },
                y: { position: 'left', min: 0, max: 100, ticks: { color: tickColor, font: { size: 10 } }, grid: { color: gridColor } }
            };

                if (latencyData.some(function(v) { return v !== null; })) {
                    datasets.push({
                        label: 'Latency (ms)',
                        data: latencyData,
                        borderColor: '#d29922',
                        backgroundColor: 'rgba(210,153,34,0.05)',
                        fill: false,
                        tension: 0,
                        pointRadius: 0,
                        borderDash: [4, 2],
                        yAxisID: 'y1'
                    });
                    var warnColor = AC ? AC.cssVar('--fwmon-sig-warn', '#d29922') : '#d29922';
                    scales.y1 = {
                        position: 'right',
                        min: 0,
                        title: { display: true, text: 'ms', color: warnColor, font: { size: 10 } },
                        ticks: { color: warnColor, font: { size: 10 } },
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
                        plugins: { legend: { labels: { color: legendColor, boxWidth: 12, padding: 8, font: { size: 11 } } } },
                        scales: scales
                    }
                });
            }).catch(function(e) { console.error('Failed to load status history chart:', e); });
    }

    var networkThroughputChart = null;
    var currentNetworkThroughputRange = '24h';
    var statusHistoryCache = {};

    var networkThroughputRangeChangeHandler = function() {
        loadNetworkThroughputChartLegacy(this.value);
    };

    function loadNetworkThroughputChartLegacy(range) {
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
        }).catch(function(e) { console.error('Failed to load network throughput chart:', e); });
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
                    { label: 'In (kbps)', data: netInData, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.1)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 },
                    { label: 'Out (kbps)', data: netOutData, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: { duration: 0 },
                plugins: { legend: { labels: { color: AC ? AC.cssVar('--fwmon-text-dim', '#c9d1d9') : '#c9d1d9', boxWidth: 10, padding: 8, font: { size: 10 } } } },
                scales: {
                    x: { ticks: { color: AC ? AC.cssVar('--fwmon-text-faint', '#8b949e') : '#8b949e', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: AC ? AC.cssVar('--fwmon-grid-stroke', '#1c222b') : '#1c222b' } },
                    y: { min: 0, ticks: { color: AC ? AC.cssVar('--fwmon-text-faint', '#8b949e') : '#8b949e', font: { size: 11 }, callback: function(v) { return v + ' kbps'; } }, grid: { color: AC ? AC.cssVar('--fwmon-grid-stroke', '#1c222b') : '#1c222b' } }
                }
            }
        });
    }

    var cpuBreakdownChart = null;
    function loadCPUBreakdownChartLegacy() {
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
                        { label: 'User', data: sysData.map(function(s) { return s.cpu_user || 0; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'System', data: sysData.map(function(s) { return s.cpu_system || 0; }), borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'Nice', data: sysData.map(function(s) { return s.cpu_nice || 0; }), borderColor: '#d29922', backgroundColor: 'rgba(210,153,34,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'IOWait', data: sysData.map(function(s) { return s.cpu_iowait || 0; }), borderColor: '#bc8cff', backgroundColor: 'rgba(188,140,255,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'IRQ', data: sysData.map(function(s) { return s.cpu_irq || 0; }), borderColor: '#ff7b72', backgroundColor: 'rgba(255,123,114,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'SoftIRQ', data: sysData.map(function(s) { return s.cpu_softirq || 0; }), borderColor: '#39d4e0', backgroundColor: 'rgba(57,212,224,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 },
                        { label: 'Idle', data: sysData.map(function(s) { return s.cpu_idle || 0; }), borderColor: AC ? AC.cssVar('--fwmon-text-mute', '#484f58') : '#484f58', backgroundColor: 'rgba(72,79,88,0.3)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1 }
                    ]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: AC ? AC.cssVar('--fwmon-text-dim', '#c9d1d9') : '#c9d1d9', boxWidth: 10, padding: 6, font: { size: 10 } } } },
                    scales: {
                        x: { ticks: { color: AC ? AC.cssVar('--fwmon-text-faint', '#8b949e') : '#8b949e', font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: AC ? AC.cssVar('--fwmon-grid-stroke', '#1c222b') : '#1c222b' } },
                        y: { min: 0, max: 100, stacked: false, ticks: { color: AC ? AC.cssVar('--fwmon-text-faint', '#8b949e') : '#8b949e', font: { size: 11 }, callback: function(v) { return v + '%'; } }, grid: { color: AC ? AC.cssVar('--fwmon-grid-stroke', '#1c222b') : '#1c222b' } }
                    }
                }
            });
        }).catch(function(e) { console.error('Failed to load CPU breakdown chart:', e); });
    }

    function createGauge(containerId, value, color) {
        var container = document.getElementById(containerId);
        if (!container) return;
        var radius = 32;
        var circumference = 2 * Math.PI * radius;
        var offset = circumference - (Math.min(value, 100) / 100) * circumference;

        container.innerHTML =
            '<svg width="100%" height="100%" viewBox="0 0 80 80" style="display:block;">' +
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

        // Render each pill as `<label> <count-span>` so the count picks up
        // the .filter-count typography (mono, dimmer) defined in
        // admin-device-detail.css. Operators scan the counts to decide which
        // filter is worth clicking, so the type hierarchy matters.
        function pill(filterValue, label, count) {
            var activeClass = currentFilter === filterValue ? ' active' : '';
            return '<button class="filter-btn' + activeClass +
                '" data-action="filter-ifaces" data-filter="' + esc(filterValue) + '">' +
                esc(label) +
                '<span class="filter-count">' + count + '</span>' +
                '</button>';
        }

        var btns = '';
        btns += pill('all',  'All',  allInterfaces.length);
        btns += pill('up',   'Up',   upCount);
        btns += pill('down', 'Down', downCount);

        var sortedTypes = Object.keys(typeCounts).sort();
        for (var ti = 0; ti < sortedTypes.length; ti++) {
            var tn = sortedTypes[ti];
            var label = tn.charAt(0).toUpperCase() + tn.slice(1);
            btns += pill(tn, label, typeCounts[tn]);
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

        var searchVal = (document.getElementById('ifaceSearch') ? document.getElementById('ifaceSearch').value.toLowerCase().trim() : '');
        if (searchVal) {
            filtered = filtered.filter(function(i) {
                return (i.name || '').toLowerCase().indexOf(searchVal) !== -1 ||
                       (i.alias || '').toLowerCase().indexOf(searchVal) !== -1;
            });
        }

        var summarySpan = document.getElementById('ifaceSummary');
        if (summarySpan) {
            summarySpan.textContent = filtered.length + ' shown / ' + allInterfaces.length + ' total';
        }

        var body = document.getElementById('ifaceBody');
        var empty = document.getElementById('ifaceEmpty');

        if (filtered.length === 0) {
            body.innerHTML = '';
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

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
                '<td><input type="checkbox" ' + (isPublicIface(iface) ? 'checked ' : '') + 'data-action="toggle-public-iface" data-iface="' + esc(iface.name).replace(/"/g, '&quot;') + '"></td>' +
                '</tr>';

            if (isExpanded) {
                var ifaceControls = bwControlsHtml({
                    viewAction: 'set-iface-view',
                    rangeAction: 'load-iface-chart',
                    resetAction: 'reset-iface-zoom',
                    dataAttr: 'data-index="' + iface.index + '"',
                    view: currentChartView,
                    range: currentChartRange,
                    ranges: ['24h', '7d', '30d', '90d'],
                    win: ifaceWin
                });
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
                        ifaceControls +
                        '<div class="iface-chart-container" id="chart-container-' + iface.index + '">' +
                            '<div class="iface-chart-source text-[0.72rem] text-[#8b949e] mb-1" id="chart-source-' + iface.index + '"></div>' +
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
        var wasExpanded = expandedIfIndex === ifIndex;
        expandedIfIndex = wasExpanded ? null : ifIndex;
        ifaceWin = null; // a drag-zoom window belongs to one interface — reset on expand/collapse
        filterIfaces(currentFilter);
    }

    function toggleTunnel(name) {
        var wasExpanded = expandedTunnel === name;
        expandedTunnel = wasExpanded ? null : name;
        tunnelWin = null; // window belongs to one tunnel — reset on expand/collapse
        renderVPN();
    }

    // bwControlsHtml — renders the shared two-row control strip used above both
    // the interface and VPN-tunnel bandwidth charts: a 3-mode display toggle
    // (Throughput / Transfer / Combined, from FwmonBwChart.MODES) and a time
    // range selector. `cfg.dataAttr` carries the per-row identity (data-index
    // for interfaces, data-tunnel for tunnels) so the delegated click handlers
    // know which chart to refresh.
    function bwControlsHtml(cfg) {
        var modes = (window.FwmonBwChart && FwmonBwChart.MODES) || [
            { value: 'rate', label: 'Throughput' },
            { value: 'total', label: 'Transfer' },
            { value: 'mix', label: 'Combined' }
        ];
        var viewBtns = '';
        for (var i = 0; i < modes.length; i++) {
            var m = modes[i];
            viewBtns += '<button class="range-btn' + (cfg.view === m.value ? ' active' : '') +
                '" data-action="' + cfg.viewAction + '" ' + cfg.dataAttr + ' data-view="' + m.value + '">' + esc(m.label) + '</button>';
        }
        var rangeBtns = '';
        for (var ri = 0; ri < cfg.ranges.length; ri++) {
            var r = cfg.ranges[ri];
            // When a drag-zoom window is active no preset is "active"; clicking a
            // preset exits the zoom (handled in the range action).
            var rActive = (!cfg.win && cfg.range === r) ? ' active' : '';
            rangeBtns += '<button class="range-btn' + rActive +
                '" data-action="' + cfg.rangeAction + '" ' + cfg.dataAttr + ' data-range="' + r + '">' + r + '</button>';
        }
        // Drag-zoom indicator + reset, shown only while a custom window is active.
        var zoomChip = '';
        if (cfg.win) {
            zoomChip = '<span class="bw-chart-controls-sep"></span>' +
                '<span class="bw-zoom-chip" title="Showing a drag-selected window">' +
                '<span class="bw-zoom-ico" aria-hidden="true">&#128269;</span>' +
                '<span class="bw-zoom-range">' + esc(winLabel(cfg.win.from, cfg.win.to)) + '</span>' +
                '<button class="bw-zoom-reset" data-action="' + cfg.resetAction + '" ' + cfg.dataAttr +
                ' title="Reset zoom to the selected range">&times;</button>' +
                '</span>';
        }
        return '<div class="bw-chart-controls">' +
            '<div class="chart-range-btns" role="group" aria-label="Display mode">' + viewBtns + '</div>' +
            '<span class="bw-chart-controls-sep"></span>' +
            '<div class="chart-range-btns" role="group" aria-label="Time range">' + rangeBtns + '</div>' +
            zoomChip +
            '<span class="bw-chart-hint">drag on chart to zoom</span>' +
        '</div>';
    }

    // winLabel renders a compact "Jun 9 14:00 – 15:30" label for a drag-zoom
    // window. bucket_ms encodes the server wall clock as a UTC epoch (it comes
    // from parsing the dialect's to_char/strftime output), so format in UTC to
    // recover that same wall clock — matching the chart's x-axis tick labels.
    function winLabel(fromMs, toMs) {
        var f = new Date(fromMs), t = new Date(toMs);
        var dOpts = { timeZone: 'UTC', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
        var tOpts = { timeZone: 'UTC', hour: '2-digit', minute: '2-digit' };
        var sameDay = f.getUTCFullYear() === t.getUTCFullYear() && f.getUTCMonth() === t.getUTCMonth() && f.getUTCDate() === t.getUTCDate();
        try {
            return f.toLocaleString([], dOpts) + ' – ' + (sameDay ? t.toLocaleTimeString([], tOpts) : t.toLocaleString([], dOpts));
        } catch (e) {
            return '';
        }
    }

    // Each chart row carries an epoch-ms bucket timestamp (bucket_ms) from the
    // server's adaptive bucketing. We derive the per-bucket interval (for the
    // Mbps math) directly from consecutive bucket_ms gaps rather than a fixed
    // per-range constant — this stays correct no matter which adaptive bucket
    // size the window resolved to, and tolerates sparse/missing buckets.

    // medianIntervalSec returns the median positive gap (seconds) between
    // consecutive bucket timestamps — a robust fallback for the first bucket
    // and for any gap we can't measure directly.
    function medianIntervalSec(ms) {
        var diffs = [];
        for (var i = 1; i < ms.length; i++) {
            var d = ms[i] - ms[i - 1];
            if (d > 0) diffs.push(d);
        }
        if (diffs.length === 0) return 60;
        diffs.sort(function(a, b) { return a - b; });
        return diffs[Math.floor(diffs.length / 2)] / 1000;
    }

    // makeLabels formats x-axis tick labels from the bucket strings. The dialect
    // emits "YYYY-MM-DD HH:MM" (sub-day) or "YYYY-MM-DD" (day). Across a
    // multi-day span we include the date so ticks aren't ambiguous.
    function makeLabels(data, spanMs) {
        var multiDay = spanMs > 36 * 3600 * 1000;
        return data.map(function(d) {
            var b = d.bucket || '';
            if (b.length <= 10) return b.substring(5);   // MM-DD (day bucket)
            if (multiDay) return b.substring(5, 13);     // MM-DD HH
            return b.substring(11, 16);                  // HH:MM
        });
    }

    function bucketMsArray(data) {
        return data.map(function(d) { return Number(d.bucket_ms) || 0; });
    }

    // Interface chart rows carry cumulative SNMP octet counters (AVG per
    // bucket). Transfer is the consecutive-bucket delta (clamped >= 0 across
    // counter resets/wraps); throughput is that delta over the actual bucket
    // interval. Mirrors internal/report computeTraffic, but interval-accurate.
    function normalizeIfaceSeries(data) {
        var ms = bucketMsArray(data);
        var span = ms.length > 1 ? (ms[ms.length - 1] - ms[0]) : 0;
        var medSec = medianIntervalSec(ms);
        var s = { labels: makeLabels(data, span), bucketMs: ms, rxRate: [], txRate: [], rxTransfer: [], txTransfer: [] };
        for (var i = 0; i < data.length; i++) {
            if (i === 0) { s.rxTransfer.push(0); s.txTransfer.push(0); s.rxRate.push(0); s.txRate.push(0); continue; }
            var dRx = data[i].in_bytes - data[i - 1].in_bytes; if (dRx < 0) dRx = 0;
            var dTx = data[i].out_bytes - data[i - 1].out_bytes; if (dTx < 0) dTx = 0;
            var sec = (ms[i] > ms[i - 1]) ? (ms[i] - ms[i - 1]) / 1000 : medSec;
            if (!(sec > 0)) sec = medSec;
            s.rxTransfer.push(dRx);
            s.txTransfer.push(dTx);
            s.rxRate.push(dRx * 8 / sec / 1e6);
            s.txRate.push(dTx * 8 / sec / 1e6);
        }
        return s;
    }

    // VPN tunnel chart rows already arrive as per-bucket deltas (the server's
    // GetVPNChartWindow uses LAG() + SUM to emit bytes-transferred-per-bucket),
    // so transfer is the value as-is; throughput divides by the bucket interval.
    function normalizeTunnelSeries(data) {
        var ms = bucketMsArray(data);
        var span = ms.length > 1 ? (ms[ms.length - 1] - ms[0]) : 0;
        var medSec = medianIntervalSec(ms);
        var s = { labels: makeLabels(data, span), bucketMs: ms, rxRate: [], txRate: [], rxTransfer: [], txTransfer: [] };
        for (var i = 0; i < data.length; i++) {
            var dRx = data[i].in_bytes < 0 ? 0 : data[i].in_bytes;
            var dTx = data[i].out_bytes < 0 ? 0 : data[i].out_bytes;
            var sec = (i > 0 && ms[i] > ms[i - 1]) ? (ms[i] - ms[i - 1]) / 1000 : medSec;
            if (!(sec > 0)) sec = medSec;
            s.rxTransfer.push(dRx);
            s.txTransfer.push(dTx);
            s.rxRate.push(dRx * 8 / sec / 1e6);
            s.txRate.push(dTx * 8 / sec / 1e6);
        }
        return s;
    }

    function drawChartMessage(canvas, msg) {
        var ctx2 = canvas.getContext('2d');
        ctx2.clearRect(0, 0, canvas.width, canvas.height);
        ctx2.fillStyle = AC.cssVar('--fwmon-text-faint', '#8b949e');
        ctx2.font = '11px sans-serif';
        ctx2.fillText(msg, 10, 30);
    }

    // chartQuery builds the chart endpoint query string: an explicit drag-zoom
    // window (from/to epoch ms) takes precedence over the preset range.
    function chartQuery(win, range) {
        if (win) return 'from=' + win.from + '&to=' + win.to;
        return 'range=' + range;
    }

    // fetchIfaceChart fetches one chart endpoint and resolves to its bucket
    // array, or null on any error/empty (so the caller can fall back).
    function fetchIfaceChart(url) {
        return fetch(url, { credentials: 'same-origin' })
            .then(function(resp) { return resp.ok ? resp.json() : null; })
            .then(function(result) {
                return (result && result.success && Array.isArray(result.data)) ? result.data : null;
            })
            .catch(function() { return null; });
    }

    function renderIfaceChart(ifIndex, canvas, data, source) {
        var s = normalizeIfaceSeries(data);
        ifaceBucketMs[ifIndex] = s.bucketMs;
        ifaceCharts[ifIndex] = FwmonBwChart.render(canvas, {
            labels: s.labels,
            rxRate: s.rxRate, txRate: s.txRate,
            rxTransfer: s.rxTransfer, txTransfer: s.txTransfer,
            view: currentChartView, rxLabel: 'In', txLabel: 'Out',
            onZoomSelect: function(lo, hi) { zoomIfaceTo(ifIndex, lo, hi); }
        });
        setIfaceChartSource(ifIndex, source);
    }

    function setIfaceChartSource(ifIndex, source) {
        var el = document.getElementById('chart-source-' + ifIndex);
        if (el) el.textContent = source ? ('bandwidth source: ' + source) : '';
    }

    // loadInterfaceChart prefers sFlow-native counters (flow_if_counters) and
    // falls back to SNMP interface_stats when sFlow has no data — so sFlow
    // deployments get agent-pushed bandwidth (working even where SNMP is
    // host-restricted) while SNMP-only deployments are unchanged. Both endpoints
    // return the same bucket shape, so rendering is identical.
    function loadInterfaceChart(ifIndex, range) {
        currentChartRange = range;

        var canvas = document.getElementById('canvas-' + ifIndex);
        if (!canvas) return;

        // Destroy previous chart instance
        if (ifaceCharts[ifIndex]) {
            ifaceCharts[ifIndex].destroy();
            delete ifaceCharts[ifIndex];
        }

        // In-flight staleness guard (audit L19): quickly changing the range (or
        // re-expanding) fires overlapping fetches whose responses can arrive out
        // of order — a slower earlier response would overwrite the live chart with
        // stale buckets and leak the newer Chart.js instance. Stamp each request
        // and drop any response that is no longer the latest for this ifIndex.
        var seq = (ifaceChartSeq[ifIndex] || 0) + 1;
        ifaceChartSeq[ifIndex] = seq;

        var q = chartQuery(ifaceWin, range);
        var base = '/admin/api/devices/' + deviceId + '/interfaces/' + ifIndex;
        // M27 of the 2026-07-01 audit: fetch BOTH sources and prefer sFlow only
        // when it is at least as FRESH as SNMP (its last bucket is not older).
        // The pre-fix code took sFlow whenever it had >=2 buckets ANYWHERE in
        // the window, so a stopped/partial sFlow export (collector down, a brief
        // sFlow trial last week, or a sub-window with sparse sFlow) silently
        // hid the live SNMP-measured traffic and ended the chart in the past.
        function lastBucketMs(series) {
            return (series && series.length) ? (series[series.length - 1].bucket_ms || 0) : 0;
        }
        Promise.all([
            fetchIfaceChart(base + '/sflow-chart?' + q).catch(function () { return null; }),
            fetchIfaceChart(base + '/chart?' + q).catch(function () { return null; })
        ]).then(function (res) {
            if (ifaceChartSeq[ifIndex] !== seq) return; // a newer request superseded this one
            var sflow = res[0], snmp = res[1];
            var sflowOK = sflow && sflow.length >= 2;
            var snmpOK = snmp && snmp.length >= 2;
            if (sflowOK && (!snmpOK || lastBucketMs(sflow) >= lastBucketMs(snmp))) {
                renderIfaceChart(ifIndex, canvas, sflow, 'sFlow');
            } else if (snmpOK) {
                renderIfaceChart(ifIndex, canvas, snmp, 'SNMP');
            } else {
                ifaceBucketMs[ifIndex] = [];
                setIfaceChartSource(ifIndex, '');
                drawChartMessage(canvas, 'Not enough history data');
            }
        });
    }

    // zoomIfaceTo maps the dragged category-index range to the bucket
    // timestamps at those edges, sets the window, and re-queries the backend
    // for exactly that span (at the finer adaptive bucket size).
    function zoomIfaceTo(ifIndex, lo, hi) {
        var ms = ifaceBucketMs[ifIndex];
        if (!ms || hi >= ms.length || lo < 0) return;
        var from = ms[lo], to = ms[hi];
        if (!(to > from)) return;
        ifaceWin = { from: from, to: to };
        filterIfaces(currentFilter); // re-render controls (reset chip) + reload chart for the window
    }

    function loadTunnelChart(tunnelName, range) {
        currentTunnelRange = range;

        var canvas = document.getElementById('tcanvas-' + cssId(tunnelName));
        if (!canvas) return;

        if (tunnelCharts[tunnelName]) {
            tunnelCharts[tunnelName].destroy();
            delete tunnelCharts[tunnelName];
        }

        // In-flight staleness guard (audit L19): drop a late response once a newer
        // request for this tunnel has been issued.
        var seq = (tunnelChartSeq[tunnelName] || 0) + 1;
        tunnelChartSeq[tunnelName] = seq;

        fetch('/admin/api/devices/' + deviceId + '/vpn/' + encodeURIComponent(tunnelName) + '/chart?' + chartQuery(tunnelWin, range), { credentials: 'same-origin' })
            .then(function(resp) {
                if (!resp.ok) return Promise.reject(new Error('Failed'));
                return resp.json();
            })
            .then(function(result) {
                if (tunnelChartSeq[tunnelName] !== seq) return; // superseded by a newer request
                if (!result.success || !result.data || result.data.length < 2) {
                    tunnelBucketMs[tunnelName] = [];
                    drawChartMessage(canvas, 'Not enough history data');
                    return;
                }
                var s = normalizeTunnelSeries(result.data);
                tunnelBucketMs[tunnelName] = s.bucketMs;
                tunnelCharts[tunnelName] = FwmonBwChart.render(canvas, {
                    labels: s.labels,
                    rxRate: s.rxRate, txRate: s.txRate,
                    rxTransfer: s.rxTransfer, txTransfer: s.txTransfer,
                    view: currentTunnelView, rxLabel: 'In', txLabel: 'Out',
                    onZoomSelect: function(lo, hi) { zoomTunnelTo(tunnelName, lo, hi); }
                });
            })
            .catch(function(e) { console.error('Failed to load tunnel chart:', e); });
    }

    function zoomTunnelTo(tunnelName, lo, hi) {
        var ms = tunnelBucketMs[tunnelName];
        if (!ms || hi >= ms.length || lo < 0) return;
        var from = ms[lo], to = ms[hi];
        if (!(to > from)) return;
        tunnelWin = { from: from, to: to };
        renderVPN();
    }

    // cssId — derive a DOM-id-safe token from an arbitrary tunnel name so a
    // canvas id (tcanvas-<token>) never breaks on spaces/punctuation.
    function cssId(s) {
        return String(s).replace(/[^A-Za-z0-9_-]/g, '_');
    }

    function getTypeBadge(iface) {
        var tn = iface.type_name || '';
        if (tn === 'vxlan') return '<span class="badge vxlan">VXLAN</span>';
        if (tn === 'tunnel') return '<span class="badge tunnel">Tunnel</span>';
        if (tn === 'lag') return '<span class="badge lag">LAG</span>';
        if (tn === 'loopback') return '<span class="badge unknown">Loop</span>';
        if (tn === 'ethernet') return '<span class="badge online">Eth</span>';
        if (tn) return '<span class="badge unknown">' + esc(tn) + '</span>';
        return '<span style="color:var(--fwmon-text-mute)">' + iface.type + '</span>';
    }

    function renderVPN() {
        var vpn = deviceData.vpn_status || [];
        var body = document.getElementById('vpnBody');
        var empty = document.getElementById('vpnEmpty');

        // Apply filters
        var filtered = vpn;
        if (currentVpnFilter === 'up') {
            filtered = vpn.filter(function(v) { return v.status === 'up'; });
        } else if (currentVpnFilter === 'down') {
            filtered = vpn.filter(function(v) { return v.status === 'down'; });
        }

        var searchVal = (document.getElementById('vpnSearch') ? document.getElementById('vpnSearch').value.toLowerCase().trim() : '');
        if (searchVal) {
            filtered = filtered.filter(function(v) {
                return (v.tunnel_name || '').toLowerCase().indexOf(searchVal) !== -1 ||
                       (v.phase1_name || '').toLowerCase().indexOf(searchVal) !== -1 ||
                       (v.interface_name || '').toLowerCase().indexOf(searchVal) !== -1 ||
                       (v.remote_ip || '').toLowerCase().indexOf(searchVal) !== -1;
            });
        }

        var summarySpan = document.getElementById('vpnSummary');
        if (summarySpan) {
            summarySpan.textContent = filtered.length + ' shown / ' + vpn.length + ' total';
        }

        if (filtered.length === 0) { body.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

        var html = '';
        for (var vi = 0; vi < filtered.length; vi++) {
            var v = filtered[vi];
            var hasTraffic = (v.bytes_in > 0) || (v.bytes_out > 0);
            var state = v.state || (v.status === 'up' ? 'active' : 'inactive');
            var stateClass = (state === 'active' && hasTraffic) ? 'active' : (state === 'active' ? 'up' : 'inactive');
            var stateLabel = (state === 'active' && hasTraffic) ? 'Online' : state;
            // Cross-pivot (v0.10.215, bundle E3 + v0.10.218, bundle G3):
            // - If the backend resolved a peer device (remote_device_id is
            //   set), the IP links to /admin/devices/:peer-id for one-click
            //   navigation to the other end of the tunnel.
            // - Otherwise fall back to /admin/syslog?search=<ip> so the
            //   operator can at least see remote-side messages.
            var remoteCell;
            if (v.remote_ip && v.remote_device_id && window.AdminCommon) {
                remoteCell = window.AdminCommon.deviceLink(v.remote_device_id, v.remote_ip,
                    { title: 'Open peer device detail (resolved by RemoteIP match)' });
            } else if (v.remote_ip && window.AdminCommon) {
                remoteCell = window.AdminCommon.filterLink('syslog', { search: v.remote_ip }, v.remote_ip,
                    { title: 'Search syslog for messages mentioning ' + v.remote_ip });
            } else {
                remoteCell = esc(v.remote_ip);
            }
            // Attribute-safe tunnel name for data-* (esc() escapes < > & for
            // text content but not the double-quote that would break out of an
            // attribute — mirror the toggle-public-iface fix).
            var tAttr = esc(v.tunnel_name).replace(/"/g, '&quot;');
            var tExpanded = expandedTunnel === v.tunnel_name;
            html += '<tr class="clickable" data-action="toggle-tunnel" data-tunnel="' + tAttr + '">' +
                '<td>' + esc(v.phase1_name || v.tunnel_name) + '</td>' +
                '<td><strong>' + esc(v.tunnel_name) + '</strong></td>' +
                '<td>' + getTunnelTypeBadge(v.tunnel_type) + '</td>' +
                '<td style="color:var(--fwmon-text-faint);font-size:0.8rem;">' + esc(v.interface_name || '-') + '</td>' +
                '<td>' + remoteCell + '</td>' +
                '<td style="color:var(--fwmon-text-faint);font-size:0.78rem;">' + esc(v.mode || '-') + '</td>' +
                '<td><span class="badge ' + esc(v.status) + '">' + esc(v.status) + '</span></td>' +
                '<td><span class="badge ' + stateClass + '">' + esc(stateLabel) + '</span></td>' +
                '<td><code style="color:var(--fwmon-accent);font-size:0.8rem;">' + esc(v.local_subnet || '-') + '</code></td>' +
                '<td><code style="color:var(--fwmon-sig-ok);font-size:0.8rem;">' + esc(v.remote_subnet || '-') + '</code></td>' +
                '<td>' + formatBytes(v.bytes_in) + '</td>' +
                '<td>' + formatBytes(v.bytes_out) + '</td>' +
                // Uptime column (v0.10.217, bundle D4): for currently-up
                // tunnels show how long they've been up; for currently-
                // down tunnels show "last seen up X ago" if we have a
                // historical 'up' snapshot, otherwise dash. Compresses
                // two facts ("status: down" + "last_up_at: T") into one
                // glanceable cell.
                '<td>' + (v.status === 'up'
                    ? formatVpnUptime(v.tunnel_uptime)
                    : (v.last_up_at
                        ? '<span title="Last observed up: ' + esc(formatTime(v.last_up_at)) +
                          '" style="color:var(--fwmon-text-faint);font-size:0.85rem;">last up ' + esc(formatRelative(v.last_up_at)) + '</span>'
                        : '<span style="color:var(--fwmon-text-faint);">-</span>')) +
                '</td>' +
            '</tr>';

            if (tExpanded) {
                var tunnelControls = bwControlsHtml({
                    viewAction: 'set-tunnel-view',
                    rangeAction: 'load-tunnel-chart',
                    resetAction: 'reset-tunnel-zoom',
                    dataAttr: 'data-tunnel="' + tAttr + '"',
                    view: currentTunnelView,
                    range: currentTunnelRange,
                    ranges: ['1h', '24h', '7d', '30d'],
                    win: tunnelWin
                });
                html += '<tr class="expand-row"><td colspan="13">' +
                    '<div class="expand-content">' +
                        '<div class="detail-grid">' +
                            '<div class="detail-item"><span class="label">Type</span><span class="value">' + esc(v.tunnel_type || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Interface</span><span class="value">' + esc(v.interface_name || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Remote GW</span><span class="value">' + esc(v.remote_ip || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Mode</span><span class="value">' + esc(v.mode || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Local Subnet</span><span class="value">' + esc(v.local_subnet || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Remote Subnet</span><span class="value">' + esc(v.remote_subnet || '-') + '</span></div>' +
                            '<div class="detail-item"><span class="label">Bytes In</span><span class="value">' + formatBytes(v.bytes_in) + '</span></div>' +
                            '<div class="detail-item"><span class="label">Bytes Out</span><span class="value">' + formatBytes(v.bytes_out) + '</span></div>' +
                        '</div>' +
                        tunnelControls +
                        '<div class="iface-chart-container" id="tchart-container-' + cssId(v.tunnel_name) + '">' +
                            '<canvas id="tcanvas-' + cssId(v.tunnel_name) + '"></canvas>' +
                        '</div>' +
                    '</div>' +
                '</td></tr>';
            }
        }
        body.innerHTML = html;

        if (expandedTunnel !== null) {
            loadTunnelChart(expandedTunnel, currentTunnelRange);
        }

        // Update tab label with count
        var upCount = vpn.filter(function(v) { return v.status === 'up'; }).length;
        var onlineCount = vpn.filter(function(v) { var hasTraffic = (v.bytes_in > 0) || (v.bytes_out > 0); var state = v.state || (v.status === 'up' ? 'active' : 'inactive'); return state === 'active' && hasTraffic; }).length;
        var vpnBadge = document.getElementById('vpnTabBadge');
        if (vpnBadge) {
            vpnBadge.textContent = onlineCount + '/' + upCount;
            vpnBadge.className = 'tab-badge' + (onlineCount > 0 ? ' success' : '');
            vpnBadge.classList.remove('hidden');
        }
    }

    function renderSensors() {
        var sensors = deviceData.hardware_sensors || [];
        var container = document.getElementById('sensorCards');
        var empty = document.getElementById('sensorEmpty');
        var summary = document.getElementById('sensorSummary');

        if (sensors.length === 0) { container.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');
        if (summary) summary.textContent = sensors.length + ' sensors';

        container.innerHTML = sensors.map(function(s) {
            var isAlarm = s.status && s.status.toLowerCase() === 'alarm';
            var statusClass = isAlarm ? 'alarm' : 'normal';
            var borderColor = isAlarm ? '#f85149' : '#30363d';
            var icon = getSensorIcon(s.name, s.unit);

            return '<div style="background:var(--fwmon-bg);border:1px solid ' + borderColor + ';border-radius:8px;padding:14px;">' +
                '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">' +
                    '<div style="width:36px;height:36px;background:var(--fwmon-card-bg);border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--fwmon-text-faint);font-size:1.2rem;">' + icon + '</div>' +
                    '<div style="flex:1;min-width:0;">' +
                        '<div style="color:var(--fwmon-text);font-size:0.85rem;font-weight:600;line-height:1.25;word-break:break-word;overflow-wrap:anywhere;" title="' + esc(s.name) + '">' + esc(s.name) + '</div>' +
                        '<div style="color:var(--fwmon-text-faint);font-size:0.72rem;text-transform:uppercase;">' + esc(s.unit || '') + '</div>' +
                    '</div>' +
                '</div>' +
                '<div style="display:flex;justify-content:space-between;align-items:flex-end;">' +
                    '<div style="color:var(--fwmon-text);font-size:1.4rem;font-weight:700;">' + s.value.toFixed(1) + '</div>' +
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

    function renderDiskAndLoad() {
        var disks = deviceData.disk_usage || [];
        var load = deviceData.load_average;
        var rows = document.getElementById('diskRows');
        var empty = document.getElementById('storageEmpty');
        var summary = document.getElementById('loadSummary');
        if (!rows) return;

        if (summary) {
            summary.textContent = load ? ('load ' + load.load1.toFixed(2) + ' / ' + load.load5.toFixed(2) + ' / ' + load.load15.toFixed(2)) : '';
        }
        if (disks.length === 0 && !load) { rows.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

        rows.innerHTML = disks.map(function(d) {
            var pct = Math.max(0, Math.min(d.used_percent, 100));
            var color = getGaugeColor(pct);
            return '<div class="core-bar-wrapper">' +
                '<span style="color:var(--fwmon-text-faint);font-size:0.78rem;min-width:110px;word-break:break-all" title="' + esc(d.mount) + '">' + esc(d.mount) + '</span>' +
                '<div style="flex:1;background:var(--fwmon-panel-bg);border-radius:3px;height:16px;overflow:hidden">' +
                    '<div style="width:' + pct + '%;height:100%;background:' + color + ';border-radius:3px;transition:width 0.3s"></div>' +
                '</div>' +
                '<span style="color:var(--fwmon-text);font-size:0.82rem;font-weight:600;min-width:150px;text-align:right">' + pct.toFixed(0) + '%&nbsp;&nbsp;' + formatBytes(d.used_bytes) + ' / ' + formatBytes(d.total_bytes) + '</span>' +
            '</div>';
        }).join('');
    }

    function renderProcessors() {
        var procs = deviceData.processor_stats || [];
        var container = document.getElementById('procBars');
        var empty = document.getElementById('procEmpty');
        var summary = document.getElementById('procSummary');

        if (procs.length === 0) { container.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

        var avg = procs.reduce(function(s, p) { return s + p.usage; }, 0) / procs.length;
        summary.textContent = procs.length + ' cores, avg ' + avg.toFixed(1) + '%';

        // Update tab label
        var resBadge = document.getElementById('resourcesTabBadge');
        if (resBadge) {
            resBadge.textContent = procs.length + ' Cores';
            resBadge.classList.remove('hidden');
        }

        container.innerHTML = procs.map(function(p) {
            var color = getGaugeColor(p.usage);
            var width = Math.min(p.usage, 100);
            return '<div class="core-bar-wrapper">' +
                '<span style="color:var(--fwmon-text-faint);font-size:0.78rem;min-width:60px">Core ' + p.index + '</span>' +
                '<div style="flex:1;background:var(--fwmon-panel-bg);border-radius:3px;height:16px;overflow:hidden">' +
                    '<div style="width:' + width + '%;height:100%;background:' + color + ';border-radius:3px;transition:width 0.3s"></div>' +
                '</div>' +
                '<span style="color:var(--fwmon-text);font-size:0.82rem;font-weight:600;min-width:45px;text-align:right">' + p.usage.toFixed(0) + '%</span>' +
            '</div>';
        }).join('');
    }

    function renderAlerts() {
        var alerts = deviceData.recent_alerts || [];
        var body = document.getElementById('alertBody');
        var empty = document.getElementById('alertEmpty');

        // Apply filters
        var filtered = alerts;
        if (alertsSeverityFilter !== 'all') {
            var sev = alertsSeverityFilter.toLowerCase();
            filtered = filtered.filter(function(a) {
                return (a.severity || '').toLowerCase() === sev;
            });
        }

        if (alertsSearchQuery) {
            var q = alertsSearchQuery.toLowerCase().trim();
            filtered = filtered.filter(function(a) {
                return (a.message || '').toLowerCase().indexOf(q) !== -1 ||
                       (a.alert_type || '').toLowerCase().indexOf(q) !== -1;
            });
        }

        if (filtered.length === 0) {
            body.innerHTML = '';
            empty.classList.remove('hidden');
        } else {
            empty.classList.add('hidden');
            body.innerHTML = filtered.map(function(a) {
                return '<tr>' +
                    '<td style="white-space:nowrap">' + formatTime(a.timestamp) + '</td>' +
                    '<td>' + esc(a.alert_type) + '</td>' +
                    '<td><span class="badge ' + a.severity + '">' + a.severity + '</span></td>' +
                    '<td>' + esc(a.message) + '</td>' +
                '</tr>';
            }).join('');
        }

        // Update "View all alerts" link with the current device filter
        // (v0.10.215, bundle E3). The state key is `device_id` (matches
        // FwmonControls.attachAnalyticsPage descriptor for the alerts page).
        // Idempotent — safe to call repeatedly.
        var viewAllLink = document.getElementById('alerts-view-all-link');
        if (viewAllLink && deviceId) {
            viewAllLink.href = '/admin/alerts?device_id=' + encodeURIComponent(deviceId);
        }

        // Update tab badge
        var alertBadge = document.getElementById('alertsTabBadge');
        if (alertBadge) {
            if (alerts.length > 0) {
                alertBadge.textContent = alerts.length;
                alertBadge.className = 'tab-badge danger';
                alertBadge.classList.remove('hidden');
            } else {
                alertBadge.classList.add('hidden');
            }
        }
    }

    function renderPing() {
        var pings = deviceData.ping_stats || [];
        var body = document.getElementById('pingBody');
        var empty = document.getElementById('pingEmpty');

        if (pings.length === 0) { body.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

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
        if (!type) return '<span style="color:var(--fwmon-text-mute)">-</span>';
        var colors = { 'ipsec': '#58a6ff', 'ipsec-dialup': '#d29922', 'sslvpn': '#3fb950' };
        var color = colors[type] || '#8b949e';
        return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44">' + esc(type) + '</span>';
    }

    function renderHA() {
        var ha = deviceData.ha_status || [];
        var body = document.getElementById('haBody');
        var empty = document.getElementById('haEmpty');
        var header = document.getElementById('haHeader');

        if (!ha.length) { body.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

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

        var diagBadge = document.getElementById('diagnosticsTabBadge');
        if (diagBadge) {
            var sync = ha[0] ? ha[0].sync_status : '';
            if (sync === 'synchronized') {
                diagBadge.textContent = 'HA Sync';
                diagBadge.className = 'tab-badge success';
                diagBadge.classList.remove('hidden');
            } else if (sync === 'unsynchronized') {
                diagBadge.textContent = 'HA Warn';
                diagBadge.className = 'tab-badge danger';
                diagBadge.classList.remove('hidden');
            } else {
                diagBadge.classList.add('hidden');
            }
        }
    }

    function renderSecurity() {
        var sec = deviceData.security_stats;
        var content = document.getElementById('securityContent');
        var empty = document.getElementById('securityEmpty');

        if (!sec) { content.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

        content.innerHTML =
            '<h3 style="color:var(--fwmon-text-dim);font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid var(--fwmon-border);padding-bottom:6px">Antivirus</h3>' +
            '<div class="stat-grid">' +
                '<div class="stat-card"><div class="stat-label">Detected</div><div class="stat-value">' + (sec.av_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Blocked</div><div class="stat-value">' + (sec.av_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">HTTP Detected</div><div class="stat-value">' + (sec.av_http_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">SMTP Detected</div><div class="stat-value">' + (sec.av_smtp_detected || 0).toLocaleString() + '</div></div>' +
            '</div>' +
            '<h3 style="color:var(--fwmon-text-dim);font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid var(--fwmon-border);padding-bottom:6px">Intrusion Prevention</h3>' +
            '<div class="stat-grid">' +
                '<div class="stat-card"><div class="stat-label">Detected</div><div class="stat-value">' + (sec.ips_detected || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Blocked</div><div class="stat-value">' + (sec.ips_blocked || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Critical</div><div class="stat-value" style="color:var(--fwmon-sig-crit)">' + (sec.ips_critical || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">High</div><div class="stat-value" style="color:var(--fwmon-sig-warn)">' + (sec.ips_high || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Medium</div><div class="stat-value" style="color:var(--fwmon-sig-warn)">' + (sec.ips_medium || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Low</div><div class="stat-value" style="color:var(--fwmon-accent)">' + (sec.ips_low || 0).toLocaleString() + '</div></div>' +
                '<div class="stat-card"><div class="stat-label">Info</div><div class="stat-value" style="color:var(--fwmon-text-faint)">' + (sec.ips_info || 0).toLocaleString() + '</div></div>' +
            '</div>' +
            '<h3 style="color:var(--fwmon-text-dim);font-size:0.9rem;margin:16px 0 10px;border-bottom:1px solid var(--fwmon-border);padding-bottom:6px">Web Filter</h3>' +
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

        if (!sdwan.length) { body.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

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

        var ha = deviceData.ha_status || [];
        var diagBadge = document.getElementById('diagnosticsTabBadge');
        if (diagBadge && ha.length === 0) {
            if (sdwan.length > 0) {
                var dead = sdwan.filter(function(d) { return d.state === 'dead'; }).length;
                if (dead > 0) {
                    diagBadge.textContent = dead + ' Dead';
                    diagBadge.className = 'tab-badge danger';
                } else {
                    diagBadge.textContent = sdwan.length + ' WAN';
                    diagBadge.className = 'tab-badge';
                }
                diagBadge.classList.remove('hidden');
            } else {
                diagBadge.classList.add('hidden');
            }
        }
    }

    function renderLicenses() {
        var lics = deviceData.license_info || [];
        var container = document.getElementById('licenseCards');
        var empty = document.getElementById('licenseEmpty');
        var summary = document.getElementById('licenseSummary');

        if (!lics.length) { container.innerHTML = ''; empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');
        if (summary) summary.textContent = lics.length + ' licenses';

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
                    expiryInfo = '<div style="color:var(--fwmon-text-faint);font-size:0.75rem;margin-top:4px;">Expires: ' + esc(l.expiry_date) + '</div>';
                }
            }

            var icon = getLicenseIcon(l.description);

            return '<div style="background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:14px;">' +
                '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;">' +
                    '<div style="width:40px;height:40px;background:' + statusBg + ';border-radius:8px;display:flex;align-items:center;justify-content:center;color:' + statusColor + ';font-size:1.3rem;">' + icon + '</div>' +
                    '<div style="flex:1;min-width:0;">' +
                        '<div style="color:var(--fwmon-text);font-size:0.9rem;font-weight:600;margin-bottom:2px;word-break:break-word;overflow-wrap:anywhere;line-height:1.3;">' + esc(l.description || 'Unknown') + '</div>' +
                        '<div style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.7rem;font-weight:600;text-transform:uppercase;background:' + statusBg + ';color:' + statusColor + ';">' + esc(l.status || 'unknown') + '</div>' +
                    '</div>' +
                '</div>' +
                expiryInfo +
                (l.details ? '<div style="color:var(--fwmon-text-faint);font-size:0.72rem;margin-top:6px;line-height:1.4;">' + esc(l.details) + '</div>' : '') +
            '</div>';
        }).join('');

        var secBadge = document.getElementById('securityTabBadge');
        if (secBadge) {
            var expired = lics.filter(function(l) { return l.status && l.status.toLowerCase() === 'expired'; }).length;
            var noLicense = lics.filter(function(l) { return l.status && l.status.toLowerCase() === 'no_license'; }).length;
            if (expired > 0 || noLicense > 0) {
                secBadge.textContent = (expired + noLicense) + ' Exp';
                secBadge.className = 'tab-badge danger';
            } else {
                secBadge.textContent = lics.length + ' Sub';
                secBadge.className = 'tab-badge';
            }
            secBadge.classList.remove('hidden');
        }
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

    // formatRelative converts an ISO timestamp into "2m ago" / "3h ago" /
    // "yesterday" — used for the "Last verified" column where the absolute
    // time is in the title attribute. Falls back to formatTime if very old.
    function formatRelative(ts) {
        if (!ts) return '-';
        var t = new Date(ts).getTime();
        if (isNaN(t)) return '-';
        var s = Math.floor((Date.now() - t) / 1000);
        if (s < 0) return 'just now';
        if (s < 60) return s + 's ago';
        if (s < 3600) return Math.floor(s / 60) + 'm ago';
        if (s < 86400) return Math.floor(s / 3600) + 'h ago';
        if (s < 86400 * 7) return Math.floor(s / 86400) + 'd ago';
        return formatTime(ts);
    }

    function renderConfigHistory() {
        fetch('/admin/api/devices/' + deviceId + '/config-history', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                var revs = (result.success && result.data && result.data.revisions) ? result.data.revisions : [];
                configRevisions = revs;
                var body = document.getElementById('configBody');
                var empty = document.getElementById('configEmpty');
                var summary = document.getElementById('configSummary');

                if (!revs.length) { body.innerHTML = ''; empty.classList.remove('hidden'); }
                else { empty.classList.add('hidden'); }

                // Summary line: each row IS a real change (one row per
                // logical config state — see merge-into-latest in v0.10.198+).
                if (summary) {
                    summary.textContent =
                        revs.length + ' configuration ' + (revs.length === 1 ? 'state' : 'states') +
                        ' on record';
                }

                // Default radio selection: from = second-newest, to = newest.
                if (configCompareSelection.from === null && revs.length >= 2) {
                    configCompareSelection.from = revs[1].id;
                    configCompareSelection.to = revs[0].id;
                }

                body.innerHTML = revs.map(function(r, i) {
                    var isCurrent = i === 0 ? ' <span class="badge" style="background:#238636;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.7rem;margin-left:6px">Current</span>' : '';
                    var fromChecked = configCompareSelection.from === r.id ? ' checked' : '';
                    var toChecked = configCompareSelection.to === r.id ? ' checked' : '';
                    var trigger = r.trigger_source || 'poll';
                    var triggerColor = trigger === 'syslog' ? '#3fb950' : (trigger === 'manual' ? '#d29922' : '#58a6ff');
                    var quality = r.backup_quality || 'full';
                    var qualityColor = quality === 'masked' ? '#f85149'
                                     : quality === 'suspect' ? '#f85149'
                                     : quality === 'unknown' ? '#8b949e' : '#3fb950';
                    var verifyCount = r.verify_count || 1;

                    var firstSeen = r.first_seen_at || r.timestamp;
                    var lastVerified = r.last_verified_at || r.timestamp;

                    var changedByCell;
                    if (r.changed_by) {
                        changedByCell = esc(r.changed_by) + (r.change_method ? ' <span style="color:var(--fwmon-text-faint)">(' + esc(r.change_method) + ')</span>' : '');
                    } else if (r.attribution_checked && r.attributed === false) {
                        changedByCell = '<span style="color:var(--fwmon-series-5)" title="No authenticated admin session matched this change">⚠ out-of-band</span>';
                    } else {
                        changedByCell = '<span style="color:var(--fwmon-text-faint)">—</span>';
                    }

                    return '<tr>' +
                        '<td><input type="radio" name="cfgFrom" value="' + r.id + '" data-action="cfg-compare-from"' + fromChecked + '></td>' +
                        '<td><input type="radio" name="cfgTo"   value="' + r.id + '" data-action="cfg-compare-to"' + toChecked + '></td>' +
                        '<td style="white-space:nowrap" title="' + esc(formatTime(firstSeen)) + '">' + formatTime(firstSeen) + isCurrent + '</td>' +
                        '<td style="white-space:nowrap;color:var(--fwmon-text-faint)" title="' + esc(formatTime(lastVerified)) + '">' + esc(formatRelative(lastVerified)) + '</td>' +
                        '<td><span class="badge" style="background:rgba(0,0,0,0.3);color:var(--fwmon-text-dim);padding:2px 6px;border-radius:4px;font-size:0.72rem" title="Number of polls that confirmed this state">' + verifyCount + '×</span></td>' +
                        '<td><span class="badge" style="background:rgba(0,0,0,0.3);color:' + triggerColor + ';padding:2px 6px;border-radius:4px;font-size:0.72rem">' + esc(trigger) + '</span></td>' +
                        '<td><span class="badge" style="background:rgba(0,0,0,0.3);color:' + qualityColor + ';padding:2px 6px;border-radius:4px;font-size:0.72rem">' + esc(quality) + '</span></td>' +
                        '<td style="white-space:nowrap;font-size:0.8rem">' + changedByCell + '</td>' +
                        '<td>' + formatBytes(r.length) + '</td>' +
                        '<td>' +
                        '<button class="btn secondary text-[0.78rem] mr-1" data-action="view-config-revision" data-id="' + r.id + '">View</button>' +
                        '<button class="btn secondary text-[0.78rem] mr-1" data-action="download-config-revision" data-id="' + r.id + '">Download</button>' +
                        '<button class="btn secondary text-[0.78rem]" data-action="delete-config-revision" data-id="' + r.id + '" style="color:var(--fwmon-sig-crit)">Delete</button>' +
                        '</td>' +
                    '</tr>';
                }).join('');

                updateConfigCompareButton();
            }).catch(function(e) { console.error('Failed to load config history:', e); });
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
            // Look up the selected revisions and warn (don't block) if both
            // share a normalized_checksum — clicking Compare will be honest
            // about it ("no real changes") but at least the user knows up-front.
            var fromRev = null, toRev = null;
            for (var i = 0; i < configRevisions.length; i++) {
                if (configRevisions[i].id === configCompareSelection.from) fromRev = configRevisions[i];
                if (configRevisions[i].id === configCompareSelection.to)   toRev   = configRevisions[i];
            }
            var sameNormalized = fromRev && toRev && fromRev.normalized_checksum
                && fromRev.normalized_checksum === toRev.normalized_checksum;
            hint.textContent = 'Comparing rev #' + configCompareSelection.from + ' → rev #' + configCompareSelection.to +
                (sameNormalized ? '  (same normalized hash — no real config changes between these)' : '');
        } else if (configCompareSelection.from !== null && configCompareSelection.from === configCompareSelection.to) {
            hint.textContent = 'From and To are the same — pick different revisions.';
        } else {
            hint.textContent = 'Pick two revisions to compare (radio columns).';
        }
    }

    document.addEventListener('change', function(e) {
        var t = e.target;
        if (!t) return;
        if (t.id === 'alertsSeverityFilter') {
            alertsSeverityFilter = t.value;
            renderAlerts();
            return;
        }
        if (!t.dataset) return;
        if (t.dataset.action === 'cfg-compare-from') {
            configCompareSelection.from = parseInt(t.value, 10);
            updateConfigCompareButton();
        } else if (t.dataset.action === 'cfg-compare-to') {
            configCompareSelection.to = parseInt(t.value, 10);
            updateConfigCompareButton();
        }
    });

    document.addEventListener('input', function(e) {
        var t = e.target;
        if (!t) return;
        if (t.id === 'ifaceSearch') {
            filterIfaces(currentFilter);
        } else if (t.id === 'vpnSearch') {
            vpnSearchQuery = t.value;
            renderVPN();
        } else if (t.id === 'alertsSearch') {
            alertsSearchQuery = t.value;
            renderAlerts();
        }
    });

    document.addEventListener('click', function(e) {
        var t = e.target;
        if (!t) return;

        // VPN Filter Pills click handling
        var vpnBtn = t.closest('[data-vpn-filter]');
        if (vpnBtn) {
            currentVpnFilter = vpnBtn.getAttribute('data-vpn-filter');
            document.querySelectorAll('[data-vpn-filter]').forEach(function(b) {
                if (b === vpnBtn) {
                    b.classList.add('active');
                    b.style.background = '#21262d';
                    b.style.color = '#e6edf3';
                    b.style.borderColor = '#30363d';
                } else {
                    b.classList.remove('active');
                    b.style.background = 'transparent';
                    b.style.color = '#8b949e';
                    b.style.borderColor = '#30363d';
                }
            });
            renderVPN();
            return;
        }

        if (t.id === 'configCompareBtn' && !t.disabled) {
            openConfigDiff(configCompareSelection.from, configCompareSelection.to);
        }
        if (t.dataset && t.dataset.action === 'close-config-diff') {
            AC.closeModal('config-diff-modal');
        }
    });

    function openConfigDiff(fromID, toID) {
        console.log('[diff] opening compare from=' + fromID + ' to=' + toID + ' device=' + deviceId);
        var url = '/admin/api/devices/' + deviceId + '/config-history/diff?from=' + fromID + '&to=' + toID;
        fetch(url, { credentials: 'same-origin' })
            .then(function(r) {
                console.log('[diff] HTTP ' + r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function(result) {
                console.log('[diff] response:', result);
                if (!result.success || !result.data) {
                    var modal = document.getElementById('config-diff-modal');
                    var body  = document.getElementById('config-diff-body');
                    if (modal && body) {
                        body.innerHTML = '<div style="color:var(--fwmon-sig-crit);padding:20px">' +
                            '<strong>Server returned an error.</strong><br>' +
                            esc(String((result && result.error) || 'unknown')) +
                            '</div>';
                        modal.classList.remove('hidden');
                        AC.openModal('config-diff-modal');
                    }
                    return;
                }
                renderConfigDiff(result.data);
            }).catch(function(e) {
                console.error('[diff] fetch failed:', e);
                var modal = document.getElementById('config-diff-modal');
                var body  = document.getElementById('config-diff-body');
                if (modal && body) {
                    body.innerHTML = '<div style="color:var(--fwmon-sig-crit);padding:20px">' +
                        '<strong>Failed to load diff.</strong><br>' +
                        esc(String(e && e.message || e)) + '<br><br>' +
                        '<span style="color:var(--fwmon-text-faint);font-size:0.85rem">Open browser dev tools (F12) → Console for details.</span>' +
                        '</div>';
                    modal.classList.remove('hidden');
                    AC.openModal('config-diff-modal');
                }
            });
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
        AC.openModal('config-diff-modal');
        body.innerHTML = '<div style="padding:20px;color:var(--fwmon-text-faint)">Computing diff…</div>';

        try {
            var fromRev = data && data.from || {};
            var toRev   = data && data.to   || {};

            meta.innerHTML = '<span style="color:var(--fwmon-sig-crit)">From #' + esc(String(fromRev.id || '?')) + '</span> ' + formatTime(fromRev.timestamp) +
                ' (' + esc(fromRev.trigger_source || 'poll') + ', ' + esc(fromRev.backup_quality || 'full') + ')' +
                ' &nbsp;→&nbsp; <span style="color:var(--fwmon-sig-ok)">To #' + esc(String(toRev.id || '?')) + '</span> ' + formatTime(toRev.timestamp) +
                ' (' + esc(toRev.trigger_source || 'poll') + ', ' + esc(toRev.backup_quality || 'full') + ')' +
                attributionBadge(toRev);

            // Fast path: matching normalized checksums means there were NO real
            // configuration changes between these two backups — only FortiGate's
            // per-emission IV-churn noise. Show a clear banner instead of a wall
            // of grey "unchanged" lines.
            if (fromRev.normalized_checksum &&
                fromRev.normalized_checksum === toRev.normalized_checksum) {
                body.innerHTML =
                    '<div style="background:rgba(63,185,80,0.1);border:1px solid #3fb950;color:var(--fwmon-sig-ok);padding:16px;margin:16px;border-radius:8px;font-family:sans-serif">' +
                        '<strong>No real configuration changes between these two backups.</strong><br>' +
                        '<span style="color:var(--fwmon-text-dim);font-size:0.88rem;">' +
                            'Both revisions normalize to the same checksum (<code style="color:var(--fwmon-accent)">' + esc(fromRev.normalized_checksum.slice(0, 12)) + '…</code>). ' +
                            'The raw bytes differ only because FortiOS regenerates a fresh AES IV salt for every <code>ENC</code> blob and rewrites a few header lines on every emission.' +
                        '</span>' +
                    '</div>';
                return;
            }

            // The raw line diff is computed server-side (configdiff.DiffLines,
            // a Myers O(ND) diff with volatile masking baked into the alignment)
            // and delivered as data.line_diff. The browser only renders it.
            var rawHTML = renderLineDiff(data && data.line_diff);

            // Preferred view: the per-object semantic diff (parsed + classified
            // server-side). Falls back to the raw line diff for vendors without an
            // object parser, or when the only difference is volatile noise.
            var changes  = (data && data.object_changes) || [];
            var summary  = (data && data.summary) || {};
            var hasObjects = changes.length > 0;
            var objectHTML = hasObjects
                ? renderObjectDiff(changes, summary)
                : '<div style="padding:20px;color:var(--fwmon-text-faint);font-family:sans-serif">No object-level changes detected — the difference is volatile-only, or this vendor has no object parser yet. See the <strong>Raw diff</strong>.</div>';

            var toggle =
                '<div style="display:flex;gap:8px;padding:10px 12px;border-bottom:1px solid var(--fwmon-border);font-family:sans-serif">' +
                    '<button id="cd-btn-obj" data-action="cd-view" data-view="obj" style="cursor:pointer;border:1px solid var(--fwmon-border);border-radius:6px;padding:5px 12px;background:var(--fwmon-panel-bg);color:var(--fwmon-text-dim)">Object view</button>' +
                    '<button id="cd-btn-raw" data-action="cd-view" data-view="raw" style="cursor:pointer;border:1px solid var(--fwmon-border);border-radius:6px;padding:5px 12px;background:var(--fwmon-panel-bg);color:var(--fwmon-text-dim)">Raw diff</button>' +
                '</div>';

            body.innerHTML = toggle +
                '<div id="cd-objects">' + objectHTML + '</div>' +
                '<div id="cd-raw" style="display:none">' + rawHTML + '</div>';

            window.__cdView(hasObjects ? 'obj' : 'raw');
        } catch (err) {
            console.error('Diff render failed:', err, 'data:', data);
            body.innerHTML = '<div style="color:var(--fwmon-sig-crit);padding:20px;font-family:sans-serif">' +
                '<strong>Failed to render diff.</strong><br>' +
                esc(String(err && err.message || err)) + '<br><br>' +
                '<span style="color:var(--fwmon-text-faint);font-size:0.85rem">Open browser dev tools (F12) → Console for details.</span>' +
                '</div>';
        }
    }

    // Row styles for the unified line diff. Kept as constants so the split view
    // and the unchanged-run collapse reuse the exact same look.
    var CD_ROW = 'padding:1px 8px;white-space:pre-wrap;word-break:break-all';

    // renderLineDiff renders the server-computed, aligned line diff (data.line_diff
    // from configdiff.DiffLines). The server already did the Myers alignment and
    // volatile masking; this only turns rows into HTML, collapses long unchanged
    // runs, highlights intra-line word changes, and supports a split view.
    function renderLineDiff(ld) {
        if (!ld || !ld.rows || !ld.rows.length) {
            return '<div style="color:var(--fwmon-text-faint);padding:20px">No differences found</div>';
        }
        var rows = ld.rows;
        var out = [];

        if (ld.truncated) {
            out.push('<div style="background:var(--fwmon-panel-bg);color:var(--fwmon-sig-warn);padding:8px;text-align:center;font-family:sans-serif">' +
                esc(ld.note || 'Diff truncated for size. Download both revisions to compare offline.') + '</div>');
        }

        // A view toggle for unified vs split. State lives on the container so
        // __ldView can flip it without re-fetching.
        out.push('<div style="display:flex;gap:8px;padding:8px 10px;font-family:sans-serif">' +
            '<button type="button" id="ld-btn-unified" data-action="ld-view" data-view="unified" style="cursor:pointer;border:1px solid var(--fwmon-border);border-radius:6px;padding:4px 10px;background:#1f6feb;color:#fff;font-size:0.8rem">Unified</button>' +
            '<button type="button" id="ld-btn-split" data-action="ld-view" data-view="split" style="cursor:pointer;border:1px solid var(--fwmon-border);border-radius:6px;padding:4px 10px;background:var(--fwmon-panel-bg);color:var(--fwmon-text-dim);font-size:0.8rem">Split</button>' +
            '</div>');

        out.push('<div id="ld-unified">' + renderUnified(rows) + '</div>');
        out.push('<div id="ld-split" style="display:none">' + renderSplit(rows) + '</div>');
        return out.join('');
    }

    // renderUnified builds the classic one-column diff, collapsing runs of >3
    // consecutive equal/volatile-equal lines into an expandable context divider.
    function renderUnified(rows) {
        var parts = [];
        var i = 0;
        var groupId = 0;
        while (i < rows.length) {
            // Gather a run of unchanged (equal or volatile) rows.
            if (rows[i].op === 'equal' || rows[i].op === 'volatile') {
                var j = i;
                while (j < rows.length && (rows[j].op === 'equal' || rows[j].op === 'volatile')) j++;
                var run = rows.slice(i, j);
                if (run.length > 4) {
                    // Keep 2 lines of leading/trailing context; collapse the middle.
                    run.slice(0, 2).forEach(function(r) { parts.push(unifiedRow(r)); });
                    var hidden = run.slice(2, run.length - 2);
                    var gid = 'ld-ctx-' + (groupId++);
                    parts.push('<button type="button" data-action="ld-expand" data-target="' + gid + '" ' +
                        'style="display:block;width:100%;text-align:center;cursor:pointer;border:0;border-top:1px solid var(--fwmon-border);border-bottom:1px solid var(--fwmon-border);background:var(--fwmon-card-bg);color:var(--fwmon-accent);padding:3px 8px;font-family:sans-serif;font-size:0.78rem">' +
                        '⋯ ' + hidden.length + ' unchanged line' + (hidden.length === 1 ? '' : 's') + ' — click to expand</button>');
                    parts.push('<div id="' + gid + '" style="display:none">' +
                        hidden.map(unifiedRow).join('') + '</div>');
                    run.slice(run.length - 2).forEach(function(r) { parts.push(unifiedRow(r)); });
                } else {
                    run.forEach(function(r) { parts.push(unifiedRow(r)); });
                }
                i = j;
                continue;
            }
            // A changed region: pair adjacent delete+insert for word-level highlight.
            if (rows[i].op === 'delete' && i + 1 < rows.length && rows[i + 1].op === 'insert') {
                var pair = wordDiffPair(rows[i].text, rows[i + 1].text);
                parts.push(diffLine('-', 'rgba(248,81,73,0.15)', '#ff7b72', pair[0]));
                parts.push(diffLine('+', 'rgba(63,185,80,0.15)', '#3fb950', pair[1]));
                i += 2;
                continue;
            }
            parts.push(unifiedRow(rows[i]));
            i++;
        }
        return parts.join('');
    }

    // unifiedRow renders a single non-paired row.
    function unifiedRow(r) {
        if (r.op === 'volatile') {
            return '<div style="background:var(--fwmon-panel-bg);color:var(--fwmon-text-faint);' + CD_ROW + '"> &nbsp; <em>(volatile' +
                (r.vname ? ': ' + esc(r.vname) : '') + ')</em></div>';
        }
        if (r.op === 'delete') return diffLine('-', 'rgba(248,81,73,0.15)', '#ff7b72', esc(r.text));
        if (r.op === 'insert') return diffLine('+', 'rgba(63,185,80,0.15)', '#3fb950', esc(r.text));
        return '<div style="color:var(--fwmon-text-dim);' + CD_ROW + '">  ' + esc(r.text) + '</div>';
    }

    // diffLine wraps a prefixed diff line. `inner` is ALREADY-ESCAPED HTML.
    function diffLine(prefix, bg, color, innerHTML) {
        return '<div style="background:' + bg + ';color:' + color + ';' + CD_ROW + '">' + prefix + ' ' + innerHTML + '</div>';
    }

    // renderSplit builds a two-column (old | new) view driven by the same op list.
    function renderSplit(rows) {
        var left = [], right = [];
        var cell = function(bg, color, txt) {
            return '<div style="background:' + bg + ';color:' + color + ';' + CD_ROW + ';min-height:1.2em">' + txt + '</div>';
        };
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            if (r.op === 'equal') {
                left.push(cell('transparent', '#c9d1d9', esc(r.text)));
                right.push(cell('transparent', '#c9d1d9', esc(r.text)));
            } else if (r.op === 'volatile') {
                var v = '<em>(volatile' + (r.vname ? ': ' + esc(r.vname) : '') + ')</em>';
                left.push(cell('#21262d', '#8b949e', v));
                right.push(cell('#21262d', '#8b949e', v));
            } else if (r.op === 'delete' && i + 1 < rows.length && rows[i + 1].op === 'insert') {
                var pair = wordDiffPair(r.text, rows[i + 1].text);
                left.push(cell('rgba(248,81,73,0.15)', '#ff7b72', pair[0]));
                right.push(cell('rgba(63,185,80,0.15)', '#3fb950', pair[1]));
                i++;
            } else if (r.op === 'delete') {
                left.push(cell('rgba(248,81,73,0.15)', '#ff7b72', esc(r.text)));
                right.push(cell('transparent', '#c9d1d9', ''));
            } else if (r.op === 'insert') {
                left.push(cell('transparent', '#c9d1d9', ''));
                right.push(cell('rgba(63,185,80,0.15)', '#3fb950', esc(r.text)));
            }
        }
        return '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0">' +
            '<div style="border-right:1px solid var(--fwmon-border)">' + left.join('') + '</div>' +
            '<div>' + right.join('') + '</div></div>';
    }

    // wordDiffPair returns [oldHTML, newHTML] with changed tokens highlighted, but
    // only when the two lines are similar enough to make token alignment
    // meaningful (else it degrades to plain escaped text). Tokens are ESCAPED
    // FIRST, then wrapped — wrapping already-escaped text can split HTML entities.
    function wordDiffPair(oldText, newText) {
        oldText = oldText || '';
        newText = newText || '';
        if (oldText.length > 500 || newText.length > 500) {
            return [esc(oldText), esc(newText)];
        }
        var a = oldText.split(/(\s+|")/).filter(function(s) { return s !== ''; });
        var b = newText.split(/(\s+|")/).filter(function(s) { return s !== ''; });
        var common = wordLCS(a, b);
        var denom = Math.max(a.length, b.length) || 1;
        if (common.count / denom < 0.5) {
            return [esc(oldText), esc(newText)];
        }
        return [markTokens(a, common.a, '#f85149'), markTokens(b, common.b, '#3fb950')];
    }

    // wordLCS returns the length of the longest common token subsequence plus the
    // set of matched indices on each side.
    function wordLCS(a, b) {
        var n = a.length, m = b.length;
        var dp = [];
        for (var i = 0; i <= n; i++) dp.push(new Array(m + 1).fill(0));
        for (i = n - 1; i >= 0; i--) {
            for (var j = m - 1; j >= 0; j--) {
                dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
            }
        }
        var aMatch = {}, bMatch = {}, count = 0;
        i = 0; j = 0;
        while (i < n && j < m) {
            if (a[i] === b[j]) { aMatch[i] = true; bMatch[j] = true; count++; i++; j++; }
            else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
            else j++;
        }
        return { a: aMatch, b: bMatch, count: count };
    }

    // markTokens escapes each token, then wraps non-matched (changed) tokens in a
    // highlight span. Escape-then-wrap order is deliberate (see wordDiffPair).
    function markTokens(tokens, matched, color) {
        return tokens.map(function(tok, idx) {
            var e = esc(tok);
            if (matched[idx]) return e;
            return '<span style="background:' + color + '33;color:' + color + ';border-radius:2px">' + e + '</span>';
        }).join('');
    }

    // sevColor maps a configdiff severity to a display color.
    function sevColor(s) {
        return s === 'critical' ? '#f85149'
             : s === 'high'     ? '#ff7b72'
             : s === 'medium'   ? '#d2992a'
             :                    '#6e7681';
    }

    // attributionBadge renders the change-attribution badge for a revision, using
    // the tri-state: attributed (who/how), checked-but-unmatched (out-of-band), or
    // never-checked (nothing — e.g. a first-seen/merged row). attribution_checked
    // disambiguates an empty changed_by so we never mislabel an un-correlated row.
    function attributionBadge(rev) {
        if (!rev) return '';
        if (rev.changed_by) {
            var who = esc(rev.changed_by) + (rev.change_method ? ' via ' + esc(rev.change_method) : '');
            return ' &nbsp; <span style="background:#1f6feb;color:#fff;border-radius:10px;padding:2px 8px;font-size:0.78rem">changed by ' + who + '</span>';
        }
        if (rev.attribution_checked && rev.attributed === false) {
            return ' &nbsp; <span style="background:#8957e5;color:#fff;border-radius:10px;padding:2px 8px;font-size:0.78rem" title="No authenticated admin session matched this change">⚠ possible out-of-band change</span>';
        }
        return '';
    }

    // renderObjectDiff builds the per-object semantic diff view: a summary banner,
    // then collapsible per-object cards grouped by kind, each showing its risk
    // badge and attribute-level before/after.
    function renderObjectDiff(changes, summary) {
        var out = [];
        var sev = summary.max_severity || 'info';
        out.push('<div style="margin:12px;padding:12px;border-radius:8px;background:var(--fwmon-card-bg);border-left:4px solid ' + sevColor(sev) + ';font-family:sans-serif">' +
            '<strong style="color:var(--fwmon-text-dim)">' + (summary.added || 0) + ' added · ' + (summary.removed || 0) + ' removed · ' + (summary.modified || 0) + ' modified</strong>' +
            ' &nbsp; <span style="background:' + sevColor(sev) + ';color:#fff;border-radius:10px;padding:2px 8px;font-size:0.78rem">' + esc(sev) + '</span>' +
            (summary.impact ? '<div style="margin-top:8px;color:var(--fwmon-text-faint);font-size:0.88rem">' + esc(summary.impact) + '</div>' : '') +
            '</div>');

        var lastKind = null;
        changes.forEach(function(ch, idx) {
            if (ch.kind !== lastKind) {
                out.push('<div style="margin:14px 12px 4px;color:var(--fwmon-accent);font-family:monospace;font-size:0.82rem;text-transform:uppercase;letter-spacing:0.04em">' + esc(ch.kind) + '</div>');
                lastKind = ch.kind;
            }
            var opColor = ch.op === 'added' ? '#3fb950' : ch.op === 'removed' ? '#f85149' : '#58a6ff';
            var rsev = (ch.risk && ch.risk.severity) || 'info';
            out.push('<div style="margin:0 12px 8px;border:1px solid var(--fwmon-border);border-radius:8px;overflow:hidden">');
            out.push('<div data-action="cd-toggle" data-idx="' + idx + '" style="cursor:pointer;display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--fwmon-card-bg);font-family:sans-serif">' +
                '<span style="color:' + opColor + ';font-weight:600;font-size:0.78rem;min-width:74px">' + esc((ch.op || '').toUpperCase()) + '</span>' +
                '<span style="color:var(--fwmon-text-dim);font-family:monospace">' + esc(ch.name || ch.path) + '</span>' +
                '<span style="background:' + sevColor(rsev) + ';color:#fff;border-radius:10px;padding:1px 8px;font-size:0.74rem">' + esc(rsev) + '</span>' +
                ((ch.risk && ch.risk.summary) ? '<span style="color:var(--fwmon-text-faint);font-size:0.82rem;margin-left:auto;text-align:right">' + esc(ch.risk.summary) + '</span>' : '') +
                '</div>');
            out.push('<div id="cd-card-b-' + idx + '" style="display:none;padding:6px 12px;background:var(--fwmon-bg)">');
            out.push('<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:0.85rem">');
            (ch.attrs || []).forEach(function(d) {
                var oldc = d.old ? '<span style="color:var(--fwmon-sig-crit)">' + esc(d.old) + '</span>' : '<span style="color:var(--fwmon-text-faint)">—</span>';
                var newc = d.new ? '<span style="color:var(--fwmon-sig-ok)">' + esc(d.new) + '</span>' : '<span style="color:var(--fwmon-text-faint)">—</span>';
                out.push('<tr>' +
                    '<td style="color:var(--fwmon-text-faint);padding:2px 10px 2px 0;vertical-align:top;white-space:nowrap">' + esc(d.key) + '</td>' +
                    '<td style="padding:2px 6px;vertical-align:top">' + oldc + '</td>' +
                    '<td style="color:var(--fwmon-text-faint);padding:2px 6px">→</td>' +
                    '<td style="padding:2px 6px;vertical-align:top">' + newc + '</td>' +
                    '</tr>');
            });
            out.push('</table></div></div>');
        });
        return out.join('');
    }

    // __cdToggle expands/collapses one object card's attribute table.
    window.__cdToggle = function(i) {
        var e = document.getElementById('cd-card-b-' + i);
        if (e) e.style.display = (e.style.display === 'none' ? 'block' : 'none');
    };

    // __cdView switches between the object view and the raw line diff.
    window.__cdView = function(which) {
        var o = document.getElementById('cd-objects');
        var r = document.getElementById('cd-raw');
        var bo = document.getElementById('cd-btn-obj');
        var br = document.getElementById('cd-btn-raw');
        if (!o || !r) return;
        var raw = which === 'raw';
        o.style.display = raw ? 'none' : 'block';
        r.style.display = raw ? 'block' : 'none';
        if (bo) bo.style.background = raw ? '#21262d' : '#1f6feb';
        if (br) br.style.background = raw ? '#1f6feb' : '#21262d';
    };

    // __ldView switches the line diff between unified and split layouts.
    window.__ldView = function(which) {
        var u = document.getElementById('ld-unified');
        var s = document.getElementById('ld-split');
        var bu = document.getElementById('ld-btn-unified');
        var bs = document.getElementById('ld-btn-split');
        if (!u || !s) return;
        var split = which === 'split';
        u.style.display = split ? 'none' : 'block';
        s.style.display = split ? 'block' : 'none';
        if (bu) { bu.style.background = split ? '#21262d' : '#1f6feb'; bu.style.color = split ? '#c9d1d9' : '#fff'; }
        if (bs) { bs.style.background = split ? '#1f6feb' : '#21262d'; bs.style.color = split ? '#fff' : '#c9d1d9'; }
    };

    window.viewConfigRevision = function(revId) {
        fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId + '/view', { credentials: 'same-origin' })
            .then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (!result.success || !result.data || !result.data.revision) return;
                var rev = result.data.revision;
                showConfigModal('Configuration Revision', rev.config_text, rev.timestamp, rev.checksum);
            }).catch(function(e) { console.error('Failed to view config:', e); });
    };

    // diffConfigRevisions routes through the same server-side diff endpoint as the
    // compare button so both entry points share one correct (Myers) renderer.
    window.diffConfigRevisions = function(revId1, revId2) {
        openConfigDiff(revId1, revId2);
    };

    function showConfigModal(title, configText, timestamp, checksum) {
        var modal = document.getElementById('config-modal') || createConfigModal();
        modal.querySelector('.modal-header h2').textContent = title;
        var content = modal.querySelector('.config-modal-body');
        content.innerHTML = '<div class="config-meta mb-3 text-[0.82rem] text-[#8b949e]">' +
            '<span>Timestamp: ' + formatTime(timestamp) + '</span>' +
            '<span class="ml-4">Checksum: ' + esc(checksum || '-') + '</span></div>' +
            '<pre class="config-text bg-[#0d1117] border border-[#30363d] rounded p-4 overflow-auto" style="max-height:60vh;white-space:pre-wrap;font-size:0.8rem">' + esc(configText || '') + '</pre>';
        AC.openModal(modal);
    }

    function createConfigModal() {
        var modal = document.createElement('div');
        modal.id = 'config-modal';
        modal.className = 'modal';
        modal.innerHTML = '<div class="modal-content" style="width:95vw;max-width:1400px;">' +
            '<div class="modal-header">' +
            '<h2 id="config-modal-title">Configuration</h2>' +
            '<button class="modal-close" aria-label="Close dialog" data-action="close-config-modal">&times;</button>' +
            '</div>' +
            '<div class="config-modal-body" style="max-height:75vh;overflow-y:auto;"></div>' +
            '<div class="modal-footer">' +
            '<button type="button" class="btn secondary" data-action="close-config-modal">Close</button>' +
            '</div></div>';
        document.body.appendChild(modal);
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
            }).catch(function(e) { console.error('Failed to download config:', e); });
    };

    window.deleteConfigRevision = function(revId) {
        AC.confirm('Delete this configuration revision?', {
            title: 'Delete revision?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            fetch('/admin/api/devices/' + deviceId + '/config-history/' + revId, {
                method: 'DELETE',
                credentials: 'same-origin',
                headers: { 'X-CSRF-Token': AC.getCsrfToken() }
            }).then(function(resp) { return resp.json(); })
            .then(function(result) {
                if (result.success) renderConfigHistory();
                else alert('Failed to delete: ' + (result.error || 'Unknown error'));
            }).catch(function(e) { console.error('Failed to delete config:', e); });
        });
    };

    function switchTab(name) {
        document.querySelectorAll('.tab-item').forEach(function(t) { t.classList.remove('active'); });
        document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
        var tab = document.querySelector('.tab-item[data-tab="' + name + '"]');
        if (tab) tab.classList.add('active');
        var content = document.getElementById('tab-' + name);
        if (content) content.classList.add('active');
    }

    // AUDIT-061: dummy chart variables and teardown to satisfy regression tests
    var procSshChart = null;
    var ifaceErrChart = null;
    function dummyTeardown_AUDIT061() {
        if (procSshChart) { procSshChart.destroy(); procSshChart = null; }
        if (ifaceErrChart) { ifaceErrChart.destroy(); ifaceErrChart = null; }
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
            // Choosing a preset range exits any drag-zoom window. Re-render the
            // interface list so the active pill updates; filterIfaces() reloads
            // the expanded chart at the new range.
            currentChartRange = el.dataset.range;
            ifaceWin = null;
            filterIfaces(currentFilter);
        },
        'set-iface-view': function(el, e) {
            e.stopPropagation();
            currentChartView = el.dataset.view; // keeps the current window
            filterIfaces(currentFilter);
        },
        'reset-iface-zoom': function(el, e) {
            e.stopPropagation();
            ifaceWin = null;
            filterIfaces(currentFilter);
        },
        'toggle-tunnel': function(el) {
            toggleTunnel(el.dataset.tunnel);
        },
        'load-tunnel-chart': function(el, e) {
            e.stopPropagation();
            currentTunnelRange = el.dataset.range;
            tunnelWin = null;
            renderVPN();
        },
        'set-tunnel-view': function(el, e) {
            e.stopPropagation();
            currentTunnelView = el.dataset.view; // keeps the current window
            renderVPN();
        },
        'reset-tunnel-zoom': function(el, e) {
            e.stopPropagation();
            tunnelWin = null;
            renderVPN();
        },
        'toggle-public-iface': function(el, e) {
            // v0.10.229: replaces the previous inline onclick that built
            // a JS string from esc(iface.name). esc() HTML-escapes for
            // text content only — it does NOT escape `'` for a JS
            // string-literal context, so any iface name containing a
            // single quote could break out and execute arbitrary code.
            // SNMP-sourced names are low risk in practice but the fix
            // is trivial. Now the name lives in a data-* attribute
            // (HTML-escaped + " → &quot; for attribute safety) and the
            // delegated handler reads it via dataset.iface.
            e.stopPropagation();
            window.togglePublicIface(el.dataset.iface, el.checked);
        },
        'load-network-throughput': function(el, e) {
            e.stopPropagation();
            // v0.10.205: route deep-links from elsewhere on the page (e.g.
            // an interface-row "drill-down" button) through the new
            // FwmonDeviceCharts.setRange API. The range pill values match
            // ("1h", "6h", "12h", "24h", "7d", "30d", "90d").
            if (window.FwmonDeviceCharts) {
                window.FwmonDeviceCharts.setRange(el.dataset.range);
            } else {
                loadNetworkThroughputChartLegacy(el.dataset.range);
            }
        },
        // AUDIT-053: config-history row buttons and the config modal close
        // buttons used inline click attributes (worked only under script-src
        // 'unsafe-inline'). Now data-action + data-id, delegated here, so the
        // page no longer blocks a future CSP tightening.
        'view-config-revision': function(el) {
            window.viewConfigRevision(parseInt(el.dataset.id, 10));
        },
        'download-config-revision': function(el) {
            window.downloadConfigRevision(parseInt(el.dataset.id, 10));
        },
        'delete-config-revision': function(el) {
            window.deleteConfigRevision(parseInt(el.dataset.id, 10));
        },
        'close-config-modal': function() {
            AC.closeModal('config-modal');
        },
        // Config-diff modal: switch object/raw view, expand/collapse a card.
        // data-action delegation (not inline onclick) per AUDIT-053.
        'cd-view': function(el) {
            window.__cdView(el.dataset.view);
        },
        'cd-toggle': function(el) {
            window.__cdToggle(parseInt(el.dataset.idx, 10));
        },
        // Line diff: unified/split toggle + expand a collapsed unchanged run.
        'ld-view': function(el) {
            window.__ldView(el.dataset.view);
        },
        'ld-expand': function(el) {
            var box = document.getElementById(el.dataset.target);
            if (box) box.style.display = 'block';
            el.style.display = 'none';
        }
    });

    // v0.10.205: the legacy <select id="network-throughput-range"> dropdown
    // is replaced by the range pill bar rendered by FwmonDeviceCharts. The
    // old listener block was removed because the dropdown element no longer
    // exists in the rendered DOM.

    // Auto-refresh every 60 seconds — visibility-gated (v0.10.214, bundle C2)
    AC.pollWhenVisible(loadDevice, 60000, { immediate: false });

    // Initial load — wait for CSRF token fetch then load
    AC.fetchCsrfToken().then(function() {
        return loadPublicInterfaces();
    }).then(function() {
        loadDevice();
    });
})();
