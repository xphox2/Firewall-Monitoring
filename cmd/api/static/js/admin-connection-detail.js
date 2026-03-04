// admin-connection-detail.js — Connection detail page logic
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;

    var connId = window.location.pathname.split('/').filter(Boolean).pop();
    var trafficChart = null;
    var protoChart = null;
    var flowTimeChart = null;
    var topSrcChart = null;
    var topDstChart = null;
    var tunnelCharts = {};
    var currentTrafficRange = '24h';
    var currentFlowHours = 24;
    var connDetail = null;

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0, val = bytes;
        while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
        return val.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    function formatNum(n) {
        if (n === undefined || n === null) return '-';
        if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
        return String(n);
    }

    function formatUptime(hundredths) {
        if (!hundredths) return '-';
        var secs = Math.floor(hundredths / 100);
        var d = Math.floor(secs / 86400);
        var h = Math.floor((secs % 86400) / 3600);
        var m = Math.floor((secs % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }

    function createGauge(containerId, value, maxVal) {
        var container = document.getElementById(containerId);
        if (!container) return;
        var pct = maxVal > 0 ? Math.min((value / maxVal) * 100, 100) : 0;
        var radius = 32;
        var circumference = 2 * Math.PI * radius;
        var offset = circumference - (pct / 100) * circumference;
        var color = '#3fb950';
        if (pct >= 90) color = '#f85149';
        else if (pct >= 70) color = '#d29922';

        container.innerHTML =
            '<svg width="80" height="80" viewBox="0 0 80 80">' +
                '<circle class="gauge-bg" cx="40" cy="40" r="' + radius + '" />' +
                '<circle class="gauge-fill" cx="40" cy="40" r="' + radius + '"' +
                    ' stroke="' + color + '"' +
                    ' stroke-dasharray="' + circumference + '"' +
                    ' stroke-dashoffset="' + offset + '" />' +
            '</svg>' +
            '<div class="gauge-text">' + Math.round(pct) + '%</div>';
    }

    // Connection type visual style mapping
    function connStyleLookup(type) {
        var styles = {
            ipsec:    { color: '#58a6ff', dash: '', width: 3 },
            ssl:      { color: '#d29922', dash: '', width: 3 },
            vxlan:    { color: '#8957e5', dash: 'stroke-dasharray="8,4"', width: 3 },
            l2vlan:   { color: '#39d4e0', dash: '', width: 3 },
            l3ipvlan: { color: '#da7de8', dash: 'stroke-dasharray="12,4"', width: 3 },
            gre:      { color: '#b392f0', dash: '', width: 3 },
            wan:      { color: '#f0883e', dash: '', width: 3 },
            lag:      { color: '#d29922', dash: '', width: 4 },
            ethernet: { color: '#6e7681', dash: '', width: 2 },
            tunnel:   { color: '#8b949e', dash: '', width: 3 }
        };
        return styles[type] || styles.tunnel;
    }

    function renderBridge(srcName, dstName, status, connType) {
        var statusColor = status === 'up' ? '#3fb950' : (status === 'down' ? '#f85149' : '#484f58');
        var cs = connStyleLookup(connType);
        var pathColor = cs.color;
        var particles = '';
        if (status === 'up') {
            particles =
                '<circle r="4" fill="' + pathColor + '" opacity="0.85">' +
                    '<animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze"><mpath href="#bridge-path"/></animateMotion>' +
                '</circle>' +
                '<circle r="4" fill="' + pathColor + '" opacity="0.85">' +
                    '<animateMotion dur="3s" begin="1.5s" repeatCount="indefinite" fill="freeze"><mpath href="#bridge-path"/></animateMotion>' +
                '</circle>' +
                '<circle r="3" fill="' + pathColor + '" opacity="0.7">' +
                    '<animateMotion dur="3.5s" begin="0.5s" repeatCount="indefinite" fill="freeze" keyPoints="1;0" keyTimes="0;1" calcMode="linear"><mpath href="#bridge-path"/></animateMotion>' +
                '</circle>' +
                '<circle r="3" fill="' + pathColor + '" opacity="0.7">' +
                    '<animateMotion dur="3.5s" begin="2s" repeatCount="indefinite" fill="freeze" keyPoints="1;0" keyTimes="0;1" calcMode="linear"><mpath href="#bridge-path"/></animateMotion>' +
                '</circle>';
        }
        var pulseAnim = status === 'down' ? '<animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite"/>' : '';
        var filterAttr = status === 'up' ? ' filter="url(#bridge-glow)"' : '';

        document.getElementById('bridge-header').innerHTML =
            '<svg class="bridge-svg" width="100%" height="100" viewBox="0 0 700 100">' +
                '<defs>' +
                    '<filter id="bridge-glow" x="-50%" y="-50%" width="200%" height="200%">' +
                        '<feGaussianBlur stdDeviation="3" result="blur"/>' +
                        '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>' +
                    '</filter>' +
                '</defs>' +
                '<rect x="20" y="25" width="140" height="50" rx="8" fill="#161b22" stroke="' + statusColor + '" stroke-width="2"/>' +
                '<text x="90" y="48" text-anchor="middle" fill="#e6edf3" font-size="12" font-weight="600">' + AC.escapeHtml(srcName || '').substring(0, 16) + '</text>' +
                '<text x="90" y="64" text-anchor="middle" fill="#8b949e" font-size="10">Source</text>' +
                '<rect x="540" y="25" width="140" height="50" rx="8" fill="#161b22" stroke="' + statusColor + '" stroke-width="2"/>' +
                '<text x="610" y="48" text-anchor="middle" fill="#e6edf3" font-size="12" font-weight="600">' + AC.escapeHtml(dstName || '').substring(0, 16) + '</text>' +
                '<text x="610" y="64" text-anchor="middle" fill="#8b949e" font-size="10">Destination</text>' +
                '<path id="bridge-path" d="M160,50 Q350,10 540,50" fill="none" stroke="' + pathColor + '" stroke-width="' + cs.width + '" ' + cs.dash + filterAttr + '>' +
                    pulseAnim +
                '</path>' +
                particles +
            '</svg>';
    }

    function loadConnectionDetail() {
        return AC.apiFetch(API_BASE + '/connections/' + connId + '/detail').then(function(result) {
            var data = result.data;
            if (!data) return;
            connDetail = data;

            var conn = data.connection;
            var srcName = conn.source_device ? conn.source_device.name : 'Device ' + conn.source_device_id;
            var dstName = conn.dest_device ? conn.dest_device.name : 'Device ' + conn.dest_device_id;

            document.title = srcName + ' - ' + dstName + ' | Connection Detail';
            renderBridge(srcName, dstName, conn.status, conn.connection_type);

            // Stat cards
            document.getElementById('stat-bytes-in').textContent = formatBytes(data.total_bytes_in);
            document.getElementById('stat-bytes-out').textContent = formatBytes(data.total_bytes_out);
            var tunnelCount = (data.source_tunnels ? data.source_tunnels.length : 0) + (data.dest_tunnels ? data.dest_tunnels.length : 0);
            document.getElementById('stat-tunnel-count').textContent = tunnelCount;
            var statusEl = document.getElementById('stat-status');
            statusEl.innerHTML = '<span class="badge ' + conn.status + '">' + (conn.status || 'unknown').toUpperCase() + '</span>';

            // Show/hide flows tab
            document.getElementById('tab-flows').style.display = data.has_flow_data ? '' : 'none';

            // Show/hide Phase 2 matches tab
            var p2matches = data.phase2_matches || [];
            document.getElementById('tab-phase2').style.display = p2matches.length > 0 ? '' : 'none';
            renderPhase2Matches(p2matches, srcName, dstName);

            // Render tunnel tables
            renderTunnelTable('src-tunnels-table', data.source_tunnels || [], conn.source_device_id);
            renderTunnelTable('dst-tunnels-table', data.dest_tunnels || [], conn.dest_device_id);
            document.getElementById('src-tunnels-title').textContent = 'Source Tunnels (' + srcName + ')';
            document.getElementById('dst-tunnels-title').textContent = 'Destination Tunnels (' + dstName + ')';
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Error loading detail:', err);
        });
    }

    function renderTunnelTable(tableId, tunnels, deviceId) {
        var tbody = document.querySelector('#' + tableId + ' tbody');
        if (!tunnels.length) {
            tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:#484f58;padding:30px;">No matching tunnels found</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < tunnels.length; i++) {
            var t = tunnels[i];
            var rowId = tableId + '-row-' + i;
            var statusBadge = (t.status === 'up' || t.state === 'up')
                ? '<span class="badge up">UP</span>'
                : '<span class="badge down">DOWN</span>';
            var typeBadge = t.tunnel_type
                ? '<span class="badge ipsec">' + AC.escapeHtml(t.tunnel_type) + '</span>'
                : '-';
            html +=
                '<tr class="tunnel-row" data-action="toggle-tunnel" data-row-id="' + rowId + '" data-device-id="' + deviceId + '" data-tunnel-name="' + AC.escapeHtml(t.tunnel_name) + '">' +
                    '<td><span class="chevron" id="chev-' + rowId + '">&#9654;</span></td>' +
                    '<td>' + AC.escapeHtml(t.phase1_name || t.tunnel_name) + '</td>' +
                    '<td>' + AC.escapeHtml(t.tunnel_name) + '</td>' +
                    '<td>' + typeBadge + '</td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' + AC.escapeHtml(t.remote_ip || '-') + '</td>' +
                    '<td><code style="color:#58a6ff;font-size:0.8rem;">' + AC.escapeHtml(t.local_subnet || '-') + '</code></td>' +
                    '<td><code style="color:#3fb950;font-size:0.8rem;">' + AC.escapeHtml(t.remote_subnet || '-') + '</code></td>' +
                    '<td>' + formatBytes(t.bytes_in) + '</td>' +
                    '<td>' + formatBytes(t.bytes_out) + '</td>' +
                    '<td>' + formatUptime(t.tunnel_uptime) + '</td>' +
                '</tr>' +
                '<tr class="tunnel-expand" id="' + rowId + '">' +
                    '<td colspan="11">' +
                        '<div class="tunnel-chart-wrap">' +
                            '<div class="range-pills" style="margin-bottom:8px;">' +
                                '<div class="range-pill active" data-action="load-tunnel-chart" data-row-id="' + rowId + '" data-device-id="' + deviceId + '" data-tunnel-name="' + AC.escapeHtml(t.tunnel_name) + '" data-range="1h">1h</div>' +
                                '<div class="range-pill" data-action="load-tunnel-chart" data-row-id="' + rowId + '" data-device-id="' + deviceId + '" data-tunnel-name="' + AC.escapeHtml(t.tunnel_name) + '" data-range="24h">24h</div>' +
                                '<div class="range-pill" data-action="load-tunnel-chart" data-row-id="' + rowId + '" data-device-id="' + deviceId + '" data-tunnel-name="' + AC.escapeHtml(t.tunnel_name) + '" data-range="7d">7d</div>' +
                                '<div class="range-pill" data-action="load-tunnel-chart" data-row-id="' + rowId + '" data-device-id="' + deviceId + '" data-tunnel-name="' + AC.escapeHtml(t.tunnel_name) + '" data-range="30d">30d</div>' +
                            '</div>' +
                            '<div class="chart-container"><canvas id="chart-' + rowId + '"></canvas></div>' +
                        '</div>' +
                    '</td>' +
                '</tr>';
        }
        tbody.innerHTML = html;
    }

    function renderPhase2Matches(matches, srcName, dstName) {
        var container = document.getElementById('phase2-matches-container');
        if (!matches.length) {
            container.innerHTML = '<div style="text-align:center;color:#484f58;padding:30px;">No Phase 2 selector matches found between these devices.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < matches.length; i++) {
            var m = matches[i];
            var srcUp = m.source_status === 'up';
            var dstUp = m.dest_status === 'up';
            var bothUp = srcUp && dstUp;
            var pathColor = bothUp ? '#3fb950' : '#f85149';
            var statusLabel = bothUp ? 'ACTIVE' : 'DOWN';
            var statusClass = bothUp ? 'up' : 'down';
            var filterAttr = bothUp ? ' filter="url(#p2glow-' + i + ')"' : '';
            var animCircles = bothUp
                ? '<circle r="3" fill="' + pathColor + '" opacity="0.85">' +
                      '<animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze"><mpath href="#p2path-' + i + '"/></animateMotion>' +
                  '</circle>' +
                  '<circle r="2.5" fill="#58a6ff" opacity="0.7">' +
                      '<animateMotion dur="3.5s" begin="1s" repeatCount="indefinite" fill="freeze" keyPoints="1;0" keyTimes="0;1" calcMode="linear"><mpath href="#p2path-' + i + '"/></animateMotion>' +
                  '</circle>'
                : '';
            html +=
                '<div class="phase2-match-card" style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px;">' +
                    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">' +
                        '<span style="font-size:0.85rem;font-weight:600;color:#e6edf3;">' + AC.escapeHtml(m.source_phase1 || m.source_tunnel) + ' &harr; ' + AC.escapeHtml(m.dest_phase1 || m.dest_tunnel) + '</span>' +
                        '<span class="badge ' + statusClass + '" style="font-size:0.7rem;">' + statusLabel + '</span>' +
                    '</div>' +
                    '<svg width="100%" height="70" viewBox="0 0 600 70" style="display:block;">' +
                        '<defs><filter id="p2glow-' + i + '" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>' +
                        '<rect x="0" y="15" width="160" height="40" rx="6" fill="#0d1117" stroke="#30363d" stroke-width="1"/>' +
                        '<text x="80" y="30" text-anchor="middle" fill="#8b949e" font-size="10">' + AC.escapeHtml(srcName) + '</text>' +
                        '<text x="80" y="46" text-anchor="middle" fill="#58a6ff" font-size="11" font-family="monospace">' + AC.escapeHtml(m.local_subnet) + '</text>' +
                        '<rect x="440" y="15" width="160" height="40" rx="6" fill="#0d1117" stroke="#30363d" stroke-width="1"/>' +
                        '<text x="520" y="30" text-anchor="middle" fill="#8b949e" font-size="10">' + AC.escapeHtml(dstName) + '</text>' +
                        '<text x="520" y="46" text-anchor="middle" fill="#3fb950" font-size="11" font-family="monospace">' + AC.escapeHtml(m.remote_subnet) + '</text>' +
                        '<path id="p2path-' + i + '" d="M160,35 Q300,10 440,35" fill="none" stroke="' + pathColor + '" stroke-width="2"' + filterAttr + '/>' +
                        '<path d="M160,35 Q300,60 440,35" fill="none" stroke="' + pathColor + '" stroke-width="1.5" stroke-dasharray="4,4" opacity="0.5"/>' +
                        animCircles +
                        '<text x="300" y="8" text-anchor="middle" fill="#484f58" font-size="9">Phase 2: ' + AC.escapeHtml(m.source_tunnel) + ' &harr; ' + AC.escapeHtml(m.dest_tunnel) + '</text>' +
                    '</svg>' +
                '</div>';
        }
        container.innerHTML = html;
    }

    function toggleTunnel(rowId, deviceId, tunnelName) {
        var expandRow = document.getElementById(rowId);
        var chev = document.getElementById('chev-' + rowId);
        if (expandRow.classList.contains('open')) {
            expandRow.classList.remove('open');
            chev.classList.remove('open');
        } else {
            expandRow.classList.add('open');
            chev.classList.add('open');
            if (!tunnelCharts[rowId]) {
                loadTunnelChart(rowId, deviceId, tunnelName, '1h');
            }
        }
    }

    function loadTunnelChart(rowId, deviceId, tunnelName, range, pillEl) {
        if (pillEl) {
            var pills = pillEl.parentElement.querySelectorAll('.range-pill');
            for (var p = 0; p < pills.length; p++) { pills[p].classList.remove('active'); }
            pillEl.classList.add('active');
        }
        return AC.apiFetch(API_BASE + '/devices/' + deviceId + '/vpn/' + encodeURIComponent(tunnelName) + '/chart?range=' + range).then(function(result) {
            var data = result.data;
            if (!data) return;

            var canvas = document.getElementById('chart-' + rowId);
            if (!canvas) return;
            if (tunnelCharts[rowId]) tunnelCharts[rowId].destroy();

            var labels = data.map(function(d) { return d.bucket.split(' ').pop() || d.bucket; });
            tunnelCharts[rowId] = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        { label: 'In Bytes', data: data.map(function(d) { return d.in_bytes; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Out Bytes', data: data.map(function(d) { return d.out_bytes; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: chartOptions()
            });
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Error loading tunnel chart:', err);
        });
    }

    function chartOptions(yCallback) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
            scales: {
                x: { ticks: { color: '#484f58', font: { size: 9 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#484f58', font: { size: 9 }, callback: yCallback || function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } }
            }
        };
    }

    function loadTrafficChart() {
        return AC.apiFetch(API_BASE + '/connections/' + connId + '/traffic?range=' + currentTrafficRange).then(function(result) {
            var data = result.data;
            if (!data) return;

            var canvas = document.getElementById('traffic-chart');
            if (trafficChart) trafficChart.destroy();

            var labels = data.map(function(d) { return d.bucket.split(' ').pop() || d.bucket; });

            // Compute throughput for gauges
            if (data.length >= 2) {
                var last = data[data.length - 1];
                var prev = data[data.length - 2];
                var inRate = Math.abs(last.in_bytes - prev.in_bytes);
                var outRate = Math.abs(last.out_bytes - prev.out_bytes);
                var maxObs = 1;
                for (var k = 0; k < data.length; k++) {
                    var mx = Math.max(data[k].in_bytes, data[k].out_bytes);
                    if (mx > maxObs) maxObs = mx;
                }
                createGauge('gauge-in', inRate, maxObs);
                createGauge('gauge-out', outRate, maxObs);
                document.getElementById('gauge-in-val').textContent = formatBytes(inRate) + '/interval';
                document.getElementById('gauge-out-val').textContent = formatBytes(outRate) + '/interval';
            }

            trafficChart = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        { label: 'Inbound', data: data.map(function(d) { return d.in_bytes; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Outbound', data: data.map(function(d) { return d.out_bytes; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: chartOptions()
            });
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Error loading traffic chart:', err);
        });
    }

    function setTrafficRange(range) {
        currentTrafficRange = range;
        var pills = document.querySelectorAll('#traffic-range .range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', pills[i].dataset.range === range);
        }
        loadTrafficChart();
    }

    function loadFlowStats() {
        return AC.apiFetch(API_BASE + '/connections/' + connId + '/flows?hours=' + currentFlowHours).then(function(result) {
            var data = result.data;
            if (!data) return;

            var hasData = data.total_flows > 0;
            document.getElementById('flow-empty').style.display = hasData ? 'none' : '';
            document.getElementById('flow-content').style.display = hasData ? '' : 'none';
            if (!hasData) return;

            document.getElementById('flow-total-bytes').textContent = formatBytes(data.total_bytes);
            document.getElementById('flow-total-packets').textContent = formatNum(data.total_packets);
            document.getElementById('flow-total-flows').textContent = formatNum(data.total_flows);

            // Protocol doughnut
            var protoColors = { TCP: '#58a6ff', UDP: '#3fb950', ICMP: '#d29922', ESP: '#8957e5', GRE: '#f0883e', AH: '#f85149' };
            if (protoChart) protoChart.destroy();
            var protoData = data.by_protocol || [];
            protoChart = new Chart(document.getElementById('proto-chart'), {
                type: 'doughnut',
                data: {
                    labels: protoData.map(function(p) { return p.key; }),
                    datasets: [{
                        data: protoData.map(function(p) { return p.count; }),
                        backgroundColor: protoData.map(function(p) { return protoColors[p.key] || '#484f58'; }),
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'right', labels: { color: '#8b949e', padding: 8, font: { size: 10 } } } }
                }
            });

            // Bytes over time
            if (flowTimeChart) flowTimeChart.destroy();
            var timeData = data.bytes_over_time || [];
            flowTimeChart = new Chart(document.getElementById('flow-time-chart'), {
                type: 'line',
                data: {
                    labels: timeData.map(function(t) { return t.bucket.split(' ').pop() || t.bucket; }),
                    datasets: [{ label: 'Total Bytes', data: timeData.map(function(t) { return t.count; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }]
                },
                options: chartOptions()
            });

            // Top sources bar
            if (topSrcChart) topSrcChart.destroy();
            var srcData = data.top_sources || [];
            topSrcChart = new Chart(document.getElementById('top-src-chart'), {
                type: 'bar',
                data: {
                    labels: srcData.map(function(s) { return s.key; }),
                    datasets: [{ label: 'Bytes', data: srcData.map(function(s) { return s.count; }), backgroundColor: 'rgba(88,166,255,0.6)', borderRadius: 4 }]
                },
                options: {
                    indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#484f58', font: { size: 9 }, callback: function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } },
                        y: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { display: false } }
                    }
                }
            });

            // Top destinations bar
            if (topDstChart) topDstChart.destroy();
            var dstData = data.top_destinations || [];
            topDstChart = new Chart(document.getElementById('top-dst-chart'), {
                type: 'bar',
                data: {
                    labels: dstData.map(function(s) { return s.key; }),
                    datasets: [{ label: 'Bytes', data: dstData.map(function(s) { return s.count; }), backgroundColor: 'rgba(63,185,80,0.6)', borderRadius: 4 }]
                },
                options: {
                    indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#484f58', font: { size: 9 }, callback: function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } },
                        y: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { display: false } }
                    }
                }
            });

            // Top conversations table
            var convos = data.top_conversations || [];
            var ctbody = document.querySelector('#convos-table tbody');
            var convHtml = '';
            for (var ci = 0; ci < convos.length; ci++) {
                var c = convos[ci];
                convHtml +=
                    '<tr>' +
                        '<td>' + AC.escapeHtml(c.src_addr) + ':' + c.src_port + '</td>' +
                        '<td>' + AC.escapeHtml(c.dst_addr) + ':' + c.dst_port + '</td>' +
                        '<td>' + AC.escapeHtml(c.protocol) + '</td>' +
                        '<td>' + formatBytes(c.bytes) + '</td>' +
                        '<td>' + formatNum(c.packets) + '</td>' +
                    '</tr>';
            }
            ctbody.innerHTML = convHtml || '<tr><td colspan="5" style="text-align:center;color:#484f58;padding:20px;">No conversations found</td></tr>';
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Error loading flow stats:', err);
        });
    }

    function setFlowRange(hours) {
        currentFlowHours = hours;
        var pills = document.querySelectorAll('#flow-range .range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', parseInt(pills[i].dataset.range, 10) === hours);
        }
        loadFlowStats();
    }

    function switchTab(name, tabEl) {
        var tabs = document.querySelectorAll('.section-tab');
        for (var i = 0; i < tabs.length; i++) { tabs[i].classList.remove('active'); }
        var contents = document.querySelectorAll('.tab-content');
        for (var j = 0; j < contents.length; j++) { contents[j].classList.remove('active'); }
        if (tabEl) tabEl.classList.add('active');
        var el = document.getElementById('tab-content-' + name);
        if (el) el.classList.add('active');
    }

    // Delegate all click actions
    AC.delegateEvent('click', {
        'logout': function() {
            AC.doLogout();
        },
        'switch-tab': function(el) {
            switchTab(el.dataset.tab, el);
        },
        'set-traffic-range': function(el) {
            setTrafficRange(el.dataset.range);
        },
        'set-flow-range': function(el) {
            setFlowRange(parseInt(el.dataset.range, 10));
        },
        'toggle-tunnel': function(el, e) {
            // Don't toggle when clicking on the range pills inside the expand row
            if (e.target.closest('.tunnel-expand')) return;
            toggleTunnel(el.dataset.rowId, parseInt(el.dataset.deviceId, 10), el.dataset.tunnelName);
        },
        'load-tunnel-chart': function(el, e) {
            e.stopPropagation();
            loadTunnelChart(el.dataset.rowId, parseInt(el.dataset.deviceId, 10), el.dataset.tunnelName, el.dataset.range, el);
        }
    });

    // Init
    function init() {
        AC.fetchCsrfToken().then(function() {
            return loadConnectionDetail();
        }).then(function() {
            return loadTrafficChart();
        }).then(function() {
            if (connDetail && connDetail.has_flow_data) {
                loadFlowStats();
            }
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Init error:', err);
        });
    }
    init();

    // Auto-refresh every 30s
    setInterval(function() {
        loadConnectionDetail().then(function() {
            return loadTrafficChart();
        }).then(function() {
            if (connDetail && connDetail.has_flow_data && document.getElementById('tab-content-flows').classList.contains('active')) {
                loadFlowStats();
            }
        })['catch'](function(err) {
            console.error('[ConnectionDetail] Refresh error:', err);
        });
    }, 30000);
})();
