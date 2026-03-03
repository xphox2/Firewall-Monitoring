// diagram-panels.js — FWDiagram.Panels: Rich detail panels for connections and VPN badges
(function() {
    'use strict';

    let panelChartInstances = {};
    let currentPanelConnId = null;

    function destroyPanelCharts() {
        Object.values(panelChartInstances).forEach(c => { if (c?.destroy) c.destroy(); });
        panelChartInstances = {};
    }

    function panelChartOptions(yCallback) {
        return {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
            scales: {
                x: { ticks: { color: '#484f58', font: { size: 9 }, maxRotation: 0, maxTicksLimit: 12 }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#484f58', font: { size: 9 }, callback: yCallback || (v => window.formatBytes(v)) }, grid: { color: '#21262d' } }
            }
        };
    }

    function formatPanelUptime(s) {
        if (!s) return '-';
        const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
        return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h` : `${Math.floor(s / 60)}m`;
    }

    function closeRichPanel() {
        destroyPanelCharts();
        currentPanelConnId = null;
        document.getElementById('conn-detail-panel-container').innerHTML = '';
    }

    function getCurrentPanelConnId() { return currentPanelConnId; }
    function setCurrentPanelConnId(id) { currentPanelConnId = id; }

    function renderPanelBridge(containerId, srcName, dstName, status, connType) {
        const statusColor = status === 'up' ? '#3fb950' : (status === 'down' ? '#f85149' : '#484f58');
        const cs = window.connStyle(connType);
        const pathColor = cs.color;
        const dashAttr = cs.dash ? `stroke-dasharray="${cs.dash}"` : '';
        const particles = status === 'up' ? `
            <circle r="3" fill="${pathColor}" opacity="0.85"><animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze"><mpath href="#panel-bridge-path"/></animateMotion></circle>
            <circle r="3" fill="${pathColor}" opacity="0.85"><animateMotion dur="3s" begin="1.5s" repeatCount="indefinite" fill="freeze"><mpath href="#panel-bridge-path"/></animateMotion></circle>
            <circle r="2.5" fill="#58a6ff" opacity="0.7"><animateMotion dur="3.5s" begin="0.5s" repeatCount="indefinite" fill="freeze" keyPoints="1;0" keyTimes="0;1" calcMode="linear"><mpath href="#panel-bridge-path"/></animateMotion></circle>
        ` : '';
        const pulseAnim = status === 'down' ? '<animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite"/>' : '';
        const el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = `
            <svg class="panel-bridge-svg" width="100%" height="80" viewBox="0 0 600 80">
                <defs><filter id="panel-bridge-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
                <rect x="10" y="18" width="130" height="44" rx="8" fill="#161b22" stroke="${statusColor}" stroke-width="1.5"/>
                <text x="75" y="38" text-anchor="middle" fill="#e6edf3" font-size="11" font-weight="600">${window.escapeHtml((srcName||'').substring(0,16))}</text>
                <text x="75" y="52" text-anchor="middle" fill="#8b949e" font-size="9">Source</text>
                <rect x="460" y="18" width="130" height="44" rx="8" fill="#161b22" stroke="${statusColor}" stroke-width="1.5"/>
                <text x="525" y="38" text-anchor="middle" fill="#e6edf3" font-size="11" font-weight="600">${window.escapeHtml((dstName||'').substring(0,16))}</text>
                <text x="525" y="52" text-anchor="middle" fill="#8b949e" font-size="9">Destination</text>
                <path id="panel-bridge-path" d="M140,40 Q300,8 460,40" fill="none" stroke="${pathColor}" stroke-width="${cs.width}" ${dashAttr} ${status === 'up' ? 'filter="url(#panel-bridge-glow)"' : ''}>
                    ${pulseAnim}
                </path>
                ${particles}
            </svg>
        `;
    }

    function switchPanelTab(tabName) {
        document.querySelectorAll('#rich-panel-tabs .panel-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
        document.querySelectorAll('#rich-panel-content .panel-tab-content').forEach(c => c.classList.toggle('active', c.id === 'ptab-' + tabName));
        if (tabName === 'flows' && currentPanelConnId && !panelChartInstances['proto']) {
            loadPanelFlowStats(currentPanelConnId, 24);
        }
    }

    async function showRichConnDetailPanel(conn) {
        destroyPanelCharts();
        currentPanelConnId = conn.id;
        const panel = document.getElementById('conn-detail-panel-container');
        const srcName = conn.source_device?.name || 'Device ' + conn.source_device_id;
        const dstName = conn.dest_device?.name || 'Device ' + conn.dest_device_id;
        const typeBadge = window.typeBadgeHtml(conn.connection_type);
        const statusBadge = `<span class="badge ${conn.status}">${window.escapeHtml((conn.status || 'unknown').toUpperCase())}</span>`;
        const methodLabels = {ip_match:'IP Match',interface_ip:'WAN IP',bidirectional:'Bidirectional',vxlan_name:'VXLAN',tunnel_name:'Tunnel Name',tunnel_indirect:'Indirect',manual:'Manual'};
        const methodBadge = conn.match_method ? `<span class="badge info" style="font-size:0.68rem;">${methodLabels[conn.match_method] || conn.match_method}</span>` : '';

        panel.innerHTML = `
            <div class="rich-detail-panel">
                <div class="panel-header">
                    <h4>${window.escapeHtml(conn.name)} ${typeBadge} ${statusBadge} ${methodBadge}</h4>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <button class="btn secondary sm" onclick="FWDiagram.TunnelZoom.show(${conn.id})" title="Inspect individual tunnels">Zoom In</button>
                        <a href="/admin/connections/${conn.id}" style="color:#58a6ff;font-size:0.8rem;text-decoration:none;font-weight:500;">Full Page &rarr;</a>
                        <button class="btn secondary sm" onclick="FWDiagram.Panels.closeRichPanel()">Close</button>
                    </div>
                </div>
                <div id="panel-bridge-container"></div>
                <div class="panel-kpi-grid">
                    <div class="panel-kpi-card"><div class="kpi-label">Bytes In</div><div class="kpi-value accent" id="pkpi-bytes-in">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label">Bytes Out</div><div class="kpi-value good" id="pkpi-bytes-out">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label">Tunnels</div><div class="kpi-value" id="pkpi-tunnels">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label">Status</div><div class="kpi-value" id="pkpi-status">--</div></div>
                </div>
                <div class="panel-tabs" id="rich-panel-tabs">
                    <div class="panel-tab active" data-tab="overview" onclick="FWDiagram.Panels.switchPanelTab('overview')">Overview</div>
                    <div class="panel-tab" data-tab="tunnels" onclick="FWDiagram.Panels.switchPanelTab('tunnels')">Tunnels</div>
                    <div class="panel-tab" data-tab="phase2" onclick="FWDiagram.Panels.switchPanelTab('phase2')" id="ptab-phase2-tab" style="display:none;">Phase 2</div>
                    <div class="panel-tab" data-tab="flows" onclick="FWDiagram.Panels.switchPanelTab('flows')" id="ptab-flows-tab" style="display:none;">Flows</div>
                </div>
                <div id="rich-panel-content">
                    <div class="panel-tab-content active" id="ptab-overview">
                        <div class="panel-range-pills" id="panel-traffic-range">
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelTrafficRange('1h')">1h</div>
                            <div class="panel-range-pill active" onclick="FWDiagram.Panels.setPanelTrafficRange('24h')">24h</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelTrafficRange('7d')">7d</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelTrafficRange('30d')">30d</div>
                        </div>
                        <div class="panel-chart-container"><canvas id="panel-traffic-chart"></canvas></div>
                    </div>
                    <div class="panel-tab-content" id="ptab-tunnels">
                        <div class="tunnel-columns">
                            <div class="tunnel-col"><h5 id="ptab-src-title">Source Tunnels</h5>
                                <table class="vpn-detail-table" id="ptab-src-tunnels"><thead><tr><th></th><th>Tunnel</th><th>Status</th><th>Remote IP</th><th>In</th><th>Out</th></tr></thead><tbody></tbody></table>
                            </div>
                            <div class="tunnel-col"><h5 id="ptab-dst-title">Dest Tunnels</h5>
                                <table class="vpn-detail-table" id="ptab-dst-tunnels"><thead><tr><th></th><th>Tunnel</th><th>Status</th><th>Remote IP</th><th>In</th><th>Out</th></tr></thead><tbody></tbody></table>
                            </div>
                        </div>
                    </div>
                    <div class="panel-tab-content" id="ptab-phase2">
                        <div id="panel-phase2-container"></div>
                    </div>
                    <div class="panel-tab-content" id="ptab-flows">
                        <div class="panel-range-pills" id="panel-flow-range">
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelFlowRange(1)">1h</div>
                            <div class="panel-range-pill active" onclick="FWDiagram.Panels.setPanelFlowRange(24)">24h</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelFlowRange(168)">7d</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.setPanelFlowRange(720)">30d</div>
                        </div>
                        <div id="panel-flow-content">
                            <div style="display:flex;gap:12px;margin-bottom:8px;">
                                <span style="font-size:0.78rem;color:#8b949e;">Total bytes: <strong style="color:#e6edf3;" id="pf-total-bytes">--</strong></span>
                                <span style="font-size:0.78rem;color:#8b949e;">Flows: <strong style="color:#e6edf3;" id="pf-total-flows">--</strong></span>
                            </div>
                            <div class="panel-flow-grid">
                                <div class="panel-flow-card"><h5>Protocols</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-proto-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Traffic Over Time</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-flow-time-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Top Sources</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-top-src-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Top Destinations</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-top-dst-chart"></canvas></div></div>
                            </div>
                            <div style="margin-top:12px;">
                                <h5 style="font-size:0.8rem;color:#8b949e;margin:0 0 6px 0;">Top Conversations</h5>
                                <div style="max-height:200px;overflow-y:auto;">
                                    <table class="vpn-detail-table" id="panel-convos-table">
                                        <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Packets</th></tr></thead>
                                        <tbody></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        renderPanelBridge('panel-bridge-container', srcName, dstName, conn.status, conn.connection_type);
        loadPanelDetail(conn.id, conn);
        loadPanelTrafficChart(conn.id, '24h');
    }

    async function loadPanelDetail(connId, conn) {
        try {
            const data = await window.apiFetch(`${window.API_BASE}/connections/${connId}/detail`);
            if (!data || currentPanelConnId !== connId) return;
            const c = data.connection || conn;
            const srcName = c.source_device?.name || conn.source_device?.name || 'Device ' + c.source_device_id;
            const dstName = c.dest_device?.name || conn.dest_device?.name || 'Device ' + c.dest_device_id;

            document.getElementById('pkpi-bytes-in').textContent = window.formatBytes(data.total_bytes_in);
            document.getElementById('pkpi-bytes-out').textContent = window.formatBytes(data.total_bytes_out);
            const tunnelCount = (data.source_tunnels?.length || 0) + (data.dest_tunnels?.length || 0);
            document.getElementById('pkpi-tunnels').textContent = tunnelCount;
            const statusEl = document.getElementById('pkpi-status');
            statusEl.innerHTML = `<span class="badge ${c.status}" style="font-size:0.75rem;">${(c.status || 'unknown').toUpperCase()}</span>`;

            document.getElementById('ptab-src-title').textContent = `Source Tunnels (${srcName})`;
            document.getElementById('ptab-dst-title').textContent = `Dest Tunnels (${dstName})`;
            renderPanelTunnelTable('ptab-src-tunnels', data.source_tunnels || [], c.source_device_id);
            renderPanelTunnelTable('ptab-dst-tunnels', data.dest_tunnels || [], c.dest_device_id);

            const p2 = data.phase2_matches || [];
            const p2Tab = document.getElementById('ptab-phase2-tab');
            if (p2Tab) p2Tab.style.display = p2.length > 0 ? '' : 'none';
            if (p2.length > 0) renderPanelPhase2(p2, srcName, dstName);

            const flowsTab = document.getElementById('ptab-flows-tab');
            if (flowsTab) flowsTab.style.display = data.has_flow_data ? '' : 'none';
        } catch (e) { console.error('Panel detail load failed:', e); }
    }

    async function loadPanelTrafficChart(connId, range) {
        try {
            const data = await window.apiFetch(`${window.API_BASE}/connections/${connId}/traffic?range=${range}`);
            if (!data || currentPanelConnId !== connId) return;
            const canvas = document.getElementById('panel-traffic-chart');
            if (!canvas) return;
            if (panelChartInstances['traffic']) panelChartInstances['traffic'].destroy();
            const labels = data.map(d => d.bucket.split(' ').pop() || d.bucket);
            panelChartInstances['traffic'] = new Chart(canvas, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        { label: 'Inbound', data: data.map(d => d.in_bytes), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Outbound', data: data.map(d => d.out_bytes), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: panelChartOptions()
            });
        } catch (e) { console.error('Panel traffic chart failed:', e); }
    }

    function setPanelTrafficRange(range) {
        document.querySelectorAll('#panel-traffic-range .panel-range-pill').forEach(p => p.classList.toggle('active', p.textContent === range));
        if (currentPanelConnId) loadPanelTrafficChart(currentPanelConnId, range);
    }

    async function loadPanelFlowStats(connId, hours) {
        try {
            const data = await window.apiFetch(`${window.API_BASE}/connections/${connId}/flows?hours=${hours}`);
            if (!data || currentPanelConnId !== connId) return;
            const hasData = data.total_flows > 0;
            const content = document.getElementById('panel-flow-content');
            if (!hasData) {
                content.innerHTML = '<div style="text-align:center;color:#484f58;padding:30px;">No sFlow data available for this connection.</div>';
                return;
            }

            document.getElementById('pf-total-bytes').textContent = window.formatBytes(data.total_bytes);
            document.getElementById('pf-total-flows').textContent = window.formatNum(data.total_flows);

            const protoColors = { TCP: '#58a6ff', UDP: '#3fb950', ICMP: '#d29922', ESP: '#8957e5', GRE: '#f0883e', AH: '#f85149' };
            if (panelChartInstances['proto']) panelChartInstances['proto'].destroy();
            const protoData = data.by_protocol || [];
            panelChartInstances['proto'] = new Chart(document.getElementById('panel-proto-chart'), {
                type: 'doughnut',
                data: { labels: protoData.map(p => p.key), datasets: [{ data: protoData.map(p => p.count), backgroundColor: protoData.map(p => protoColors[p.key] || '#484f58'), borderWidth: 0 }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8b949e', padding: 6, font: { size: 9 } } } } }
            });

            if (panelChartInstances['flowTime']) panelChartInstances['flowTime'].destroy();
            const timeData = data.bytes_over_time || [];
            panelChartInstances['flowTime'] = new Chart(document.getElementById('panel-flow-time-chart'), {
                type: 'line',
                data: { labels: timeData.map(t => t.bucket.split(' ').pop() || t.bucket), datasets: [{ label: 'Total Bytes', data: timeData.map(t => t.count), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }] },
                options: panelChartOptions()
            });

            if (panelChartInstances['topSrc']) panelChartInstances['topSrc'].destroy();
            const srcData = data.top_sources || [];
            panelChartInstances['topSrc'] = new Chart(document.getElementById('panel-top-src-chart'), {
                type: 'bar',
                data: { labels: srcData.map(s => s.key), datasets: [{ label: 'Bytes', data: srcData.map(s => s.count), backgroundColor: 'rgba(88,166,255,0.6)', borderRadius: 4 }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#484f58', font: { size: 9 }, callback: v => window.formatBytes(v) }, grid: { color: '#21262d' } }, y: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { display: false } } } }
            });

            if (panelChartInstances['topDst']) panelChartInstances['topDst'].destroy();
            const dstData = data.top_destinations || [];
            panelChartInstances['topDst'] = new Chart(document.getElementById('panel-top-dst-chart'), {
                type: 'bar',
                data: { labels: dstData.map(s => s.key), datasets: [{ label: 'Bytes', data: dstData.map(s => s.count), backgroundColor: 'rgba(63,185,80,0.6)', borderRadius: 4 }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#484f58', font: { size: 9 }, callback: v => window.formatBytes(v) }, grid: { color: '#21262d' } }, y: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { display: false } } } }
            });

            const convos = data.top_conversations || [];
            const ctbody = document.querySelector('#panel-convos-table tbody');
            ctbody.innerHTML = convos.map(c => `<tr><td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(c.src_addr)}:${c.src_port}</td><td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(c.dst_addr)}:${c.dst_port}</td><td>${window.escapeHtml(c.protocol)}</td><td>${window.formatBytes(c.bytes)}</td><td>${window.formatNum(c.packets)}</td></tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:#484f58;">No conversations</td></tr>';
        } catch (e) { console.error('Panel flow stats failed:', e); }
    }

    function setPanelFlowRange(hours) {
        const labels = {1:'1h', 24:'24h', 168:'7d', 720:'30d'};
        document.querySelectorAll('#panel-flow-range .panel-range-pill').forEach(p => p.classList.toggle('active', p.textContent === labels[hours]));
        if (currentPanelConnId) loadPanelFlowStats(currentPanelConnId, hours);
    }

    function renderPanelTunnelTable(tableId, tunnels, deviceId) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (!tunnels.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#484f58;padding:16px;">No tunnels</td></tr>';
            return;
        }
        let html = '';
        tunnels.forEach((t, i) => {
            const rowId = `${tableId}-row-${i}`;
            const statusBadge = t.status === 'up' || t.state === 'up' ? '<span class="badge up">UP</span>' : '<span class="badge down">DOWN</span>';
            html += `
                <tr class="panel-tunnel-row" onclick="FWDiagram.Panels.togglePanelTunnel('${rowId}', ${deviceId}, '${window.escapeHtml(t.tunnel_name)}')">
                    <td><span class="chevron" id="pchev-${rowId}">&#9654;</span></td>
                    <td>${window.escapeHtml(t.tunnel_name)}</td>
                    <td>${statusBadge}</td>
                    <td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(t.remote_ip || '-')}</td>
                    <td>${window.formatBytes(t.bytes_in)}</td>
                    <td>${window.formatBytes(t.bytes_out)}</td>
                </tr>
                <tr class="panel-tunnel-expand" id="${rowId}">
                    <td colspan="6">
                        <div class="panel-range-pills" style="margin-bottom:6px;">
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${deviceId}, '${window.escapeHtml(t.tunnel_name)}', '1h', event)">1h</div>
                            <div class="panel-range-pill active" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${deviceId}, '${window.escapeHtml(t.tunnel_name)}', '24h', event)">24h</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${deviceId}, '${window.escapeHtml(t.tunnel_name)}', '7d', event)">7d</div>
                            <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${deviceId}, '${window.escapeHtml(t.tunnel_name)}', '30d', event)">30d</div>
                        </div>
                        <div class="panel-chart-container" style="height:150px;"><canvas id="pchart-${rowId}"></canvas></div>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function togglePanelTunnel(rowId, deviceId, tunnelName) {
        const expandRow = document.getElementById(rowId);
        const chev = document.getElementById('pchev-' + rowId);
        if (expandRow.classList.contains('open')) {
            expandRow.classList.remove('open');
            if (chev) chev.classList.remove('open');
        } else {
            expandRow.classList.add('open');
            if (chev) chev.classList.add('open');
            if (!panelChartInstances['tunnel-' + rowId]) {
                loadPanelTunnelChart(rowId, deviceId, tunnelName, '24h');
            }
        }
    }

    async function loadPanelTunnelChart(rowId, deviceId, tunnelName, range, evt) {
        if (evt) {
            evt.stopPropagation();
            const pills = evt.target.parentElement.querySelectorAll('.panel-range-pill');
            pills.forEach(p => p.classList.remove('active'));
            evt.target.classList.add('active');
        }
        try {
            const data = await window.apiFetch(`${window.API_BASE}/devices/${deviceId}/vpn/${encodeURIComponent(tunnelName)}/chart?range=${range}`);
            if (!data) return;
            const canvas = document.getElementById('pchart-' + rowId);
            if (!canvas) return;
            if (panelChartInstances['tunnel-' + rowId]) panelChartInstances['tunnel-' + rowId].destroy();
            const labels = data.map(d => d.bucket.split(' ').pop() || d.bucket);
            panelChartInstances['tunnel-' + rowId] = new Chart(canvas, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        { label: 'In', data: data.map(d => d.in_bytes), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Out', data: data.map(d => d.out_bytes), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.05)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: panelChartOptions()
            });
        } catch (e) { console.error('Tunnel chart failed:', e); }
    }

    function renderPanelPhase2(matches, srcName, dstName) {
        const container = document.getElementById('panel-phase2-container');
        if (!matches.length) {
            container.innerHTML = '<div style="text-align:center;color:#484f58;padding:20px;">No Phase 2 selector matches.</div>';
            return;
        }
        let html = '';
        matches.forEach((m, i) => {
            const srcUp = m.source_status === 'up';
            const dstUp = m.dest_status === 'up';
            const bothUp = srcUp && dstUp;
            const pathColor = bothUp ? '#3fb950' : '#f85149';
            const statusClass = bothUp ? 'up' : 'down';
            html += `
            <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px;margin-bottom:8px;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                    <span style="font-size:0.8rem;font-weight:600;color:#e6edf3;">${window.escapeHtml(m.source_phase1 || m.source_tunnel)} &harr; ${window.escapeHtml(m.dest_phase1 || m.dest_tunnel)}</span>
                    <span class="badge ${statusClass}" style="font-size:0.65rem;">${bothUp ? 'ACTIVE' : 'DOWN'}</span>
                </div>
                <svg width="100%" height="60" viewBox="0 0 500 60" style="display:block;">
                    <rect x="0" y="10" width="130" height="40" rx="6" fill="#161b22" stroke="#30363d" stroke-width="1"/>
                    <text x="65" y="26" text-anchor="middle" fill="#8b949e" font-size="9">${window.escapeHtml(srcName)}</text>
                    <text x="65" y="40" text-anchor="middle" fill="#58a6ff" font-size="10" font-family="monospace">${window.escapeHtml(m.local_subnet)}</text>
                    <rect x="370" y="10" width="130" height="40" rx="6" fill="#161b22" stroke="#30363d" stroke-width="1"/>
                    <text x="435" y="26" text-anchor="middle" fill="#8b949e" font-size="9">${window.escapeHtml(dstName)}</text>
                    <text x="435" y="40" text-anchor="middle" fill="#3fb950" font-size="10" font-family="monospace">${window.escapeHtml(m.remote_subnet)}</text>
                    <path id="pp2-${i}" d="M130,30 Q250,8 370,30" fill="none" stroke="${pathColor}" stroke-width="2"/>
                    ${bothUp ? `<circle r="2.5" fill="${pathColor}" opacity="0.85"><animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze"><mpath href="#pp2-${i}"/></animateMotion></circle>` : ''}
                </svg>
            </div>`;
        });
        container.innerHTML = html;
    }

    // --- Rich VPN Badge Detail Panel ---
    function showRichVPNDetailPanel(deviceId, offnetOnly, devices, vpnMap) {
        destroyPanelCharts();
        currentPanelConnId = null;
        const panel = document.getElementById('conn-detail-panel-container');
        const vpnInfo = vpnMap[String(deviceId)];
        if (!vpnInfo) return;
        const device = devices.find(d => d.id === deviceId);
        const devName = device ? window.escapeHtml(device.name) : 'Device ' + deviceId;

        let tunnels = vpnInfo.tunnels;
        let heading = `${devName} - VPN Tunnels`;
        if (offnetOnly) {
            tunnels = tunnels.filter(t => t.matched_device_id === 0);
            heading = `${devName} - Off-Net Tunnels`;
        }

        const matched = tunnels.filter(t => t.matched_device_id > 0);
        const offnet = tunnels.filter(t => t.matched_device_id === 0);

        function renderVPNTunnelRows(prefix, rows, devId) {
            if (!rows.length) return '<tr><td colspan="7" style="text-align:center;color:#484f58;padding:12px;">None</td></tr>';
            return rows.map((t, i) => {
                const rowId = `${prefix}-${i}`;
                const dest = t.matched_device_id ? `<a href="/admin/devices/${t.matched_device_id}" style="color:#58a6ff;text-decoration:none;font-size:0.78rem;">${window.escapeHtml(t.matched_name)}</a>` : '<span style="color:#d29922;font-size:0.78rem;">Off-Net</span>';
                const statusBadge = `<span class="badge ${t.status}">${t.status.toUpperCase()}</span>`;
                return `
                    <tr class="panel-tunnel-row" onclick="FWDiagram.Panels.togglePanelTunnel('${rowId}', ${devId}, '${window.escapeHtml(t.tunnel_name)}')">
                        <td><span class="chevron" id="pchev-${rowId}">&#9654;</span></td>
                        <td>${window.escapeHtml(t.tunnel_name)}</td>
                        <td>${window.escapeHtml((t.tunnel_type || 'ipsec').toUpperCase())}</td>
                        <td>${statusBadge}</td>
                        <td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(t.remote_ip || '-')}</td>
                        <td>${dest}</td>
                        <td>${t.status === 'up' ? formatPanelUptime(t.tunnel_uptime) : '-'}</td>
                    </tr>
                    <tr class="panel-tunnel-expand" id="${rowId}">
                        <td colspan="7">
                            <div class="panel-range-pills" style="margin-bottom:6px;">
                                <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${devId}, '${window.escapeHtml(t.tunnel_name)}', '1h', event)">1h</div>
                                <div class="panel-range-pill active" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${devId}, '${window.escapeHtml(t.tunnel_name)}', '24h', event)">24h</div>
                                <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${devId}, '${window.escapeHtml(t.tunnel_name)}', '7d', event)">7d</div>
                                <div class="panel-range-pill" onclick="FWDiagram.Panels.loadPanelTunnelChart('${rowId}', ${devId}, '${window.escapeHtml(t.tunnel_name)}', '30d', event)">30d</div>
                            </div>
                            <div class="panel-chart-container" style="height:150px;"><canvas id="pchart-${rowId}"></canvas></div>
                        </td>
                    </tr>`;
            }).join('');
        }

        let sectionsHtml = '';
        if (!offnetOnly && matched.length > 0) {
            sectionsHtml += `
                <h5 style="font-size:0.82rem;color:#e6edf3;margin:12px 0 6px 0;">Matched Tunnels (${matched.length})</h5>
                <table class="vpn-detail-table"><thead><tr><th></th><th>Tunnel</th><th>Type</th><th>Status</th><th>Remote IP</th><th>Destination</th><th>Uptime</th></tr></thead>
                <tbody>${renderVPNTunnelRows('vpn-m', matched, deviceId)}</tbody></table>`;
        }
        if (offnet.length > 0) {
            sectionsHtml += `
                <h5 style="font-size:0.82rem;color:#d29922;margin:12px 0 6px 0;">Off-Net Tunnels (${offnet.length})</h5>
                <table class="vpn-detail-table"><thead><tr><th></th><th>Tunnel</th><th>Type</th><th>Status</th><th>Remote IP</th><th>Destination</th><th>Uptime</th></tr></thead>
                <tbody>${renderVPNTunnelRows('vpn-o', offnet, deviceId)}</tbody></table>`;
        }
        if (!offnetOnly && matched.length === 0 && offnet.length === 0) {
            sectionsHtml = '<div style="text-align:center;color:#484f58;padding:20px;">No tunnels</div>';
        }

        panel.innerHTML = `
            <div class="rich-detail-panel">
                <div class="panel-header">
                    <h4>${heading} <span style="font-size:0.8rem;font-weight:400;color:#8b949e;margin-left:8px;">${vpnInfo.up} up / ${vpnInfo.down} down</span></h4>
                    <button class="btn secondary sm" onclick="FWDiagram.Panels.closeRichPanel()">Close</button>
                </div>
                ${sectionsHtml}
            </div>
        `;
    }

    FWDiagram.Panels = {
        showRichConnDetailPanel,
        showRichVPNDetailPanel,
        closeRichPanel,
        switchPanelTab,
        setPanelTrafficRange,
        setPanelFlowRange,
        togglePanelTunnel,
        loadPanelTunnelChart,
        destroyPanelCharts,
        getCurrentPanelConnId,
        setCurrentPanelConnId
    };
})();
