// diagram-panels.js — FWDiagram.Panels: Rich detail panels for connections and VPN badges
(function() {
    'use strict';

    let panelChartInstances = {};
    let currentPanelConnId = null;
    let pendingOverlayCharts = []; // overlay iface charts to load when the Overlay tab is first shown (avoids 0-size render on a hidden tab)

    function destroyPanelCharts() {
        Object.values(panelChartInstances).forEach(c => { if (c?.destroy) c.destroy(); });
        panelChartInstances = {};
    }

    function panelChartOptions(yCallback) {
        return {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { labels: { boxWidth: 10, padding: 8, font: { size: 10, family: 'Outfit, "Segoe UI", sans-serif' } } },
                tooltip: { callbacks: { label: function(ctx) { var v = ctx.chart.options.indexAxis === 'y' ? ctx.parsed.x : ctx.parsed.y; return ctx.dataset.label + ': ' + window.formatBytes(v != null ? v : 0); } } }
            },
            scales: {
                x: { ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, maxRotation: 0, maxTicksLimit: 12 } },
                y: { beginAtZero: true, ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, callback: yCallback || (v => window.formatBytes(v)) } }
            }
        };
    }

    function formatPanelUptime(s) {
        if (!s) return '-';
        const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
        return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h` : `${Math.floor(s / 60)}m`;
    }

    function formatSpeed(bitsPerSec) {
        if (!bitsPerSec) return '-';
        const u = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
        let v = bitsPerSec, i = 0;
        while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
        return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
    }

    // familyOf mirrors the backend connectionFamily (internal/database/connection_detail.go):
    // it selects which telemetry source + detail view a connection uses.
    function familyOf(connType) {
        switch ((connType || '').toLowerCase().trim()) {
            case 'vxlan': case 'l3ipvlan': return 'overlay';
            case 'ethernet': case 'lag': case 'l2vlan': case 'bridge': case 'wan': return 'direct';
            case 'offnet': return 'offnet';
            default: return 'tunnel'; // ipsec/ssl/gre/tunnel + unknown
        }
    }

    // Per-family chrome: relabels the count KPI and the second tab so the same
    // panel frame reads correctly for tunnels, overlays, direct links, and
    // off-net. Direct/off-net never have Phase 2, so that tab stays hidden.
    function applyFamilyChrome(family) {
        const countLabel = document.getElementById('pkpi-count-label');
        const secondTab = document.querySelector('#rich-panel-tabs .panel-tab[data-tab="tunnels"]');
        const cfg = {
            tunnel:  { count: 'Phase 1', tab: 'Tunnels' },
            overlay: { count: 'Overlay',  tab: 'Overlay' },
            direct:  { count: 'Interfaces', tab: 'Interfaces' },
            offnet:  { count: 'Peers',    tab: 'Peers' }
        }[family] || { count: 'Tunnels', tab: 'Tunnels' };
        if (countLabel) countLabel.textContent = cfg.count;
        if (secondTab) secondTab.textContent = cfg.tab;
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
        if (tabName === 'tunnels') {
            flushOverlayCharts();
        }
        if (tabName === 'flows' && currentPanelConnId && !panelChartInstances['proto']) {
            loadPanelFlowStats(currentPanelConnId, 24);
        }
        if (tabName === 'events' && currentPanelConnId) {
            loadPanelEvents(currentPanelConnId, 24);
        }
    }

    function loadPanelEvents(connId, hours) {
        const container = document.getElementById('panel-events-list');
        if (!container) return;
        container.innerHTML = '<div class="loading" style="padding:20px;">Loading events...</div>';

        window.apiFetch(window.AdminCommon.API_BASE + '/connections/' + connId + '/events?hours=' + hours).then(function(res) {
            const events = res && res.data ? res.data : [];
            if (events.length === 0) {
                container.innerHTML = '<div style="padding:20px;color:var(--fwmon-text-faint);text-align:center;">No events in the last ' + hours + 'h</div>';
                return;
            }
            const sourceIcons = { alert: '\u{1F514}', trap: '\u26A1', syslog: '\u{1F4DD}' };
            const sevColors = { critical: '#f85149', warning: '#d29922', info: '#58a6ff', notice: '#8b949e' };
            container.innerHTML = '<table class="vpn-detail-table" style="font-size:0.78rem;"><thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Type</th><th>Message</th></tr></thead><tbody>' +
                events.map(function(e) {
                    const icon = sourceIcons[e.source] || '';
                    const sevColor = sevColors[e.severity] || '#8b949e';
                    const time = (function(ts) {
                        const d = new Date(ts);
                        const tz = window.AdminCommon.getTimezone();
                        return d.toLocaleString('en-US', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
                    })(e.timestamp);
                    return '<tr>' +
                        '<td style="white-space:nowrap;">' + window.escapeHtml(time) + '</td>' +
                        '<td>' + icon + ' ' + window.escapeHtml(e.source) + '</td>' +
                        '<td><span style="color:' + sevColor + ';font-weight:600;">' + window.escapeHtml(e.severity).toUpperCase() + '</span></td>' +
                        '<td>' + window.escapeHtml(e.type || '-') + '</td>' +
                        '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + window.escapeHtml(e.message || '') + '">' + window.escapeHtml(e.message || '-') + '</td>' +
                    '</tr>';
                }).join('') +
                '</tbody></table>';
        }).catch(function() {
            container.innerHTML = '<div style="padding:20px;color:var(--fwmon-sig-crit);">Failed to load events</div>';
        });
    }

    async function showRichConnDetailPanel(conn) {
        destroyPanelCharts();
        pendingOverlayCharts = [];
        currentPanelConnId = conn.id;
        const panel = document.getElementById('conn-detail-panel-container');
        const srcName = conn.source_device?.name || 'Device ' + conn.source_device_id;
        const dstName = conn.dest_device?.name || 'Device ' + conn.dest_device_id;
        const typeBadge = window.typeBadgeHtml(conn.connection_type);
        const statusBadge = `<span class="badge ${conn.status}">${window.escapeHtml((conn.status || 'unknown').toUpperCase())}</span>`;
        const methodLabels = {ip_match:'Direct',interface_ip:'Direct',bidirectional:'Direct',tunnel_indirect:'Indirect',wan_inferred:'Indirect',name_match:'Indirect',overlay_name:'Indirect',lldp_neighbor:'LLDP confirmed',fdb_match:'MAC-table matched',arp_match:'ARP inferred'};
        const methodBadge = conn.match_method ? `<span class="badge info" style="font-size:0.68rem;">${methodLabels[conn.match_method] || conn.match_method}</span>` : '';

        panel.innerHTML = `
            <div class="rich-detail-panel">
                <div class="panel-header">
                    <h4>${window.escapeHtml(conn.name)} ${typeBadge} ${statusBadge} ${methodBadge}</h4>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <a href="/admin/connections/${conn.id}" style="color:var(--fwmon-accent);font-size:0.8rem;text-decoration:none;font-weight:500;">Full Page &rarr;</a>
                        <button class="btn secondary sm" data-action="dp-close-panel">Close</button>
                    </div>
                </div>
                <div id="panel-bridge-container"></div>
                <div class="panel-kpi-grid">
                    <div class="panel-kpi-card"><div class="kpi-label">Bytes In</div><div class="kpi-value accent" id="pkpi-bytes-in">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label">Bytes Out</div><div class="kpi-value good" id="pkpi-bytes-out">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label" id="pkpi-count-label">Tunnels</div><div class="kpi-value" id="pkpi-tunnels">--</div></div>
                    <div class="panel-kpi-card"><div class="kpi-label">Status</div><div class="kpi-value" id="pkpi-status">--</div></div>
                </div>
                <div class="panel-tabs" id="rich-panel-tabs">
                    <div class="panel-tab active" data-tab="overview" data-action="dp-switch-tab">Overview</div>
                    <div class="panel-tab" data-tab="tunnels" data-action="dp-switch-tab">Tunnels</div>
                    <div class="panel-tab" data-tab="phase2" data-action="dp-switch-tab" id="ptab-phase2-tab" style="display:none;">Phase 2</div>
                    <div class="panel-tab" data-tab="flows" data-action="dp-switch-tab" id="ptab-flows-tab" style="display:none;">Flows</div>
                    <div class="panel-tab" data-tab="events" data-action="dp-switch-tab">Events</div>
                </div>
                <div id="rich-panel-content">
                    <div class="panel-tab-content active" id="ptab-overview">
                        <div class="panel-range-pills" id="panel-traffic-range">
                            <div class="panel-range-pill" data-action="dp-traffic-range" data-range="1h">1h</div>
                            <div class="panel-range-pill active" data-action="dp-traffic-range" data-range="24h">24h</div>
                            <div class="panel-range-pill" data-action="dp-traffic-range" data-range="7d">7d</div>
                            <div class="panel-range-pill" data-action="dp-traffic-range" data-range="30d">30d</div>
                        </div>
                        <div id="panel-traffic-chart-host" class="panel-chart-container"><canvas id="panel-traffic-chart"></canvas></div>
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
                            <div class="panel-range-pill" data-action="dp-flow-range" data-hours="1">1h</div>
                            <div class="panel-range-pill active" data-action="dp-flow-range" data-hours="24">24h</div>
                            <div class="panel-range-pill" data-action="dp-flow-range" data-hours="168">7d</div>
                            <div class="panel-range-pill" data-action="dp-flow-range" data-hours="720">30d</div>
                        </div>
                        <div id="panel-flow-content">
                            <div style="display:flex;gap:12px;margin-bottom:8px;">
                                <span style="font-size:0.78rem;color:var(--fwmon-text-faint);">Total bytes: <strong style="color:var(--fwmon-text);" id="pf-total-bytes">--</strong></span>
                                <span style="font-size:0.78rem;color:var(--fwmon-text-faint);">Flows: <strong style="color:var(--fwmon-text);" id="pf-total-flows">--</strong></span>
                            </div>
                            <div class="panel-flow-grid">
                                <div class="panel-flow-card"><h5>Protocols</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-proto-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Traffic Over Time</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-flow-time-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Top Sources</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-top-src-chart"></canvas></div></div>
                                <div class="panel-flow-card"><h5>Top Destinations</h5><div class="panel-chart-container" style="height:160px;"><canvas id="panel-top-dst-chart"></canvas></div></div>
                            </div>
                            <div style="margin-top:12px;">
                                <h5 style="font-size:0.8rem;color:var(--fwmon-text-faint);margin:0 0 6px 0;">Top Conversations</h5>
                                <div style="max-height:200px;overflow-y:auto;">
                                    <table class="vpn-detail-table" id="panel-convos-table">
                                        <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Packets</th></tr></thead>
                                        <tbody></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="panel-tab-content" id="ptab-events">
                        <div class="panel-range-pills" id="panel-events-range">
                            <div class="panel-range-pill" data-action="dp-events-range" data-hours="1">1h</div>
                            <div class="panel-range-pill" data-action="dp-events-range" data-hours="6">6h</div>
                            <div class="panel-range-pill active" data-action="dp-events-range" data-hours="24">24h</div>
                            <div class="panel-range-pill" data-action="dp-events-range" data-hours="168">7d</div>
                        </div>
                        <div id="panel-events-list" style="max-height:400px;overflow-y:auto;">
                            <div class="loading" style="padding:20px;">Loading events...</div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        applyFamilyChrome(familyOf(conn.connection_type));
        renderPanelBridge('panel-bridge-container', srcName, dstName, conn.status, conn.connection_type);
        loadPanelDetail(conn.id, conn);
        loadPanelTrafficChart(conn.id, '24h');
    }

    async function loadPanelDetail(connId, conn) {
        try {
            const resp = await window.apiFetch(`${window.API_BASE}/connections/${connId}/detail`);
            const data = resp && resp.data ? resp.data : resp;
            if (!data || currentPanelConnId !== connId) return;
            const c = data.connection || conn;
            const srcName = c.source_device?.name || conn.source_device?.name || 'Device ' + c.source_device_id;
            const dstName = c.dest_device?.name || conn.dest_device?.name || 'Device ' + c.dest_device_id;

            const family = data.family || familyOf(c.connection_type);
            document.getElementById('pkpi-bytes-in').textContent = window.formatBytes(data.total_bytes_in);
            document.getElementById('pkpi-bytes-out').textContent = window.formatBytes(data.total_bytes_out);
            const statusEl = document.getElementById('pkpi-status');
            statusEl.innerHTML = `<span class="badge ${c.status}" style="font-size:0.75rem;">${(c.status || 'unknown').toUpperCase()}</span>`;

            const p2Tab = document.getElementById('ptab-phase2-tab');

            if (family === 'direct') {
                // Direct links carry interfaces, not tunnels — render the member
                // interfaces (from interface_stats) into the second tab, topped
                // by the L2 port-pair summary and followed by the discovery
                // evidence that drew the link.
                const ifaces = data.interfaces || [];
                const countLabel = document.getElementById('pkpi-count-label');
                if (countLabel) countLabel.textContent = 'Interfaces';
                document.getElementById('pkpi-tunnels').textContent = ifaces.length;
                renderPanelInterfaceTab(ifaces, c, srcName, dstName);
                renderPanelL2Evidence(c, data.evidence || []);
                if (p2Tab) p2Tab.style.display = 'none';
            } else if (family === 'overlay') {
                // Overlay (VXLAN/L3VLAN): show config + SNMP-derived overlay
                // detail (VNI, carrier iface, VTEPs) plus the carrier tunnel.
                const overlays = data.overlays || [];
                const srcT = data.source_tunnels || [], dstT = data.dest_tunnels || [];
                document.getElementById('pkpi-tunnels').textContent = overlays.length || (countPhase1(srcT) + countPhase1(dstT));
                renderPanelOverlayTab(data, c, srcName, dstName);
                if (p2Tab) p2Tab.style.display = 'none';
            } else {
                // Tunnel / overlay / off-net: group Phase 2 selectors under their
                // Phase 1 (one graph per Phase 1 — Phase 2 selectors share it).
                const srcT = data.source_tunnels || [], dstT = data.dest_tunnels || [];
                document.getElementById('pkpi-tunnels').textContent = countPhase1(srcT) + countPhase1(dstT);
                const tnoun = family === 'overlay' ? 'Carrier' : 'Source Tunnels';
                const dnoun = family === 'overlay' ? 'Carrier (remote)' : 'Dest Tunnels';
                document.getElementById('ptab-src-title').textContent = `${tnoun} (${srcName})`;
                document.getElementById('ptab-dst-title').textContent = `${dnoun} (${dstName})`;
                renderPanelTunnelTable('ptab-src-tunnels', srcT, c.source_device_id, family);
                renderPanelTunnelTable('ptab-dst-tunnels', dstT, c.dest_device_id, family);

                const p2 = data.phase2_matches || [];
                if (p2Tab) p2Tab.style.display = p2.length > 0 ? '' : 'none';
                if (p2.length > 0) renderPanelPhase2(p2, srcName, dstName);
            }

            const flowsTab = document.getElementById('ptab-flows-tab');
            if (flowsTab) flowsTab.style.display = data.has_flow_data ? '' : 'none';

            // Auto-switch to Events tab when connection is DOWN
            if (conn.status === 'down') {
                switchPanelTab('events');
            }
        } catch (e) { console.error('Panel detail load failed:', e); }
    }

    async function loadPanelTrafficChart(connId, range) {
        try {
            const resp = await window.apiFetch(`${window.API_BASE}/connections/${connId}/traffic?range=${range}`);
            const data = resp && resp.data ? resp.data : resp;
            if (!data || currentPanelConnId !== connId) return;
            // M13 of the 2026-07-01 audit: operate on the stable host, and
            // re-create the canvas if a prior empty-state removed it — otherwise
            // `if (!canvas) return` silently killed the panel traffic tab forever.
            const host = document.getElementById('panel-traffic-chart-host');
            let canvas = document.getElementById('panel-traffic-chart');
            if (panelChartInstances['traffic']) panelChartInstances['traffic'].destroy();
            if (!Array.isArray(data) || data.length === 0) {
                if (host) host.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No traffic data available for this connection.</div>';
                return;
            }
            if (!canvas && host) {
                host.innerHTML = '<canvas id="panel-traffic-chart"></canvas>';
                canvas = document.getElementById('panel-traffic-chart');
            }
            if (!canvas) return;
            // Connection traffic arrives as per-bucket deltas — render
            // throughput/transfer/combined via the shared 3-mode component.
            const series = window.FwmonBwChart.normalizeDeltas(data);
            panelChartInstances['traffic'] = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'Inbound', txLabel: 'Outbound' });
        } catch (e) { console.error('Panel traffic chart failed:', e); }
    }

    function setPanelTrafficRange(range) {
        document.querySelectorAll('#panel-traffic-range .panel-range-pill').forEach(p => p.classList.toggle('active', p.textContent === range));
        if (currentPanelConnId) loadPanelTrafficChart(currentPanelConnId, range);
    }

    async function loadPanelFlowStats(connId, hours) {
        try {
            const resp = await window.apiFetch(`${window.API_BASE}/connections/${connId}/flows?hours=${hours}`);
            const data = resp && resp.data ? resp.data : resp;
            if (!data || currentPanelConnId !== connId) return;
            const hasData = data.total_flows > 0;
            const content = document.getElementById('panel-flow-content');
            if (!hasData) {
                content.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No sFlow data available for this connection.</div>';
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
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { padding: 6, font: { size: 11 } } } } }
            });

            if (panelChartInstances['flowTime']) panelChartInstances['flowTime'].destroy();
            const timeData = data.bytes_over_time || [];
            // bytes_over_time.count is a per-bucket SUM (not cumulative); render it
            // as throughput (Mbps) rather than a raw byte total so it reads like the
            // public dashboard and doesn't look like an ever-climbing line.
            const flowIntervalSec = data.bucket_seconds || 3600;
            panelChartInstances['flowTime'] = new Chart(document.getElementById('panel-flow-time-chart'), {
                type: 'line',
                data: { labels: timeData.map(t => t.bucket.split(' ').pop() || t.bucket), datasets: [{ label: 'Throughput', data: timeData.map(t => (t.count * 8) / flowIntervalSec / 1e6), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { boxWidth: 10, padding: 8, font: { size: 10 } } },
                        tooltip: { callbacks: { label: function(ctx) { return 'Throughput: ' + (ctx.parsed.y != null ? ctx.parsed.y.toFixed(2) : '0') + ' Mbps'; } } }
                    },
                    scales: {
                        x: { ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, maxRotation: 0, maxTicksLimit: 12 } },
                        y: { beginAtZero: true, ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, callback: v => v.toFixed(1) + ' Mbps' } }
                    }
                }
            });

            if (panelChartInstances['topSrc']) panelChartInstances['topSrc'].destroy();
            const srcData = data.top_sources || [];
            panelChartInstances['topSrc'] = new Chart(document.getElementById('panel-top-src-chart'), {
                type: 'bar',
                data: { labels: srcData.map(s => s.key), datasets: [{ label: 'Bytes', data: srcData.map(s => s.count), backgroundColor: 'rgba(125, 211, 252, 0.45)', borderRadius: 4 }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { callbacks: { label: function(ctx) { return window.formatBytes(ctx.parsed.x || 0); } } } }, scales: { x: { beginAtZero: true, ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, callback: v => window.formatBytes(v) } }, y: { ticks: { font: { size: 10, family: 'Outfit, "Segoe UI", sans-serif' } }, grid: { display: false } } } }
            });

            if (panelChartInstances['topDst']) panelChartInstances['topDst'].destroy();
            const dstData = data.top_destinations || [];
            panelChartInstances['topDst'] = new Chart(document.getElementById('panel-top-dst-chart'), {
                type: 'bar',
                data: { labels: dstData.map(s => s.key), datasets: [{ label: 'Bytes', data: dstData.map(s => s.count), backgroundColor: 'rgba(134, 239, 172, 0.45)', borderRadius: 4 }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { callbacks: { label: function(ctx) { return window.formatBytes(ctx.parsed.x || 0); } } } }, scales: { x: { beginAtZero: true, ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, callback: v => window.formatBytes(v) } }, y: { ticks: { font: { size: 10, family: 'Outfit, "Segoe UI", sans-serif' } }, grid: { display: false } } } }
            });

            const convos = data.top_conversations || [];
            const ctbody = document.querySelector('#panel-convos-table tbody');
            const AC = window.AdminCommon;
            ctbody.innerHTML = convos.map(c => `<tr><td style="font-family:monospace;font-size:0.78rem;white-space:nowrap;">${AC.ipRef(c.src_addr, { port: c.src_port })}</td><td style="font-family:monospace;font-size:0.78rem;white-space:nowrap;">${AC.ipRef(c.dst_addr, { port: c.dst_port })}</td><td>${window.escapeHtml(c.protocol)}</td><td>${window.formatBytes(c.bytes)}</td><td>${window.formatNum(c.packets)}</td></tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--fwmon-text-mute);">No conversations</td></tr>';
            AC.enrichIps(ctbody);
        } catch (e) { console.error('Panel flow stats failed:', e); }
    }

    function setPanelFlowRange(hours) {
        const labels = {1:'1h', 24:'24h', 168:'7d', 720:'30d'};
        document.querySelectorAll('#panel-flow-range .panel-range-pill').forEach(p => p.classList.toggle('active', p.textContent === labels[hours]));
        if (currentPanelConnId) loadPanelFlowStats(currentPanelConnId, hours);
    }

    // groupByPhase1 collapses Phase 2 selectors that share a Phase 1 IKE gateway
    // into one group. Multiple Phase 2 selectors under one Phase 1 share a single
    // counter series, so the UI shows ONE graph per Phase 1 (keyed off a
    // representative selector) and lists the selectors as non-graphed children.
    function groupByPhase1(tunnels) {
        const groups = {}, order = [];
        (tunnels || []).forEach(t => {
            const key = (t.phase1_name && t.phase1_name.trim()) || t.tunnel_name;
            if (!groups[key]) { groups[key] = []; order.push(key); }
            groups[key].push(t);
        });
        return order.map(k => ({ phase1: k, phase2: groups[k] }));
    }

    function countPhase1(tunnels) { return groupByPhase1(tunnels).length; }

    function renderPanelTunnelTable(tableId, tunnels, deviceId, family) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        const noun = family === 'overlay' ? 'carrier tunnels' : 'tunnels';
        if (!tunnels.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--fwmon-text-mute);padding:16px;">No ${noun}</td></tr>`;
            return;
        }
        let html = '';
        groupByPhase1(tunnels).forEach((g, gi) => {
            const rowId = `${tableId}-row-${gi}`;
            const rep = g.phase2[0].tunnel_name; // representative selector — shared counter series
            const anyUp = g.phase2.some(t => t.status === 'up' || t.state === 'up');
            const statusBadge = anyUp ? '<span class="badge up">UP</span>' : '<span class="badge down">DOWN</span>';
            const sumIn = g.phase2.reduce((a, t) => a + (t.bytes_in || 0), 0);
            const sumOut = g.phase2.reduce((a, t) => a + (t.bytes_out || 0), 0);
            const remoteIP = g.phase2[0].remote_ip || '-';
            const selCount = g.phase2.length;
            const label = window.escapeHtml(g.phase1) + (selCount > 1 ? ` <span style="color:var(--fwmon-text-mute);font-size:0.72rem;">(${selCount} selectors)</span>` : '');
            const pill = (r, lbl, active) => `<div class="panel-range-pill${active ? ' active' : ''}" data-action="dp-tunnel-chart" data-row="${rowId}" data-device="${deviceId}" data-tunnel="${window.escapeHtml(rep)}" data-range="${r}">${lbl}</div>`;
            html += `
                <tr class="panel-tunnel-row" data-action="dp-toggle-tunnel" data-row="${rowId}" data-device="${deviceId}" data-tunnel="${window.escapeHtml(rep)}">
                    <td><span class="chevron" id="pchev-${rowId}">&#9654;</span></td>
                    <td>${label}</td>
                    <td>${statusBadge}</td>
                    <td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(remoteIP)}</td>
                    <td>${window.formatBytes(sumIn)}</td>
                    <td>${window.formatBytes(sumOut)}</td>
                </tr>`;
            // Phase 2 selector child rows (subnets) — informational, no graph.
            g.phase2.forEach(t => {
                if (!t.local_subnet && !t.remote_subnet) return;
                const sUp = t.status === 'up' || t.state === 'up';
                html += `
                <tr class="panel-tunnel-p2child">
                    <td></td>
                    <td style="font-family:monospace;font-size:0.74rem;color:var(--fwmon-text-faint);padding-left:14px;">&#8627; ${window.escapeHtml(t.local_subnet || '?')} &rarr; ${window.escapeHtml(t.remote_subnet || '?')}</td>
                    <td><span class="badge ${sUp ? 'up' : 'down'}" style="font-size:0.6rem;">${sUp ? 'UP' : 'DOWN'}</span></td>
                    <td></td>
                    <td style="font-size:0.74rem;">${window.formatBytes(t.bytes_in)}</td>
                    <td style="font-size:0.74rem;">${window.formatBytes(t.bytes_out)}</td>
                </tr>`;
            });
            html += `
                <tr class="panel-tunnel-expand" id="${rowId}">
                    <td colspan="6">
                        <div class="panel-range-pills" style="margin-bottom:6px;">
                            ${pill('1h', '1h', false)}${pill('24h', '24h', true)}${pill('7d', '7d', false)}${pill('30d', '30d', false)}
                        </div>
                        <div class="panel-chart-container" style="height:150px;"><canvas id="pchart-${rowId}"></canvas></div>
                    </td>
                </tr>`;
        });
        tbody.innerHTML = html;
    }

    // kindLabel maps an ifType name to a short human label.
    function kindLabel(kind) {
        return ({ l2vlan: 'VLAN', l3ipvlan: 'L3VLAN', bridge: 'Bridge', propVirtual: 'SoftSwitch', lag: 'LAG', ethernet: 'Physical', tunnel: 'Tunnel', vxlan: 'VXLAN' })[kind] || kind || '';
    }

    // ifaceMeta builds the kind/VLAN/parent annotation under an interface name,
    // making the interface's role and relationships explicit.
    function ifaceMeta(f) {
        const bits = [];
        const k = kindLabel(f.kind);
        if (k) bits.push(k);
        if (f.vlan_id > 0) bits.push('VLAN ' + f.vlan_id);
        if (f.parent) bits.push('&#8627; ' + window.escapeHtml(f.parent));
        return bits.join('<span style="color:var(--fwmon-border-strong);"> · </span>');
    }

    // ifaceRowsHtml renders the expandable per-interface rows for one side of a
    // network segment. `rowKey` makes each row id unique across segments.
    function ifaceRowsHtml(ifaces, rowKey) {
        return ifaces.map((f, i) => {
            const rowId = `iface-${rowKey}-${i}`;
            const up = f.status === 'up';
            const statusBadge = `<span class="badge ${up ? 'up' : 'down'}" style="font-size:0.62rem;">${(f.status || 'unknown').toUpperCase()}</span>`;
            const errs = (f.in_errors || 0) + (f.out_errors || 0);
            const errCell = errs > 0 ? `<span style="color:var(--fwmon-sig-warn);">${window.formatNum(errs)} err</span>` : '';
            const meta = ifaceMeta(f);
            const pill = (r, lbl, active) => `<div class="panel-range-pill${active ? ' active' : ''}" data-action="dp-iface-chart" data-row="${rowId}" data-device="${f.device_id}" data-ifindex="${f.if_index}" data-range="${r}">${lbl}</div>`;
            return `
                <tr class="panel-tunnel-row" data-action="dp-toggle-iface" data-row="${rowId}" data-device="${f.device_id}" data-ifindex="${f.if_index}">
                    <td><span class="chevron" id="pchev-${rowId}">&#9654;</span></td>
                    <td><div style="font-family:monospace;">${window.escapeHtml(f.if_name)}</div>${meta ? `<div style="font-size:0.66rem;color:var(--fwmon-text-mute);">${meta}</div>` : ''}</td>
                    <td style="font-family:monospace;font-size:0.76rem;color:var(--fwmon-accent);">${window.escapeHtml(f.ip_address || '-')}</td>
                    <td style="font-size:0.76rem;">${formatSpeed(f.speed)}</td>
                    <td>${statusBadge}</td>
                    <td>${window.formatBytes(f.in_bytes)}</td>
                    <td>${window.formatBytes(f.out_bytes)}</td>
                    <td style="font-size:0.74rem;">${errCell}</td>
                </tr>
                <tr class="panel-tunnel-expand" id="${rowId}">
                    <td colspan="8">
                        <div class="panel-range-pills" style="margin-bottom:6px;">
                            ${pill('1h', '1h', false)}${pill('24h', '24h', true)}${pill('7d', '7d', false)}${pill('30d', '30d', false)}
                        </div>
                        <div class="panel-chart-container" style="height:150px;"><canvas id="pchart-${rowId}"></canvas></div>
                    </td>
                </tr>`;
        }).join('');
    }

    function ifaceSideTable(title, ifaces, rowKey) {
        const head = `<div style="font-size:0.74rem;color:var(--fwmon-text-faint);margin:0 0 4px 2px;">${window.escapeHtml(title)}</div>`;
        if (!ifaces.length) {
            return head + '<div style="color:var(--fwmon-text-mute);font-size:0.76rem;padding:6px 2px;">— no interfaces reported —</div>';
        }
        return head + `<table class="vpn-detail-table" style="margin:0;"><thead><tr><th></th><th>Interface</th><th>IP</th><th>Speed</th><th>Status</th><th>In</th><th>Out</th><th></th></tr></thead><tbody>${ifaceRowsHtml(ifaces, rowKey)}</tbody></table>`;
    }

    function ifaceSegmentCard(header, srcName, dstName, srcSide, dstSide, rowKey) {
        return `
            <div style="background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:12px;margin-bottom:10px;">
                ${header}
                <div class="tunnel-columns">
                    <div class="tunnel-col">${ifaceSideTable(srcName, srcSide, `${rowKey}-s`)}</div>
                    <div class="tunnel-col">${ifaceSideTable(dstName, dstSide, `${rowKey}-d`)}</div>
                </div>
            </div>`;
    }

    // jsNormalizeIfName mirrors the backend normalizeIfName so the UI can pair
    // interfaces the same way the detector matched them (vlan100 ≈ VLAN-100).
    function jsNormalizeIfName(name) {
        return (name || '').toLowerCase().trim().replace(/[ ._-]/g, '');
    }

    // segmentLabel picks the clearest identity for a group of interfaces that
    // form one logical segment: the bridge/switch name > VLAN id > subnet > name.
    function segmentLabel(members) {
        const bridge = members.find(f => f.kind === 'bridge' || f.kind === 'propVirtual');
        const vlans = [...new Set(members.filter(f => f.vlan_id > 0).map(f => f.vlan_id))];
        if (bridge) return { icon: '&#128279;', label: bridge.if_name, sub: vlans.length === 1 ? 'VLAN ' + vlans[0] : 'bridge' }; // 🔗
        if (vlans.length === 1) return { icon: '&#127991;', label: 'VLAN ' + vlans[0], sub: 'vlan' };        // 🏷
        const subnet = (members.find(f => f.subnet) || {}).subnet;
        if (subnet) return { icon: '&#127760;', label: subnet, sub: 'network' };                             // 🌐
        const parent = (members.find(f => f.parent) || {}).parent;
        if (parent) return { icon: '&#128279;', label: parent, sub: 'parent interface' };
        return { icon: '&#128279;', label: (members[0] || {}).if_name || 'segment', sub: 'interface' };
    }

    // renderPanelInterfaceTab groups interfaces into logical segments and makes
    // the device↔segment↔device pairing explicit. Interfaces are merged into the
    // same segment when they share a VLAN id OR a parent/root interface name
    // (union-find over both signals), so a VLAN sub-interface and its parent
    // bridge — and the same segment across the two devices, even when named
    // differently — collapse into one card instead of showing as separate items.
    // Each segment present on both ends is a paired card; the rest fall into a
    // combined "Other interfaces" card. Every interface stays expandable to its
    // own chart and is annotated with its kind / VLAN / parent.
    function renderPanelInterfaceTab(ifaces, c, srcName, dstName) {
        const container = document.getElementById('ptab-tunnels');
        if (!container) return;
        if (!ifaces.length) {
            container.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:16px;">No interface telemetry for this link</div>';
            return;
        }
        const srcId = c.source_device_id, dstId = c.dest_device_id;
        const onSrc = f => f.device_id === srcId;
        const onDst = f => f.device_id === dstId;

        // Union-find: merge interfaces that are the same logical segment. Signals:
        //  - same normalized interface name (separator diffs / same name on both ends)
        //  - a sub-interface with its parent, but ONLY when the parent interface is
        //    itself present (bridge + its VLAN) — never merge two VLANs just because
        //    they happen to share a parent string (distinct VLANs on a trunk)
        //  - same VLAN id (same broadcast domain across devices)
        //  - same IP subnet
        const uf = ifaces.map((_, i) => i);
        const find = x => { while (uf[x] !== x) { uf[x] = uf[uf[x]]; x = uf[x]; } return x; };
        const union = (a, b) => { uf[find(a)] = find(b); };
        const nameIdx = {}; // normalized name → representative index (built first)
        ifaces.forEach((f, i) => { const n = jsNormalizeIfName(f.if_name); if (n && nameIdx[n] == null) nameIdx[n] = i; });
        const byVlan = {}, bySubnet = {};
        ifaces.forEach((f, i) => {
            const n = jsNormalizeIfName(f.if_name);
            if (n && nameIdx[n] != null) union(i, nameIdx[n]);
            if (f.parent) { const p = jsNormalizeIfName(f.parent); if (nameIdx[p] != null) union(i, nameIdx[p]); }
            if (f.vlan_id > 0) { if (byVlan[f.vlan_id] != null) union(i, byVlan[f.vlan_id]); else byVlan[f.vlan_id] = i; }
            if (f.subnet) { if (bySubnet[f.subnet] != null) union(i, bySubnet[f.subnet]); else bySubnet[f.subnet] = i; }
        });
        const groupsMap = {};
        ifaces.forEach((f, i) => { const r = find(i); (groupsMap[r] = groupsMap[r] || []).push(f); });
        const groups = Object.values(groupsMap);

        let html = '', gi = 0;
        const leftover = [];
        groups.forEach(members => {
            const s = members.filter(onSrc), dd = members.filter(onDst);
            if (s.length && dd.length) {
                const seg = segmentLabel(members);
                const header = `
                    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
                        <span style="font-family:monospace;font-size:0.82rem;font-weight:600;color:var(--fwmon-text);background:var(--fwmon-card-bg);border:1px solid var(--fwmon-border);border-radius:5px;padding:2px 8px;">${seg.icon} ${window.escapeHtml(seg.label)}</span>
                        <span style="font-size:0.7rem;color:var(--fwmon-text-mute);text-transform:uppercase;letter-spacing:0.3px;">${seg.sub}</span>
                        <span style="font-size:0.78rem;color:var(--fwmon-text-faint);">${window.escapeHtml(srcName)} <span style="color:#2dd4bf;">&harr;</span> ${window.escapeHtml(dstName)}</span>
                    </div>`;
                html += ifaceSegmentCard(header, srcName, dstName, s, dd, `seg${gi++}`);
            } else {
                leftover.push(...members);
            }
        });

        if (leftover.length) {
            const label = gi ? 'Other interfaces' : 'Interfaces on this link';
            const hint = gi ? ' (could not be paired to the other end)' : '';
            const header = `<div style="font-size:0.8rem;color:var(--fwmon-text-faint);margin-bottom:8px;">${label}<span style="color:var(--fwmon-text-mute);font-size:0.72rem;">${hint}</span></div>`;
            html += ifaceSegmentCard(header, srcName, dstName, leftover.filter(onSrc), leftover.filter(onDst), 'rest');
        }
        container.innerHTML = html;
    }

    // l2MethodLabel: user-facing names for the L2 evidence tiers.
    const L2_METHOD_LABELS = { lldp_neighbor: 'LLDP confirmed', fdb_match: 'MAC-table matched', arp_match: 'ARP inferred' };
    const L2_TIER_LABELS = { lldp: 'LLDP', fdb: 'MAC table', arp: 'ARP' };

    function l2RelativeAge(ts) {
        const ms = Date.now() - new Date(ts).getTime();
        if (!isFinite(ms) || ms < 0) return '-';
        const min = Math.floor(ms / 60000);
        if (min < 1) return 'now';
        if (min < 60) return min + 'm ago';
        const h = Math.floor(min / 60);
        if (h < 48) return h + 'h ago';
        return Math.floor(h / 24) + 'd ago';
    }

    // renderPanelL2Evidence: prepends the port-pair summary line and appends
    // the discovery-evidence list around the interface cards in the direct
    // tab. EVERY rendered value is neighbor-/network-controlled (LLDP sysnames,
    // port strings, MACs) — all go through escapeHtml.
    function renderPanelL2Evidence(c, evidence) {
        const container = document.getElementById('ptab-tunnels');
        if (!container) return;
        const esc = window.escapeHtml;

        // Summary line: port pair + method chip + VLANs (only for L2 links).
        if (c.source_if_name || c.dest_if_name || L2_METHOD_LABELS[c.match_method]) {
            const ports = `${esc(c.source_if_name || '?')} <span style="color:#2dd4bf;">&harr;</span> ${esc(c.dest_if_name || '?')}`;
            const chip = L2_METHOD_LABELS[c.match_method]
                ? `<span class="badge info" style="font-size:0.68rem;">${esc(L2_METHOD_LABELS[c.match_method])}</span>` : '';
            const vlans = c.vlan_ids ? `<span style="font-size:0.72rem;color:var(--fwmon-text-mute);">VLAN ${esc(c.vlan_ids)}</span>` : '';
            const stale = c.status === 'stale'
                ? `<span class="badge stale" style="font-size:0.68rem;">STALE EVIDENCE</span>` : '';
            container.insertAdjacentHTML('afterbegin',
                `<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;font-weight:600;color:var(--fwmon-text);background:var(--fwmon-card-bg);border:1px solid var(--fwmon-border);border-radius:5px;padding:2px 10px;">${ports}</span>
                    ${chip}${vlans}${stale}
                </div>`);
        }

        if (!L2_METHOD_LABELS[c.match_method]) return; // manual/legacy link — no discovery evidence section

        let rows = '';
        (evidence || []).forEach(function(ev) {
            const observed = [
                ev.remote_mac ? `MAC ${esc(ev.remote_mac)}` : '',
                ev.remote_ip ? `IP ${esc(ev.remote_ip)}` : '',
                ev.remote_port ? `port ${esc(ev.remote_port)}` : '',
                ev.remote_sysname ? `sys ${esc(ev.remote_sysname)}` : ''
            ].filter(Boolean).join(' · ');
            const freshDot = ev.fresh
                ? '<span style="color:var(--fwmon-sig-ok);">&#9679;</span>'
                : '<span style="color:var(--fwmon-sig-warn);" title="older than the fresh window">&#9679;</span>';
            const note = ev.note ? `<div style="font-size:0.68rem;color:var(--fwmon-sig-warn);">${esc(ev.note)}</div>` : '';
            rows += `<tr>
                <td><span class="badge info" style="font-size:0.66rem;">${esc(L2_TIER_LABELS[ev.tier] || ev.tier)}</span></td>
                <td><a href="/admin/devices/${encodeURIComponent(ev.device_id)}" style="color:var(--fwmon-accent);text-decoration:none;">${esc(ev.device_name || ('Device ' + ev.device_id))}</a></td>
                <td style="font-family:'JetBrains Mono',monospace;">${esc(ev.local_if_name || String(ev.local_if_index || '-'))}</td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:0.74rem;">${observed || '-'}${note}</td>
                <td>${ev.vlan_id ? esc(String(ev.vlan_id)) : '-'}</td>
                <td>${esc(l2RelativeAge(ev.timestamp))} ${freshDot}</td>
            </tr>`;
        });
        const body = rows
            ? `<div style="overflow-x:auto;"><table class="vpn-detail-table">
                 <thead><tr><th>Source</th><th>Reported by</th><th>Local port</th><th>Observed</th><th>VLAN</th><th>Age</th></tr></thead>
                 <tbody>${rows}</tbody></table></div>`
            : `<div style="color:var(--fwmon-text-mute);font-size:0.78rem;padding:6px 2px;">No layer-2 evidence in the current snapshots — the discovery data behind this link has expired. The link is marked stale and will be removed if no fresh evidence arrives.</div>`;
        container.insertAdjacentHTML('beforeend',
            `<div style="margin-top:14px;">
                <h5 style="font-size:0.8rem;color:var(--fwmon-text-faint);margin:0 0 6px 0;">Discovery Evidence <span style="font-weight:400;color:var(--fwmon-text-mute);">— why this link is drawn</span></h5>
                ${body}
            </div>`);
    }

    // renderPanelOverlayTab shows VXLAN/L3VLAN overlay detail derived from the
    // FortiGate config (VNI, carrier interface, UDP dstport, remote VTEP peers)
    // and SNMP (the overlay interface's own counters + chart), followed by the
    // carrier tunnel(s) the overlay actually rides on.
    function renderPanelOverlayTab(data, c, srcName, dstName) {
        const container = document.getElementById('ptab-tunnels');
        if (!container) return;
        const overlays = data.overlays || [];
        const typeLabel = t => (t === 'l3ipvlan' ? 'L3VLAN' : 'VXLAN');
        const kv = (label, val) => `<div><div style="font-size:0.66rem;color:var(--fwmon-text-mute);text-transform:uppercase;letter-spacing:0.4px;">${label}</div><div style="font-size:0.82rem;color:var(--fwmon-text);font-family:'JetBrains Mono',monospace;">${val}</div></div>`;

        let html = '';
        if (!overlays.length) {
            html += '<div style="color:var(--fwmon-text-mute);padding:8px 2px;font-size:0.8rem;">No overlay interface detail available — config not captured for these devices (the carrier tunnel is shown below).</div>';
        }
        overlays.forEach((o, i) => {
            const rowId = 'ov-' + i;
            const up = o.status === 'up';
            const vteps = (o.remote_vteps || []).length
                ? o.remote_vteps.map(ip => `<span style="font-family:monospace;font-size:0.74rem;color:var(--fwmon-accent);">${window.escapeHtml(ip)}</span>`).join('<span style="color:var(--fwmon-border-strong);"> · </span>')
                : '<span style="color:var(--fwmon-text-mute);">— not in captured config —</span>';
            const pill = (r, lbl, active) => `<div class="panel-range-pill${active ? ' active' : ''}" data-action="dp-iface-chart" data-row="${rowId}" data-device="${o.device_id}" data-ifindex="${o.if_index}" data-range="${r}">${lbl}</div>`;
            html += `
                <div style="background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:12px;margin-bottom:10px;">
                    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
                        <span style="font-size:0.66rem;font-weight:700;letter-spacing:0.5px;color:var(--fwmon-series-6);background:var(--fwmon-card-bg);border:1px solid var(--fwmon-border);border-radius:4px;padding:2px 7px;">${typeLabel(o.type)}</span>
                        <span style="font-family:monospace;font-size:0.85rem;font-weight:600;color:var(--fwmon-text);">${window.escapeHtml(o.name)}</span>
                        <span style="font-size:0.78rem;color:var(--fwmon-text-faint);">on ${window.escapeHtml(o.device_name || '-')}</span>
                        <span class="badge ${up ? 'up' : 'down'}" style="font-size:0.62rem;">${(o.status || 'unknown').toUpperCase()}</span>
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(86px,1fr));gap:10px;margin-bottom:10px;">
                        ${kv('VNI', o.vni ? o.vni : '—')}
                        ${kv('Carrier iface', o.carrier_iface ? window.escapeHtml(o.carrier_iface) : '—')}
                        ${kv('UDP port', o.dest_port ? o.dest_port : '4789')}
                        ${kv('In', window.formatBytes(o.in_bytes))}
                        ${kv('Out', window.formatBytes(o.out_bytes))}
                    </div>
                    <div style="margin-bottom:${o.if_index ? '10px' : '0'};"><span style="font-size:0.66rem;color:var(--fwmon-text-mute);text-transform:uppercase;letter-spacing:0.4px;">Remote VTEPs</span>&nbsp; ${vteps}</div>
                    ${o.if_index ? `
                    <div class="panel-range-pills" style="margin-bottom:6px;">${pill('1h', '1h', false)}${pill('24h', '24h', true)}${pill('7d', '7d', false)}${pill('30d', '30d', false)}</div>
                    <div class="panel-chart-container" style="height:140px;"><canvas id="pchart-${rowId}"></canvas></div>` : ''}
                </div>`;
        });

        const tunHead = `<thead><tr><th></th><th>Tunnel</th><th>Status</th><th>Remote IP</th><th>In</th><th>Out</th></tr></thead><tbody></tbody>`;
        html += `
            <div style="margin-top:6px;">
                <h5 style="font-size:0.82rem;color:var(--fwmon-text-faint);margin:0 0 6px 0;">Carrier tunnel <span style="color:var(--fwmon-text-mute);font-weight:400;font-size:0.72rem;">— the encrypted path the overlay rides on</span></h5>
                <div class="tunnel-columns">
                    <div class="tunnel-col"><div style="font-size:0.74rem;color:var(--fwmon-text-faint);margin:0 0 4px 2px;">${window.escapeHtml(srcName)}</div><table class="vpn-detail-table" id="ov-src-tunnels">${tunHead}</table></div>
                    <div class="tunnel-col"><div style="font-size:0.74rem;color:var(--fwmon-text-faint);margin:0 0 4px 2px;">${window.escapeHtml(dstName)}</div><table class="vpn-detail-table" id="ov-dst-tunnels">${tunHead}</table></div>
                </div>
            </div>`;
        container.innerHTML = html;

        renderPanelTunnelTable('ov-src-tunnels', data.source_tunnels || [], c.source_device_id, 'overlay');
        renderPanelTunnelTable('ov-dst-tunnels', data.dest_tunnels || [], c.dest_device_id, 'overlay');

        // Defer chart loads until the Overlay tab is visible (see switchPanelTab).
        pendingOverlayCharts = overlays
            .map((o, i) => ({ rowId: 'ov-' + i, deviceId: o.device_id, ifIndex: o.if_index }))
            .filter(x => x.ifIndex);
    }

    function flushOverlayCharts() {
        if (!pendingOverlayCharts.length) return;
        const pending = pendingOverlayCharts;
        pendingOverlayCharts = [];
        pending.forEach(x => loadPanelInterfaceChart(x.rowId, x.deviceId, x.ifIndex, '24h'));
    }

    function togglePanelInterface(rowId, deviceId, ifIndex) {
        const expandRow = document.getElementById(rowId);
        const chev = document.getElementById('pchev-' + rowId);
        if (expandRow.classList.contains('open')) {
            expandRow.classList.remove('open');
            if (chev) chev.classList.remove('open');
        } else {
            expandRow.classList.add('open');
            if (chev) chev.classList.add('open');
            if (!panelChartInstances['iface-' + rowId]) {
                loadPanelInterfaceChart(rowId, deviceId, ifIndex, '24h');
            }
        }
    }

    async function loadPanelInterfaceChart(rowId, deviceId, ifIndex, range) {
        try {
            const resp = await window.apiFetch(`${window.API_BASE}/devices/${deviceId}/interfaces/${ifIndex}/chart?range=${range}`);
            const data = resp && resp.data ? resp.data : resp;
            if (!Array.isArray(data)) return;
            const canvas = document.getElementById('pchart-' + rowId);
            if (!canvas) return;
            if (panelChartInstances['iface-' + rowId]) panelChartInstances['iface-' + rowId].destroy();
            if (!data.length) return;
            // Interface rows carry CUMULATIVE SNMP octet counters — delta + rate
            // them through the shared 3-mode component. (Was plotting the raw
            // cumulative counter, so the line only ever climbed.)
            const series = window.FwmonBwChart.normalizeCumulative(data);
            panelChartInstances['iface-' + rowId] = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'In', txLabel: 'Out' });
        } catch (e) { console.error('Interface chart failed:', e); }
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

    async function loadPanelTunnelChart(rowId, deviceId, tunnelName, range) {
        try {
            const resp = await window.apiFetch(`${window.API_BASE}/devices/${deviceId}/vpn/${encodeURIComponent(tunnelName)}/chart?range=${range}`);
            const data = resp && resp.data ? resp.data : resp;
            if (!data) return;
            const canvas = document.getElementById('pchart-' + rowId);
            if (!canvas) return;
            if (panelChartInstances['tunnel-' + rowId]) panelChartInstances['tunnel-' + rowId].destroy();
            if (!Array.isArray(data) || !data.length) return;
            // VPN tunnel rows already arrive as per-bucket deltas (LAG()+SUM) —
            // render throughput/transfer/combined via the shared component.
            const series = window.FwmonBwChart.normalizeDeltas(data);
            panelChartInstances['tunnel-' + rowId] = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'In', txLabel: 'Out' });
        } catch (e) { console.error('Tunnel chart failed:', e); }
    }

    function renderPanelPhase2(matches, srcName, dstName) {
        const container = document.getElementById('panel-phase2-container');
        if (!matches.length) {
            container.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:20px;">No Phase 2 selector matches.</div>';
            return;
        }
        let html = '';
        matches.forEach((m, i) => {
            const srcUp = m.source_status === 'up';
            const dstUp = m.dest_status === 'up';
            const bothUp = srcUp && dstUp;
            const pathColor = bothUp ? '#3fb950' : '#f85149';
            const statusClass = bothUp ? 'up' : 'down';
            const fmtB = window.formatBytes || function(v) { return v + ' B'; };
            const srcTotal = (m.src_bytes_in || 0) + (m.src_bytes_out || 0);
            html += `
            <div style="background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:6px;padding:12px;margin-bottom:8px;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                    <span style="font-size:0.8rem;font-weight:600;color:var(--fwmon-text);">${window.escapeHtml(m.source_phase1 || m.source_tunnel)} &harr; ${window.escapeHtml(m.dest_phase1 || m.dest_tunnel)}</span>
                    <span class="badge ${statusClass}" style="font-size:0.65rem;">${bothUp ? 'ACTIVE' : 'DOWN'}</span>
                </div>
                <div style="display:flex;gap:12px;margin-bottom:6px;font-size:0.72rem;color:var(--fwmon-text-faint);">
                    <span>&darr; In: <strong style="color:var(--fwmon-accent);">${fmtB(m.src_bytes_in || 0)}</strong></span>
                    <span>&uarr; Out: <strong style="color:var(--fwmon-sig-ok);">${fmtB(m.src_bytes_out || 0)}</strong></span>
                    <span>Total: <strong style="color:var(--fwmon-text);">${fmtB(srcTotal)}</strong></span>
                    ${m.src_uptime ? `<span>Up: ${Math.floor(m.src_uptime / 3600)}h</span>` : ''}
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
            if (!rows.length) return '<tr><td colspan="9" style="text-align:center;color:var(--fwmon-text-mute);padding:12px;">None</td></tr>';
            return rows.map((t, i) => {
                const rowId = `${prefix}-${i}`;
                const dest = t.matched_device_id ? `<a href="/admin/devices/${t.matched_device_id}" style="color:var(--fwmon-accent);text-decoration:none;font-size:0.78rem;">${window.escapeHtml(t.matched_name)}</a>` : '<span style="color:var(--fwmon-sig-warn);font-size:0.78rem;">Off-Net</span>';
                const statusBadge = `<span class="badge ${t.status}">${t.status.toUpperCase()}</span>`;
                return `
                    <tr class="panel-tunnel-row" data-action="dp-toggle-tunnel" data-row="${rowId}" data-device="${devId}" data-tunnel="${window.escapeHtml(t.tunnel_name)}">
                        <td><span class="chevron" id="pchev-${rowId}">&#9654;</span></td>
                        <td>${window.escapeHtml(t.tunnel_name)}</td>
                        <td>${window.escapeHtml((t.tunnel_type || 'ipsec').toUpperCase())}</td>
                        <td style="color:var(--fwmon-text-faint);font-size:0.78rem;">${window.escapeHtml(t.interface_name || '-')}</td>
                        <td style="color:var(--fwmon-text-faint);font-size:0.78rem;">${window.escapeHtml(t.mode || '-')}</td>
                        <td>${statusBadge}</td>
                        <td style="font-family:monospace;font-size:0.78rem;">${window.escapeHtml(t.remote_ip || '-')}</td>
                        <td>${dest}</td>
                        <td>${t.status === 'up' ? formatPanelUptime(t.tunnel_uptime) : '-'}</td>
                    </tr>
                    <tr class="panel-tunnel-expand" id="${rowId}">
                        <td colspan="9">
                            <div class="panel-range-pills" style="margin-bottom:6px;">
                                <div class="panel-range-pill" data-action="dp-tunnel-chart" data-row="${rowId}" data-device="${devId}" data-tunnel="${window.escapeHtml(t.tunnel_name)}" data-range="1h">1h</div>
                                <div class="panel-range-pill active" data-action="dp-tunnel-chart" data-row="${rowId}" data-device="${devId}" data-tunnel="${window.escapeHtml(t.tunnel_name)}" data-range="24h">24h</div>
                                <div class="panel-range-pill" data-action="dp-tunnel-chart" data-row="${rowId}" data-device="${devId}" data-tunnel="${window.escapeHtml(t.tunnel_name)}" data-range="7d">7d</div>
                                <div class="panel-range-pill" data-action="dp-tunnel-chart" data-row="${rowId}" data-device="${devId}" data-tunnel="${window.escapeHtml(t.tunnel_name)}" data-range="30d">30d</div>
                            </div>
                            <div class="panel-chart-container" style="height:150px;"><canvas id="pchart-${rowId}"></canvas></div>
                        </td>
                    </tr>`;
            }).join('');
        }

        let sectionsHtml = '';
        if (!offnetOnly && matched.length > 0) {
            sectionsHtml += `
                <h5 style="font-size:0.82rem;color:var(--fwmon-text);margin:12px 0 6px 0;">Matched Tunnels (${matched.length})</h5>
                <table class="vpn-detail-table"><thead><tr><th></th><th>Tunnel</th><th>Type</th><th>Interface</th><th>Mode</th><th>Status</th><th>Remote IP</th><th>Destination</th><th>Uptime</th></tr></thead>
                <tbody>${renderVPNTunnelRows('vpn-m', matched, deviceId)}</tbody></table>`;
        }
        if (offnet.length > 0) {
            sectionsHtml += `
                <h5 style="font-size:0.82rem;color:var(--fwmon-sig-warn);margin:12px 0 6px 0;">Off-Net Tunnels (${offnet.length})</h5>
                <table class="vpn-detail-table"><thead><tr><th></th><th>Tunnel</th><th>Type</th><th>Interface</th><th>Mode</th><th>Status</th><th>Remote IP</th><th>Destination</th><th>Uptime</th></tr></thead>
                <tbody>${renderVPNTunnelRows('vpn-o', offnet, deviceId)}</tbody></table>`;
        }
        if (!offnetOnly && matched.length === 0 && offnet.length === 0) {
            sectionsHtml = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:20px;">No tunnels</div>';
        }

        panel.innerHTML = `
            <div class="rich-detail-panel">
                <div class="panel-header">
                    <h4>${heading} <span style="font-size:0.8rem;font-weight:400;color:var(--fwmon-text-faint);margin-left:8px;">${vpnInfo.up} up / ${vpnInfo.down} down</span></h4>
                    <button class="btn secondary sm" data-action="dp-close-panel">Close</button>
                </div>
                ${sectionsHtml}
            </div>
        `;
    }

    // Event delegation for all dynamic panel content
    document.addEventListener('click', function(e) {
        var el = e.target.closest('[data-action]');
        if (!el) return;
        var action = el.dataset.action;
        if (action === 'dp-close-panel') {
            closeRichPanel();
        } else if (action === 'dp-switch-tab') {
            switchPanelTab(el.dataset.tab);
        } else if (action === 'dp-traffic-range') {
            setPanelTrafficRange(el.dataset.range);
        } else if (action === 'dp-flow-range') {
            setPanelFlowRange(parseInt(el.dataset.hours));
        } else if (action === 'dp-events-range') {
            var hrs = parseInt(el.dataset.hours);
            el.parentElement.querySelectorAll('.panel-range-pill').forEach(function(p) { p.classList.remove('active'); });
            el.classList.add('active');
            if (currentPanelConnId) loadPanelEvents(currentPanelConnId, hrs);
        } else if (action === 'dp-toggle-tunnel') {
            togglePanelTunnel(el.dataset.row, parseInt(el.dataset.device), el.dataset.tunnel);
        } else if (action === 'dp-tunnel-chart') {
            e.stopPropagation();
            var pills = el.parentElement.querySelectorAll('.panel-range-pill');
            pills.forEach(function(p) { p.classList.remove('active'); });
            el.classList.add('active');
            loadPanelTunnelChart(el.dataset.row, parseInt(el.dataset.device), el.dataset.tunnel, el.dataset.range);
        } else if (action === 'dp-toggle-iface') {
            togglePanelInterface(el.dataset.row, parseInt(el.dataset.device), parseInt(el.dataset.ifindex));
        } else if (action === 'dp-iface-chart') {
            e.stopPropagation();
            var ipills = el.parentElement.querySelectorAll('.panel-range-pill');
            ipills.forEach(function(p) { p.classList.remove('active'); });
            el.classList.add('active');
            loadPanelInterfaceChart(el.dataset.row, parseInt(el.dataset.device), parseInt(el.dataset.ifindex), el.dataset.range);
        }
    });

    FWDiagram.Panels = {
        showRichConnDetailPanel,
        showRichVPNDetailPanel,
        closeRichPanel,
        switchPanelTab,
        setPanelTrafficRange,
        setPanelFlowRange,
        togglePanelTunnel,
        loadPanelTunnelChart,
        togglePanelInterface,
        loadPanelInterfaceChart,
        destroyPanelCharts,
        getCurrentPanelConnId,
        setCurrentPanelConnId
    };
})();
