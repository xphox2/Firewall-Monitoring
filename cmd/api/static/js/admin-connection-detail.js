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

    function formatSpeed(bytesPerSec) {
        if (!bytesPerSec || bytesPerSec <= 0) return '0 bps';
        var bps = bytesPerSec * 8;
        if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
        if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
        if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
        return bps.toFixed(0) + ' bps';
    }

    function createGauge(containerId, value, maxVal) {
        var container = document.getElementById(containerId);
        if (!container) return;
        var pct = maxVal > 0 ? Math.min((value / maxVal) * 100, 100) : 0;
        var radius = 32;
        var circumference = 2 * Math.PI * radius;
        var offset = circumference - (pct / 100) * circumference;
        // var() so a Day/Night flip re-resolves instantly (SVG presentation
        // attributes can't take var(), inline style can).
        var color = 'var(--fwmon-sig-ok)';
        if (pct >= 90) color = 'var(--fwmon-sig-crit)';
        else if (pct >= 70) color = 'var(--fwmon-sig-warn)';

        container.innerHTML =
            '<svg width="80" height="80" viewBox="0 0 80 80">' +
                '<circle class="gauge-bg" cx="40" cy="40" r="' + radius + '" />' +
                '<circle class="gauge-fill" cx="40" cy="40" r="' + radius + '"' +
                    ' style="stroke:' + color + '"' +
                    ' stroke-dasharray="' + circumference + '"' +
                    ' stroke-dashoffset="' + offset + '" />' +
            '</svg>' +
            '<div class="gauge-text">' + Math.round(pct) + '%</div>';
    }

    // Connection type visual style mapping
    function renderBridge(srcName, dstName, status, connType) {
        var statusColor = status === 'up' ? 'var(--fwmon-sig-ok)' : (status === 'down' ? 'var(--fwmon-sig-crit)' : 'var(--fwmon-text-mute)');
        var cs = connStyle(connType);
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
                '<rect x="20" y="25" width="140" height="50" rx="8" style="fill:var(--fwmon-card-bg);stroke:' + statusColor + '" stroke-width="2"/>' +
                '<text x="90" y="48" text-anchor="middle" style="fill:var(--fwmon-text)" font-size="12" font-weight="600">' + AC.escapeHtml(srcName || '').substring(0, 16) + '</text>' +
                '<text x="90" y="64" text-anchor="middle" style="fill:var(--fwmon-text-faint)" font-size="10">Source</text>' +
                '<rect x="540" y="25" width="140" height="50" rx="8" style="fill:var(--fwmon-card-bg);stroke:' + statusColor + '" stroke-width="2"/>' +
                '<text x="610" y="48" text-anchor="middle" style="fill:var(--fwmon-text)" font-size="12" font-weight="600">' + AC.escapeHtml(dstName || '').substring(0, 16) + '</text>' +
                '<text x="610" y="64" text-anchor="middle" style="fill:var(--fwmon-text-faint)" font-size="10">Destination</text>' +
                '<path id="bridge-path" d="M160,50 Q350,10 540,50" fill="none" stroke="' + pathColor + '" stroke-width="' + cs.width + '" ' + cs.dash + filterAttr + '>' +
                    pulseAnim +
                '</path>' +
                particles +
            '</svg>';
    }

    // L2 discovery labels (port-to-port links inferred from LLDP/FDB/ARP).
    var L2_METHOD_LABELS = { lldp_neighbor: 'LLDP confirmed', fdb_match: 'MAC-table matched', arp_match: 'ARP inferred' };
    var L2_TIER_LABELS = { lldp: 'LLDP', fdb: 'MAC table', arp: 'ARP' };

    function relativeAge(ts) {
        var ms = Date.now() - new Date(ts).getTime();
        if (!isFinite(ms) || ms < 0) return '-';
        var min = Math.floor(ms / 60000);
        if (min < 1) return 'now';
        if (min < 60) return min + 'm ago';
        var h = Math.floor(min / 60);
        if (h < 48) return h + 'h ago';
        return Math.floor(h / 24) + 'd ago';
    }

    // renderBridgeSubtitle: "port5 ↔ lan3 · LLDP confirmed · VLAN 10,20" under
    // the bridge for L2-inferred links. All values are network-controlled —
    // escaped.
    function renderBridgeSubtitle(conn) {
        var el = document.getElementById('bridge-subtitle');
        if (!el) return;
        if (!conn.source_if_name && !conn.dest_if_name && !L2_METHOD_LABELS[conn.match_method]) {
            el.innerHTML = '';
            return;
        }
        var parts = [];
        if (conn.source_if_name || conn.dest_if_name) {
            parts.push('<span style="font-family:\'JetBrains Mono\',monospace;font-weight:600;color:var(--fwmon-text);">' +
                AC.escapeHtml(conn.source_if_name || '?') + ' &harr; ' + AC.escapeHtml(conn.dest_if_name || '?') + '</span>');
        }
        if (L2_METHOD_LABELS[conn.match_method]) {
            parts.push('<span class="badge info" style="font-size:0.7rem;">' + AC.escapeHtml(L2_METHOD_LABELS[conn.match_method]) + '</span>');
        }
        if (conn.vlan_ids) {
            parts.push('<span style="color:var(--fwmon-text-faint);font-size:0.78rem;">VLAN ' + AC.escapeHtml(conn.vlan_ids) + '</span>');
        }
        if (conn.status === 'stale') {
            parts.push('<span class="badge stale" style="font-size:0.7rem;">STALE EVIDENCE</span>');
        }
        el.innerHTML = '<div style="display:inline-flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:center;">' + parts.join(' ') + '</div>';
    }

    // renderInterfaceTable: direct links show member interfaces instead of
    // tunnels (the first tab is retitled "Interfaces").
    function renderInterfaceTable(ifaces, conn, srcName, dstName) {
        document.getElementById('src-tunnels-title').textContent = 'Interfaces (' + srcName + ' ↔ ' + dstName + ')';
        var host = document.querySelector('#tab-content-src-tunnels .overflow-x-auto');
        if (!host) return;
        if (!ifaces.length) {
            host.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No interface telemetry for this link yet.</div>';
            return;
        }
        var rows = '';
        ifaces.forEach(function(f) {
            var statusBadge = '<span class="badge ' + AC.escapeHtml(f.status || 'unknown') + '">' + AC.escapeHtml((f.status || 'unknown').toUpperCase()) + '</span>';
            rows +=
                '<tr>' +
                    '<td><a href="/admin/devices/' + encodeURIComponent(f.device_id) + '" style="color:var(--fwmon-accent);text-decoration:none;">' + AC.escapeHtml(f.device_name || ('Device ' + f.device_id)) + '</a></td>' +
                    '<td style="font-family:\'JetBrains Mono\',monospace;">' + AC.escapeHtml(f.if_name || '-') + '</td>' +
                    '<td>' + AC.escapeHtml(f.kind || '-') + '</td>' +
                    '<td>' + (f.vlan_id ? AC.escapeHtml(String(f.vlan_id)) : '-') + '</td>' +
                    '<td><code style="color:var(--fwmon-accent);font-size:0.8rem;">' + AC.escapeHtml(f.ip_address || '-') + '</code></td>' +
                    '<td><code style="font-size:0.8rem;">' + AC.escapeHtml(f.subnet || '-') + '</code></td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' + formatBytes(f.in_bytes) + '</td>' +
                    '<td>' + formatBytes(f.out_bytes) + '</td>' +
                '</tr>';
        });
        host.innerHTML =
            '<table class="tunnel-table">' +
                '<thead><tr><th>Device</th><th>Interface</th><th>Kind</th><th>VLAN</th><th>IP</th><th>Subnet</th><th>Status</th><th>Bytes In</th><th>Bytes Out</th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
            '</table>';
    }

    // renderEvidence: the LLDP/FDB/ARP rows that produced the link. Every
    // value is neighbor-controlled (LLDP sysnames/ports) or network-derived
    // (MACs/IPs) — all escaped. No dead ends: devices link to their pages and
    // the empty state explains itself.
    function renderEvidence(conn, evidence) {
        var container = document.getElementById('evidence-container');
        if (!container) return;
        if (!evidence.length) {
            container.innerHTML =
                '<div style="color:var(--fwmon-text-mute);padding:16px;font-size:0.875rem;">' +
                'No layer-2 evidence in the current snapshots — the discovery data behind this link has expired. ' +
                'The link is marked <span class="badge stale" style="font-size:0.7rem;">STALE</span> and will be removed automatically if no fresh evidence arrives.' +
                '</div>';
            return;
        }
        var rows = '';
        evidence.forEach(function(ev) {
            var observed = [];
            if (ev.remote_mac) observed.push('MAC ' + AC.escapeHtml(ev.remote_mac));
            if (ev.remote_ip) observed.push('IP ' + AC.escapeHtml(ev.remote_ip));
            if (ev.remote_port) observed.push('port ' + AC.escapeHtml(ev.remote_port));
            if (ev.remote_sysname) observed.push('sys ' + AC.escapeHtml(ev.remote_sysname));
            var freshBadge = ev.fresh
                ? '<span class="badge up">FRESH</span>'
                : '<span class="badge stale">AGING</span>';
            var note = ev.note ? '<div style="font-size:0.7rem;color:var(--fwmon-sig-warn);margin-top:2px;">' + AC.escapeHtml(ev.note) + '</div>' : '';
            rows +=
                '<tr>' +
                    '<td><span class="badge info" style="font-size:0.68rem;">' + AC.escapeHtml(L2_TIER_LABELS[ev.tier] || ev.tier) + '</span></td>' +
                    '<td><a href="/admin/devices/' + encodeURIComponent(ev.device_id) + '" style="color:var(--fwmon-accent);text-decoration:none;">' + AC.escapeHtml(ev.device_name || ('Device ' + ev.device_id)) + '</a></td>' +
                    '<td style="font-family:\'JetBrains Mono\',monospace;">' + AC.escapeHtml(ev.local_if_name || String(ev.local_if_index || '-')) + '</td>' +
                    '<td style="font-family:\'JetBrains Mono\',monospace;font-size:0.8rem;">' + (observed.join(' &middot; ') || '-') + note + '</td>' +
                    '<td>' + (ev.vlan_id ? AC.escapeHtml(String(ev.vlan_id)) : '-') + '</td>' +
                    '<td>' + AC.escapeHtml(relativeAge(ev.timestamp)) + '</td>' +
                    '<td>' + freshBadge + '</td>' +
                '</tr>';
        });
        container.innerHTML =
            '<table class="tunnel-table">' +
                '<thead><tr><th>Source</th><th>Reported by</th><th>Local port</th><th>Observed</th><th>VLAN</th><th>Age</th><th></th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
            '</table>';
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
            renderBridgeSubtitle(conn);

            // Stat cards
            document.getElementById('stat-bytes-in').textContent = formatBytes(data.total_bytes_in);
            document.getElementById('stat-bytes-out').textContent = formatBytes(data.total_bytes_out);
            var statusEl = document.getElementById('stat-status');
            // AUDIT-065: escape conn.status before it lands in innerHTML (both the
            // class attribute and the text). The server validates it to an enum,
            // but this closes the defense-in-depth gap. Uppercase first, then
            // escape, so an entity can't be split by toUpperCase().
            statusEl.innerHTML = '<span class="badge ' + AC.escapeHtml(conn.status) + '">' + AC.escapeHtml((conn.status || 'unknown').toUpperCase()) + '</span>';

            // Show/hide flows tab. v0.10.230: was setting style.display = '',
            // which can't override the .hidden { display: none } class on
            // the tab button (admin-shared.css). The tab stayed invisible
            // even when data was present — Traffic Analysis was effectively
            // a dead feature. Toggle the .hidden class directly so the
            // visibility matches the data condition.
            document.getElementById('tab-flows').classList.toggle('hidden', !data.has_flow_data);

            // Family branch: direct (ethernet/lag/l2vlan/bridge) links carry
            // interfaces + L2 discovery evidence, not tunnels — the tunnel
            // tabs render interface tables and the Evidence tab appears.
            if (data.family === 'direct') {
                var countCard = document.querySelector('#stat-tunnel-count');
                var countLabel = countCard && countCard.parentElement.querySelector('.stat-label');
                if (countLabel) countLabel.textContent = 'Interfaces';
                document.getElementById('stat-tunnel-count').textContent = (data.interfaces || []).length;

                document.getElementById('tab-src-tunnels').textContent = 'Interfaces';
                document.getElementById('tab-dst-tunnels').classList.add('hidden');
                document.getElementById('tab-phase2').classList.add('hidden');
                document.getElementById('tab-evidence').classList.remove('hidden');

                renderInterfaceTable(data.interfaces || [], conn, srcName, dstName);
                renderEvidence(conn, data.evidence || []);
            } else {
                var tunnelCount = (data.source_tunnels ? data.source_tunnels.length : 0) + (data.dest_tunnels ? data.dest_tunnels.length : 0);
                document.getElementById('stat-tunnel-count').textContent = tunnelCount;
                document.getElementById('tab-evidence').classList.add('hidden');

                // Show/hide Phase 2 matches tab (same .hidden bug as above)
                var p2matches = data.phase2_matches || [];
                document.getElementById('tab-phase2').classList.toggle('hidden', p2matches.length === 0);
                renderPhase2Matches(p2matches, srcName, dstName);

                // Render tunnel tables
                renderTunnelTable('src-tunnels-table', data.source_tunnels || [], conn.source_device_id);
                renderTunnelTable('dst-tunnels-table', data.dest_tunnels || [], conn.dest_device_id);
                document.getElementById('src-tunnels-title').textContent = 'Source Tunnels (' + srcName + ')';
                document.getElementById('dst-tunnels-title').textContent = 'Destination Tunnels (' + dstName + ')';
            }
        }).catch(function(err) {
            console.error('[ConnectionDetail] Error loading detail:', err);
            AC.showError('Failed to load connection details');
        });
    }

    function renderTunnelTable(tableId, tunnels, deviceId) {
        var tbody = document.querySelector('#' + tableId + ' tbody');
        if (!tunnels.length) {
            tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No matching tunnels found</td></tr>';
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
                    '<td><code style="color:var(--fwmon-accent);font-size:0.8rem;">' + AC.escapeHtml(t.local_subnet || '-') + '</code></td>' +
                    '<td><code style="color:var(--fwmon-sig-ok);font-size:0.8rem;">' + AC.escapeHtml(t.remote_subnet || '-') + '</code></td>' +
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
            container.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No Phase 2 selector matches found between these devices.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < matches.length; i++) {
            var m = matches[i];
            var srcUp = m.source_status === 'up';
            var dstUp = m.dest_status === 'up';
            var bothUp = srcUp && dstUp;
            var pathColor = bothUp ? 'var(--fwmon-sig-ok)' : 'var(--fwmon-sig-crit)';
            var statusLabel = bothUp ? 'ACTIVE' : 'DOWN';
            var statusClass = bothUp ? 'up' : 'down';
            var filterAttr = bothUp ? ' filter="url(#p2glow-' + i + ')"' : '';
            var animCircles = bothUp
                ? '<circle r="3" style="fill:' + pathColor + '" opacity="0.85">' +
                      '<animateMotion dur="3s" begin="0s" repeatCount="indefinite" fill="freeze"><mpath href="#p2path-' + i + '"/></animateMotion>' +
                  '</circle>' +
                  '<circle r="2.5" style="fill:var(--fwmon-accent)" opacity="0.7">' +
                      '<animateMotion dur="3.5s" begin="1s" repeatCount="indefinite" fill="freeze" keyPoints="1;0" keyTimes="0;1" calcMode="linear"><mpath href="#p2path-' + i + '"/></animateMotion>' +
                  '</circle>'
                : '';
            html +=
                '<div class="phase2-match-card" style="background:var(--fwmon-card-bg);border:1px solid var(--fwmon-border);border-radius:8px;padding:16px;margin-bottom:12px;">' +
                    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">' +
                        '<span style="font-size:0.85rem;font-weight:600;color:var(--fwmon-text);">' + AC.escapeHtml(m.source_phase1 || m.source_tunnel) + ' &harr; ' + AC.escapeHtml(m.dest_phase1 || m.dest_tunnel) + '</span>' +
                        '<span class="badge ' + statusClass + '" style="font-size:0.7rem;">' + statusLabel + '</span>' +
                    '</div>' +
                    '<svg width="100%" height="70" viewBox="0 0 600 70" style="display:block;">' +
                        '<defs><filter id="p2glow-' + i + '" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>' +
                        '<rect x="0" y="15" width="160" height="40" rx="6" style="fill:var(--fwmon-bg);stroke:var(--fwmon-border)" stroke-width="1"/>' +
                        '<text x="80" y="30" text-anchor="middle" style="fill:var(--fwmon-text-faint)" font-size="10">' + AC.escapeHtml(srcName) + '</text>' +
                        '<text x="80" y="46" text-anchor="middle" style="fill:var(--fwmon-accent)" font-size="11" font-family="monospace">' + AC.escapeHtml(m.local_subnet) + '</text>' +
                        '<rect x="440" y="15" width="160" height="40" rx="6" style="fill:var(--fwmon-bg);stroke:var(--fwmon-border)" stroke-width="1"/>' +
                        '<text x="520" y="30" text-anchor="middle" style="fill:var(--fwmon-text-faint)" font-size="10">' + AC.escapeHtml(dstName) + '</text>' +
                        '<text x="520" y="46" text-anchor="middle" style="fill:var(--fwmon-sig-ok)" font-size="11" font-family="monospace">' + AC.escapeHtml(m.remote_subnet) + '</text>' +
                        '<path id="p2path-' + i + '" d="M160,35 Q300,10 440,35" fill="none" style="stroke:' + pathColor + '" stroke-width="2"' + filterAttr + '/>' +
                        '<path d="M160,35 Q300,60 440,35" fill="none" style="stroke:' + pathColor + '" stroke-width="1.5" stroke-dasharray="4,4" opacity="0.5"/>' +
                        animCircles +
                        '<text x="300" y="8" text-anchor="middle" style="fill:var(--fwmon-text-mute)" font-size="9">Phase 2: ' + AC.escapeHtml(m.source_tunnel) + ' &harr; ' + AC.escapeHtml(m.dest_tunnel) + '</text>' +
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
            if (!Array.isArray(data) || !data.length) return;

            // VPN tunnel rows arrive as per-bucket deltas — render
            // throughput/transfer/combined via the shared 3-mode component.
            var series = window.FwmonBwChart.normalizeDeltas(data);
            tunnelCharts[rowId] = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'In', txLabel: 'Out' });
        }).catch(function(err) {
            console.error('[ConnectionDetail] Error loading tunnel chart:', err);
            AC.showError('Failed to load tunnel chart');
        });
    }

    function chartOptions(yCallback) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            // No explicit colors: legend/tick/grid colors come from the
            // token-based Chart defaults (setupChartDefaults), which the
            // Day/Night recolor pass re-runs — hardcoding them here would
            // pin the dark palette (the pre-v0.11.70 bug).
            plugins: { legend: { labels: { boxWidth: 10, padding: 8, font: { size: 10 } } },
                tooltip: { callbacks: { label: function(ctx) { var v = ctx.chart.options.indexAxis === 'y' ? ctx.parsed.x : ctx.parsed.y; return ctx.dataset.label + ': ' + formatBytes(v != null ? v : 0); } } }
            },
            scales: {
                x: { ticks: { font: { size: 11 }, maxRotation: 0, maxTicksLimit: 12 } },
                y: { beginAtZero: true, ticks: { font: { size: 11 }, callback: yCallback || function(v) { return formatBytes(v); } } }
            }
        };
    }

    function loadTrafficChart() {
        return AC.apiFetch(API_BASE + '/connections/' + connId + '/traffic?range=' + currentTrafficRange).then(function(result) {
            var data = result.data;
            if (!data) return;

            // M13 of the 2026-07-01 audit: use the STABLE host container, never
            // the canvas's parent, so an empty-state that replaced the canvas
            // with a message can't later throw (canvas would be null) — and the
            // data path re-creates the canvas if a prior empty-state removed it
            // (the admin-flows.js pattern).
            var host = document.getElementById('traffic-chart-host');
            var canvas = document.getElementById('traffic-chart');

            if (!Array.isArray(data) || data.length === 0) {
                if (trafficChart) { trafficChart.destroy(); trafficChart = null; }
                if (host) host.innerHTML = '<div style="text-align:center;color:var(--fwmon-text-faint);padding:30px;">No traffic data available. Tunnel byte counters may not be populated yet.</div>';
                return;
            }

            if (!canvas && host) {
                host.innerHTML = '<canvas id="traffic-chart"></canvas>';
                canvas = document.getElementById('traffic-chart');
            }
            if (!canvas) return;

            // Throughput gauges — use server-computed bytes/sec, gauge max = 1 Gbps (125 MB/s)
            var oneGbps = 125000000; // 1 Gbps in bytes/sec
            var tIn = connDetail ? (connDetail.throughput_in || 0) : 0;
            var tOut = connDetail ? (connDetail.throughput_out || 0) : 0;
            createGauge('gauge-in', tIn, oneGbps);
            createGauge('gauge-out', tOut, oneGbps);
            document.getElementById('gauge-in-val').textContent = formatSpeed(tIn);
            document.getElementById('gauge-out-val').textContent = formatSpeed(tOut);

            // Connection traffic arrives as per-bucket deltas — render
            // throughput/transfer/combined via the shared 3-mode component. The
            // 30s poll re-mounts (the toggle DOM persists; only the Chart.js
            // instance is rebuilt), matching every other bandwidth chart.
            var series = window.FwmonBwChart.normalizeDeltas(data);
            if (trafficChart) trafficChart.destroy();
            trafficChart = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'Inbound', txLabel: 'Outbound' });
        }).catch(function(err) {
            console.error('[ConnectionDetail] Error loading traffic chart:', err);
            AC.showError('Failed to load traffic chart');
        });
    }

    function setTrafficRange(range) {
        currentTrafficRange = range;
        var pills = document.querySelectorAll('#traffic-range .range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', pills[i].dataset.range === range);
        }
        var select = document.getElementById('traffic-range-select');
        if (select) select.value = range;
        loadTrafficChart();
    }

    function loadFlowStats() {
        return AC.apiFetch(API_BASE + '/connections/' + connId + '/flows?hours=' + currentFlowHours).then(function(result) {
            var data = result.data;
            if (!data) return;

            var hasData = data.total_flows > 0;
            // v0.10.230: flow-empty has class="hidden …" in the markup, so
            // setting style.display = '' can't unhide it (the .hidden class
            // wins). Toggle the class directly so the "no samples yet"
            // banner actually appears when sFlow is enabled but no samples
            // match the connection's tunnel interfaces. flow-content has no
            // such class so plain style.display works there.
            document.getElementById('flow-empty').classList.toggle('hidden', hasData);
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
                    plugins: { legend: { position: 'right', labels: { padding: 8, font: { size: 10 } } } }
                }
            });

            // Bytes over time
            if (flowTimeChart) flowTimeChart.destroy();
            var timeData = data.bytes_over_time || [];
            // Render throughput (Mbps) from the per-bucket byte SUM rather than a
            // raw byte total, so it reads like the public dashboard and doesn't
            // look like an ever-climbing line.
            var flowIntervalSec = data.bucket_seconds || 3600;
            flowTimeChart = new Chart(document.getElementById('flow-time-chart'), {
                type: 'line',
                data: {
                    labels: timeData.map(function(t) { return t.bucket.split(' ').pop() || t.bucket; }),
                    datasets: [{ label: 'Throughput', data: timeData.map(function(t) { return (t.count * 8) / flowIntervalSec / 1e6; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0, pointRadius: 0, borderWidth: 1.5 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { boxWidth: 10, padding: 8, font: { size: 10 } } },
                        tooltip: { callbacks: { label: function(ctx) { return 'Throughput: ' + (ctx.parsed.y != null ? ctx.parsed.y.toFixed(2) : '0') + ' Mbps'; } } }
                    },
                    scales: {
                        x: { ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, maxRotation: 0, maxTicksLimit: 12 } },
                        y: { beginAtZero: true, ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, callback: function(v) { return v.toFixed(1) + ' Mbps'; } } }
                    }
                }
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
                        x: { ticks: { font: { size: 11 }, callback: function(v) { return formatBytes(v); } } },
                        y: { ticks: { font: { size: 11 } }, grid: { display: false } }
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
                        x: { ticks: { font: { size: 11 }, callback: function(v) { return formatBytes(v); } } },
                        y: { ticks: { font: { size: 11 } }, grid: { display: false } }
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
                        '<td>' + AC.ipRef(c.src_addr, { port: c.src_port }) + '</td>' +
                        '<td>' + AC.ipRef(c.dst_addr, { port: c.dst_port }) + '</td>' +
                        '<td>' + AC.escapeHtml(c.protocol) + '</td>' +
                        '<td>' + formatBytes(c.bytes) + '</td>' +
                        '<td>' + formatNum(c.packets) + '</td>' +
                    '</tr>';
            }
            ctbody.innerHTML = convHtml || '<tr><td colspan="5" style="text-align:center;color:var(--fwmon-text-mute);padding:20px;">No conversations found</td></tr>';
            if (ctbody) AC.enrichIps(ctbody);
        }).catch(function(err) {
            console.error('[ConnectionDetail] Error loading flow stats:', err);
            AC.showError('Failed to load flow statistics');
        });
    }

    function setFlowRange(hours) {
        currentFlowHours = hours;
        var pills = document.querySelectorAll('#flow-range .range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', parseInt(pills[i].dataset.range, 10) === hours);
        }
        var select = document.getElementById('flow-range-select');
        if (select) select.value = hours;
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

    // Traffic range select dropdown
    var trafficSelect = document.getElementById('traffic-range-select');
    if (trafficSelect) {
        trafficSelect.addEventListener('change', function() {
            setTrafficRange(this.value);
        });
    }

    // Flow range select dropdown
    var flowSelect = document.getElementById('flow-range-select');
    if (flowSelect) {
        flowSelect.addEventListener('change', function() {
            setFlowRange(parseFloat(this.value));
        });
    }

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
        }).catch(function(err) {
            console.error('[ConnectionDetail] Init error:', err);
            AC.showError('Failed to initialize connection detail view');
        });
    }
    init();

    // Auto-refresh every 30s, with race-condition guard + visibility gating
    // (v0.10.214, bundle C2). When the tab is hidden the timer suspends —
    // saves a chart-rebuild + 2-3 fetches every 30s for a browser sitting
    // in the background.
    var refreshTimeout = null;
    var isRefreshing = false;
    AC.pollWhenVisible(function() {
        if (isRefreshing) return;
        isRefreshing = true;
        refreshTimeout = Date.now();
        loadConnectionDetail().then(function() {
            if (Date.now() - refreshTimeout > 25000) return;
            return loadTrafficChart();
        }).then(function() {
            if (connDetail && connDetail.has_flow_data && document.getElementById('tab-content-flows').classList.contains('active')) {
                return loadFlowStats();
            }
        }).catch(function(err) {
            if (err.name === 'AbortError' || err.name === 'CancelError') return;
            console.error('[ConnectionDetail] Refresh error:', err);
            AC.showError('Failed to refresh connection data');
        }).finally(function() {
            isRefreshing = false;
        });
    }, 30000, { immediate: false });
})();
