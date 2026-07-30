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

    // formatUptime lived here and divided tunnel_uptime by 100, treating it as
    // TimeTicks hundredths. It is seconds — an OPNsense tunnel deployed at 22:10
    // and read at 23:03 reported 3171 — so this column rendered a 53-minute
    // tunnel as "0m", a hundred-fold understatement on every row. The panel's
    // formatter always treated it as seconds; the two pages disagreed. Both now
    // call AC.formatTunnelUptime so there is only one answer.

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
    function renderBridgeSubtitle(conn, srcName, dstName) {
        var el = document.getElementById('bridge-subtitle');
        if (!el) return;
        if (!conn.source_if_name && !conn.dest_if_name && !L2_METHOD_LABELS[conn.match_method]) {
            el.innerHTML = '';
            return;
        }
        var parts = [];
        if (conn.source_if_name || conn.dest_if_name) {
            // Device-qualified so port ownership is unambiguous
            // ("DC2-FW2:dmz ↔ OPNsense:dtsec1", never a bare "dmz").
            var qual = function(dev, port) {
                return '<span style="color:var(--fwmon-text-faint);font-weight:400;">' + AC.escapeHtml(dev || '?') + ':</span>' + AC.escapeHtml(port || '?');
            };
            parts.push('<span style="font-family:\'JetBrains Mono\',monospace;font-weight:600;color:var(--fwmon-text);">' +
                qual(srcName, conn.source_if_name) + ' &harr; ' + qual(dstName, conn.dest_if_name) + '</span>');
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
            renderBridgeSubtitle(conn, srcName, dstName);

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
                document.getElementById('tab-evidence').classList.remove('hidden');

                renderInterfaceTable(data.interfaces || [], conn, srcName, dstName);
                renderEvidence(conn, data.evidence || []);
            } else {
                // One tunnel is one tunnel from either end. Adding the two sides'
                // ROW counts reported 9 for the single tunnel of connection 23984
                // — five FortiGate rows (four config children plus the SNMP
                // dialup row) and four OPNsense children.
                document.getElementById('stat-tunnel-count').textContent =
                    countLogicalTunnels(data.source_tunnels, data.dest_tunnels);
                document.getElementById('tab-evidence').classList.add('hidden');

                // phase2_matches drives the per-row "both ends reported this"
                // chip rather than a tab of its own; the server emits a match
                // only when each device made the claim from its own side.
                var p2matches = data.phase2_matches || [];
                var srcAgreed = {}, dstAgreed = {};
                p2matches.forEach(function(m) {
                    if (m.source_tunnel) srcAgreed[m.source_tunnel] = true;
                    if (m.dest_tunnel) dstAgreed[m.dest_tunnel] = true;
                });

                // Render tunnel tables
                renderTunnelTable('src-tunnels-table', data.source_tunnels || [], conn.source_device_id, srcAgreed);
                renderTunnelTable('dst-tunnels-table', data.dest_tunnels || [], conn.dest_device_id, dstAgreed);
                renderTunnelCharts('src-tunnel-charts', data.source_tunnels || [], conn.source_device_id);
                renderTunnelCharts('dst-tunnel-charts', data.dest_tunnels || [], conn.dest_device_id);
                document.getElementById('src-tunnels-title').textContent = 'Source Tunnels (' + srcName + ')';
                document.getElementById('dst-tunnels-title').textContent = 'Destination Tunnels (' + dstName + ')';
            }
        }).catch(function(err) {
            console.error('[ConnectionDetail] Error loading detail:', err);
            AC.showError('Failed to load connection details');
        });
    }

    // One chart per LOGICAL tunnel, full width, above its table.
    //
    // Previously every row expanded to its own small chart, so a tunnel drew one
    // chart per side AND one per phase2 row — and because a config-derived row
    // (FortiGate SSH phase1) carries no counters at all, one of them was always
    // blank. Rows of one tunnel are united by tunnel_group, which the server
    // resolves from the provisioning record; the group query sums their
    // per-bucket deltas, and counterless rows contribute nothing.
    //
    // Scoped to one device per table on purpose: the two ends report the SAME
    // traffic from their own side, so a combined chart would double every byte.
    // Selected chart range per logical tunnel, so the 30s poll does not throw the
    // user's choice away every refresh (the same pattern currentTrafficRange /
    // currentFlowHours already use for the other charts on this page).
    //
    // Keyed by host + GROUP NAME, never by the canvas id. The canvas id is
    // positional (`-g0`, `-g1`, …) over a group list derived from row order,
    // which has no ORDER BY — so when a tunnel appears, disappears or simply
    // comes back in a different order, index N names a different tunnel and the
    // remembered range would silently land on the wrong chart. The host id is in
    // the key because the same provisioned group legitimately appears in BOTH
    // the source and destination tables.
    var groupRanges = {};
    // Monotonic token per canvas: a click-initiated load still in flight when the
    // refresh wipes host.innerHTML would otherwise resolve against the NEW canvas
    // of the same positional id — possibly a different tunnel — and overwrite the
    // fresh chart with the old group's data.
    var groupChartGen = {};

    function groupKey(hostId, group) { return hostId + '|' + group; }

    function renderTunnelCharts(hostId, tunnels, deviceId) {
        var host = document.getElementById(hostId);
        if (!host) return;
        var groups = [], seen = {};
        for (var i = 0; i < tunnels.length; i++) {
            var g = tunnels[i].tunnel_group || tunnels[i].phase1_name || tunnels[i].tunnel_name;
            if (!g || seen[g]) continue;
            seen[g] = true;
            groups.push(g);
        }
        if (!groups.length) { destroyGroupCharts(hostId); host.innerHTML = ''; return; }
        destroyGroupCharts(hostId, groups);

        var html = '';
        for (var k = 0; k < groups.length; k++) {
            var cid = hostId + '-g' + k;
            var activeRange = groupRanges[groupKey(hostId, groups[k])] || '24h';
            html +=
                '<div class="tunnel-chart-wrap" style="margin-bottom:16px;">' +
                    '<div style="display:flex;align-items:baseline;gap:10px;margin-bottom:6px;">' +
                        '<span style="font-weight:600;color:var(--fwmon-text);">' + AC.escapeHtml(groups[k]) + '</span>' +
                        '<span style="font-size:0.75rem;color:var(--fwmon-text-mute);">combined across this tunnel\'s phase 2 entries</span>' +
                    '</div>' +
                    '<div class="range-pills" style="margin-bottom:8px;">' +
                        ['1h', '24h', '7d', '30d'].map(function(rg) {
                            return '<div class="range-pill' + (rg === activeRange ? ' active' : '') + '" data-action="load-group-chart"' +
                                ' data-canvas-id="' + cid + '" data-device-id="' + deviceId + '"' +
                                ' data-host-id="' + hostId + '"' +
                                ' data-group="' + AC.escapeHtml(groups[k]) + '" data-range="' + rg + '">' + rg + '</div>';
                        }).join('') +
                    '</div>' +
                    '<div class="chart-container"><canvas id="' + cid + '"></canvas></div>' +
                '</div>';
        }
        host.innerHTML = html;
        for (var m = 0; m < groups.length; m++) {
            loadGroupChart(hostId + '-g' + m, deviceId, groups[m],
                groupRanges[groupKey(hostId, groups[m])] || '24h', null, hostId, true);
        }
    }

    // destroyGroupCharts tears down Chart.js instances for a host's groups.
    // Without it, wiping host.innerHTML orphans the canvases while the Chart
    // objects (and their listeners) live on in tunnelCharts forever. `keep` is
    // the set of groups still being rendered; omit it to destroy all of them.
    function destroyGroupCharts(hostId, keep) {
        var keepIds = {};
        if (keep) {
            for (var k = 0; k < keep.length; k++) { keepIds[hostId + '-g' + k] = true; }
        }
        Object.keys(tunnelCharts).forEach(function(cid) {
            if (cid.indexOf(hostId + '-g') !== 0 || keepIds[cid]) return;
            try { tunnelCharts[cid].destroy(); } catch (e) { /* already detached */ }
            delete tunnelCharts[cid];
        });
    }

    // fromRefresh marks a load the user did not ask for. Those must fail quietly:
    // one API blip would otherwise pop a toast per group per side, every 30s.
    function loadGroupChart(canvasId, deviceId, group, range, pillEl, hostId, fromRefresh) {
        if (pillEl) {
            var pills = pillEl.parentElement.querySelectorAll('.range-pill');
            for (var p = 0; p < pills.length; p++) { pills[p].classList.remove('active'); }
            pillEl.classList.add('active');
        }
        // Remember the choice so the next poll re-applies it instead of snapping
        // every chart back to 24h.
        if (hostId && group) { groupRanges[groupKey(hostId, group)] = range; }

        var gen = (groupChartGen[canvasId] || 0) + 1;
        groupChartGen[canvasId] = gen;

        return AC.apiFetch(API_BASE + '/devices/' + deviceId + '/vpn-group-chart?group=' +
                encodeURIComponent(group) + '&range=' + range).then(function(result) {
            // A refresh may have rebuilt the DOM while this was in flight; the
            // canvas of this id can now belong to a different tunnel.
            if (groupChartGen[canvasId] !== gen) return;
            var data = result.data;
            var canvas = document.getElementById(canvasId);
            if (!canvas) return;
            if (tunnelCharts[canvasId]) { tunnelCharts[canvasId].destroy(); delete tunnelCharts[canvasId]; }
            if (!Array.isArray(data) || !data.length) return;
            var series = window.FwmonBwChart.normalizeDeltas(data);
            tunnelCharts[canvasId] = window.FwmonBwChart.mount(canvas, series, { rxLabel: 'In', txLabel: 'Out' });
        }).catch(function(err) {
            // A request cancelled by navigation or a superseding poll is not an
            // error worth showing anyone.
            if (err && (err.name === 'AbortError' || err.name === 'CancelError')) return;
            console.error('[ConnectionDetail] Error loading tunnel chart:', err);
            if (!fromRefresh) AC.showError('Failed to load tunnel chart');
        });
    }

    // One tunnel is one tunnel from either end — union the two sides' logical
    // groups rather than adding their row counts. Mirrors countLogicalTunnels in
    // diagram-panels.js; both pages must give the operator the same number.
    function countLogicalTunnels(srcTunnels, dstTunnels) {
        var names = {}, n = 0;
        [srcTunnels || [], dstTunnels || []].forEach(function(list) {
            list.forEach(function(t) {
                var key = (t.tunnel_group && t.tunnel_group.trim()) ||
                    (t.phase1_name && t.phase1_name.trim()) || t.tunnel_name;
                if (key && !names[key]) { names[key] = true; n++; }
            });
        });
        return n;
    }

    // A writer that counts nothing renders an em dash, not "0 B" — see
    // AC.tunnelCountersObserved.
    function noCounters() {
        return '<span style="color:var(--fwmon-text-mute);" title="This writer reads configuration and reports no counters.">&mdash;</span>';
    }

    function renderTunnelTable(tableId, tunnels, deviceId, agreed) {
        var tbody = document.querySelector('#' + tableId + ' tbody');
        if (!tunnels.length) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--fwmon-text-mute);padding:30px;">No matching tunnels found</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < tunnels.length; i++) {
            var t = tunnels[i];
            // This table is FLAT — no grouping, so there is no SNMP sibling to
            // supply the state a config row lacks. Collapsing 'unknown' into DOWN
            // therefore badged all four of connection 23984's FortiGate rows DOWN
            // on a tunnel that was up and passing traffic. Only 'up' and 'down'
            // are claims; see AC.tunnelClaim.
            var statusBadge = AC.tunnelStateBadge(AC.tunnelClaim(t));
            var observed = AC.tunnelCountersObserved(t);
            var typeBadge = t.tunnel_type
                ? '<span class="badge ipsec">' + AC.escapeHtml(t.tunnel_type) + '</span>'
                : '-';
            // Absence is neutral: no mirrored selector was observed, NOT that the
            // peer disagrees.
            var chip = (agreed && t.tunnel_name && agreed[t.tunnel_name])
                ? ' <span style="font-size:0.68rem;color:var(--fwmon-sig-ok);" title="Both ends independently reported this selector pair.">&harr; peer</span>'
                : '';
            html +=
                '<tr class="tunnel-row">' +
                    '<td>' + AC.escapeHtml(t.phase1_name || t.tunnel_name) + '</td>' +
                    '<td>' + AC.escapeHtml(t.tunnel_name) + chip + '</td>' +
                    '<td>' + typeBadge + '</td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' + AC.escapeHtml(t.remote_ip || '-') + '</td>' +
                    '<td><code style="color:var(--fwmon-accent);font-size:0.8rem;">' + AC.escapeHtml(t.local_subnet || '-') + '</code></td>' +
                    '<td><code style="color:var(--fwmon-sig-ok);font-size:0.8rem;">' + AC.escapeHtml(t.remote_subnet || '-') + '</code></td>' +
                    '<td>' + (observed ? formatBytes(t.bytes_in) : noCounters()) + '</td>' +
                    '<td>' + (observed ? formatBytes(t.bytes_out) : noCounters()) + '</td>' +
                    '<td>' + AC.formatTunnelUptime(t.tunnel_uptime) + '</td>' +
                '</tr>';
        }
        tbody.innerHTML = html;
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
        'load-group-chart': function(el) {
            // hostId is what makes the chosen range survive the 30s refresh —
            // without it loadGroupChart cannot key the store, and every poll
            // silently snaps the chart back to 24h.
            loadGroupChart(el.dataset.canvasId, parseInt(el.dataset.deviceId, 10),
                el.dataset.group, el.dataset.range, el, el.dataset.hostId, false);
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
