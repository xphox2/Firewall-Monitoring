// diagram-cytoscape.js — FWDiagram namespace: Cytoscape.js-based network diagram
// Tunnel-bundled visualization: overlays ride inside tunnel carriers
(function() {
    'use strict';

    var STORAGE_KEY = 'fwmon-diagram-positions';
    var MAX_PARTICLES = 80;

    var cy = null;
    var container = null;
    var onConnClick = null;
    var onVPNClick = null;
    var hiddenTypes = {};
    var showDown = true;
    var particleAnimId = null;
    var particleEls = [];
    var expandedTunnels = {}; // tunnelEdgeId -> true
    var keydownHandler = null;
    var nodeAlerts = {};      // deviceId -> "warning"|"critical" (open-alert overlay)
    var pulsingNodes = {};    // nodeId -> true while a pulse loop is active (teardown registry)
    var pendingFocus = null;  // { kind, id } queued until the graph has laid out

    // Connection type classification
    // OVERLAY_TYPES (vxlan, l3ipvlan) ride inside IPSec tunnels - shown when expanding tunnel
    // DIRECT_TYPES (l2vlan, bridge/Software Switch) are same-site local connections - shown as direct
    var TUNNEL_TYPES = { ipsec: true, ssl: true, gre: true, tunnel: true };
    var OVERLAY_TYPES = { l3ipvlan: true, vxlan: true };
    var DIRECT_TYPES = { ethernet: true, lag: true, l2vlan: true, bridge: true };

    var TYPE_COLORS = {
        ipsec: '#7dd3fc', // sky-300
        ssl: '#fdba74',   // orange-300
        gre: '#c4b5fd',   // violet-300
        tunnel: '#94a3b8', // slate-400
        vxlan: '#f0abfc',  // fuchsia-300
        l2vlan: '#2dd4bf', // teal-400 (direct)
        l3ipvlan: '#f472b6', // pink-400
        bridge: '#2dd4bf', // teal-400 (direct)
        wan: '#fb923c',    // orange-400
        lag: '#2dd4bf',    // teal-400 (direct — physical, distinguished by width)
        ethernet: '#2dd4bf', // teal-400 (direct — physical, distinguished by width)
        offnet: '#4ade80'  // green-400
    };

    var TYPE_LABELS = {
        ipsec: 'IPSec', ssl: 'SSL-VPN', gre: 'GRE', tunnel: 'Tunnel',
        vxlan: 'VXLAN', l2vlan: 'L2VLAN', l3ipvlan: 'L3VLAN', bridge: 'Software Switch',
        wan: 'WAN', lag: 'LAG', ethernet: 'Ethernet', offnet: 'Off-Net'
    };

    function getTypeLabel(type) {
        return TYPE_LABELS[type] || type;
    }

    // ---- 1a. Data Transformation (tunnel-bundled) ----
    function buildElements(devices, connections, siteMap, vpnMap, siteNames) {
        var elements = [];
        var siteIds = {};

        // Site compound nodes
        devices.forEach(function(d) {
            var sid = siteMap[d.id];
            if (sid && !siteIds[sid]) {
                siteIds[sid] = true;
                elements.push({ group: 'nodes', data: {
                    id: 'site-' + sid,
                    label: (siteNames && siteNames[sid]) || ('Site ' + sid),
                    nodeType: 'site'
                }});
            }
        });

        // Device nodes
        devices.forEach(function(d) {
            var sid = siteMap[d.id];
            var vpnInfo = vpnMap[String(d.id)];
            var vpnLabel = '';
            if (vpnInfo && vpnInfo.total > 0) {
                vpnLabel = '\nVPN ' + vpnInfo.up + '/' + vpnInfo.total;
            }
            var nodeData = {
                id: 'dev-' + d.id,
                label: (d.name.length > 18 ? d.name.slice(0, 17) + '\u2026' : d.name) + '\n' + d.ip_address + vpnLabel,
                nodeType: 'device', deviceId: d.id,
                status: d.status || 'unknown', deviceObj: d, vpnInfo: vpnInfo || null,
                // Open-alert overlay severity seeded from the last status poll so an
                // already-alerting device pulses on first paint (not only after a
                // later change). Kept in sync by applyAlertSeverities().
                alert: nodeAlerts[d.id] || (d.alert_severity || '')
            };
            if (sid) nodeData.parent = 'site-' + sid;
            elements.push({ group: 'nodes', data: nodeData });
        });

        // Build set of device IDs that have mapped connections (to filter off-net)
        var mappedDevicePeers = {}; // deviceId -> set of peer deviceIds with connections
        connections.forEach(function(c) {
            if (!mappedDevicePeers[c.source_device_id]) mappedDevicePeers[c.source_device_id] = {};
            if (!mappedDevicePeers[c.dest_device_id]) mappedDevicePeers[c.dest_device_id] = {};
            mappedDevicePeers[c.source_device_id][c.dest_device_id] = true;
            mappedDevicePeers[c.dest_device_id][c.source_device_id] = true;
        });

        // Off-net cloud — only for truly unmatched tunnels (remote users, unmonitored devices)
        var hasCloud = false;
        var offnetDevices = [];
        devices.forEach(function(d) {
            var vpnInfo = vpnMap[String(d.id)];
            if (!vpnInfo) return;
            // Filter to tunnels with no matched device AND whose remote IP isn't a monitored peer
            var trueOffnet = vpnInfo.tunnels.filter(function(t) {
                if (t.matched_device_id > 0) return false; // already matched
                return true; // genuinely unmatched (remote user, unknown device)
            });
            if (trueOffnet.length > 0) {
                offnetDevices.push({
                    deviceId: d.id,
                    anyUp: trueOffnet.some(function(t) { return t.status === 'up'; }),
                    count: trueOffnet.length
                });
                hasCloud = true;
            }
        });
        if (hasCloud) {
            elements.push({ group: 'nodes', data: { id: 'cloud-internet', nodeType: 'cloud' }});

            offnetDevices.forEach(function(info) {
                elements.push({ group: 'edges', data: {
                    id: 'offnet-' + info.deviceId, source: 'dev-' + info.deviceId, target: 'cloud-internet',
                    edgeType: 'offnet', status: info.anyUp ? 'up' : 'down', deviceId: info.deviceId, connType: 'offnet',
                    label: info.count + ' unmatched'
                }});
            });
        }

        // Build device→site lookup for cross-site detection
        var deviceSiteLocal = {};
        devices.forEach(function(d) { deviceSiteLocal[d.id] = siteMap[d.id] || null; });
        var isCrossSite = function(srcId, dstId) {
            var s1 = deviceSiteLocal[srcId], s2 = deviceSiteLocal[dstId];
            if (!s1 || !s2) return true; // no site = assume cross-site (WAN)
            return s1 !== s2;
        };

        // Ensure Internet cloud exists for cross-site tunnels
        var needCloud = false;

        // Group connections by device pair
        var pairKey = function(a, b) { return Math.min(a, b) + ':' + Math.max(a, b); };
        var pairs = {};

        connections.forEach(function(c) {
            var srcExists = devices.some(function(d) { return d.id === c.source_device_id; });
            var dstExists = devices.some(function(d) { return d.id === c.dest_device_id; });
            if (!srcExists || !dstExists) return;

            var key = pairKey(c.source_device_id, c.dest_device_id);
            if (!pairs[key]) pairs[key] = { tunnels: [], overlays: [], directs: [], srcId: c.source_device_id, dstId: c.dest_device_id };

            if (TUNNEL_TYPES[c.connection_type]) {
                pairs[key].tunnels.push(c);
                if (isCrossSite(c.source_device_id, c.dest_device_id)) needCloud = true;
            } else if (OVERLAY_TYPES[c.connection_type]) {
                pairs[key].overlays.push(c);
            } else {
                pairs[key].directs.push(c);
            }
        });

        // Add cloud node if cross-site tunnels exist and cloud wasn't already added
        if (needCloud && !hasCloud) {
            elements.push({ group: 'nodes', data: { id: 'cloud-internet', nodeType: 'cloud' }});
            hasCloud = true;
        }

        // Create edges per pair
        Object.keys(pairs).forEach(function(key) {
            var p = pairs[key];
            var crossSite = p.tunnels.length > 0 && isCrossSite(p.srcId, p.dstId);

            // Tunnel carriers
            var overlaysAssigned = false;
            p.tunnels.forEach(function(tunnel) {
                var childConns = (!overlaysAssigned && p.overlays.length > 0) ? p.overlays.slice() : [];
                if (childConns.length > 0) overlaysAssigned = true;
                var isDialUp = tunnel.match_method === 'tunnel_indirect' || tunnel.match_method === 'wan_inferred';
                var p2Count = tunnel.tunnel_names ? tunnel.tunnel_names.split(',').filter(function(n) { return n.trim(); }).length : 0;
                var labelParts = [getTypeLabel(tunnel.connection_type)];
                if (p2Count > 1) labelParts.push('(' + p2Count + ' P2)');
                if (childConns.length > 0) labelParts.push('+' + childConns.length);
                if (isDialUp) labelParts.push('DIAL-UP');
                var labelText = labelParts.join(' ');

                if (crossSite && hasCloud) {
                    // Cross-site: route through Internet cloud as two half-edges
                    elements.push({ group: 'edges', data: {
                        id: 'conn-' + tunnel.id + '-src',
                        source: 'dev-' + tunnel.source_device_id,
                        target: 'cloud-internet',
                        edgeType: 'tunnel-bundle',
                        connType: tunnel.connection_type,
                        status: tunnel.status || 'unknown',
                        connObj: tunnel,
                        childConns: childConns,
                        expanded: false,
                        tunnelHalf: 'src',
                        tunnelPeerId: 'conn-' + tunnel.id + '-dst',
                        label: labelText
                    }});
                    elements.push({ group: 'edges', data: {
                        id: 'conn-' + tunnel.id + '-dst',
                        source: 'cloud-internet',
                        target: 'dev-' + tunnel.dest_device_id,
                        edgeType: 'tunnel-bundle',
                        connType: tunnel.connection_type,
                        status: tunnel.status || 'unknown',
                        connObj: tunnel,
                        childConns: [],
                        expanded: false,
                        tunnelHalf: 'dst',
                        tunnelPeerId: 'conn-' + tunnel.id + '-src',
                        label: labelText
                    }});
                } else {
                    // Same-site or no cloud: direct edge
                    elements.push({ group: 'edges', data: {
                        id: 'conn-' + tunnel.id,
                        source: 'dev-' + tunnel.source_device_id,
                        target: 'dev-' + tunnel.dest_device_id,
                        edgeType: 'tunnel-bundle',
                        connType: tunnel.connection_type,
                        status: tunnel.status || 'unknown',
                        connObj: tunnel,
                        childConns: childConns,
                        expanded: false,
                        label: labelText
                    }});
                }
            });

            // Orphan overlays (no tunnel carrier)
            if (p.tunnels.length === 0 && p.overlays.length > 0) {
                p.overlays.forEach(function(c) {
                    elements.push({ group: 'edges', data: {
                        id: 'conn-' + c.id,
                        source: 'dev-' + c.source_device_id, target: 'dev-' + c.dest_device_id,
                        edgeType: 'connection', connType: c.connection_type,
                        status: c.status || 'unknown', connObj: c,
                        label: getTypeLabel(c.connection_type) + ' (no tunnel)'
                    }});
                });
            }

            // Direct connections (same-site) — standalone edges
            p.directs.forEach(function(c) {
                elements.push({ group: 'edges', data: {
                    id: 'conn-' + c.id,
                    source: 'dev-' + c.source_device_id, target: 'dev-' + c.dest_device_id,
                    edgeType: 'connection', connType: c.connection_type,
                    status: c.status || 'unknown', connObj: c,
                    label: getTypeLabel(c.connection_type)
                }});
            });
        });

        return elements;
    }

    function cssVar(name, fallback) {
        try {
            if (window.AdminCommon && window.AdminCommon.cssVar) {
                return window.AdminCommon.cssVar(name, fallback);
            }
            var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (e) { return fallback; }
    }

    function updateTypeColorsForTheme() {
        var isLight = document.documentElement.getAttribute('data-theme') === 'light';
        if (isLight) {
            TYPE_COLORS.ipsec = '#1d4fc4';
            TYPE_COLORS.ssl = '#c24a1a';
            TYPE_COLORS.gre = '#6d28d9';
            TYPE_COLORS.tunnel = '#475569';
            TYPE_COLORS.vxlan = '#b5179e';
            TYPE_COLORS.l2vlan = '#0f766e';
            TYPE_COLORS.l3ipvlan = '#be185d';
            TYPE_COLORS.bridge = '#0f766e';
            TYPE_COLORS.wan = '#c24a1a';
            TYPE_COLORS.lag = '#0f766e';
            TYPE_COLORS.ethernet = '#0f766e';
            TYPE_COLORS.offnet = '#15803d';
        } else {
            TYPE_COLORS.ipsec = '#7dd3fc';
            TYPE_COLORS.ssl = '#fdba74';
            TYPE_COLORS.gre = '#c4b5fd';
            TYPE_COLORS.tunnel = '#94a3b8';
            TYPE_COLORS.vxlan = '#f0abfc';
            TYPE_COLORS.l2vlan = '#2dd4bf';
            TYPE_COLORS.l3ipvlan = '#f472b6';
            TYPE_COLORS.bridge = '#2dd4bf';
            TYPE_COLORS.wan = '#fb923c';
            TYPE_COLORS.lag = '#2dd4bf';
            TYPE_COLORS.ethernet = '#2dd4bf';
            TYPE_COLORS.offnet = '#4ade80';
        }
    }

    // ---- 1b. Stylesheet ----
    function buildStylesheet() {
        updateTypeColorsForTheme();
        return [
            // Site compound nodes — label above with dark background for visibility
            { selector: 'node[nodeType="site"]', style: {
                'background-opacity': 0, 'border-width': 1.5, 'border-style': 'dashed',
                'border-color': cssVar('--fwmon-border-strong', 'rgba(255, 255, 255, 0.15)'), 'border-opacity': 0.7, 'label': 'data(label)',
                'text-valign': 'top', 'text-halign': 'center', 'font-size': '13px',
                'font-family': 'Outfit, "Inter", sans-serif', 'font-weight': '600',
                'color': cssVar('--fwmon-accent', '#7dd3fc'), 'text-margin-y': -12,
                'text-background-color': cssVar('--fwmon-bg', '#0d1117'), 'text-background-opacity': 0.9,
                'text-background-padding': '6px', 'text-background-shape': 'roundrectangle',
                'padding': '40px', 'shape': 'roundrectangle', 'corner-radius': 12,
                'min-width': '200px', 'min-height': '90px', 'z-index': 1
            }},
            // Device nodes
            { selector: 'node[nodeType="device"]', style: {
                'width': 150, 'height': 64, 'shape': 'roundrectangle', 'background-color': cssVar('--fwmon-card-bg', '#12161f'),
                'border-width': 2, 'border-color': cssVar('--fwmon-border', '#30363d'), 'label': 'data(label)',
                'text-valign': 'center', 'text-halign': 'center', 'font-size': '11px',
                'font-family': 'Outfit, "Inter", "Segoe UI", sans-serif', 'font-weight': '500',
                'color': cssVar('--fwmon-text', '#e6edf3'), 'text-wrap': 'wrap', 'text-max-width': '140px', 'corner-radius': 8,
                'ghost': 'yes', 'ghost-opacity': 0.15, 'ghost-offset-x': 0, 'ghost-offset-y': 4
            }},
            { selector: 'node[nodeType="device"][status="online"]', style: { 'border-color': cssVar('--fwmon-sig-ok', '#4ade80') } },
            { selector: 'node[nodeType="device"][status="offline"]', style: { 'border-color': cssVar('--fwmon-sig-crit', '#f87171') } },
            // Open-alert overlay (v0.10.523) — declared AFTER status so an alerting
            // device's border colour wins over online/offline. The pulse (border
            // width) is driven by cy.animate (canvas nodes ignore CSS keyframes),
            // see pulseNode(). Colours match the NOC severity ramp.
            { selector: 'node[nodeType="device"][alert="warning"]', style: { 'border-color': cssVar('--fwmon-sig-warn', '#e7b53c') } },
            { selector: 'node[nodeType="device"][alert="critical"]', style: { 'border-color': cssVar('--fwmon-sig-crit', '#f2555a') } },
            // Cloud node — large cloud icon centered
            { selector: 'node[nodeType="cloud"]', style: {
                'width': 10, 'height': 10, 'shape': 'ellipse',
                'background-opacity': 0, 'border-width': 0,
                'padding': 0,
                'label': '\u2601\uFE0F', 'text-valign': 'center', 'text-halign': 'center',
                'font-size': '80px', 'color': '#64748b',
                'text-margin-x': 0, 'text-margin-y': 0
            }},
            // Default edge — all straight lines
            { selector: 'edge', style: {
                'curve-style': 'straight',
                'width': 3, 'line-color': cssVar('--fwmon-text-mute', '#8b949e'), 'target-arrow-shape': 'none', 'opacity': 1
            }},
            // Tunnel bundle edges — thicker pipe
            { selector: 'edge[edgeType="tunnel-bundle"]', style: { 'width': 4, 'label': 'data(label)', 'font-size': '9px', 'font-family': 'JetBrains Mono, monospace', 'color': cssVar('--fwmon-text-mute', '#8b949e'), 'text-rotation': 'autorotate', 'text-margin-y': -10 } },
            // Direct connection edges — bezier so parallel same-pair direct links stack/offset instead of overlapping into one line
            { selector: 'edge[edgeType="connection"]', style: { 'curve-style': 'bezier', 'control-point-step-size': 18 } },
            // Connection type colors
            { selector: 'edge[connType="ipsec"]', style: { 'line-color': TYPE_COLORS.ipsec } },
            { selector: 'edge[connType="ssl"]', style: { 'line-color': TYPE_COLORS.ssl } },
            { selector: 'edge[connType="vxlan"]', style: { 'line-color': TYPE_COLORS.vxlan, 'line-style': 'dashed', 'line-dash-pattern': [8, 4] } },
            { selector: 'edge[connType="l2vlan"]', style: { 'line-color': TYPE_COLORS.l2vlan } },
            // bridge (Software Switch) is the same VLAN-layer direct link as l2vlan — same teal color, stacked alongside it
            { selector: 'edge[connType="bridge"]', style: { 'line-color': TYPE_COLORS.bridge } },
            { selector: 'edge[connType="l3ipvlan"]', style: { 'line-color': TYPE_COLORS.l3ipvlan, 'line-style': 'dashed', 'line-dash-pattern': [12, 4] } },
            { selector: 'edge[connType="gre"]', style: { 'line-color': TYPE_COLORS.gre } },
            { selector: 'edge[connType="wan"]', style: { 'line-color': TYPE_COLORS.wan } },
            { selector: 'edge[connType="lag"]', style: { 'line-color': TYPE_COLORS.lag, 'width': 4 } },
            { selector: 'edge[connType="ethernet"]', style: { 'line-color': TYPE_COLORS.ethernet, 'width': 2 } },
            { selector: 'edge[connType="tunnel"]', style: { 'line-color': TYPE_COLORS.tunnel } },
            // Sub-lane edges (expansion) — offset bezier for visual separation
            { selector: 'edge[edgeType="sublane"]', style: {
                'width': 3, 'curve-style': 'unbundled-bezier',
                'label': 'data(label)', 'font-size': '9px', 'font-family': 'JetBrains Mono, monospace', 'color': cssVar('--fwmon-text-dim', '#c9d1d9'),
                'text-rotation': 'autorotate', 'text-margin-y': -10,
                'text-background-color': cssVar('--fwmon-bg', '#0d1117'), 'text-background-opacity': 0.8,
                'text-background-padding': '2px'
            }},
            // Pipe background (expansion)
            { selector: 'edge[edgeType="pipe-bg"]', style: { 'width': 20, 'opacity': 0.08, 'line-color': cssVar('--fwmon-accent', '#7dd3fc') } },
            // Off-net edges — gentle curve to separate from tunnel edges
            { selector: 'edge[edgeType="offnet"]', style: {
                'line-color': cssVar('--fwmon-sig-ok', '#4ade80'), 'width': 1.5, 'opacity': 0.6,
                'line-style': 'dashed', 'line-dash-pattern': [3, 6],
                'curve-style': 'unbundled-bezier',
                'control-point-distances': [40], 'control-point-weights': [0.5]
            }},
            // DOWN edges — red X
            { selector: 'edge[status="down"]', style: {
                'line-style': 'dashed', 'line-dash-pattern': [6, 4], 'opacity': 0.6,
                'label': '\u2716', 'text-rotation': 'autorotate', 'font-size': '18px',
                'color': cssVar('--fwmon-sig-crit', '#f87171'), 'text-background-color': cssVar('--fwmon-bg', '#0d1117'),
                'text-background-opacity': 0.9, 'text-background-padding': '4px',
                'text-background-shape': 'roundrectangle', 'text-border-color': cssVar('--fwmon-sig-crit', '#f87171'),
                'text-border-width': 1.5, 'text-border-opacity': 0.8,
                'text-halign': 'center', 'text-valign': 'center'
            }},
            // Selected states
            { selector: 'node:selected', style: { 'border-color': cssVar('--fwmon-accent', '#7dd3fc'), 'border-width': 3 } },
            { selector: 'edge:selected', style: { 'width': 5, 'opacity': 1 } },
            // Focus/dim (v0.10.523) — driven by the NOC "focus this node on the map"
            // sync. .focused uses an overlay ring (not the border) so it never
            // fights the status/alert/selected border colours.
            { selector: '.dimmed', style: { 'opacity': 0.18 } },
            { selector: 'node.focused', style: {
                'overlay-color': '#22d3ee', 'overlay-opacity': 0.28, 'overlay-padding': 8, 'z-index': 20
            }}
        ];
    }

    // ---- 1c. Layout ----
    // Fixed positions: cloud center, sites at cardinal directions (L, R, T, B, then corners)
    var SITE_POSITIONS = [
        { x: -400, y: 0 },    // left
        { x: 400, y: 0 },     // right
        { x: 0, y: -350 },    // top
        { x: 0, y: 350 },     // bottom
        { x: -350, y: -300 }, // top-left
        { x: 350, y: -300 },  // top-right
        { x: -350, y: 300 },  // bottom-left
        { x: 350, y: 300 }    // bottom-right
    ];

    function buildLayoutOptions(elements, siteMap) {
        // Compute fresh positions first
        var positions = computePositions(elements, siteMap);

        // Overlay saved positions (keyed by full node ID)
        var saved = loadPositions();
        if (saved && Object.keys(saved).length > 0) {
            Object.keys(saved).forEach(function(key) { positions[key] = saved[key]; });
        }

        return { name: 'preset', positions: function(node) {
            return positions[node.id()] || undefined;
        }, fit: true, padding: 60 };
    }

    function computePositions(elements, siteMap) {
        var positions = {};
        positions['cloud-internet'] = { x: 0, y: 0 };

        var siteIds = [], seenSites = {};
        elements.forEach(function(el) {
            if (el.group === 'nodes' && el.data.nodeType === 'site') {
                var sid = el.data.id.replace('site-', '');
                if (!seenSites[sid]) { seenSites[sid] = true; siteIds.push(sid); }
            }
        });
        var sitePositions = {};
        siteIds.forEach(function(sid, i) { sitePositions[sid] = SITE_POSITIONS[i % SITE_POSITIONS.length]; });

        var siteBuckets = {};
        if (siteMap) {
            Object.keys(siteMap).forEach(function(devId) {
                var sid = siteMap[devId];
                if (!sid) return;
                if (!siteBuckets[sid]) siteBuckets[sid] = [];
                siteBuckets[sid].push(devId);
            });
        }
        Object.keys(siteBuckets).forEach(function(sid) {
            var devs = siteBuckets[sid];
            var sp = sitePositions[sid] || { x: 0, y: 0 };
            var startX = sp.x - (devs.length - 1) * 170 / 2;
            devs.forEach(function(devId, i) { positions['dev-' + devId] = { x: startX + i * 170, y: sp.y }; });
        });

        // Unsited devices below cloud
        var unsited = [];
        elements.forEach(function(el) {
            if (el.group === 'nodes' && el.data.nodeType === 'device' && !positions[el.data.id]) unsited.push(el.data.id);
        });
        unsited.forEach(function(id, i) { positions[id] = { x: -(unsited.length - 1) * 170 / 2 + i * 170, y: 450 }; });


        return positions;
    }

    // ---- 1d. Init & Render ----
    function init(containerId) {
        cleanup();
        container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = '';
        container.style.position = 'relative';
    }

    function render(devices, connections, siteMap, vpnMap, siteNames) {
        if (!container) return;
        if (devices.length === 0) {
            container.innerHTML = '<div class="loading" style="padding:60px 20px;">Add devices to see the network diagram</div>';
            return;
        }
        var elements = buildElements(devices, connections, siteMap, vpnMap, siteNames);
        var stylesheet = buildStylesheet();
        var layoutOpts = buildLayoutOptions(elements, siteMap);

        var cyDiv = document.createElement('div');
        cyDiv.id = 'cy-canvas';
        cyDiv.style.cssText = 'width:100%;height:100%;min-height:500px;';
        container.appendChild(cyDiv);

        cy = cytoscape({ container: cyDiv, elements: elements, style: stylesheet, layout: layoutOpts,
            minZoom: 0.3, maxZoom: 3, wheelSensitivity: 0.3, boxSelectionEnabled: false });


        applyFilters();
        wireEvents(devices, vpnMap);
        cy.one('layoutstop', function() {
            startParticles();
            applyAlertPulses();           // begin pulsing any already-alerting nodes
            if (pendingFocus) { var pf = pendingFocus; pendingFocus = null; focusNode(pf.kind, pf.id); }
        });
        setTimeout(function() { startParticles(); }, 600);
    }


    function cleanup() {
        stopParticles();
        pulsingNodes = {}; // pulse loops self-terminate once cy is destroyed
        expandedTunnels = {};
        if (keydownHandler) { document.removeEventListener('keydown', keydownHandler); keydownHandler = null; }
        if (cy) { cy.destroy(); cy = null; }
    }

    // ---- 1e. Event Handling ----
    function wireEvents(devices, vpnMap) {
        if (!cy) return;

        cy.on('tap', 'edge', function(evt) {
            var edge = evt.target;
            var data = edge.data();

            // Tunnel bundle: toggle expand/collapse
            if (data.edgeType === 'tunnel-bundle') {
                // Resolve to the -src half (which holds childConns) for cross-site pairs
                var srcEdge = edge;
                if (data.tunnelHalf === 'dst' && data.tunnelPeerId) {
                    var peer = cy.getElementById(data.tunnelPeerId);
                    if (peer && !peer.empty()) srcEdge = peer;
                }
                var srcData = srcEdge.data();

                // Select both halves visually
                cy.edges(':selected').unselect();
                edge.select();
                if (data.tunnelPeerId) {
                    var peerSel = cy.getElementById(data.tunnelPeerId);
                    if (peerSel && !peerSel.empty()) peerSel.select();
                }

                // Expand/collapse if has children
                if (srcData.childConns && srcData.childConns.length > 0) {
                    if (expandedTunnels[srcData.id]) {
                        collapseTunnel(srcData.id);
                    } else {
                        expandTunnel(srcEdge);
                    }
                    return;
                }

                // No children — show detail panel
                if (srcData.connObj && onConnClick) {
                    onConnClick(srcData.connObj);
                }
                return;
            }

            // Pipe background: ignored (collapse via Escape or background tap)
            if (data.edgeType === 'pipe-bg') return;

            // Regular connection or sublane: show detail panel
            if ((data.edgeType === 'connection' || data.edgeType === 'sublane') && data.connObj && onConnClick) {
                onConnClick(data.connObj);
            } else if (data.edgeType === 'offnet' && data.deviceId && onVPNClick) {
                onVPNClick(data.deviceId, true);
            }
        });

        cy.on('tap', 'node[nodeType="device"]', function(evt) {
            var node = evt.target;
            var data = node.data();
            if (data.vpnInfo && data.vpnInfo.total > 0) {
                var pos = evt.position;
                var nodePos = node.position();
                var h = node.height();
                var relY = pos.y - (nodePos.y - h / 2);
                if (relY > h * 0.6 && onVPNClick) { onVPNClick(data.deviceId, false); return; }
            }
            // Tapping a device opens its Alert History (filtered to that device) —
            // the same destination as a NOC card click, so "click a device" means
            // the same thing everywhere. Uses SPA navigation (not a full reload);
            // a canvas tap isn't an <a>, so we route through a hidden anchor click
            // that the admin router's click-interceptor picks up.
            spaNavigate('/admin/alerts?device_id=' + data.deviceId);
        });

        cy.on('tap', 'node[nodeType="cloud"]', function() {
            var edges = cy.edges('[edgeType="offnet"]');
            if (edges.length === 1 && onVPNClick) onVPNClick(edges[0].data('deviceId'), true);
        });

        cy.on('dragfree', 'node[nodeType="device"]', savePositions);
        cy.on('dragfree', 'node[nodeType="site"]', savePositions);

        // Background tap: collapse all expanded tunnels and fit view
        cy.on('tap', function(evt) {
            if (evt.target === cy && Object.keys(expandedTunnels).length > 0) {
                Object.keys(expandedTunnels).forEach(collapseTunnel);
                cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: 400 });
            }
        });

        // Escape key collapses all expanded tunnels (store ref for cleanup)
        if (keydownHandler) document.removeEventListener('keydown', keydownHandler);
        keydownHandler = function(e) {
            if (e.key === 'Escape' && Object.keys(expandedTunnels).length > 0) {
                Object.keys(expandedTunnels).forEach(collapseTunnel);
                if (cy) cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: 400 });
            }
        };
        document.addEventListener('keydown', keydownHandler);
    }

    // ---- 1f. Tunnel Inline Expansion ----
    function expandTunnel(edge) {
        if (!cy) return;
        var data = edge.data();
        var children = data.childConns || [];
        if (children.length === 0) return;

        var tunnelId = data.id;
        expandedTunnels[tunnelId] = true;

        // Hide ALL other edges so only the expanded tunnel sublanes are visible
        cy.edges().forEach(function(e) {
            e.style('display', 'none');
        });

        // Determine if cross-site (sublanes must route through cloud)
        var isCrossSite = !!data.tunnelPeerId;
        var laneSrc = data.source; // dev-X or cloud
        var laneDst = data.target; // cloud or dev-Y
        var remoteDst = laneDst;
        if (isCrossSite) {
            var peerEdge = cy.getElementById(data.tunnelPeerId);
            if (peerEdge && !peerEdge.empty()) {
                remoteDst = peerEdge.data('target');
            }
        }

        // Calculate offsets for visual separation
        var totalLanes = children.length + 1;
        var spacing = 25;
        var baseOffset = -(totalLanes - 1) * spacing / 2;

        // Helper: add a sublane with vertical offset
        function addSublane(laneId, connType, status, connObj, labelText, color, laneIdx) {
            var offset = baseOffset + laneIdx * spacing;
            var cpDist = [offset];
            var cpWeight = [0.5];

            function styleLane(id) {
                cy.getElementById(id).style({
                    'line-color': color,
                    'control-point-distances': cpDist,
                    'control-point-weights': cpWeight
                });
            }

            if (isCrossSite) {
                cy.add({ group: 'edges', data: {
                    id: laneId + '-a', source: laneSrc, target: 'cloud-internet',
                    edgeType: 'sublane', connType: connType, status: status,
                    connObj: connObj, parentTunnel: tunnelId, label: labelText
                }});
                styleLane(laneId + '-a');
                cy.add({ group: 'edges', data: {
                    id: laneId + '-b', source: 'cloud-internet', target: remoteDst,
                    edgeType: 'sublane', connType: connType, status: status,
                    connObj: connObj, parentTunnel: tunnelId, label: ''
                }});
                // Mirror the offset on the other side so lanes fan outward symmetrically
                cy.getElementById(laneId + '-b').style({
                    'line-color': color,
                    'control-point-distances': [-offset],
                    'control-point-weights': cpWeight
                });
            } else {
                cy.add({ group: 'edges', data: {
                    id: laneId, source: laneSrc, target: laneDst,
                    edgeType: 'sublane', connType: connType, status: status,
                    connObj: connObj, parentTunnel: tunnelId, label: labelText
                }});
                styleLane(laneId);
            }
        }

        // Pipe background (for cross-site: two halves through cloud)
        if (isCrossSite) {
            cy.add({ group: 'edges', data: { id: tunnelId + '-pipe-a', source: laneSrc, target: 'cloud-internet', edgeType: 'pipe-bg', status: data.status, parentTunnel: tunnelId }});
            cy.add({ group: 'edges', data: { id: tunnelId + '-pipe-b', source: 'cloud-internet', target: remoteDst, edgeType: 'pipe-bg', status: data.status, parentTunnel: tunnelId }});
        } else {
            cy.add({ group: 'edges', data: { id: tunnelId + '-pipe', source: laneSrc, target: laneDst, edgeType: 'pipe-bg', status: data.status, parentTunnel: tunnelId }});
        }

        // Carrier sublane (index 0)
        addSublane(tunnelId + '-carrier', data.connType, data.status, data.connObj, getTypeLabel(data.connType), TYPE_COLORS[data.connType] || '#8b949e', 0);

        // Child overlay sublanes (index 1, 2, ...)
        children.forEach(function(child, idx) {
            addSublane(tunnelId + '-lane-' + child.id, child.connection_type, child.status, child, getTypeLabel(child.connection_type), TYPE_COLORS[child.connection_type] || '#8b949e', idx + 1);
        });

        // Restart particles to include new sublanes
        stopParticles();
        startParticles();

        // Zoom to fit the expanded tunnel's source and destination nodes
        var nodesToFit = cy.collection();
        var srcNode = cy.getElementById(laneSrc);
        if (srcNode && !srcNode.empty()) nodesToFit = nodesToFit.union(srcNode);
        if (isCrossSite) {
            var cloudNode = cy.getElementById('cloud-internet');
            if (cloudNode && !cloudNode.empty()) nodesToFit = nodesToFit.union(cloudNode);
            var dstNode = cy.getElementById(remoteDst);
            if (dstNode && !dstNode.empty()) nodesToFit = nodesToFit.union(dstNode);
        } else {
            var dstNode2 = cy.getElementById(laneDst);
            if (dstNode2 && !dstNode2.empty()) nodesToFit = nodesToFit.union(dstNode2);
        }
        if (nodesToFit.length > 0) {
            cy.animate({ fit: { eles: nodesToFit, padding: 80 } }, { duration: 400 });
        }
    }

    function collapseTunnel(tunnelId) {
        if (!cy) return;
        delete expandedTunnels[tunnelId];

        // Remove sublane and pipe edges for this tunnel
        cy.edges('[parentTunnel="' + tunnelId + '"]').remove();

        // Show all edges again and re-apply filters
        cy.edges().forEach(function(e) { e.style('display', 'element'); });
        applyFilters();

        stopParticles();
        startParticles();
    }

    // ---- 1g. Layer Filtering & DOWN Toggle ----
    function applyFilters() {
        if (!cy) return;
        // Track which tunnel types are hidden so sublanes inherit
        var hiddenTunnelIds = {};
        cy.edges().forEach(function(edge) {
            var data = edge.data();
            if (data.edgeType === 'sublane' || data.edgeType === 'pipe-bg') return; // handled below
            var hide = false;
            if ((data.edgeType === 'connection' || data.edgeType === 'tunnel-bundle' || data.edgeType === 'offnet') && hiddenTypes[data.connType]) hide = true;
            if (!showDown && data.status === 'down') hide = true;
            if (expandedTunnels[data.id]) hide = true;
            if (hide && data.edgeType === 'tunnel-bundle') hiddenTunnelIds[data.id] = true;
            edge.style('display', hide ? 'none' : 'element');
        });
        // Hide sublanes/pipe-bg of hidden or DOWN tunnels
        cy.edges('[edgeType="sublane"], [edgeType="pipe-bg"]').forEach(function(edge) {
            var parentId = edge.data('parentTunnel');
            edge.style('display', hiddenTunnelIds[parentId] ? 'none' : 'element');
        });
    }

    function toggleType(type) {
        if (type === 'all') { hiddenTypes = {}; }
        else if (type === 'direct') {
            // "Direct" is a legend group covering all DIRECT_TYPES (ethernet, lag,
            // l2vlan, bridge) — they share one color on the map, so they toggle as one.
            var keys = Object.keys(DIRECT_TYPES);
            var anyVisible = keys.some(function(t) { return !hiddenTypes[t]; });
            keys.forEach(function(t) { if (anyVisible) hiddenTypes[t] = true; else delete hiddenTypes[t]; });
        }
        else { if (hiddenTypes[type]) delete hiddenTypes[type]; else hiddenTypes[type] = true; }
        applyFilters(); updateToolbarButtons();
    }

    function toggleDown() {
        showDown = !showDown;
        applyFilters();
        var btn = document.getElementById('btn-toggle-down');
        if (btn) { btn.classList.toggle('active', showDown); btn.textContent = showDown ? 'Hide DOWN' : 'Show DOWN'; }
    }

    function updateToolbarButtons() {
        document.querySelectorAll('[data-action="dg-filter-type"]').forEach(function(btn) {
            var type = btn.dataset.type;
            var active;
            if (type === 'all') active = Object.keys(hiddenTypes).length === 0;
            else if (type === 'direct') active = Object.keys(DIRECT_TYPES).some(function(t) { return !hiddenTypes[t]; });
            else active = !hiddenTypes[type];
            btn.classList.toggle('active', active);
        });
    }

    // ---- 1h. Particle Animation (directional, tunnel-bundled) ----
    function startParticles() {
        if (!cy || particleAnimId) return;
        particleEls = [];

        var visibleEdges = cy.edges().filter(function(e) {
            return e.style('display') !== 'none' && e.data('status') === 'up';
        });
        if (visibleEdges.length === 0) return;

        var canvasDiv = container.querySelector('#cy-canvas');
        if (!canvasDiv) return;

        var canvas = document.createElement('canvas');
        canvas.id = 'particle-canvas';
        canvas.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:5;';
        container.appendChild(canvas);

        var resizeCanvas = function() {
            var rect = canvasDiv.getBoundingClientRect();
            canvas.width = rect.width * (window.devicePixelRatio || 1);
            canvas.height = rect.height * (window.devicePixelRatio || 1);
            canvas.style.width = rect.width + 'px';
            canvas.style.height = rect.height + 'px';
        };
        resizeCanvas();

        var count = 0;
        visibleEdges.forEach(function(edge) {
            if (count >= MAX_PARTICLES) return;
            var data = edge.data();

            if (data.edgeType === 'tunnel-bundle') {
                var carrierColor = TYPE_COLORS[data.connType] || '#8b949e';
                var isSplit = !!data.tunnelHalf;

                if (isSplit) {
                    // Cross-site split half: forward + dimmer return particle
                    if (particleEls.length < MAX_PARTICLES) {
                        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.0003 + Math.random() * 0.00015,
                            direction: 1, color: carrierColor, radius: 3, alpha: 0.85 });
                        count++;
                    }
                    if (particleEls.length < MAX_PARTICLES) {
                        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.00022 + Math.random() * 0.0001,
                            direction: -1, color: carrierColor, radius: 3, alpha: 0.85 });
                        count++;
                    }
                } else {
                    // Same-site: normal bidirectional pair
                    count += addParticlePair(edge, carrierColor);
                }

                // For overlay dots: use this half's childConns, or if empty (dst half), use peer's childConns
                var children = data.childConns || [];
                if (children.length === 0 && data.tunnelPeerId) {
                    var peerEdge = cy.getElementById(data.tunnelPeerId);
                    if (peerEdge && !peerEdge.empty()) {
                        children = peerEdge.data('childConns') || [];
                    }
                }
                children.forEach(function(child) {
                    if (particleEls.length >= MAX_PARTICLES) return;
                    var childColor = TYPE_COLORS[child.connection_type] || '#8b949e';
                    // Forward dot
                    particleEls.push({ edge: edge, progress: Math.random(), speed: 0.00025 + Math.random() * 0.0001,
                        direction: 1, color: childColor, radius: 2.5, alpha: 0.9 });
                    count++;
                    // Return dot (dimmer, smaller)
                    if (particleEls.length < MAX_PARTICLES) {
                        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.0002 + Math.random() * 0.0001,
                            direction: -1, color: childColor, radius: 2.5, alpha: 0.9 });
                        count++;
                    }
                });
            } else if (data.edgeType === 'sublane') {
                var color = TYPE_COLORS[data.connType] || '#8b949e';
                var isSplitLane = data.id && (data.id.endsWith('-a') || data.id.endsWith('-b'));
                if (isSplitLane) {
                    // Cross-site sublane half: forward + dimmer return
                    if (particleEls.length < MAX_PARTICLES) {
                        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.0003 + Math.random() * 0.00015,
                            direction: 1, color: color, radius: 3, alpha: 0.85 });
                        count++;
                    }
                    if (particleEls.length < MAX_PARTICLES) {
                        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.00022 + Math.random() * 0.0001,
                            direction: -1, color: color, radius: 3, alpha: 0.85 });
                        count++;
                    }
                } else {
                    // Same-site sublane: normal bidirectional pair
                    count += addParticlePair(edge, color);
                }
            } else if (data.edgeType === 'offnet') {
                if (particleEls.length < MAX_PARTICLES) {
                    particleEls.push({ edge: edge, progress: Math.random(), speed: 0.0003 + Math.random() * 0.0002,
                        direction: 1, color: '#3fb950', radius: 3, alpha: 0.85 });
                    count++;
                }
            } else if (data.edgeType === 'pipe-bg') {
                // No particles
            } else {
                var directColor = TYPE_COLORS[data.connType] || '#8b949e';
                count += addParticlePair(edge, directColor);
            }
        });

        var ctx = canvas.getContext('2d');
        var dpr = window.devicePixelRatio || 1;
        var lastTime = 0;

        function animate(timestamp) {
            if (!cy) { stopParticles(); return; }
            if (!lastTime) lastTime = timestamp;
            var dt = timestamp - lastTime;
            lastTime = timestamp;

            var rect = canvasDiv.getBoundingClientRect();
            if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) resizeCanvas();

            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.save();
            ctx.scale(dpr, dpr);
            var pan = cy.pan();
            var zoom = cy.zoom();

            particleEls.forEach(function(p) {
                if (!p.edge || p.edge.removed()) return;
                if (p.edge.style('display') === 'none') return;

                p.progress += p.speed * dt * p.direction;
                if (p.progress > 1) p.progress -= 1;
                if (p.progress < 0) p.progress += 1;

                var src = p.edge.sourceEndpoint();
                var tgt = p.edge.targetEndpoint();
                if (!src || !tgt) return;

                var mx, my;
                var curveStyle = p.edge.style('curve-style');

                if (curveStyle === 'unbundled-bezier' || curveStyle === 'segments') {
                    // Follow the curve: compute quadratic bezier through control point
                    var cpd = p.edge.numericStyle('control-point-distances') || 0;
                    var midX = (src.x + tgt.x) / 2;
                    var midY = (src.y + tgt.y) / 2;
                    // Perpendicular offset direction
                    var dx = tgt.x - src.x;
                    var dy = tgt.y - src.y;
                    var len = Math.sqrt(dx * dx + dy * dy) || 1;
                    var nx = -dy / len; // perpendicular normal
                    var ny = dx / len;
                    var cpx = midX + nx * cpd;
                    var cpy = midY + ny * cpd;
                    // Quadratic bezier: B(t) = (1-t)^2*P0 + 2*(1-t)*t*P1 + t^2*P2
                    var t = p.progress;
                    var mt = 1 - t;
                    mx = mt * mt * src.x + 2 * mt * t * cpx + t * t * tgt.x;
                    my = mt * mt * src.y + 2 * mt * t * cpy + t * t * tgt.y;
                } else {
                    // Straight line interpolation
                    mx = src.x + (tgt.x - src.x) * p.progress;
                    my = src.y + (tgt.y - src.y) * p.progress;
                }

                var rx = mx * zoom + pan.x;
                var ry = my * zoom + pan.y;

                ctx.beginPath();
                ctx.arc(rx, ry, p.radius * zoom, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.globalAlpha = p.alpha || 0.85;
                ctx.fill();
            });

            ctx.restore();
            particleAnimId = requestAnimationFrame(animate);
        }
        particleAnimId = requestAnimationFrame(animate);
    }

    function addParticlePair(edge, color) {
        if (particleEls.length >= MAX_PARTICLES) return 0;
        particleEls.push({ edge: edge, progress: Math.random(), speed: 0.0003 + Math.random() * 0.00015,
            direction: 1, color: color, radius: 3, alpha: 0.85 });
        if (particleEls.length < MAX_PARTICLES) {
            particleEls.push({ edge: edge, progress: Math.random(), speed: 0.00022 + Math.random() * 0.0001,
                direction: -1, color: color, radius: 2, alpha: 0.4 });
            return 2;
        }
        return 1;
    }

    function stopParticles() {
        if (particleAnimId) { cancelAnimationFrame(particleAnimId); particleAnimId = null; }
        particleEls = [];
        var canvas = document.getElementById('particle-canvas');
        if (canvas && canvas.parentNode) canvas.parentNode.removeChild(canvas);
    }

    // ---- 1i. Position Persistence ----
    function savePositions() {
        if (!cy) return;
        var data = {};
        cy.nodes().forEach(function(node) {
            var pos = node.position();
            if (pos) data[node.id()] = { x: Math.round(pos.x), y: Math.round(pos.y) };
        });
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
    }
    function loadPositions() { try { var raw = localStorage.getItem(STORAGE_KEY); return raw ? JSON.parse(raw) : {}; } catch (e) { return {}; } }
    function resetLayout() { try { localStorage.removeItem(STORAGE_KEY); } catch (e) {} if (window.drawConnectionDiagram) window.drawConnectionDiagram(); }
    function fitGraph() { if (cy) cy.fit(undefined, 40); }

    function toggleFullscreen() {
        if (!container) return;
        // Target the card wrapping the diagram (parent of connection-diagram)
        var card = container.closest('.card') || container;
        if (document.fullscreenElement) {
            document.exitFullscreen();
        } else {
            card.requestFullscreen().then(function() {
                // Resize cytoscape to fill the fullscreen container
                setTimeout(function() {
                    if (cy) { cy.resize(); cy.fit(undefined, 40); }
                    stopParticles(); startParticles();
                }, 200);
            }).catch(function() {});
        }
    }

    // Update button text and resize on fullscreen change
    document.addEventListener('fullscreenchange', function() {
        var btn = document.getElementById('btn-fullscreen');
        if (btn) btn.textContent = document.fullscreenElement ? 'Exit Fullscreen' : 'Fullscreen';
        setTimeout(function() {
            if (cy) { cy.resize(); cy.fit(undefined, 40); }
            stopParticles(); startParticles();
        }, 200);
    });

    function setCallbacks(connClickFn, vpnClickFn) { onConnClick = connClickFn; onVPNClick = vpnClickFn; }

    // ---- 1k. Live Status Updates ----
    function updateStatuses(connChanges, deviceChanges) {
        if (!cy) return;
        if (connChanges && connChanges.length > 0) {
            connChanges.forEach(function(ch) {
                // Try direct edge, then cross-site split edges (-src/-dst)
                var edge = cy.getElementById('conn-' + ch.id);
                if (!edge || edge.empty()) edge = cy.getElementById('conn-' + ch.id + '-src');

                // If still not found, it may be an overlay bundled inside a tunnel
                if (!edge || edge.empty()) {
                    cy.edges('[edgeType="tunnel-bundle"]').forEach(function(tunnelEdge) {
                        var children = tunnelEdge.data('childConns') || [];
                        children.forEach(function(child) {
                            if (child.id === ch.id) child.status = ch.status;
                        });
                    });
                    return;
                }

                // For cross-site split tunnels, also update the dst half
                var peerEdge = edge.data('tunnelPeerId') ? cy.getElementById(edge.data('tunnelPeerId')) : null;
                var oldStatus = edge.data('status');
                if (oldStatus === ch.status) return;
                if (ch.status === 'down') {
                    animateFlash(edge, '#f85149', function() {
                        edge.data('status', 'down');
                        if (peerEdge && !peerEdge.empty()) peerEdge.data('status', 'down');
                        particleEls = particleEls.filter(function(p) { return p.edge !== edge && p.edge !== peerEdge; });
                    });
                } else if (ch.status === 'up') {
                    animateFlash(edge, '#3fb950', function() {
                        edge.data('status', 'up');
                        if (peerEdge && !peerEdge.empty()) peerEdge.data('status', 'up');
                        addParticlePair(edge, TYPE_COLORS[edge.data('connType')] || '#8b949e');
                        if (peerEdge && !peerEdge.empty()) addParticlePair(peerEdge, TYPE_COLORS[edge.data('connType')] || '#8b949e');
                    });
                } else {
                    edge.data('status', ch.status);
                    if (peerEdge && !peerEdge.empty()) peerEdge.data('status', ch.status);
                }
                if (edge.data('connObj')) edge.data('connObj').status = ch.status;
            });
            applyFilters();
        }
        if (deviceChanges && deviceChanges.length > 0) {
            deviceChanges.forEach(function(ch) {
                var node = cy.getElementById('dev-' + ch.id);
                if (!node || node.empty()) return;
                node.data('status', ch.status);
            });
        }
    }

    // Update VPN badge counts on device nodes
    function updateVPNBadges(vpnMap) {
        if (!cy || !vpnMap) return;
        Object.keys(vpnMap).forEach(function(devId) {
            var node = cy.getElementById('dev-' + devId);
            if (!node || node.empty()) return;
            var info = vpnMap[devId];
            var d = node.data('deviceObj');
            if (!d) return;
            var vpnLabel = '';
            if (info && info.total > 0) {
                vpnLabel = '\nVPN ' + info.up + '/' + info.total;
            }
            var newLabel = (d.name.length > 18 ? d.name.slice(0, 17) + '\u2026' : d.name) + '\n' + d.ip_address + vpnLabel;
            node.data('label', newLabel);
            node.data('vpnInfo', info);
        });
    }

    function animateFlash(edge, color, onComplete) {
        var origColor = edge.style('line-color');
        var step = 0;
        function flash() {
            if (step >= 6 || !edge || edge.removed()) { if (onComplete) onComplete(); return; }
            edge.animate({ style: { 'line-color': step % 2 === 0 ? color : origColor, 'width': step % 2 === 0 ? 6 : 3, 'opacity': 1 } },
                { duration: 200, complete: function() { step++; flash(); } });
        }
        flash();
    }

    // ---- 1l. NOC sync: alert overlay, node focus, SPA nav ----

    // spaNavigate routes through the admin SPA click-interceptor by synthesizing a
    // hidden anchor click — a Cytoscape canvas tap is not an <a>, so it can't be
    // caught directly. Keeps navigation client-side (no full reload).
    function spaNavigate(href) {
        var a = document.createElement('a');
        a.href = href;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        setTimeout(function() { if (a.parentNode) a.parentNode.removeChild(a); }, 0);
    }

    // pulseNode animates a device node's border width in a loop while it carries an
    // open alert. Canvas nodes ignore CSS keyframes, so the pulse is a self-
    // terminating cy.animate recursion registered in pulsingNodes for teardown. It
    // stops (and drops the inline width so the stylesheet border takes over) as
    // soon as the alert clears, the node is removed, or the graph is destroyed.
    function pulseNode(node) {
        var id = node.id();
        if (pulsingNodes[id]) return;
        pulsingNodes[id] = true;
        (function loop(wide) {
            if (!cy || node.removed() || !node.data('alert')) {
                delete pulsingNodes[id];
                if (node && !node.removed()) { node.stop(); node.removeStyle('border-width'); }
                return;
            }
            node.animate({ style: { 'border-width': wide ? 6 : 2 } },
                { duration: 700, complete: function() { loop(!wide); } });
        })(true);
    }

    // applyAlertPulses starts a pulse for every device node currently flagged with
    // an alert (called after layout and after each severity update).
    function applyAlertPulses() {
        if (!cy) return;
        cy.nodes('node[nodeType="device"]').forEach(function(n) {
            if (n.data('alert')) pulseNode(n);
        });
    }

    // applyAlertSeverities updates the per-device open-alert overlay from the
    // status-summary poll (deviceId -> "info"|"warning"|"critical"|""). "info" is
    // treated as no visual overlay (matches the NOC ramp). Starts/stops pulses so
    // an alert clearing removes the colour within one poll — even when the device's
    // online/offline status did NOT change.
    function applyAlertSeverities(sevByDevice) {
        nodeAlerts = {};
        Object.keys(sevByDevice || {}).forEach(function(k) {
            var sev = sevByDevice[k];
            if (sev === 'warning' || sev === 'critical') nodeAlerts[k] = sev;
        });
        if (!cy) return;
        cy.nodes('node[nodeType="device"]').forEach(function(n) {
            var sev = nodeAlerts[n.data('deviceId')] || '';
            if (n.data('alert') !== sev) n.data('alert', sev);
        });
        applyAlertPulses();
    }

    // resolveFocusTarget maps a NOC focus token to a Cytoscape collection.
    //   device:<id>       -> the device node
    //   site:<id>         -> the site compound (all its devices)
    //   site:unassigned   -> every device node with no site parent
    function resolveFocusTarget(kind, id) {
        if (!cy) return null;
        if (kind === 'device') {
            var n = cy.getElementById('dev-' + id);
            return (n && !n.empty()) ? n : null;
        }
        if (kind === 'site') {
            if (String(id) === 'unassigned') {
                var orphans = cy.nodes('node[nodeType="device"]').filter(function(el) {
                    return el.isOrphan();
                });
                return orphans.length ? orphans : null;
            }
            var s = cy.getElementById('site-' + id);
            return (s && !s.empty()) ? s : null;
        }
        return null;
    }

    // focusNode highlights a site/device on the map: dim everything else, ring the
    // target(s), and pan/zoom to them. Queues until layout completes if called
    // before the graph is ready (deep-link race). Reused by the NOC "focus on map".
    function focusNode(kind, id) {
        if (!cy) { pendingFocus = { kind: kind, id: id }; return; }
        var target = resolveFocusTarget(kind, id);
        if (!target || target.length === 0) { pendingFocus = { kind: kind, id: id }; return; }
        cy.elements().removeClass('focused');
        cy.elements().addClass('dimmed');
        var focusSet = target;
        // Include a device's parent site + directly connected edges for context.
        target.forEach(function(el) {
            focusSet = focusSet.union(el.connectedEdges ? el.connectedEdges() : cy.collection());
            if (el.parent && el.parent().nonempty && el.parent().nonempty()) focusSet = focusSet.union(el.parent());
        });
        focusSet.removeClass('dimmed');
        target.addClass('focused');
        try {
            cy.animate({ fit: { eles: target.union(target.parent ? target.parent() : cy.collection()), padding: 90 } },
                { duration: 400 });
        } catch (e) { /* fit best-effort */ }
    }

    // clearFocus removes the dim/highlight applied by focusNode.
    function clearFocus() {
        if (!cy) return;
        cy.elements().removeClass('dimmed').removeClass('focused');
    }

    // ---- Toolbar event delegation ----
    document.addEventListener('click', function(e) {
        var el = e.target.closest('[data-action]');
        if (!el) return;
        var action = el.dataset.action;
        if (action === 'dg-filter-type') toggleType(el.dataset.type);
        else if (action === 'dg-toggle-down') toggleDown();
        else if (action === 'dg-fit') fitGraph();
        else if (action === 'dg-reset-layout') resetLayout();
        else if (action === 'dg-fullscreen') toggleFullscreen();
        else if (action === 'dg-clear-focus') clearFocus();
    });

    window.addEventListener('fwmon:themechange', function() {
        if (cy) {
            cy.style(buildStylesheet()).update();
        }
    });

    // ---- Public API ----
    window.FWDiagram = {
        init: init, render: render, cleanup: cleanup,
        setCallbacks: setCallbacks, updateStatuses: updateStatuses, updateVPNBadges: updateVPNBadges,
        applyAlertSeverities: applyAlertSeverities, focusNode: focusNode, clearFocus: clearFocus,
        Layout: { resetLayout: resetLayout },
        Particles: { start: startParticles, stop: stopParticles }
    };
})();
