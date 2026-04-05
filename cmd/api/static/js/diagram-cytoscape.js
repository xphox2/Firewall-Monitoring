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

    // Connection type classification
    var TUNNEL_TYPES = { ipsec: true, ssl: true, gre: true, tunnel: true };
    var OVERLAY_TYPES = { l3ipvlan: true, vxlan: true };
    var DIRECT_TYPES = { ethernet: true, lag: true, l2vlan: true, bridge: true };

    var TYPE_COLORS = {
        ipsec: '#58a6ff', ssl: '#d29922', gre: '#b392f0', tunnel: '#8b949e',
        vxlan: '#8957e5', l2vlan: '#39d4e0', l3ipvlan: '#da7de8', bridge: '#39d4e0',
        wan: '#f0883e', lag: '#d29922', ethernet: '#6e7681', offnet: '#3fb950'
    };

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
                status: d.status || 'unknown', deviceObj: d, vpnInfo: vpnInfo || null
            };
            if (sid) nodeData.parent = 'site-' + sid;
            elements.push({ group: 'nodes', data: nodeData });
        });

        // Off-net cloud
        var hasCloud = false;
        var offnetDevices = [];
        devices.forEach(function(d) {
            var vpnInfo = vpnMap[String(d.id)];
            if (!vpnInfo) return;
            var offnet = vpnInfo.tunnels.filter(function(t) { return t.matched_device_id === 0; });
            if (offnet.length > 0) {
                offnetDevices.push({ deviceId: d.id, anyUp: offnet.some(function(t) { return t.status === 'up'; }) });
                hasCloud = true;
            }
        });
        if (hasCloud) {
            elements.push({ group: 'nodes', data: { id: 'cloud-internet', label: '\u2601 Internet', nodeType: 'cloud' }});
            offnetDevices.forEach(function(info) {
                elements.push({ group: 'edges', data: {
                    id: 'offnet-' + info.deviceId, source: 'dev-' + info.deviceId, target: 'cloud-internet',
                    edgeType: 'offnet', status: info.anyUp ? 'up' : 'down', deviceId: info.deviceId, connType: 'offnet'
                }});
            });
        }

        // Group connections by device pair
        var pairKey = function(a, b) { return Math.min(a, b) + ':' + Math.max(a, b); };
        var pairs = {}; // pairKey -> { tunnels: [], overlays: [], directs: [] }

        connections.forEach(function(c) {
            var srcExists = devices.some(function(d) { return d.id === c.source_device_id; });
            var dstExists = devices.some(function(d) { return d.id === c.dest_device_id; });
            if (!srcExists || !dstExists) return;

            var key = pairKey(c.source_device_id, c.dest_device_id);
            if (!pairs[key]) pairs[key] = { tunnels: [], overlays: [], directs: [] };

            if (TUNNEL_TYPES[c.connection_type]) {
                pairs[key].tunnels.push(c);
            } else if (OVERLAY_TYPES[c.connection_type]) {
                pairs[key].overlays.push(c);
            } else {
                pairs[key].directs.push(c);
            }
        });

        // Create edges per pair
        Object.keys(pairs).forEach(function(key) {
            var p = pairs[key];

            // Tunnel carriers — assign overlays to first tunnel only (avoid duplication)
            var overlaysAssigned = false;
            p.tunnels.forEach(function(tunnel) {
                var childConns = (!overlaysAssigned && p.overlays.length > 0) ? p.overlays.slice() : [];
                if (childConns.length > 0) overlaysAssigned = true;
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
                    label: tunnel.connection_type.toUpperCase() + (childConns.length > 0 ? ' +' + childConns.length : '')
                }});
            });

            // Orphan overlays (no tunnel carrier found) — show with warning
            if (p.tunnels.length === 0 && p.overlays.length > 0) {
                p.overlays.forEach(function(c) {
                    elements.push({ group: 'edges', data: {
                        id: 'conn-' + c.id,
                        source: 'dev-' + c.source_device_id, target: 'dev-' + c.dest_device_id,
                        edgeType: 'connection', connType: c.connection_type,
                        status: c.status || 'unknown', connObj: c,
                        label: c.connection_type.toUpperCase() + ' (no tunnel)'
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
                    label: c.connection_type.toUpperCase()
                }});
            });
        });

        return elements;
    }

    // ---- 1b. Stylesheet ----
    function buildStylesheet() {
        return [
            // Site compound nodes
            { selector: 'node[nodeType="site"]', style: {
                'background-opacity': 0, 'border-width': 1.5, 'border-style': 'dashed',
                'border-color': '#30363d', 'border-opacity': 0.7, 'label': 'data(label)',
                'text-valign': 'top', 'text-halign': 'center', 'font-size': '12px',
                'color': '#8b949e', 'font-weight': '500', 'text-margin-y': -8,
                'padding': '30px', 'shape': 'roundrectangle', 'corner-radius': 12,
                'min-width': '180px', 'min-height': '80px'
            }},
            // Device nodes
            { selector: 'node[nodeType="device"]', style: {
                'width': 150, 'height': 64, 'shape': 'roundrectangle', 'background-color': '#161b22',
                'border-width': 2, 'border-color': '#30363d', 'label': 'data(label)',
                'text-valign': 'center', 'text-halign': 'center', 'font-size': '11px',
                'color': '#e6edf3', 'text-wrap': 'wrap', 'text-max-width': '140px', 'corner-radius': 8
            }},
            { selector: 'node[nodeType="device"][status="online"]', style: { 'border-color': '#3fb950' } },
            { selector: 'node[nodeType="device"][status="offline"]', style: { 'border-color': '#f85149' } },
            // Cloud node
            { selector: 'node[nodeType="cloud"]', style: {
                'width': 120, 'height': 40, 'shape': 'roundrectangle', 'background-color': '#0d1117',
                'border-width': 1.5, 'border-style': 'dashed', 'border-color': '#30363d',
                'label': 'data(label)', 'text-valign': 'center', 'text-halign': 'center',
                'font-size': '11px', 'color': '#8b949e', 'corner-radius': 20
            }},
            // Default edge
            { selector: 'edge', style: {
                'curve-style': 'bezier', 'control-point-step-size': 30,
                'width': 3, 'line-color': '#8b949e', 'target-arrow-shape': 'none', 'opacity': 1
            }},
            // Tunnel bundle edges — thicker pipe
            { selector: 'edge[edgeType="tunnel-bundle"]', style: { 'width': 4, 'label': 'data(label)', 'font-size': '9px', 'color': '#484f58', 'text-rotation': 'autorotate', 'text-margin-y': -10 } },
            // Connection type colors
            { selector: 'edge[connType="ipsec"]', style: { 'line-color': '#58a6ff' } },
            { selector: 'edge[connType="ssl"]', style: { 'line-color': '#d29922' } },
            { selector: 'edge[connType="vxlan"]', style: { 'line-color': '#8957e5', 'line-style': 'dashed', 'line-dash-pattern': [8, 4] } },
            { selector: 'edge[connType="l2vlan"]', style: { 'line-color': '#39d4e0' } },
            { selector: 'edge[connType="l3ipvlan"]', style: { 'line-color': '#da7de8', 'line-style': 'dashed', 'line-dash-pattern': [12, 4] } },
            { selector: 'edge[connType="gre"]', style: { 'line-color': '#b392f0' } },
            { selector: 'edge[connType="wan"]', style: { 'line-color': '#f0883e' } },
            { selector: 'edge[connType="lag"]', style: { 'line-color': '#d29922', 'width': 4 } },
            { selector: 'edge[connType="ethernet"]', style: { 'line-color': '#6e7681', 'width': 2 } },
            { selector: 'edge[connType="tunnel"]', style: { 'line-color': '#8b949e' } },
            // Sub-lane edges (expansion)
            { selector: 'edge[edgeType="sublane"]', style: { 'width': 2, 'curve-style': 'unbundled-bezier', 'label': 'data(label)', 'font-size': '8px', 'color': '#8b949e', 'text-rotation': 'autorotate', 'text-margin-y': -8 } },
            // Pipe background (expansion)
            { selector: 'edge[edgeType="pipe-bg"]', style: { 'width': 12, 'opacity': 0.15, 'line-color': '#58a6ff', 'curve-style': 'bezier' } },
            // Off-net edges
            { selector: 'edge[edgeType="offnet"]', style: { 'line-color': '#3fb950', 'width': 2, 'line-style': 'dashed', 'line-dash-pattern': [2, 4, 8, 4] } },
            // DOWN edges — red X
            { selector: 'edge[status="down"]', style: {
                'line-style': 'dashed', 'line-dash-pattern': [6, 4], 'opacity': 0.6,
                'label': '\u2716', 'text-rotation': 'autorotate', 'font-size': '18px',
                'color': '#f85149', 'text-background-color': '#0d1117',
                'text-background-opacity': 0.9, 'text-background-padding': '4px',
                'text-background-shape': 'roundrectangle', 'text-border-color': '#f85149',
                'text-border-width': 1.5, 'text-border-opacity': 0.8,
                'text-halign': 'center', 'text-valign': 'center'
            }},
            // Selected states
            { selector: 'node:selected', style: { 'border-color': '#58a6ff', 'border-width': 3 } },
            { selector: 'edge:selected', style: { 'width': 5, 'opacity': 1 } }
        ];
    }

    // ---- 1c. Layout ----
    function buildLayoutOptions(elements, siteMap) {
        var saved = loadPositions();
        var hasSaved = saved && Object.keys(saved).length > 0;
        if (hasSaved) {
            return { name: 'preset', positions: function(node) {
                var key = node.id().replace('dev-', '');
                if (saved[key]) return { x: saved[key].x, y: saved[key].y };
                return undefined;
            }, fit: false };
        }
        var useFcose = false;
        try {
            var testDiv = document.createElement('div');
            testDiv.style.cssText = 'width:1px;height:1px;position:absolute;left:-9999px;';
            document.body.appendChild(testDiv);
            var testCy = cytoscape({ container: testDiv, elements: [{ data: { id: 'test' } }] });
            try { testCy.layout({ name: 'fcose' }); useFcose = true; } catch (e2) {}
            testCy.destroy(); document.body.removeChild(testDiv);
        } catch (e) {}

        var opts = {
            name: useFcose ? 'fcose' : 'cose', animate: true, animationDuration: 500,
            fit: true, padding: 40, nodeDimensionsIncludeLabels: true,
            idealEdgeLength: function(edge) {
                var src = edge.source(), tgt = edge.target();
                if (src.data('parent') && src.data('parent') === tgt.data('parent')) return 100;
                return 200;
            }, nodeRepulsion: function() { return 8000; }, gravity: 0.3
        };
        if (useFcose) { opts.edgeElasticity = function() { return 0.1; }; opts.gravityRange = 2.0; opts.quality = 'default'; }
        return opts;
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
            minZoom: 0.3, maxZoom: 3, wheelSensitivity: 1, boxSelectionEnabled: false });

        applyFilters();
        wireEvents(devices, vpnMap);
        cy.one('layoutstop', function() { startParticles(); });
        setTimeout(function() { startParticles(); }, 600);
    }

    function cleanup() {
        stopParticles();
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
            if (data.edgeType === 'tunnel-bundle' && data.childConns && data.childConns.length > 0) {
                if (expandedTunnels[data.id]) {
                    collapseTunnel(data.id);
                } else {
                    expandTunnel(edge);
                }
                return;
            }

            // Regular connection or sublane: show detail panel
            if ((data.edgeType === 'connection' || data.edgeType === 'tunnel-bundle' || data.edgeType === 'sublane') && data.connObj && onConnClick) {
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
            window.location.href = '/admin/devices/' + data.deviceId;
        });

        cy.on('tap', 'node[nodeType="cloud"]', function() {
            var edges = cy.edges('[edgeType="offnet"]');
            if (edges.length === 1 && onVPNClick) onVPNClick(edges[0].data('deviceId'), true);
        });

        cy.on('dragfree', 'node[nodeType="device"]', savePositions);
        cy.on('dragfree', 'node[nodeType="site"]', savePositions);

        // Escape key collapses all expanded tunnels (store ref for cleanup)
        if (keydownHandler) document.removeEventListener('keydown', keydownHandler);
        keydownHandler = function(e) {
            if (e.key === 'Escape') Object.keys(expandedTunnels).forEach(collapseTunnel);
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

        // Hide the parent tunnel edge
        edge.style('display', 'none');

        // Add pipe background edge
        cy.add({ group: 'edges', data: {
            id: tunnelId + '-pipe', source: data.source, target: data.target,
            edgeType: 'pipe-bg', status: data.status, parentTunnel: tunnelId
        }});

        // Add carrier lane
        var offsets = [];
        var totalLanes = children.length + 1; // +1 for the carrier itself
        for (var i = 0; i < totalLanes; i++) {
            offsets.push(-15 + (30 / (totalLanes - 1 || 1)) * i);
        }

        // Carrier sublane (the tunnel itself)
        cy.add({ group: 'edges', data: {
            id: tunnelId + '-carrier', source: data.source, target: data.target,
            edgeType: 'sublane', connType: data.connType, status: data.status,
            connObj: data.connObj, parentTunnel: tunnelId,
            label: data.connType.toUpperCase()
        }});
        cy.getElementById(tunnelId + '-carrier').style({
            'control-point-distances': [offsets[0]],
            'control-point-weights': [0.5],
            'line-color': TYPE_COLORS[data.connType] || '#8b949e'
        });

        // Child overlay sublanes
        children.forEach(function(child, idx) {
            var laneId = tunnelId + '-lane-' + child.id;
            var color = TYPE_COLORS[child.connection_type] || '#8b949e';
            cy.add({ group: 'edges', data: {
                id: laneId, source: data.source, target: data.target,
                edgeType: 'sublane', connType: child.connection_type, status: child.status,
                connObj: child, parentTunnel: tunnelId,
                label: child.connection_type.toUpperCase()
            }});
            cy.getElementById(laneId).style({
                'control-point-distances': [offsets[idx + 1]],
                'control-point-weights': [0.5],
                'line-color': color
            });
        });

        // Restart particles to include new sublanes
        stopParticles();
        startParticles();
    }

    function collapseTunnel(tunnelId) {
        if (!cy) return;
        delete expandedTunnels[tunnelId];

        // Remove all sublane and pipe edges for this tunnel
        cy.edges('[parentTunnel="' + tunnelId + '"]').remove();

        // Show the parent tunnel edge again
        var parentEdge = cy.getElementById(tunnelId);
        if (parentEdge && !parentEdge.empty()) {
            parentEdge.style('display', 'element');
        }

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
            if ((data.edgeType === 'connection' || data.edgeType === 'tunnel-bundle') && hiddenTypes[data.connType]) hide = true;
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
            btn.classList.toggle('active', type === 'all' ? Object.keys(hiddenTypes).length === 0 : !hiddenTypes[type]);
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
                // Bundled: carrier particle + one dot per child overlay
                var carrierColor = TYPE_COLORS[data.connType] || '#8b949e';
                count += addParticlePair(edge, carrierColor);

                var children = data.childConns || [];
                children.forEach(function(child) {
                    if (particleEls.length >= MAX_PARTICLES) return;
                    var childColor = TYPE_COLORS[child.connection_type] || '#8b949e';
                    particleEls.push({ edge: edge, progress: Math.random(), speed: 0.00025 + Math.random() * 0.0001,
                        direction: 1, color: childColor, radius: 2.5, alpha: 0.9 });
                    count++;
                });
            } else if (data.edgeType === 'sublane') {
                var color = TYPE_COLORS[data.connType] || '#8b949e';
                count += addParticlePair(edge, color);
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

                var mx = src.x + (tgt.x - src.x) * p.progress;
                var my = src.y + (tgt.y - src.y) * p.progress;
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
        cy.nodes('[nodeType="device"]').forEach(function(node) {
            var pos = node.position();
            data[String(node.data('deviceId'))] = { x: Math.round(pos.x), y: Math.round(pos.y) };
        });
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
    }
    function loadPositions() { try { var raw = localStorage.getItem(STORAGE_KEY); return raw ? JSON.parse(raw) : {}; } catch (e) { return {}; } }
    function resetLayout() { try { localStorage.removeItem(STORAGE_KEY); } catch (e) {} if (window.drawConnectionDiagram) window.drawConnectionDiagram(); }
    function fitGraph() { if (cy) cy.fit(undefined, 40); }

    function setCallbacks(connClickFn, vpnClickFn) { onConnClick = connClickFn; onVPNClick = vpnClickFn; }

    // ---- 1k. Live Status Updates ----
    function updateStatuses(connChanges, deviceChanges) {
        if (!cy) return;
        if (connChanges && connChanges.length > 0) {
            connChanges.forEach(function(ch) {
                var edge = cy.getElementById('conn-' + ch.id);

                // If edge not found, it may be an overlay bundled inside a tunnel
                if (!edge || edge.empty()) {
                    cy.edges('[edgeType="tunnel-bundle"]').forEach(function(tunnelEdge) {
                        var children = tunnelEdge.data('childConns') || [];
                        children.forEach(function(child) {
                            if (child.id === ch.id) child.status = ch.status;
                        });
                    });
                    return;
                }
                var oldStatus = edge.data('status');
                if (oldStatus === ch.status) return;
                if (ch.status === 'down') {
                    animateFlash(edge, '#f85149', function() {
                        edge.data('status', 'down');
                        particleEls = particleEls.filter(function(p) { return p.edge !== edge; });
                    });
                } else if (ch.status === 'up') {
                    animateFlash(edge, '#3fb950', function() { edge.data('status', 'up'); addParticlePair(edge, TYPE_COLORS[edge.data('connType')] || '#8b949e'); });
                } else { edge.data('status', ch.status); }
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

    // ---- Toolbar event delegation ----
    document.addEventListener('click', function(e) {
        var el = e.target.closest('[data-action]');
        if (!el) return;
        var action = el.dataset.action;
        if (action === 'dg-filter-type') toggleType(el.dataset.type);
        else if (action === 'dg-toggle-down') toggleDown();
        else if (action === 'dg-fit') fitGraph();
        else if (action === 'dg-reset-layout') resetLayout();
    });

    // ---- Public API ----
    window.FWDiagram = {
        init: init, render: render, cleanup: cleanup,
        setCallbacks: setCallbacks, updateStatuses: updateStatuses,
        Layout: { resetLayout: resetLayout },
        Particles: { start: startParticles, stop: stopParticles }
    };
})();
