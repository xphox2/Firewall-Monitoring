// diagram-cytoscape.js — FWDiagram namespace: Cytoscape.js-based network diagram
(function() {
    'use strict';

    var NS = 'http://www.w3.org/2000/svg';
    var STORAGE_KEY = 'fwmon-diagram-positions';
    var MAX_PARTICLES = 50;

    var cy = null;
    var container = null;
    var svgOverlay = null;
    var onConnClick = null;
    var onVPNClick = null;
    var hiddenTypes = {};
    var showDown = false;
    var particleAnimId = null;
    var particleEls = [];

    // ---- 1a. Data Transformation ----
    function buildElements(devices, connections, siteMap, vpnMap, siteNames) {
        var elements = [];
        var siteIds = {};

        // Collect unique sites
        devices.forEach(function(d) {
            var sid = siteMap[d.id];
            if (sid && !siteIds[sid]) {
                siteIds[sid] = true;
                elements.push({
                    group: 'nodes',
                    data: {
                        id: 'site-' + sid,
                        label: (siteNames && siteNames[sid]) || ('Site ' + sid),
                        nodeType: 'site'
                    }
                });
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
                nodeType: 'device',
                deviceId: d.id,
                status: d.status || 'unknown',
                deviceObj: d,
                vpnInfo: vpnInfo || null
            };
            if (sid) nodeData.parent = 'site-' + sid;
            elements.push({ group: 'nodes', data: nodeData });
        });

        // Check for off-net tunnels -> internet cloud
        var hasCloud = false;
        var offnetDevices = [];
        devices.forEach(function(d) {
            var vpnInfo = vpnMap[String(d.id)];
            if (!vpnInfo) return;
            var offnet = vpnInfo.tunnels.filter(function(t) { return t.matched_device_id === 0; });
            if (offnet.length > 0) {
                var anyUp = offnet.some(function(t) { return t.status === 'up'; });
                offnetDevices.push({ deviceId: d.id, anyUp: anyUp });
                hasCloud = true;
            }
        });

        if (hasCloud) {
            elements.push({
                group: 'nodes',
                data: {
                    id: 'cloud-internet',
                    label: '\u2601 Internet',
                    nodeType: 'cloud'
                }
            });

            offnetDevices.forEach(function(info) {
                elements.push({
                    group: 'edges',
                    data: {
                        id: 'offnet-' + info.deviceId,
                        source: 'dev-' + info.deviceId,
                        target: 'cloud-internet',
                        edgeType: 'offnet',
                        status: info.anyUp ? 'up' : 'down',
                        deviceId: info.deviceId,
                        connType: 'offnet'
                    }
                });
            });
        }

        // Connection edges — include ALL (UP and DOWN)
        connections.forEach(function(c) {
            var srcExists = devices.some(function(d) { return d.id === c.source_device_id; });
            var dstExists = devices.some(function(d) { return d.id === c.dest_device_id; });
            if (!srcExists || !dstExists) return;

            elements.push({
                group: 'edges',
                data: {
                    id: 'conn-' + c.id,
                    source: 'dev-' + c.source_device_id,
                    target: 'dev-' + c.dest_device_id,
                    edgeType: 'connection',
                    connType: c.connection_type || 'tunnel',
                    status: c.status || 'unknown',
                    isIndirect: c.match_method === 'tunnel_indirect' || c.match_method === 'wan_inferred' || c.match_method === 'overlay_name',
                    connObj: c,
                    label: (c.connection_type || 'tunnel').toUpperCase()
                }
            });
        });

        return elements;
    }

    // ---- 1b. Stylesheet ----
    function buildStylesheet() {
        var styles = window.connStyle;
        return [
            // Site compound nodes
            {
                selector: 'node[nodeType="site"]',
                style: {
                    'background-opacity': 0,
                    'border-width': 1.5,
                    'border-style': 'dashed',
                    'border-color': '#30363d',
                    'border-opacity': 0.7,
                    'label': 'data(label)',
                    'text-valign': 'top',
                    'text-halign': 'center',
                    'font-size': '12px',
                    'color': '#8b949e',
                    'font-weight': '500',
                    'text-margin-y': -8,
                    'padding': '30px',
                    'shape': 'roundrectangle',
                    'corner-radius': 12,
                    'min-width': '180px',
                    'min-height': '80px'
                }
            },
            // Device nodes
            {
                selector: 'node[nodeType="device"]',
                style: {
                    'width': 150,
                    'height': 64,
                    'shape': 'roundrectangle',
                    'background-color': '#161b22',
                    'border-width': 2,
                    'border-color': '#30363d',
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '11px',
                    'color': '#e6edf3',
                    'text-wrap': 'wrap',
                    'text-max-width': '140px',
                    'corner-radius': 8
                }
            },
            {
                selector: 'node[nodeType="device"][status="online"]',
                style: { 'border-color': '#3fb950' }
            },
            {
                selector: 'node[nodeType="device"][status="offline"]',
                style: { 'border-color': '#f85149' }
            },
            // Cloud node
            {
                selector: 'node[nodeType="cloud"]',
                style: {
                    'width': 120,
                    'height': 40,
                    'shape': 'roundrectangle',
                    'background-color': '#0d1117',
                    'border-width': 1.5,
                    'border-style': 'dashed',
                    'border-color': '#30363d',
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '11px',
                    'color': '#8b949e',
                    'corner-radius': 20
                }
            },
            // Particle nodes
            {
                selector: 'node[nodeType="particle"]',
                style: {
                    'width': 6,
                    'height': 6,
                    'shape': 'ellipse',
                    'background-color': 'data(color)',
                    'background-opacity': 0.85,
                    'border-width': 0,
                    'label': '',
                    'events': 'no',
                    'overlay-opacity': 0
                }
            },
            // Default edge style
            {
                selector: 'edge',
                style: {
                    'curve-style': 'bezier',
                    'control-point-step-size': 30,
                    'width': 3,
                    'line-color': '#8b949e',
                    'target-arrow-shape': 'none',
                    'opacity': 1
                }
            },
            // Connection type edge styles
            { selector: 'edge[connType="ipsec"]', style: { 'line-color': '#58a6ff', 'width': 3 } },
            { selector: 'edge[connType="ssl"]', style: { 'line-color': '#d29922', 'width': 3 } },
            { selector: 'edge[connType="vxlan"]', style: { 'line-color': '#8957e5', 'width': 3, 'line-style': 'dashed', 'line-dash-pattern': [8, 4] } },
            { selector: 'edge[connType="l2vlan"]', style: { 'line-color': '#39d4e0', 'width': 3 } },
            { selector: 'edge[connType="l3ipvlan"]', style: { 'line-color': '#da7de8', 'width': 3, 'line-style': 'dashed', 'line-dash-pattern': [12, 4] } },
            { selector: 'edge[connType="gre"]', style: { 'line-color': '#b392f0', 'width': 3 } },
            { selector: 'edge[connType="wan"]', style: { 'line-color': '#f0883e', 'width': 3 } },
            { selector: 'edge[connType="lag"]', style: { 'line-color': '#d29922', 'width': 4 } },
            { selector: 'edge[connType="ethernet"]', style: { 'line-color': '#6e7681', 'width': 2 } },
            { selector: 'edge[connType="tunnel"]', style: { 'line-color': '#8b949e', 'width': 3 } },
            // Off-net edges
            {
                selector: 'edge[edgeType="offnet"]',
                style: {
                    'line-color': '#3fb950',
                    'width': 2,
                    'line-style': 'dashed',
                    'line-dash-pattern': [2, 4, 8, 4]
                }
            },
            // DOWN edges
            {
                selector: 'edge[status="down"]',
                style: {
                    'line-style': 'dashed',
                    'line-dash-pattern': [6, 4],
                    'opacity': 0.4
                }
            },
            // Indirect match edges
            {
                selector: 'edge[?isIndirect]',
                style: {
                    'line-color': '#f0883e',
                    'line-style': 'dashed',
                    'line-dash-pattern': [4, 6],
                    'width': 2
                }
            },
            // Selected states
            {
                selector: 'node:selected',
                style: { 'border-color': '#58a6ff', 'border-width': 3 }
            },
            {
                selector: 'edge:selected',
                style: { 'width': 5, 'opacity': 1 }
            }
        ];
    }

    // ---- 1c. Layout ----
    function buildLayoutOptions(elements, siteMap) {
        var saved = loadPositions();
        var hasSaved = saved && Object.keys(saved).length > 0;

        if (hasSaved) {
            return {
                name: 'preset',
                positions: function(node) {
                    var id = node.id();
                    var key = id.replace('dev-', '');
                    if (saved[key]) return { x: saved[key].x, y: saved[key].y };
                    return undefined;
                },
                fit: false
            };
        }

        // Check if fcose is available
        if (typeof cytoscape !== 'undefined' && cytoscape.layouts && cytoscape.layouts['fcose']) {
            // Use fcose if registered
        }

        // Try fcose, fall back to cose
        var layoutName = 'cose';
        try {
            if (typeof cytoscapeFcose !== 'undefined' || (typeof cytoscape !== 'undefined' && cytoscape('core', 'layout') && true)) {
                layoutName = 'fcose';
            }
        } catch (e) {}

        // Test if fcose is actually available by checking registration
        var useFcose = false;
        try {
            var testDiv = document.createElement('div');
            testDiv.style.cssText = 'width:1px;height:1px;position:absolute;left:-9999px;';
            document.body.appendChild(testDiv);
            var testCy = cytoscape({ container: testDiv, elements: [{ data: { id: 'test' } }] });
            try {
                testCy.layout({ name: 'fcose' });
                useFcose = true;
            } catch (e2) {}
            testCy.destroy();
            document.body.removeChild(testDiv);
        } catch (e) {}

        if (useFcose) {
            return {
                name: 'fcose',
                animate: true,
                animationDuration: 500,
                fit: true,
                padding: 40,
                nodeDimensionsIncludeLabels: true,
                idealEdgeLength: function(edge) {
                    // Shorter edges for same-site connections
                    var src = edge.source();
                    var tgt = edge.target();
                    if (src.data('parent') && src.data('parent') === tgt.data('parent')) {
                        return 100;
                    }
                    return 200;
                },
                nodeRepulsion: function() { return 8000; },
                edgeElasticity: function() { return 0.1; },
                gravity: 0.3,
                gravityRange: 2.0,
                quality: 'default'
            };
        }

        return {
            name: 'cose',
            animate: true,
            animationDuration: 500,
            fit: true,
            padding: 40,
            nodeDimensionsIncludeLabels: true,
            idealEdgeLength: function(edge) {
                var src = edge.source();
                var tgt = edge.target();
                if (src.data('parent') && src.data('parent') === tgt.data('parent')) {
                    return 100;
                }
                return 200;
            },
            nodeRepulsion: function() { return 8000; },
            gravity: 0.3
        };
    }

    // ---- 1d. Init & Render ----
    function init(containerId) {
        // Destroy previous instance
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

        // Create cytoscape canvas div
        var cyDiv = document.createElement('div');
        cyDiv.id = 'cy-canvas';
        cyDiv.style.cssText = 'width:100%;height:100%;min-height:500px;';
        container.appendChild(cyDiv);

        cy = cytoscape({
            container: cyDiv,
            elements: elements,
            style: stylesheet,
            layout: layoutOpts,
            minZoom: 0.3,
            maxZoom: 3,
            wheelSensitivity: 0.3,
            boxSelectionEnabled: false
        });

        // Apply filters
        applyFilters();

        // Wire events
        wireEvents(devices, vpnMap);

        // Start particles after layout settles
        cy.one('layoutstop', function() {
            startParticles();
        });
        // Also start after a timeout in case layoutstop doesn't fire (preset layout)
        setTimeout(function() { startParticles(); }, 600);
    }

    function cleanup() {
        stopParticles();
        if (svgOverlay && svgOverlay.parentNode) {
            svgOverlay.parentNode.removeChild(svgOverlay);
        }
        svgOverlay = null;
        if (cy) {
            cy.destroy();
            cy = null;
        }
    }

    // ---- 1e. Event Handling ----
    function wireEvents(devices, vpnMap) {
        if (!cy) return;

        // Edge tap
        cy.on('tap', 'edge', function(evt) {
            var edge = evt.target;
            var data = edge.data();
            if (data.edgeType === 'connection' && data.connObj && onConnClick) {
                onConnClick(data.connObj);
            } else if (data.edgeType === 'offnet' && data.deviceId && onVPNClick) {
                onVPNClick(data.deviceId, true);
            }
        });

        // Device node tap
        cy.on('tap', 'node[nodeType="device"]', function(evt) {
            var node = evt.target;
            var data = node.data();
            var deviceId = data.deviceId;

            // Check if click is on VPN badge area (bottom third)
            if (data.vpnInfo && data.vpnInfo.total > 0) {
                var pos = evt.position;
                var nodePos = node.position();
                var h = node.height();
                var relY = pos.y - (nodePos.y - h / 2);
                if (relY > h * 0.6 && onVPNClick) {
                    onVPNClick(deviceId, false);
                    return;
                }
            }

            // Navigate to device page
            window.location.href = '/admin/devices/' + deviceId;
        });

        // Cloud node tap
        cy.on('tap', 'node[nodeType="cloud"]', function(evt) {
            // Find connected off-net device
            var edges = cy.edges('[edgeType="offnet"]');
            if (edges.length === 1 && onVPNClick) {
                onVPNClick(edges[0].data('deviceId'), true);
            }
        });

        // Save positions on drag
        cy.on('dragfree', 'node[nodeType="device"]', function() {
            savePositions();
        });

        // Site compound drag - save all child positions
        cy.on('dragfree', 'node[nodeType="site"]', function() {
            savePositions();
        });
    }

    // ---- 1f. Layer Filtering & DOWN Toggle ----
    function applyFilters() {
        if (!cy) return;

        cy.edges().forEach(function(edge) {
            var data = edge.data();
            var hide = false;

            // Type filter
            if (data.edgeType === 'connection' && hiddenTypes[data.connType]) {
                hide = true;
            }

            // DOWN filter
            if (!showDown && data.status === 'down') {
                hide = true;
            }

            edge.style('display', hide ? 'none' : 'element');
        });
    }

    function toggleType(type) {
        if (type === 'all') {
            hiddenTypes = {};
        } else {
            if (hiddenTypes[type]) {
                delete hiddenTypes[type];
            } else {
                hiddenTypes[type] = true;
            }
        }
        applyFilters();
        updateToolbarButtons();
    }

    function toggleDown() {
        showDown = !showDown;
        applyFilters();
        var btn = document.getElementById('btn-toggle-down');
        if (btn) {
            btn.classList.toggle('active', showDown);
            btn.textContent = showDown ? 'Hide DOWN' : 'Show DOWN';
        }
    }

    function updateToolbarButtons() {
        var btns = document.querySelectorAll('[data-action="dg-filter-type"]');
        btns.forEach(function(btn) {
            var type = btn.dataset.type;
            if (type === 'all') {
                btn.classList.toggle('active', Object.keys(hiddenTypes).length === 0);
            } else {
                btn.classList.toggle('active', !hiddenTypes[type]);
            }
        });
    }

    // ---- 1g. Particle Animation ----
    function startParticles() {
        if (!cy || particleAnimId) return;

        particleEls = [];
        var visibleEdges = cy.edges().filter(function(e) {
            return e.style('display') !== 'none' && e.data('status') === 'up';
        });

        if (visibleEdges.length === 0) return;

        // Create particle overlay canvas
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

        // Create particles for visible UP edges
        var count = 0;
        visibleEdges.forEach(function(edge) {
            if (count >= MAX_PARTICLES) return;
            var data = edge.data();
            var cs = window.connStyle(data.connType);
            var color = data.isIndirect ? '#f0883e' : (data.edgeType === 'offnet' ? '#3fb950' : cs.color);

            // Forward particle
            particleEls.push({
                edge: edge,
                progress: Math.random(),
                speed: 0.0003 + Math.random() * 0.0002,
                direction: 1,
                color: color,
                radius: 3
            });
            count++;

            if (count < MAX_PARTICLES) {
                // Reverse particle
                particleEls.push({
                    edge: edge,
                    progress: Math.random(),
                    speed: 0.00025 + Math.random() * 0.00015,
                    direction: -1,
                    color: '#58a6ff',
                    radius: 2.5
                });
                count++;
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

            // Ensure canvas is right size
            var rect = canvasDiv.getBoundingClientRect();
            if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
                resizeCanvas();
            }

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

                // Get edge endpoints in model space
                var src = p.edge.sourceEndpoint();
                var tgt = p.edge.targetEndpoint();
                if (!src || !tgt) return;

                // Interpolate position in model space
                var mx = src.x + (tgt.x - src.x) * p.progress;
                var my = src.y + (tgt.y - src.y) * p.progress;

                // Convert to rendered space
                var rx = mx * zoom + pan.x;
                var ry = my * zoom + pan.y;

                ctx.beginPath();
                ctx.arc(rx, ry, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.globalAlpha = 0.85;
                ctx.fill();
            });

            ctx.restore();
            particleAnimId = requestAnimationFrame(animate);
        }

        particleAnimId = requestAnimationFrame(animate);
    }

    function stopParticles() {
        if (particleAnimId) {
            cancelAnimationFrame(particleAnimId);
            particleAnimId = null;
        }
        particleEls = [];
        var canvas = document.getElementById('particle-canvas');
        if (canvas && canvas.parentNode) canvas.parentNode.removeChild(canvas);
    }

    // ---- 1h. Position Persistence ----
    function savePositions() {
        if (!cy) return;
        var data = {};
        cy.nodes('[nodeType="device"]').forEach(function(node) {
            var pos = node.position();
            var key = String(node.data('deviceId'));
            data[key] = { x: Math.round(pos.x), y: Math.round(pos.y) };
        });
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
    }

    function loadPositions() {
        try {
            var raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : {};
        } catch (e) { return {}; }
    }

    function resetLayout() {
        try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
        if (window.drawConnectionDiagram) window.drawConnectionDiagram();
    }

    function fitGraph() {
        if (cy) cy.fit(undefined, 40);
    }

    // ---- 1i. Compatibility Shim for diagram-tunnel-zoom.js ----
    function getSVG() {
        if (svgOverlay) return svgOverlay;
        if (!container) return null;

        svgOverlay = document.createElementNS(NS, 'svg');
        var rect = container.getBoundingClientRect();
        var w = rect.width || 800;
        var h = Math.max(rect.height, 500);
        svgOverlay.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
        svgOverlay.setAttribute('width', '100%');
        svgOverlay.setAttribute('height', h);
        svgOverlay.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;z-index:20;pointer-events:auto;';
        container.appendChild(svgOverlay);
        return svgOverlay;
    }

    function getDimensions() {
        var rect = container ? container.getBoundingClientRect() : { width: 800, height: 500 };
        var w = rect.width || 800;
        var h = Math.max(rect.height, 500);
        return { W: w, H: h, cx: w / 2, cy: h / 2, R: Math.min(w / 2, h / 2) - 90 };
    }

    function createEl(tag) {
        return document.createElementNS(NS, tag);
    }

    function svgPoint(clientX, clientY) {
        if (!svgOverlay) return { x: clientX, y: clientY };
        var pt = svgOverlay.createSVGPoint();
        pt.x = clientX;
        pt.y = clientY;
        var ctm = svgOverlay.getScreenCTM();
        if (!ctm) return { x: clientX, y: clientY };
        var inv = ctm.inverse();
        var svgPt = pt.matrixTransform(inv);
        return { x: svgPt.x, y: svgPt.y };
    }

    function setCallbacks(connClickFn, vpnClickFn) {
        onConnClick = connClickFn;
        onVPNClick = vpnClickFn;
    }

    // ---- Toolbar event delegation ----
    document.addEventListener('click', function(e) {
        var el = e.target.closest('[data-action]');
        if (!el) return;
        var action = el.dataset.action;
        if (action === 'dg-filter-type') {
            toggleType(el.dataset.type);
        } else if (action === 'dg-toggle-down') {
            toggleDown();
        } else if (action === 'dg-fit') {
            fitGraph();
        } else if (action === 'dg-reset-layout') {
            resetLayout();
        }
    });

    // ---- Public API ----
    window.FWDiagram = {
        NS: NS,
        init: init,
        render: render,
        cleanup: cleanup,
        getSVG: getSVG,
        getDimensions: getDimensions,
        createEl: createEl,
        svgPoint: svgPoint,
        setCallbacks: setCallbacks,
        Layout: { resetLayout: resetLayout },
        Connections: { redrawPaths: function() {} },
        Particles: { start: startParticles, stop: stopParticles }
    };
    // diagram-panels.js assigns FWDiagram.Panels = {...}
    // diagram-tunnel-zoom.js assigns FWDiagram.TunnelZoom = {...}
})();
