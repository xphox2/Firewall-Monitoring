// diagram-core.js — FWDiagram namespace: SVG setup, viewBox zoom/pan, coordinate helpers
(function() {
    'use strict';

    const NS = 'http://www.w3.org/2000/svg';
    let svg = null;
    let container = null;
    let W = 800, H = 500;
    let zoom = 1;
    const ZOOM_MIN = 0.3, ZOOM_MAX = 3;
    let panX = 0, panY = 0;
    let isPanning = false;
    let panStart = { x: 0, y: 0, px: 0, py: 0 };

    function init(containerId) {
        container = document.getElementById(containerId);
        if (!container) return null;

        const rect = container.getBoundingClientRect();
        W = rect.width || 800;
        H = Math.max(rect.height, 500);

        container.innerHTML = '';
        container.style.touchAction = 'none';

        svg = document.createElementNS(NS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', H);
        svg.style.minHeight = '500px';

        const defs = document.createElementNS(NS, 'defs');
        defs.innerHTML = `
            <filter id="conn-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="4" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
        `;
        svg.appendChild(defs);

        // Zoom controls overlay
        const controls = document.createElement('div');
        controls.style.cssText = 'position:absolute;top:8px;right:8px;display:flex;flex-direction:column;gap:4px;z-index:10;';
        controls.innerHTML = `
            <button class="btn secondary sm" data-action="dg-zoom-in" title="Zoom In" style="width:28px;height:28px;padding:0;font-size:1rem;line-height:1;">+</button>
            <button class="btn secondary sm" data-action="dg-zoom-out" title="Zoom Out" style="width:28px;height:28px;padding:0;font-size:1rem;line-height:1;">&minus;</button>
            <button class="btn secondary sm" data-action="dg-reset-zoom" title="Reset Zoom" style="width:28px;height:28px;padding:0;font-size:0.65rem;line-height:1;">1:1</button>
            <button class="btn secondary sm" data-action="dg-reset-layout" title="Reset Layout" style="width:28px;height:28px;padding:0;font-size:0.65rem;line-height:1;">&#8634;</button>
        `;
        container.appendChild(controls);

        // Delegate zoom/layout button clicks
        controls.addEventListener('click', function(e) {
            var el = e.target.closest('[data-action]');
            if (!el) return;
            var action = el.dataset.action;
            if (action === 'dg-zoom-in') zoomIn();
            else if (action === 'dg-zoom-out') zoomOut();
            else if (action === 'dg-reset-zoom') resetZoom();
            else if (action === 'dg-reset-layout' && FWDiagram.Layout) FWDiagram.Layout.resetLayout();
        });

        // Wire events
        svg.addEventListener('wheel', handleWheel, { passive: false });
        svg.addEventListener('mousedown', handlePanStart);
        window.addEventListener('mousemove', handlePanMove);
        window.addEventListener('mouseup', handlePanEnd);

        zoom = 1;
        panX = 0;
        panY = 0;

        container.appendChild(svg);
        return svg;
    }

    function handleWheel(e) {
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        const newZoom = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, zoom * delta));
        if (newZoom === zoom) return;

        // Zoom toward cursor
        const pt = svgPoint(e.clientX, e.clientY);
        panX = pt.x - (pt.x - panX) * (zoom / newZoom);
        panY = pt.y - (pt.y - panY) * (zoom / newZoom);
        zoom = newZoom;
        updateViewBox();
    }

    function handlePanStart(e) {
        if (!e.ctrlKey && !e.metaKey && e.button !== 1) return;
        e.preventDefault();
        isPanning = true;
        const pt = svgPoint(e.clientX, e.clientY);
        panStart = { x: e.clientX, y: e.clientY, px: panX, py: panY };
        svg.style.cursor = 'grabbing';
    }

    function handlePanMove(e) {
        if (!isPanning) return;
        const vbW = W / zoom;
        const dx = (e.clientX - panStart.x) * (vbW / svg.getBoundingClientRect().width);
        const dy = (e.clientY - panStart.y) * (vbW / svg.getBoundingClientRect().width);
        panX = panStart.px - dx;
        panY = panStart.py - dy;
        updateViewBox();
    }

    function handlePanEnd() {
        if (!isPanning) return;
        isPanning = false;
        if (svg) svg.style.cursor = '';
    }

    function svgPoint(clientX, clientY) {
        if (!svg) return { x: 0, y: 0 };
        const pt = svg.createSVGPoint();
        pt.x = clientX;
        pt.y = clientY;
        const ctm = svg.getScreenCTM();
        if (!ctm) return { x: clientX, y: clientY };
        const inv = ctm.inverse();
        const svgPt = pt.matrixTransform(inv);
        return { x: svgPt.x, y: svgPt.y };
    }

    function updateViewBox() {
        if (!svg) return;
        const vbW = W / zoom;
        const vbH = H / zoom;
        svg.setAttribute('viewBox', `${panX} ${panY} ${vbW} ${vbH}`);
    }

    function zoomIn() {
        zoom = Math.min(ZOOM_MAX, zoom * 1.25);
        updateViewBox();
    }

    function zoomOut() {
        zoom = Math.max(ZOOM_MIN, zoom * 0.8);
        updateViewBox();
    }

    function resetZoom() {
        zoom = 1;
        panX = 0;
        panY = 0;
        updateViewBox();
    }

    function createEl(tag) {
        return document.createElementNS(NS, tag);
    }

    function getSVG() { return svg; }
    function getDimensions() { return { W, H, cx: W / 2, cy: H / 2, R: Math.min(W / 2, H / 2) - 90 }; }
    function getContainer() { return container; }

    function cleanup() {
        if (svg) {
            svg.removeEventListener('wheel', handleWheel);
            svg.removeEventListener('mousedown', handlePanStart);
        }
        window.removeEventListener('mousemove', handlePanMove);
        window.removeEventListener('mouseup', handlePanEnd);
    }

    window.FWDiagram = {
        NS,
        init,
        zoomIn,
        zoomOut,
        resetZoom,
        createEl,
        getSVG,
        getDimensions,
        getContainer,
        svgPoint,
        cleanup
    };
})();
