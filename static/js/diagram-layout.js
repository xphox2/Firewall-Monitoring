// diagram-layout.js — FWDiagram.Layout: Circular positions, drag-and-drop, device/cloud node rendering
(function() {
    'use strict';

    const STORAGE_KEY = 'fwmon-diagram-positions';
    const NODE_W = 150, NODE_H = 64;
    let positions = [];
    let dragTarget = null;
    let dragStartPos = null;
    let dragMoved = false;
    let dragOffset = { x: 0, y: 0 };

    function computePositions(devices) {
        const dim = FWDiagram.getDimensions();
        const saved = loadPositions();
        positions = devices.map((d, i) => {
            const a = (2 * Math.PI * i) / devices.length - Math.PI / 2;
            const defaultX = dim.cx + dim.R * Math.cos(a);
            const defaultY = dim.cy + dim.R * Math.sin(a);
            const key = String(d.id);
            return {
                x: saved[key]?.x ?? defaultX,
                y: saved[key]?.y ?? defaultY,
                defaultX,
                defaultY,
                device: d
            };
        });
        return positions;
    }

    function getPositions() { return positions; }

    function drawDeviceNode(p, vpnInfo, onBadgeClick) {
        const svg = FWDiagram.getSVG();
        const g = FWDiagram.createEl('g');
        g.setAttribute('class', 'device-node');
        g.setAttribute('transform', `translate(${p.x - NODE_W/2}, ${p.y - NODE_H/2})`);
        g.dataset.deviceId = p.device.id;

        const r = FWDiagram.createEl('rect');
        r.setAttribute('width', NODE_W);
        r.setAttribute('height', NODE_H);
        r.setAttribute('rx', '8');
        r.setAttribute('fill', '#161b22');
        r.setAttribute('stroke', p.device.status === 'online' ? '#3fb950' : (p.device.status === 'offline' ? '#f85149' : '#30363d'));
        r.setAttribute('stroke-width', '2');
        g.appendChild(r);

        const name = FWDiagram.createEl('text');
        name.setAttribute('x', NODE_W/2);
        name.setAttribute('y', 22);
        name.setAttribute('text-anchor', 'middle');
        name.setAttribute('class', 'dev-name');
        name.textContent = p.device.name.length > 16 ? p.device.name.slice(0,15) + '\u2026' : p.device.name;
        g.appendChild(name);

        const ip = FWDiagram.createEl('text');
        ip.setAttribute('x', NODE_W/2);
        ip.setAttribute('y', 38);
        ip.setAttribute('text-anchor', 'middle');
        ip.setAttribute('class', 'dev-ip');
        ip.textContent = p.device.ip_address;
        g.appendChild(ip);

        const dot = FWDiagram.createEl('circle');
        dot.setAttribute('cx', NODE_W - 12);
        dot.setAttribute('cy', 12);
        dot.setAttribute('r', '5');
        dot.setAttribute('fill', p.device.status === 'online' ? '#3fb950' : (p.device.status === 'offline' ? '#f85149' : '#484f58'));
        g.appendChild(dot);

        // VPN badge
        if (vpnInfo && vpnInfo.total > 0) {
            const badgeColor = vpnInfo.down === 0 ? '#3fb950' : (vpnInfo.up === 0 ? '#f85149' : '#d29922');
            const badgeText = `VPN ${vpnInfo.up}/${vpnInfo.total}`;
            const badgeW = 62, badgeH = 14;
            const bx = 6, by = NODE_H - badgeH - 4;

            const bg = FWDiagram.createEl('rect');
            bg.setAttribute('x', bx);
            bg.setAttribute('y', by);
            bg.setAttribute('width', badgeW);
            bg.setAttribute('height', badgeH);
            bg.setAttribute('rx', '7');
            bg.setAttribute('fill', badgeColor + '22');
            bg.setAttribute('stroke', badgeColor);
            bg.setAttribute('stroke-width', '0.8');
            bg.style.cursor = 'pointer';
            g.appendChild(bg);

            const txt = FWDiagram.createEl('text');
            txt.setAttribute('x', bx + badgeW/2);
            txt.setAttribute('y', by + badgeH/2 + 3.5);
            txt.setAttribute('text-anchor', 'middle');
            txt.setAttribute('fill', badgeColor);
            txt.setAttribute('font-size', '9');
            txt.setAttribute('font-weight', '600');
            txt.textContent = badgeText;
            txt.style.cursor = 'pointer';
            g.appendChild(txt);

            const hitRect = FWDiagram.createEl('rect');
            hitRect.setAttribute('x', bx);
            hitRect.setAttribute('y', by);
            hitRect.setAttribute('width', badgeW);
            hitRect.setAttribute('height', badgeH);
            hitRect.setAttribute('fill', 'transparent');
            hitRect.style.cursor = 'pointer';
            hitRect.addEventListener('click', (e) => { e.stopPropagation(); if (onBadgeClick) onBadgeClick(p.device.id); });
            g.appendChild(hitRect);
        }

        // Drag and click handling
        g.addEventListener('mousedown', (e) => startDrag(e, g, p));
        g.addEventListener('touchstart', (e) => startDrag(e.touches[0], g, p), { passive: false });

        svg.appendChild(g);
        return g;
    }

    function drawCloudNode(cx, cy, linkCount) {
        const svg = FWDiagram.getSVG();
        const cloudW = Math.min(130, 100 + linkCount * 3), cloudH = 40;
        const g = FWDiagram.createEl('g');
        g.setAttribute('transform', `translate(${cx - cloudW/2}, ${cy - cloudH/2})`);
        g.setAttribute('class', 'cloud-node');
        g.style.cursor = 'pointer';

        const r = FWDiagram.createEl('rect');
        r.setAttribute('width', cloudW);
        r.setAttribute('height', cloudH);
        r.setAttribute('rx', '20');
        r.setAttribute('fill', '#0d1117');
        r.setAttribute('stroke', '#30363d');
        r.setAttribute('stroke-width', '1.5');
        r.setAttribute('stroke-dasharray', '4,3');
        g.appendChild(r);

        const icon = FWDiagram.createEl('text');
        icon.setAttribute('x', cloudW/2);
        icon.setAttribute('y', 18);
        icon.setAttribute('text-anchor', 'middle');
        icon.setAttribute('fill', '#8b949e');
        icon.setAttribute('font-size', '14');
        icon.textContent = '\u2601';
        g.appendChild(icon);

        const label = FWDiagram.createEl('text');
        label.setAttribute('x', cloudW/2);
        label.setAttribute('y', 33);
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('fill', '#8b949e');
        label.setAttribute('font-size', '10');
        label.setAttribute('font-weight', '500');
        label.textContent = 'Internet';
        g.appendChild(label);

        svg.appendChild(g);
        return g;
    }

    function startDrag(e, g, p) {
        if (e.ctrlKey || e.metaKey) return; // let pan handle it
        e.preventDefault();
        e.stopPropagation();
        dragTarget = { g, p };
        dragStartPos = { x: e.clientX, y: e.clientY };
        dragMoved = false;
        const pt = FWDiagram.svgPoint(e.clientX, e.clientY);
        dragOffset = { x: pt.x - p.x, y: pt.y - p.y };

        window.addEventListener('mousemove', onDrag);
        window.addEventListener('mouseup', endDrag);
        window.addEventListener('touchmove', onDragTouch, { passive: false });
        window.addEventListener('touchend', endDrag);
    }

    function onDragTouch(e) {
        e.preventDefault();
        onDrag(e.touches[0]);
    }

    function onDrag(e) {
        if (!dragTarget) return;
        const dist = Math.sqrt((e.clientX - dragStartPos.x)**2 + (e.clientY - dragStartPos.y)**2);
        if (dist > 5) dragMoved = true;
        if (!dragMoved) return;

        const pt = FWDiagram.svgPoint(e.clientX, e.clientY);
        dragTarget.p.x = pt.x - dragOffset.x;
        dragTarget.p.y = pt.y - dragOffset.y;
        dragTarget.g.setAttribute('transform', `translate(${dragTarget.p.x - NODE_W/2}, ${dragTarget.p.y - NODE_H/2})`);
        FWDiagram.Connections.redrawPaths();
    }

    function endDrag(e) {
        window.removeEventListener('mousemove', onDrag);
        window.removeEventListener('mouseup', endDrag);
        window.removeEventListener('touchmove', onDragTouch);
        window.removeEventListener('touchend', endDrag);

        if (dragTarget) {
            if (dragMoved) {
                savePositions();
            } else {
                // It was a click, not a drag — navigate
                window.location.href = `/admin/devices/${dragTarget.p.device.id}`;
            }
        }
        dragTarget = null;
    }

    function savePositions() {
        const data = {};
        positions.forEach(p => {
            data[String(p.device.id)] = { x: Math.round(p.x), y: Math.round(p.y) };
        });
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch(e) {}
    }

    function loadPositions() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : {};
        } catch(e) { return {}; }
    }

    function resetLayout() {
        try { localStorage.removeItem(STORAGE_KEY); } catch(e) {}
        // Trigger a full re-render via the wrapper
        if (window.drawConnectionDiagram) window.drawConnectionDiagram();
    }

    FWDiagram.Layout = {
        computePositions,
        getPositions,
        drawDeviceNode,
        drawCloudNode,
        resetLayout,
        savePositions,
        NODE_W,
        NODE_H
    };
})();
