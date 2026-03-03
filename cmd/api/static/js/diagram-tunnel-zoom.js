// diagram-tunnel-zoom.js — FWDiagram.TunnelZoom: SVG overlay for per-tunnel inspection
(function() {
    'use strict';

    let overlayGroup = null;
    let zoomChartInstances = {};

    function show(connId) {
        // Find connection from current data
        const conn = window.currentConnections?.find(c => c.id === connId);
        if (!conn) return;

        // Fetch detail data for tunnels
        window.apiFetch(`${window.API_BASE}/connections/${connId}/detail`).then(resp => {
            const data = resp && resp.data ? resp.data : resp;
            if (!data) return;
            renderOverlay(conn, data);
        }).catch(e => console.error('Tunnel zoom failed:', e));
    }

    function renderOverlay(conn, detail) {
        hide(); // Clear any existing overlay

        const svg = FWDiagram.getSVG();
        if (!svg) return;

        const dim = FWDiagram.getDimensions();
        overlayGroup = FWDiagram.createEl('g');
        overlayGroup.setAttribute('class', 'tunnel-zoom-overlay');

        // Dark backdrop
        const backdrop = FWDiagram.createEl('rect');
        backdrop.setAttribute('x', '0');
        backdrop.setAttribute('y', '0');
        backdrop.setAttribute('width', dim.W);
        backdrop.setAttribute('height', dim.H);
        backdrop.setAttribute('fill', 'rgba(0,0,0,0.75)');
        backdrop.style.cursor = 'pointer';
        backdrop.addEventListener('click', hide);
        overlayGroup.appendChild(backdrop);

        // Title
        const srcName = conn.source_device?.name || 'Source';
        const dstName = conn.dest_device?.name || 'Dest';
        const title = FWDiagram.createEl('text');
        title.setAttribute('x', dim.W / 2);
        title.setAttribute('y', 30);
        title.setAttribute('text-anchor', 'middle');
        title.setAttribute('fill', '#e6edf3');
        title.setAttribute('font-size', '14');
        title.setAttribute('font-weight', '600');
        title.textContent = `${srcName} \u2194 ${dstName} — Tunnel Detail`;
        overlayGroup.appendChild(title);

        // Close hint
        const hint = FWDiagram.createEl('text');
        hint.setAttribute('x', dim.W / 2);
        hint.setAttribute('y', 48);
        hint.setAttribute('text-anchor', 'middle');
        hint.setAttribute('fill', '#484f58');
        hint.setAttribute('font-size', '10');
        hint.textContent = 'Click backdrop to close';
        overlayGroup.appendChild(hint);

        // Source node on left
        const nodeW = 120, nodeH = 50;
        const leftX = 60, rightX = dim.W - 60 - nodeW;
        const nodesY = 70;

        drawZoomNode(overlayGroup, leftX, nodesY, nodeW, nodeH, srcName, 'Source', conn.status);
        drawZoomNode(overlayGroup, rightX, nodesY, nodeW, nodeH, dstName, 'Dest', conn.status);

        // Collect all tunnels from both sides
        const allTunnels = [];
        (detail.source_tunnels || []).forEach(t => allTunnels.push({ ...t, side: 'source', deviceId: conn.source_device_id }));
        (detail.dest_tunnels || []).forEach(t => allTunnels.push({ ...t, side: 'dest', deviceId: conn.dest_device_id }));

        // Remove duplicates by tunnel_name
        const seen = new Set();
        const uniqueTunnels = allTunnels.filter(t => {
            if (seen.has(t.tunnel_name)) return false;
            seen.add(t.tunnel_name);
            return true;
        });

        // Draw each tunnel as a horizontal path with generous spacing
        const startY = nodesY + nodeH + 30;
        const spacing = Math.min(50, (dim.H - startY - 40) / Math.max(uniqueTunnels.length, 1));
        const pathStartX = leftX + nodeW + 10;
        const pathEndX = rightX - 10;

        uniqueTunnels.forEach((t, i) => {
            const y = startY + i * spacing;
            const isUp = t.status === 'up' || t.state === 'up';
            const pathId = `tz-path-${i}`;

            // Tunnel path
            const path = FWDiagram.createEl('path');
            const pathD = `M${pathStartX},${y} L${pathEndX},${y}`;
            path.setAttribute('d', pathD);
            path.setAttribute('fill', 'none');
            path.setAttribute('id', pathId);
            if (isUp) {
                path.setAttribute('stroke', window.connStyle(conn.connection_type).color);
                path.setAttribute('stroke-width', '2.5');
            } else {
                path.setAttribute('stroke', '#484f58');
                path.setAttribute('stroke-width', '1.5');
                path.setAttribute('stroke-dasharray', '6,4');
            }
            path.style.cursor = 'pointer';
            path.addEventListener('click', (e) => {
                e.stopPropagation();
                showTunnelTooltip(t, e.clientX, e.clientY);
            });
            overlayGroup.appendChild(path);

            // Tunnel name label
            const label = FWDiagram.createEl('text');
            label.setAttribute('x', (pathStartX + pathEndX) / 2);
            label.setAttribute('y', y - 6);
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('fill', isUp ? '#e6edf3' : '#8b949e');
            label.setAttribute('font-size', '10');
            label.setAttribute('font-weight', '500');
            label.textContent = t.tunnel_name;
            overlayGroup.appendChild(label);

            // Status badge
            const badge = FWDiagram.createEl('text');
            badge.setAttribute('x', pathEndX + 15);
            badge.setAttribute('y', y + 4);
            badge.setAttribute('fill', isUp ? '#3fb950' : '#f85149');
            badge.setAttribute('font-size', '9');
            badge.setAttribute('font-weight', '600');
            badge.textContent = isUp ? 'UP' : 'DOWN';
            overlayGroup.appendChild(badge);

            // Bytes label
            const bytesLabel = FWDiagram.createEl('text');
            bytesLabel.setAttribute('x', pathStartX - 10);
            bytesLabel.setAttribute('y', y + 4);
            bytesLabel.setAttribute('text-anchor', 'end');
            bytesLabel.setAttribute('fill', '#8b949e');
            bytesLabel.setAttribute('font-size', '9');
            bytesLabel.textContent = `${window.formatBytes(t.bytes_in || 0)} / ${window.formatBytes(t.bytes_out || 0)}`;
            overlayGroup.appendChild(bytesLabel);

            // Animate UP tunnels
            if (isUp) {
                const circle = FWDiagram.createEl('circle');
                circle.setAttribute('r', '3');
                circle.setAttribute('fill', window.connStyle(conn.connection_type).color);
                circle.setAttribute('opacity', '0.85');
                const motion = FWDiagram.createEl('animateMotion');
                motion.setAttribute('dur', '3s');
                motion.setAttribute('repeatCount', 'indefinite');
                motion.setAttribute('fill', 'freeze');
                const mpath = FWDiagram.createEl('mpath');
                mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`);
                motion.appendChild(mpath);
                circle.appendChild(motion);
                overlayGroup.appendChild(circle);

                // Return particle
                const circle2 = FWDiagram.createEl('circle');
                circle2.setAttribute('r', '2.5');
                circle2.setAttribute('fill', '#58a6ff');
                circle2.setAttribute('opacity', '0.7');
                const motion2 = FWDiagram.createEl('animateMotion');
                motion2.setAttribute('dur', '3.5s');
                motion2.setAttribute('begin', '1s');
                motion2.setAttribute('repeatCount', 'indefinite');
                motion2.setAttribute('fill', 'freeze');
                motion2.setAttribute('keyPoints', '1;0');
                motion2.setAttribute('keyTimes', '0;1');
                motion2.setAttribute('calcMode', 'linear');
                const mpath2 = FWDiagram.createEl('mpath');
                mpath2.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`);
                motion2.appendChild(mpath2);
                circle2.appendChild(motion2);
                overlayGroup.appendChild(circle2);
            }
        });

        if (uniqueTunnels.length === 0) {
            const noData = FWDiagram.createEl('text');
            noData.setAttribute('x', dim.W / 2);
            noData.setAttribute('y', startY + 40);
            noData.setAttribute('text-anchor', 'middle');
            noData.setAttribute('fill', '#484f58');
            noData.setAttribute('font-size', '12');
            noData.textContent = 'No tunnels found for this connection';
            overlayGroup.appendChild(noData);
        }

        svg.appendChild(overlayGroup);
    }

    function drawZoomNode(parent, x, y, w, h, name, label, status) {
        const statusColor = status === 'up' ? '#3fb950' : (status === 'down' ? '#f85149' : '#30363d');
        const r = FWDiagram.createEl('rect');
        r.setAttribute('x', x);
        r.setAttribute('y', y);
        r.setAttribute('width', w);
        r.setAttribute('height', h);
        r.setAttribute('rx', '8');
        r.setAttribute('fill', '#161b22');
        r.setAttribute('stroke', statusColor);
        r.setAttribute('stroke-width', '1.5');
        parent.appendChild(r);

        const nameEl = FWDiagram.createEl('text');
        nameEl.setAttribute('x', x + w/2);
        nameEl.setAttribute('y', y + 20);
        nameEl.setAttribute('text-anchor', 'middle');
        nameEl.setAttribute('fill', '#e6edf3');
        nameEl.setAttribute('font-size', '11');
        nameEl.setAttribute('font-weight', '600');
        nameEl.textContent = name.length > 14 ? name.slice(0,13) + '\u2026' : name;
        parent.appendChild(nameEl);

        const labelEl = FWDiagram.createEl('text');
        labelEl.setAttribute('x', x + w/2);
        labelEl.setAttribute('y', y + 36);
        labelEl.setAttribute('text-anchor', 'middle');
        labelEl.setAttribute('fill', '#8b949e');
        labelEl.setAttribute('font-size', '9');
        labelEl.textContent = label;
        parent.appendChild(labelEl);
    }

    function showTunnelTooltip(tunnel, clientX, clientY) {
        // Create a floating HTML tooltip for per-tunnel details
        let existing = document.getElementById('tz-tooltip');
        if (existing) existing.remove();

        const div = document.createElement('div');
        div.id = 'tz-tooltip';
        div.style.cssText = `position:fixed;top:${clientY + 10}px;left:${clientX + 10}px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;z-index:300;max-width:300px;font-size:0.82rem;color:#c9d1d9;box-shadow:0 4px 12px rgba(0,0,0,0.4);`;
        const isUp = tunnel.status === 'up' || tunnel.state === 'up';
        div.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <strong style="color:#e6edf3;">${window.escapeHtml(tunnel.tunnel_name)}</strong>
                <span class="badge ${isUp ? 'up' : 'down'}" style="font-size:0.7rem;">${isUp ? 'UP' : 'DOWN'}</span>
            </div>
            <div style="color:#8b949e;font-size:0.78rem;">
                <div>Remote IP: <span class="mono">${window.escapeHtml(tunnel.remote_ip || '-')}</span></div>
                <div>In: ${window.formatBytes(tunnel.bytes_in || 0)} | Out: ${window.formatBytes(tunnel.bytes_out || 0)}</div>
                ${tunnel.local_subnet ? `<div>Local: ${window.escapeHtml(tunnel.local_subnet)}</div>` : ''}
                ${tunnel.remote_subnet ? `<div>Remote: ${window.escapeHtml(tunnel.remote_subnet)}</div>` : ''}
            </div>
            <div style="margin-top:8px;text-align:right;">
                <button class="btn secondary sm" onclick="this.closest('#tz-tooltip').remove()">Close</button>
            </div>
        `;
        document.body.appendChild(div);

        // Auto-remove after 10s
        setTimeout(() => { if (div.parentNode) div.remove(); }, 10000);
    }

    function hide() {
        if (overlayGroup && overlayGroup.parentNode) {
            overlayGroup.parentNode.removeChild(overlayGroup);
        }
        overlayGroup = null;
        Object.values(zoomChartInstances).forEach(c => { if (c?.destroy) c.destroy(); });
        zoomChartInstances = {};

        const tooltip = document.getElementById('tz-tooltip');
        if (tooltip) tooltip.remove();
    }

    FWDiagram.TunnelZoom = {
        show,
        hide
    };
})();
