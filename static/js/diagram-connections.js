// diagram-connections.js — FWDiagram.Connections: Path drawing, UP-only filter, arc geometry
(function() {
    'use strict';

    let pathRegistry = []; // { pathEl, seg1El, seg2El, conn, srcIdx, dstIdx, type }
    let offnetRegistry = []; // { pathEl, deviceIdx }

    function drawAll(devices, conns, siteMap, vpnMap, onConnClick, onVPNClick) {
        const svg = FWDiagram.getSVG();
        const positions = FWDiagram.Layout.getPositions();
        const dim = FWDiagram.getDimensions();
        const cx = dim.cx, cy = dim.cy;

        pathRegistry = [];
        offnetRegistry = [];

        // Classify connections
        const isCrossSite = (conn) => {
            const srcSite = siteMap[conn.source_device_id];
            const dstSite = siteMap[conn.dest_device_id];
            if (!srcSite || !dstSite) return true;
            return srcSite !== dstSite;
        };

        // Compute off-net data
        const devicesWithOffnet = [];
        devices.forEach(d => {
            const vpnInfo = vpnMap[String(d.id)];
            if (!vpnInfo) return;
            const offnetTunnels = vpnInfo.tunnels.filter(t => t.matched_device_id === 0);
            if (offnetTunnels.length > 0) {
                const anyUp = offnetTunnels.some(t => t.status === 'up');
                devicesWithOffnet.push({ deviceId: d.id, tunnels: offnetTunnels, anyUp });
            }
        });

        const crossSiteConns = conns.filter(c => isCrossSite(c));
        const sameSiteConns = conns.filter(c => !isCrossSite(c));
        // UP-only filter for drawn paths
        const upCrossSite = crossSiteConns.filter(c => c.status === 'up');
        const upSameSite = sameSiteConns.filter(c => c.status === 'up');

        const hasCloudNode = devicesWithOffnet.length > 0 || crossSiteConns.length > 0;
        let cloudPathIdx = 0;

        // --- 1) Off-net cloud-to-device dashed paths (only UP) ---
        devicesWithOffnet.forEach(info => {
            if (!info.anyUp) return;
            const pi = devices.findIndex(d => d.id === info.deviceId);
            if (pi < 0) return;
            const p = positions[pi];
            const pathId = `cloud-path-${cloudPathIdx}`;
            const pathD = computePathD_line(p.x, p.y, cx, cy);

            const hitPath = FWDiagram.createEl('path');
            hitPath.setAttribute('d', pathD);
            hitPath.setAttribute('class', 'conn-hit-area');
            hitPath.addEventListener('click', () => onVPNClick(info.deviceId, true));
            svg.appendChild(hitPath);

            const path = FWDiagram.createEl('path');
            path.setAttribute('d', pathD);
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', '#3fb950');
            path.setAttribute('stroke-width', '2');
            path.setAttribute('stroke-dasharray', '2,4,8,4');
            path.setAttribute('id', pathId);
            path.style.cursor = 'pointer';
            path.addEventListener('click', () => onVPNClick(info.deviceId, true));
            svg.appendChild(path);

            offnetRegistry.push({ pathEl: path, hitEl: hitPath, deviceIdx: pi });

            // Particle
            FWDiagram.Particles.addSVGParticle(svg, pathId, '#3fb950', 2, '5s', 0);
            cloudPathIdx++;
        });

        // --- 2) Same-site UP connections (outward arcs) ---
        upSameSite.forEach((conn, ci) => {
            const si = devices.findIndex(d => d.id === conn.source_device_id);
            const di = devices.findIndex(d => d.id === conn.dest_device_id);
            if (si < 0 || di < 0) return;

            const s = positions[si], t = positions[di];
            const cs = window.connStyle(conn.connection_type);
            const isIndirect = conn.match_method === 'tunnel_indirect';
            const color = isIndirect ? '#f0883e' : cs.color;

            const pathD = buildSameSiteArc(s.x, s.y, t.x, t.y, cx, cy, ci);
            const pathId = `conn-path-ss-${ci}`;

            const hitPath = FWDiagram.createEl('path');
            hitPath.setAttribute('d', pathD);
            hitPath.setAttribute('class', 'conn-hit-area');
            hitPath.addEventListener('click', () => onConnClick(conn));
            svg.appendChild(hitPath);

            const path = FWDiagram.createEl('path');
            path.setAttribute('d', pathD);
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', color);
            path.setAttribute('stroke-width', String(isIndirect ? 2 : cs.width));
            path.setAttribute('class', 'conn-path');
            path.setAttribute('id', pathId);
            if (cs.dash) path.setAttribute('stroke-dasharray', cs.dash);
            if (isIndirect) path.setAttribute('stroke-dasharray', '4,6');
            if (!isIndirect) path.setAttribute('filter', 'url(#conn-glow)');
            path.addEventListener('click', () => onConnClick(conn));
            svg.appendChild(path);

            pathRegistry.push({ pathEl: path, hitEl: hitPath, conn, srcIdx: si, dstIdx: di, type: 'same', ci });

            // Traffic-proportional particles
            const vpnInfo = vpnMap[String(conn.source_device_id)];
            const bytesIn = vpnInfo ? vpnInfo.tunnels.reduce((s, t) => s + (t.bytes_in || 0), 0) : 0;
            const bytesOut = vpnInfo ? vpnInfo.tunnels.reduce((s, t) => s + (t.bytes_out || 0), 0) : 0;
            FWDiagram.Particles.addTrafficParticles(svg, pathId, color, bytesIn, bytesOut, isIndirect);
        });

        // --- 3) Cross-site UP connections (angular fan through cloud) ---
        upCrossSite.forEach((conn, ci) => {
            const si = devices.findIndex(d => d.id === conn.source_device_id);
            const di = devices.findIndex(d => d.id === conn.dest_device_id);
            if (si < 0 || di < 0) return;

            const s = positions[si], t = positions[di];
            const cs = window.connStyle(conn.connection_type);
            const isIndirect = conn.match_method === 'tunnel_indirect';
            const color = isIndirect ? '#f0883e' : cs.color;

            const { seg1D, seg2D } = buildCrossSiteSegments(s.x, s.y, t.x, t.y, cx, cy, ci, upCrossSite.length);
            const seg1Id = `conn-path-cs1-${ci}`;
            const seg2Id = `conn-path-cs2-${ci}`;

            const elements = [];
            [{ d: seg1D, id: seg1Id }, { d: seg2D, id: seg2Id }].forEach(seg => {
                const hitPath = FWDiagram.createEl('path');
                hitPath.setAttribute('d', seg.d);
                hitPath.setAttribute('class', 'conn-hit-area');
                hitPath.addEventListener('click', () => onConnClick(conn));
                svg.appendChild(hitPath);

                const path = FWDiagram.createEl('path');
                path.setAttribute('d', seg.d);
                path.setAttribute('fill', 'none');
                path.setAttribute('stroke', color);
                path.setAttribute('stroke-width', String(isIndirect ? 2 : cs.width));
                path.setAttribute('class', 'conn-path');
                path.setAttribute('id', seg.id);
                if (cs.dash) path.setAttribute('stroke-dasharray', cs.dash);
                if (isIndirect) path.setAttribute('stroke-dasharray', '4,6');
                if (!isIndirect) path.setAttribute('filter', 'url(#conn-glow)');
                path.addEventListener('click', () => onConnClick(conn));
                svg.appendChild(path);

                elements.push({ pathEl: path, hitEl: hitPath });

                // Particles for each segment
                const vpnInfo = vpnMap[String(conn.source_device_id)];
                const bytesIn = vpnInfo ? vpnInfo.tunnels.reduce((s, t) => s + (t.bytes_in || 0), 0) : 0;
                const bytesOut = vpnInfo ? vpnInfo.tunnels.reduce((s, t) => s + (t.bytes_out || 0), 0) : 0;
                FWDiagram.Particles.addTrafficParticles(svg, seg.id, color, bytesIn, bytesOut, isIndirect);
            });

            pathRegistry.push({
                seg1El: elements[0].pathEl, seg1HitEl: elements[0].hitEl,
                seg2El: elements[1].pathEl, seg2HitEl: elements[1].hitEl,
                conn, srcIdx: si, dstIdx: di, type: 'cross', ci
            });
        });

        // --- 4) Cloud node on top ---
        if (hasCloudNode) {
            const linkCount = devicesWithOffnet.length + crossSiteConns.length;
            const cloudG = FWDiagram.Layout.drawCloudNode(cx, cy, linkCount);
            if (devicesWithOffnet.length === 1) {
                cloudG.addEventListener('click', () => onVPNClick(devicesWithOffnet[0].deviceId, true));
            }
        }

        return { hasCloudNode, crossSiteConns, sameSiteConns, devicesWithOffnet };
    }

    // Outward arc: control point pushes AWAY from cloud center
    function buildSameSiteArc(sx, sy, tx, ty, cx, cy, idx) {
        const mx = (sx + tx) / 2, my = (sy + ty) / 2;
        // Direction from center to midpoint (outward)
        const dx = mx - cx, dy = my - cy;
        const len = Math.sqrt(dx*dx + dy*dy) || 1;
        const outX = dx / len, outY = dy / len;
        const bulge = 60 + idx * 20;
        const cpx = mx + outX * bulge;
        const cpy = my + outY * bulge;
        return `M${sx},${sy} Q${cpx},${cpy} ${tx},${ty}`;
    }

    // Cross-site: fan across 60-degree arc through cloud transit points
    function buildCrossSiteSegments(sx, sy, tx, ty, cx, cy, idx, total) {
        // Compute angular spread: 60 degrees total, centered on midpoint angle
        const midAngle = Math.atan2((sy + ty) / 2 - cy, (sx + tx) / 2 - cx);
        const spreadDeg = 60;
        const spreadRad = spreadDeg * Math.PI / 180;
        const step = total > 1 ? spreadRad / (total - 1) : 0;
        const startAngle = midAngle - spreadRad / 2;
        const angle = startAngle + idx * step;

        // Transit point near cloud center with offset
        const transitR = 25;
        const transitX = cx + transitR * Math.cos(angle);
        const transitY = cy + transitR * Math.sin(angle);

        // Build curved segments: Source→transit, transit→Dest
        const off1 = 20 + idx * 8;
        const off2 = -(20 + idx * 8);
        const seg1D = buildCurvedSegment(sx, sy, transitX, transitY, off1);
        const seg2D = buildCurvedSegment(transitX, transitY, tx, ty, off2);

        return { seg1D, seg2D };
    }

    function buildCurvedSegment(x1, y1, x2, y2, offset) {
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        const dx = x2 - x1, dy = y2 - y1;
        const len = Math.sqrt(dx*dx + dy*dy) || 1;
        const cpx = mx + (-dy / len) * offset;
        const cpy = my + (dx / len) * offset;
        return `M${x1},${y1} Q${cpx},${cpy} ${x2},${y2}`;
    }

    function computePathD_line(x1, y1, x2, y2) {
        return `M${x1},${y1} L${x2},${y2}`;
    }

    // Redraw all path `d` attributes in-place (called during drag)
    function redrawPaths() {
        const positions = FWDiagram.Layout.getPositions();
        const dim = FWDiagram.getDimensions();
        const cx = dim.cx, cy = dim.cy;

        pathRegistry.forEach(entry => {
            const s = positions[entry.srcIdx], t = positions[entry.dstIdx];
            if (!s || !t) return;

            if (entry.type === 'same') {
                const d = buildSameSiteArc(s.x, s.y, t.x, t.y, cx, cy, entry.ci);
                entry.pathEl.setAttribute('d', d);
                if (entry.hitEl) entry.hitEl.setAttribute('d', d);
            } else if (entry.type === 'cross') {
                // Re-derive total from pathRegistry cross entries
                const crossCount = pathRegistry.filter(e => e.type === 'cross').length;
                const { seg1D, seg2D } = buildCrossSiteSegments(s.x, s.y, t.x, t.y, cx, cy, entry.ci, crossCount);
                entry.seg1El.setAttribute('d', seg1D);
                entry.seg2El.setAttribute('d', seg2D);
                if (entry.seg1HitEl) entry.seg1HitEl.setAttribute('d', seg1D);
                if (entry.seg2HitEl) entry.seg2HitEl.setAttribute('d', seg2D);
            }
        });

        offnetRegistry.forEach(entry => {
            const p = positions[entry.deviceIdx];
            if (!p) return;
            const d = computePathD_line(p.x, p.y, cx, cy);
            entry.pathEl.setAttribute('d', d);
            if (entry.hitEl) entry.hitEl.setAttribute('d', d);
        });
    }

    FWDiagram.Connections = {
        drawAll,
        redrawPaths,
        buildCurvedSegment
    };
})();
