// diagram-particles.js — FWDiagram.Particles: Traffic-proportional animated particles
(function() {
    'use strict';

    let animationId = null;
    let particles = [];

    // Add SVG <animateMotion> based particle (simple, for off-net paths)
    function addSVGParticle(svg, pathId, color, radius, dur, beginDelay) {
        const circle = FWDiagram.createEl('circle');
        circle.setAttribute('r', String(radius));
        circle.setAttribute('fill', color);
        circle.setAttribute('opacity', '0.7');
        const motion = FWDiagram.createEl('animateMotion');
        motion.setAttribute('dur', dur);
        motion.setAttribute('begin', beginDelay + 's');
        motion.setAttribute('repeatCount', 'indefinite');
        motion.setAttribute('fill', 'freeze');
        const mpath = FWDiagram.createEl('mpath');
        mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`);
        motion.appendChild(mpath);
        circle.appendChild(motion);
        svg.appendChild(circle);
        return circle;
    }

    // Traffic-proportional particles using rAF + getPointAtLength
    function addTrafficParticles(svg, pathId, color, bytesIn, bytesOut, isIndirect) {
        const totalBytes = (bytesIn || 0) + (bytesOut || 0);
        // Log scale: 0 bytes = 1 particle, 1GB+ = 6 particles
        const logVal = totalBytes > 0 ? Math.log10(totalBytes) : 0;
        const fwdCount = Math.max(1, Math.min(6, Math.round(logVal / 2)));
        const revCount = Math.max(1, Math.min(4, Math.round(logVal / 2.5)));
        // Speed: higher traffic = faster. Base duration 6s, minimum 2s
        const speed = Math.max(2, 6 - logVal * 0.4);

        // Forward particles (connection type color)
        for (let i = 0; i < fwdCount; i++) {
            const circle = FWDiagram.createEl('circle');
            circle.setAttribute('r', isIndirect ? '2' : '3');
            circle.setAttribute('fill', color);
            circle.setAttribute('opacity', '0.85');
            svg.appendChild(circle);
            particles.push({
                el: circle,
                pathId,
                progress: i / fwdCount,
                speed: 1 / (speed * 1000),
                direction: 1
            });
        }

        // Reverse particles (#58a6ff)
        for (let i = 0; i < revCount; i++) {
            const circle = FWDiagram.createEl('circle');
            circle.setAttribute('r', isIndirect ? '1.5' : '2.5');
            circle.setAttribute('fill', '#58a6ff');
            circle.setAttribute('opacity', '0.7');
            svg.appendChild(circle);
            particles.push({
                el: circle,
                pathId,
                progress: i / revCount,
                speed: 1 / ((speed + 0.5) * 1000),
                direction: -1
            });
        }
    }

    let lastTime = 0;

    function animate(timestamp) {
        if (!lastTime) lastTime = timestamp;
        const dt = timestamp - lastTime;
        lastTime = timestamp;

        particles.forEach(p => {
            p.progress += p.speed * dt * p.direction;
            if (p.progress > 1) p.progress -= 1;
            if (p.progress < 0) p.progress += 1;

            const pathEl = document.getElementById(p.pathId);
            if (!pathEl) return;
            try {
                const len = pathEl.getTotalLength();
                const pt = pathEl.getPointAtLength(p.progress * len);
                p.el.setAttribute('cx', pt.x);
                p.el.setAttribute('cy', pt.y);
            } catch(e) {}
        });

        animationId = requestAnimationFrame(animate);
    }

    function start() {
        if (animationId) return;
        lastTime = 0;
        animationId = requestAnimationFrame(animate);
    }

    function stop() {
        if (animationId) {
            cancelAnimationFrame(animationId);
            animationId = null;
        }
        particles = [];
        lastTime = 0;
    }

    FWDiagram.Particles = {
        addSVGParticle,
        addTrafficParticles,
        start,
        stop
    };
})();
