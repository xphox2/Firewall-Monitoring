/* admin-bw-chart.js — shared 3-mode bandwidth chart for admin pages.
 *
 * Mirrors the public dashboard's interface bandwidth widget
 * (public-dashboard.js renderBandwidthChart) so the admin device-detail
 * interface and VPN-tunnel graphs offer the same three display modes and
 * visual style:
 *
 *   - 'rate'  (Throughput) — RX/TX line chart in Mbps
 *   - 'total' (Transfer)   — RX/TX bar chart of bytes-per-bucket
 *   - 'mix'   (Combined)   — Mbps lines (left axis) + byte bars (right axis)
 *
 * The caller passes already-normalized per-bucket series (rate in Mbps,
 * transfer in bytes) plus the active view; this module owns only the Chart.js
 * dataset/scale construction. Chart state (which view, which range) lives with
 * the caller so a single page can host many independent charts (one per
 * expanded interface / tunnel row).
 *
 *   var chart = FwmonBwChart.render(canvas, {
 *       labels:     [...],   // x-axis tick labels
 *       rxRate:     [...],   // Mbps
 *       txRate:     [...],   // Mbps
 *       rxTransfer: [...],   // bytes/bucket
 *       txTransfer: [...],   // bytes/bucket
 *       view:       'rate',  // 'rate' | 'total' | 'mix'
 *       rxLabel:    'In',    // series prefix (e.g. In/Out, RX/TX)
 *       txLabel:    'Out',
 *       onZoomSelect: function(loIdx, hiIdx) { ... } // optional drag-to-zoom
 *   });
 *
 * When onZoomSelect is supplied (and chartjs-plugin-zoom is loaded), the chart
 * enables drag-to-select on the x-axis; on release it reports the selected
 * category index range so the caller can re-query the backend for exactly that
 * window at finer resolution.
 */
(function () {
    'use strict';

    // The three display modes, in the same order/labels the public dashboard
    // header dropdown uses (#bw-view). Callers iterate this to render a toggle.
    var MODES = [
        { value: 'rate',  label: 'Throughput' },
        { value: 'total', label: 'Transfer' },
        { value: 'mix',   label: 'Combined' }
    ];

    var RX_COLOR = '#3fb950'; // green  — matches public dashboard RX
    var TX_COLOR = '#ff9500'; // orange — matches public dashboard TX

    // 1024-based, matching public-dashboard.js / admin-device-detail.js so the
    // chart's byte axis reads the same as the table cells right above it.
    function formatBytes(bytes) {
        if (bytes == null || isNaN(bytes) || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        var val = bytes;
        while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
        return val.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    // Common Chart.js options — dark NOC theme aligned with the rest of the
    // admin UI. scaleOverrides is merged on top of the shared x-axis.
    function chartOpts(scaleOverrides) {
        var scales = {
            x: { ticks: { color: '#484f58', maxTicksLimit: 12, maxRotation: 0, font: { size: 11 } }, grid: { color: '#21262d' } }
        };
        for (var key in scaleOverrides) {
            if (Object.prototype.hasOwnProperty.call(scaleOverrides, key)) {
                scales[key] = scaleOverrides[key];
            }
        }
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            interaction: { intersect: false, mode: 'index' },
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } } } },
            scales: scales
        };
    }

    function render(canvas, o) {
        var view = o.view || 'rate';
        var rxLabel = o.rxLabel || 'RX';
        var txLabel = o.txLabel || 'TX';
        var rxRate = o.rxRate || [];
        var txRate = o.txRate || [];
        var rxTransfer = o.rxTransfer || [];
        var txTransfer = o.txTransfer || [];

        var datasets, scales;

        if (view === 'total') {
            // Transfer: per-bucket bytes as paired bars.
            datasets = [
                { type: 'bar', label: rxLabel + ' Transfer', data: rxTransfer, backgroundColor: 'rgba(63,185,80,0.6)', borderColor: RX_COLOR, borderWidth: 1 },
                { type: 'bar', label: txLabel + ' Transfer', data: txTransfer, backgroundColor: 'rgba(255,149,0,0.6)', borderColor: TX_COLOR, borderWidth: 1 }
            ];
            scales = {
                y: { beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return formatBytes(v); } }, grid: { color: '#21262d' }, title: { display: true, text: 'Bytes / interval', color: '#484f58' } }
            };
        } else if (view === 'mix') {
            // Combined: Mbps lines on the left axis, byte bars on the right.
            datasets = [
                { label: rxLabel + ' (Mbps)', data: rxRate, borderColor: RX_COLOR, backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                { label: txLabel + ' (Mbps)', data: txRate, borderColor: TX_COLOR, backgroundColor: 'rgba(255,149,0,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                { type: 'bar', label: rxLabel + ' Transfer', data: rxTransfer, backgroundColor: 'rgba(63,185,80,0.3)', borderWidth: 0, yAxisID: 'y1' },
                { type: 'bar', label: txLabel + ' Transfer', data: txTransfer, backgroundColor: 'rgba(255,149,0,0.3)', borderWidth: 0, yAxisID: 'y1' }
            ];
            scales = {
                y:  { position: 'left',  beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return v.toFixed(1); } }, grid: { color: '#21262d' }, title: { display: true, text: 'Mbps', color: '#484f58' } },
                y1: { position: 'right', beginAtZero: true, grid: { display: false }, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return formatBytes(v); } }, title: { display: true, text: 'Bytes', color: '#484f58' } }
            };
        } else {
            // Throughput (default): Mbps as filled lines.
            datasets = [
                { label: rxLabel + ' (Mbps)', data: rxRate, borderColor: RX_COLOR, backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 },
                { label: txLabel + ' (Mbps)', data: txRate, borderColor: TX_COLOR, backgroundColor: 'rgba(255,149,0,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 }
            ];
            scales = {
                y: { beginAtZero: true, ticks: { color: '#484f58', font: { size: 11 }, callback: function (v) { return v.toFixed(1) + ' Mbps'; } }, grid: { color: '#21262d' } }
            };
        }

        var options = chartOpts(scales);

        // Drag-to-zoom: select an x-range, then re-query the backend for that
        // window. Requires chartjs-plugin-zoom (auto-registers on load). On a
        // category x-axis the post-drag scale min/max are fractional category
        // indices; we snap outward (floor/ceil) and clamp to the data bounds.
        if (typeof o.onZoomSelect === 'function' && window.Chart && Chart.registry && hasZoomPlugin()) {
            var n = (o.labels || []).length;
            options.plugins.zoom = {
                zoom: {
                    drag: {
                        enabled: true,
                        backgroundColor: 'rgba(88,166,255,0.18)',
                        borderColor: 'rgba(88,166,255,0.8)',
                        borderWidth: 1
                    },
                    mode: 'x',
                    onZoomComplete: function (ctx) {
                        var sx = ctx && ctx.chart && ctx.chart.scales && ctx.chart.scales.x;
                        if (!sx) return;
                        var lo = Math.floor(sx.min);
                        var hi = Math.ceil(sx.max);
                        if (lo < 0) lo = 0;
                        if (hi > n - 1) hi = n - 1;
                        if (hi - lo < 1) return; // selection too small to be meaningful
                        o.onZoomSelect(lo, hi);
                    }
                }
            };
        }

        return new Chart(canvas, {
            type: 'line',
            data: { labels: o.labels || [], datasets: datasets },
            options: options
        });
    }

    // hasZoomPlugin reports whether chartjs-plugin-zoom registered itself.
    function hasZoomPlugin() {
        try {
            return !!Chart.registry.plugins.get('zoom');
        } catch (e) {
            return false;
        }
    }

    window.FwmonBwChart = {
        MODES: MODES,
        render: render,
        formatBytes: formatBytes
    };
})();
