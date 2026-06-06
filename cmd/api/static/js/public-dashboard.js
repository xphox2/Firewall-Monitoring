// public-dashboard.js — Gridstack-based public dashboard with widget persistence
(function() {
    'use strict';

    var API_BASE = '/api';
    var LAYOUT_KEY = 'fwmon-public-layout';
    var HIDDEN_KEY = 'fwmon-hidden-widgets';
    var grid = null;
    var allDevices = [];
    var allWidgetDefs = []; // {id, title, type, w, h, x, y}
    var hiddenWidgets = {};
    var chartInstances = {};
    var displaySettings = {};
    var refreshTimer = null;
    var uptimeTimers = {}; // deviceId -> { baseSeconds, startedAt }
    var uptimeIntervalId = null;
    var bwView = 'rate';
    var dashRange = 1;
    var modalChart = null;
    var modalWidgetDef = null;
    var modalDragStart = null;
    var modalRequestId = 0;

    // Timezone handling - use display_timezone from settings, fallback to browser local
    function getTimezone() {
        return (displaySettings && displaySettings.display_timezone) || Intl.DateTimeFormat().resolvedOptions().timeZone;
    }

    // Format a date string or timestamp using the configured timezone
    function formatInTimezone(dateStr, options) {
        if (!dateStr) return '-';
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        var tz = getTimezone();
        return d.toLocaleString('en-US', Object.assign({ timeZone: tz }, options));
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, function(c) {
            return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
        });
    }

    function formatBytes(bytes) {
        if (bytes == null || bytes === 0) return '0 B';
        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024));
        if (i >= sizes.length) i = sizes.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
    }

    function formatNumber(n) { return n != null ? Number(n).toLocaleString() : '--'; }

    function progressClass(v) { return v >= 80 ? 'high' : v >= 60 ? 'medium' : 'low'; }

    // ---- Fetch helpers ----
    function apiFetch(url) {
        return fetch(url).then(function(r) { return r.json(); }).then(function(d) {
            return d && d.success ? d.data : null;
        });
    }

    // ---- Initialization ----
    function init() {
        apiFetch(API_BASE + '/public/display-settings').then(function(settings) {
            displaySettings = settings || {};
            return apiFetch(API_BASE + '/public/devices');
        }).then(function(devices) {
            allDevices = devices || [];
            loadHiddenWidgets();
            buildWidgetDefs();
            initGrid();
            renderAllWidgets();
            startRefresh();
        })['catch'](function(e) { console.error('Dashboard init failed:', e); });
    }

    function loadHiddenWidgets() {
        try { hiddenWidgets = JSON.parse(localStorage.getItem(HIDDEN_KEY)) || {}; } catch(e) { hiddenWidgets = {}; }
    }

    function saveHiddenWidgets() {
        localStorage.setItem(HIDDEN_KEY, JSON.stringify(hiddenWidgets));
    }

    // ---- Widget definitions ----
    function buildWidgetDefs() {
        allWidgetDefs = [];
        var y = 0;

        // CPU/Memory charts per device
        var cpuX = 0;
        allDevices.forEach(function(d) {
            var w = allDevices.length === 1 ? 12 : 6;
            allWidgetDefs.push({ id: 'cpu-' + d.id, title: d.name + ' CPU/Memory', type: 'cpumem', deviceId: d.id, x: cpuX, y: y, w: w, h: 5 });
            cpuX += w;
            if (cpuX >= 12) { cpuX = 0; y += 5; }
        });
        if (cpuX > 0) y += 5;

        // Bandwidth charts per public interface
        fetchPublicInterfaces().then(function(ifaces) {
            var bwX = 0;
            var bwY = y;
            ifaces.forEach(function(iface) {
                var w = ifaces.length === 1 ? 12 : 6;
                allWidgetDefs.push({ id: 'bw-' + iface.deviceId + '-' + iface.name, title: iface.deviceName + ' ' + iface.name, type: 'bandwidth', iface: iface, x: bwX, y: bwY, w: w, h: 5 });
                bwX += w;
                if (bwX >= 12) { bwX = 0; bwY += 5; }
            });
            if (bwX > 0) bwY += 5;

            // VPN widget
            if (displaySettings['public_show_vpn'] !== 'false') {
                allWidgetDefs.push({ id: 'vpn', title: 'VPN Tunnels', type: 'vpn', x: 0, y: bwY, w: 12, h: 4 });
                bwY += 4;
            }

            // Connection map widget
            if (displaySettings['public_show_connections'] !== 'false') {
                allWidgetDefs.push({ id: 'connmap', title: 'Connection Map', type: 'connmap', x: 0, y: bwY, w: 12, h: 5 });
            }

            // Add late widgets to grid
            addLateWidgets();
            updateWidgetMenu();
        });
    }

    function fetchPublicInterfaces() {
        var publicIfaces = {};
        try { publicIfaces = JSON.parse(displaySettings['public_interfaces'] || '{}'); } catch(e) {}

        var promises = allDevices.map(function(device) {
            return apiFetch(API_BASE + '/public/interfaces?device_id=' + device.id).then(function(ifaces) {
                if (!ifaces) return [];
                var allowed = publicIfaces[String(device.id)] || [];
                if (allowed.length > 0) {
                    ifaces = ifaces.filter(function(i) { return allowed.indexOf(i.name) !== -1; });
                }
                return ifaces.map(function(i) {
                    return { deviceId: device.id, deviceName: device.name, name: i.name, index: i.index, status: i.status };
                });
            })['catch'](function() { return []; });
        });

        return Promise.all(promises).then(function(results) {
            var flat = [];
            results.forEach(function(arr) { flat = flat.concat(arr); });
            return flat;
        });
    }

    // ---- Grid initialization ----
    function initGrid() {
        grid = GridStack.init({
            column: 12,
            float: false,
            cellHeight: 50,
            margin: 4,
            animate: true,
            handle: '.widget-hdr',
            columnOpts: {
                breakpoints: [{ w: 768, c: 1 }]
            }
        }, '#dashboard-grid');

        // Save layout on drag/resize
        grid.on('dragstop resizestop', saveLayout);

        // Resize charts when widget resizes
        grid.on('resizestop', function(event, el) {
            var wid = el.getAttribute('gs-id');
            if (chartInstances[wid]) {
                setTimeout(function() { chartInstances[wid].resize(); }, 50);
            }
        });

        // Add initial widgets (only those defined so far — late ones added by addLateWidgets)
        var saved = loadLayout();
        allWidgetDefs.forEach(function(def) {
            if (hiddenWidgets[def.id]) return;
            var pos = saved ? saved[def.id] : null;
            addWidgetToGrid(def, pos);
        });

        updateWidgetMenu();
    }

    function addLateWidgets() {
        if (!grid) return;
        var saved = loadLayout();
        allWidgetDefs.forEach(function(def) {
            if (hiddenWidgets[def.id]) return;
            var existing = grid.engine.nodes.find(function(n) { return n.id === def.id; });
            if (existing) return;
            var pos = saved ? saved[def.id] : null;
            addWidgetToGrid(def, pos);
            renderWidgetContent(def);
        });
    }

    function addWidgetToGrid(def, savedPos) {
        var x = savedPos ? savedPos.x : def.x;
        var y = savedPos ? savedPos.y : def.y;
        var w = savedPos ? savedPos.w : def.w;
        var h = savedPos ? savedPos.h : def.h;

        var uptimeHtml = def.type === 'cpumem' ? '<span class="uptime-live" id="uptime-' + def.id + '" style="font-size:0.7rem;color:#58a6ff;font-weight:400;letter-spacing:0;text-transform:none;margin-left:8px;font-family:monospace;"></span>' : '';
        var html = '<div class="widget-hdr"><h3>' + escapeHtml(def.title) + uptimeHtml + '</h3>' +
            '<button class="widget-close" data-wid="' + def.id + '">&times;</button></div>' +
            '<div class="widget-body" id="wb-' + def.id + '">' +
            (def.type === 'bandwidth' || def.type === 'cpumem' ? '<div class="widget-chart"><canvas id="wc-' + def.id + '"></canvas></div>' : '<div class="loading">Loading...</div>') +
            '</div>';

        grid.addWidget({ id: def.id, x: x, y: y, w: w, h: h, content: html });
    }

    // ---- Layout persistence ----
    function saveLayout() {
        if (!grid) return;
        var layout = {};
        grid.engine.nodes.forEach(function(n) {
            layout[n.id] = { x: n.x, y: n.y, w: n.w, h: n.h };
        });
        localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
    }

    function loadLayout() {
        try { return JSON.parse(localStorage.getItem(LAYOUT_KEY)); } catch(e) { return null; }
    }

    function resetLayout() {
        // AUDIT-063: confirm before wiping the operator's saved widget layout —
        // a single misclick previously destroyed it. A native confirm() is used
        // deliberately instead of pulling admin-common.js (AdminCommon.confirm)
        // into the public wallboard: that 36 KB + its /admin/api load-time fetch
        // would partly undo the AUDIT-052 first-paint optimization on a page
        // that is often an unattended TV.
        if (!window.confirm('Reset dashboard layout? This clears your saved widget arrangement and cannot be undone.')) return;
        localStorage.removeItem(LAYOUT_KEY);
        localStorage.removeItem(HIDDEN_KEY);
        location.reload();
    }

    // ---- Widget show/hide ----
    function hideWidget(widgetId) {
        var el = document.querySelector('[gs-id="' + widgetId + '"]');
        if (el && grid) {
            destroyWidgetChart(widgetId);
            grid.removeWidget(el);
        }
        hiddenWidgets[widgetId] = true;
        saveHiddenWidgets();
        saveLayout();
        updateWidgetMenu();
    }

    function showWidget(widgetId) {
        delete hiddenWidgets[widgetId];
        saveHiddenWidgets();
        var def = allWidgetDefs.find(function(d) { return d.id === widgetId; });
        if (def && grid) {
            addWidgetToGrid(def, null);
            renderWidgetContent(def);
        }
        updateWidgetMenu();
    }

    function updateWidgetMenu() {
        var dropdown = document.getElementById('widget-dropdown');
        if (!dropdown) return;
        dropdown.innerHTML = allWidgetDefs.map(function(def) {
            var checked = !hiddenWidgets[def.id] ? 'checked' : '';
            return '<label><input type="checkbox" ' + checked + ' data-toggle-widget="' + def.id + '"> ' + escapeHtml(def.title) + '</label>';
        }).join('');
    }

    function destroyWidgetChart(wid) {
        if (chartInstances[wid]) {
            chartInstances[wid].destroy();
            delete chartInstances[wid];
        }
    }

    // ---- Render widget contents ----
    function renderAllWidgets() {
        allWidgetDefs.forEach(function(def) {
            if (hiddenWidgets[def.id]) return;
            renderWidgetContent(def);
        });
    }

    function renderWidgetContent(def) {
        if (def.type === 'cpumem') renderCpuMemChart(def);
        else if (def.type === 'bandwidth') renderBandwidthChart(def);
        else if (def.type === 'vpn') renderVPN(def);
        else if (def.type === 'connmap') renderConnMap(def);
    }

    // ---- Uptime live counter ----
    function formatUptimeSeconds(totalSec) {
        if (!totalSec || totalSec <= 0) return '--';
        var d = Math.floor(totalSec / 86400);
        var h = Math.floor((totalSec % 86400) / 3600);
        var m = Math.floor((totalSec % 3600) / 60);
        var s = Math.floor(totalSec % 60);
        var parts = [];
        if (d > 0) parts.push(d + 'D');
        parts.push(h + 'H');
        parts.push(('0' + m).slice(-2) + 'M');
        parts.push(('0' + s).slice(-2) + 'S');
        return 'UPTIME ' + parts.join(' ');
    }

    function startUptimeCounter(wid, uptimeSeconds) {
        uptimeTimers[wid] = { baseSeconds: uptimeSeconds, startedAt: Date.now() };
        if (!uptimeIntervalId) {
            uptimeIntervalId = setInterval(tickUptimes, 1000);
        }
        tickUptimes();
    }

    function tickUptimes() {
        // Visibility gate (v0.10.214, bundle C2): no point paying for 1Hz DOM
        // writes when the dashboard isn't on-screen.
        if (document.hidden) return;
        var now = Date.now();
        Object.keys(uptimeTimers).forEach(function(wid) {
            var t = uptimeTimers[wid];
            var elapsed = Math.floor((now - t.startedAt) / 1000);
            var current = t.baseSeconds + elapsed;
            var el = document.getElementById('uptime-' + wid);
            if (el) el.textContent = formatUptimeSeconds(current);
        });
    }

    // ---- CPU/Memory Charts ----
    function renderCpuMemChart(def) {
        var wid = def.id;

        // Fetch uptime for this device (uptime_raw is SNMP timeticks in hundredths of a second)
        apiFetch(API_BASE + '/public/dashboard?device_id=' + def.deviceId).then(function(data) {
            if (data && data.uptime_raw) {
                startUptimeCounter(wid, Math.floor(data.uptime_raw / 100));
            } else if (data && data.uptime) {
                var el = document.getElementById('uptime-' + wid);
                if (el) el.textContent = 'UPTIME ' + data.uptime;
            }
        })['catch'](function() {});

        apiFetch(API_BASE + '/public/status-history?device_id=' + def.deviceId + '&hours=' + dashRange).then(function(points) {
            if (!points || points.length === 0) return;
            var labels;
            if (dashRange >= 168) {
                labels = points.map(function(p) { return formatInTimezone(p.timestamp, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }); });
            } else {
                labels = points.map(function(p) { return formatInTimezone(p.timestamp, { hour: '2-digit', minute: '2-digit' }); });
            }

            destroyWidgetChart(wid);
            var canvas = document.getElementById('wc-' + wid);
            if (!canvas) return;

            chartInstances[wid] = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        { label: 'CPU %', data: points.map(function(p) { return p.cpu_usage; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Memory %', data: points.map(function(p) { return p.memory_usage; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: chartOpts({ y: { min: 0, max: 100, ticks: { callback: function(v) { return v + '%'; } } } })
            });
        });
    }

    // ---- Bandwidth Charts (with bug fixes) ----
    function renderBandwidthChart(def) {
        var iface = def.iface;
        if (!iface) return;
        var wid = def.id;
        var url = API_BASE + '/public/interfaces/chart?device_id=' + iface.deviceId + '&index=' + iface.index + '&view=' + bwView + '&range=' + dashRange;

        apiFetch(url).then(function(data) {
            if (!data) return;

            var rxRate = (data.rx_rate || []).map(Number);
            var txRate = (data.tx_rate || []).map(Number);
            var rxTotal = (data.rx_total || []).map(Number);
            var txTotal = (data.tx_total || []).map(Number);

            // Per-interval deltas (fixes cumulative bug)
            var deltaRx = rxTotal.map(function(v, i) { if (i === 0) return 0; var d = v - rxTotal[i - 1]; return d > 0 ? d : 0; });
            var deltaTx = txTotal.map(function(v, i) { if (i === 0) return 0; var d = v - txTotal[i - 1]; return d > 0 ? d : 0; });

            // Format labels from timestamps for proper timezone handling
            var chartLabels;
            if (data.timestamps && data.timestamps.length > 0) {
                chartLabels = data.timestamps.map(function(ts) {
                    if (dashRange >= 168) {
                        return formatInTimezone(ts, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
                    } else {
                        return formatInTimezone(ts, { hour: '2-digit', minute: '2-digit' });
                    }
                });
            } else {
                chartLabels = data.labels || [];
            }

            var datasets = [];
            var scales = {};

            if (bwView === 'rate') {
                datasets = [
                    { label: 'RX (Mbps)', data: rxRate, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 },
                    { label: 'TX (Mbps)', data: txRate, borderColor: '#ff9500', backgroundColor: 'rgba(255,149,0,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 }
                ];
                scales = { y: { ticks: { callback: function(v) { return v.toFixed(1) + ' Mbps'; } }, title: { display: true, text: 'Mbps', color: '#484f58' } } };
            } else if (bwView === 'total') {
                // Bar chart with per-interval deltas
                datasets = [
                    { type: 'bar', label: 'RX Transfer', data: deltaRx, backgroundColor: 'rgba(63,185,80,0.6)', borderColor: '#3fb950', borderWidth: 1 },
                    { type: 'bar', label: 'TX Transfer', data: deltaTx, backgroundColor: 'rgba(255,149,0,0.6)', borderColor: '#ff9500', borderWidth: 1 }
                ];
                scales = { y: { ticks: { callback: function(v) { return formatBytes(v); } }, title: { display: true, text: 'Bytes/interval', color: '#484f58' } } };
            } else {
                // Mix: lines for rate (left axis) + bars for transfer delta (right axis)
                datasets = [
                    { label: 'RX (Mbps)', data: rxRate, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                    { label: 'TX (Mbps)', data: txRate, borderColor: '#ff9500', backgroundColor: 'rgba(255,149,0,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                    { type: 'bar', label: 'RX Transfer', data: deltaRx, backgroundColor: 'rgba(63,185,80,0.3)', borderWidth: 0, yAxisID: 'y1' },
                    { type: 'bar', label: 'TX Transfer', data: deltaTx, backgroundColor: 'rgba(255,149,0,0.3)', borderWidth: 0, yAxisID: 'y1' }
                ];
                scales = {
                    y: { position: 'left', ticks: { callback: function(v) { return v.toFixed(1); } }, title: { display: true, text: 'Mbps', color: '#484f58' } },
                    y1: { position: 'right', grid: { display: false }, ticks: { callback: function(v) { return formatBytes(v); } }, title: { display: true, text: 'Bytes', color: '#484f58' } }
                };
            }

            destroyWidgetChart(wid);
            var canvas = document.getElementById('wc-' + wid);
            if (!canvas) return;

            chartInstances[wid] = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: { labels: chartLabels, datasets: datasets },
                options: chartOpts(scales)
            });
        });
    }

    // ---- VPN Tunnels ----
    function renderVPN(def) {
        var body = document.getElementById('wb-' + def.id);
        if (!body) return;
        body.innerHTML = '<div class="loading">Loading VPN...</div>';

        var promises = allDevices.map(function(d) {
            return apiFetch(API_BASE + '/public/vpn?device_id=' + d.id).then(function(vpns) {
                return (vpns || []).map(function(v) { v.deviceName = d.name; return v; });
            })['catch'](function() { return []; });
        });

        Promise.all(promises).then(function(results) {
            var all = [];
            results.forEach(function(arr) { all = all.concat(arr); });
            if (all.length === 0) { body.innerHTML = '<div class="loading">No VPN tunnels</div>'; return; }
            body.innerHTML = '<div class="vpn-grid">' + all.map(function(v) {
                return '<div class="vpn-card"><div class="vpn-name">' + escapeHtml(v.tunnel_name) + '</div>' +
                    '<span class="vpn-status ' + (v.status || 'down') + '">' + (v.status || 'down').toUpperCase() + '</span> ' +
                    '<span style="color:#768390;font-size:0.6rem;">' + escapeHtml(v.deviceName) + '</span></div>';
            }).join('') + '</div>';
        });
    }

    // ---- Connection Map ----
    function renderConnMap(def) {
        var body = document.getElementById('wb-' + def.id);
        if (!body) return;
        body.innerHTML = '<div class="loading">Loading connections...</div>';

        apiFetch(API_BASE + '/public/connections').then(function(conns) {
            if (!conns || conns.length === 0) { body.innerHTML = '<div class="loading">No connections</div>'; return; }
            body.innerHTML = '<div style="position:relative;width:100%;height:100%;min-height:150px;">' +
                conns.map(function(c, i) {
                    var x = 15 + (i % 4) * 20;
                    var y = 15 + Math.floor(i / 4) * 30;
                    return '<div style="position:absolute;left:' + x + '%;top:' + y + '%;font-size:0.7rem;background:#21262d;padding:4px 8px;border-radius:4px;border:1px solid #30363d;">' +
                        '<span style="color:' + (c.status === 'up' ? '#3fb950' : '#f85149') + ';">●</span> ' +
                        escapeHtml(c.name) + '</div>';
                }).join('') + '</div>';
        });
    }

    // ---- Chart.js common options ----
    function chartOpts(scaleOverrides) {
        var scales = { x: { ticks: { color: '#484f58', maxTicksLimit: 8, maxRotation: 0 }, grid: { color: '#21262d' } } };
        for (var key in scaleOverrides) {
            scales[key] = Object.assign({}, { ticks: { color: '#484f58' }, grid: { color: '#21262d' } }, scaleOverrides[key]);
            if (scaleOverrides[key].ticks) scales[key].ticks = Object.assign({}, { color: '#484f58' }, scaleOverrides[key].ticks);
            if (scaleOverrides[key].title) scales[key].title = Object.assign({}, scaleOverrides[key].title);
        }
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            interaction: { intersect: false, mode: 'index' },
            plugins: { legend: { labels: { color: '#8b949e', font: { size: 10 } } } },
            scales: scales
        };
    }

    // ---- Auto-refresh ----
    function startRefresh() {
        var interval = parseInt(displaySettings['public_refresh_interval']) || 30;
        // Visibility-gated (v0.10.214, bundle C2). The previous setInterval
        // re-fetched every widget every N seconds even when the public
        // dashboard tab was hidden — wasted bandwidth on TVs/wallboards
        // when the browser was minimised.
        refreshTimer = setInterval(function() {
            if (document.hidden) return;
            allWidgetDefs.forEach(function(def) {
                if (hiddenWidgets[def.id]) return;
                renderWidgetContent(def);
            });
        }, interval * 1000);
        document.addEventListener('visibilitychange', function() {
            // On tab-becoming-visible, fire a refresh immediately so the
            // operator doesn't see stale data after switching back.
            if (!document.hidden) {
                allWidgetDefs.forEach(function(def) {
                    if (hiddenWidgets[def.id]) return;
                    renderWidgetContent(def);
                });
            }
        });
    }

    // ---- Event handlers ----
    document.addEventListener('click', function(e) {
        // Close widget
        var closeBtn = e.target.closest('.widget-close');
        if (closeBtn) {
            hideWidget(closeBtn.dataset.wid);
            return;
        }

        // Widget menu toggle
        if (e.target.id === 'widget-menu-btn' || e.target.closest('#widget-menu-btn')) {
            document.getElementById('widget-dropdown').classList.toggle('open');
            return;
        }

        // Reset layout
        if (e.target.id === 'btn-reset-layout' || e.target.closest('#btn-reset-layout')) {
            resetLayout();
            return;
        }

        // Close dropdown when clicking outside
        var dropdown = document.getElementById('widget-dropdown');
        if (dropdown && dropdown.classList.contains('open') && !dropdown.contains(e.target)) {
            dropdown.classList.remove('open');
        }
    });

    // Chart click to open modal - detect click vs GridStack drag
    document.addEventListener('mousedown', function(e) {
        var chartBody = e.target.closest('.widget-chart');
        if (chartBody) {
            modalDragStart = { x: e.clientX, y: e.clientY, time: Date.now() };
        }
    });

    document.addEventListener('mouseup', function(e) {
        if (!modalDragStart) return;
        var chartBody = e.target.closest('.widget-chart');
        if (chartBody) {
            var dx = e.clientX - modalDragStart.x;
            var dy = e.clientY - modalDragStart.y;
            var dist = Math.sqrt(dx*dx + dy*dy);
            var duration = Date.now() - modalDragStart.time;
            if (dist < 5 && duration < 200) {
                var wid = chartBody.querySelector('canvas').id.replace('wc-', '');
                var def = allWidgetDefs.find(function(d) { return d.id === wid; });
                if (def) openChartModal(def);
            }
        }
        modalDragStart = null;
    });

    // Modal controls
    document.addEventListener('click', function(e) {
        if (e.target.id === 'btn-close-modal' || e.target.closest('#btn-close-modal')) {
            closeChartModal();
            return;
        }
        if (e.target.id === 'btn-reset-zoom' || e.target.closest('#btn-reset-zoom')) {
            if (modalChart) modalChart.resetZoom();
            return;
        }
    });

    // Close modal on ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && document.getElementById('chart-modal').classList.contains('active')) {
            closeChartModal();
        }
    });

    // Widget toggle checkboxes
    document.addEventListener('change', function(e) {
        var toggle = e.target.dataset.toggleWidget;
        if (toggle) {
            if (e.target.checked) showWidget(toggle);
            else hideWidget(toggle);
        }
    });

    // View/range selects
    document.addEventListener('change', function(e) {
        if (e.target.id === 'bw-view') {
            bwView = e.target.value;
            refreshBandwidthCharts();
        } else if (e.target.id === 'dash-range') {
            dashRange = parseInt(e.target.value);
            refreshBandwidthCharts();
            refreshCpuCharts();
        }
    });

    function refreshBandwidthCharts() {
        allWidgetDefs.forEach(function(def) {
            if (def.type === 'bandwidth' && !hiddenWidgets[def.id]) renderBandwidthChart(def);
        });
    }

    function refreshCpuCharts() {
        allWidgetDefs.forEach(function(def) {
            if (def.type === 'cpumem' && !hiddenWidgets[def.id]) renderCpuMemChart(def);
        });
    }

    // ---- Chart Modal ----
    function openChartModal(def) {
        modalWidgetDef = def;
        modalRequestId++;
        var myRequestId = modalRequestId;
        document.getElementById('chart-modal-title').textContent = def.title;
        document.getElementById('chart-modal').classList.add('active');

        if (def.type === 'cpumem') {
            var url = API_BASE + '/public/status-history?device_id=' + def.deviceId + '&hours=' + dashRange;
            renderModalCpuChart(url, myRequestId);
        } else if (def.type === 'bandwidth') {
            var url = API_BASE + '/public/interfaces/chart?device_id=' + def.iface.deviceId + '&index=' + def.iface.index + '&view=' + bwView + '&range=' + dashRange;
            renderModalBandwidthChart(url, myRequestId);
        }
    }

    function closeChartModal() {
        if (modalChart) { modalChart.destroy(); modalChart = null; }
        modalWidgetDef = null;
        modalRequestId++;
        document.getElementById('chart-modal').classList.remove('active');
    }

    function renderModalCpuChart(url, requestId) {
        if (modalChart) { modalChart.destroy(); modalChart = null; }
        if (requestId !== modalRequestId) return;
        var canvas = document.getElementById('modal-chart-canvas');

        apiFetch(url).then(function(points) {
            if (requestId !== modalRequestId) return;
            if (!points || points.length === 0) return;
            var labels;
            if (dashRange >= 168) {
                labels = points.map(function(p) { return formatInTimezone(p.timestamp, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }); });
            } else {
                labels = points.map(function(p) { return formatInTimezone(p.timestamp, { hour: '2-digit', minute: '2-digit' }); });
            }

            modalChart = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        { label: 'CPU %', data: points.map(function(p) { return p.cpu_usage; }), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                        { label: 'Memory %', data: points.map(function(p) { return p.memory_usage; }), borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 0 },
                    interaction: { intersect: false, mode: 'index' },
                    plugins: {
                        legend: { labels: { color: '#8b949e', font: { size: 11 } } },
                        zoom: {
                            zoom: {
                                wheel: { enabled: true },
                                drag: { enabled: true },
                                mode: 'x'
                            }
                        }
                    },
                    scales: {
                        x: { ticks: { color: '#484f58', maxTicksLimit: 12, maxRotation: 0 }, grid: { color: '#21262d' } },
                        y: { min: 0, max: 100, ticks: { color: '#484f58', callback: function(v) { return v + '%'; } }, grid: { color: '#21262d' } }
                    }
                }
            });
        });
    }

    function renderModalBandwidthChart(url, requestId) {
        if (modalChart) { modalChart.destroy(); modalChart = null; }
        if (requestId !== modalRequestId) return;
        var canvas = document.getElementById('modal-chart-canvas');

        apiFetch(url).then(function(data) {
            if (requestId !== modalRequestId) return;
            if (!data) return;

            var chartLabels;
            if (data.timestamps && data.timestamps.length > 0) {
                chartLabels = data.timestamps.map(function(ts) {
                    if (dashRange >= 168) {
                        return formatInTimezone(ts, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
                    } else {
                        return formatInTimezone(ts, { hour: '2-digit', minute: '2-digit' });
                    }
                });
            } else {
                chartLabels = data.labels || [];
            }

            if (chartLabels.length === 0) return;

            var rxRate = (data.rx_rate || []).map(Number);
            var txRate = (data.tx_rate || []).map(Number);
            var rxTotal = (data.rx_total || []).map(Number);
            var txTotal = (data.tx_total || []).map(Number);
            var deltaRx = rxTotal.map(function(v, i) { if (i === 0) return 0; var d = v - rxTotal[i - 1]; return d > 0 ? d : 0; });
            var deltaTx = txTotal.map(function(v, i) { if (i === 0) return 0; var d = v - txTotal[i - 1]; return d > 0 ? d : 0; });

            var datasets, scales;
            if (bwView === 'rate') {
                datasets = [
                    { label: 'RX (Mbps)', data: rxRate, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 },
                    { label: 'TX (Mbps)', data: txRate, borderColor: '#ff9500', backgroundColor: 'rgba(255,149,0,0.1)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5 }
                ];
                scales = { y: { ticks: { color: '#484f58', callback: function(v) { return v.toFixed(1) + ' Mbps'; } }, grid: { color: '#21262d' } } };
            } else if (bwView === 'total') {
                datasets = [
                    { type: 'bar', label: 'RX Transfer', data: deltaRx, backgroundColor: 'rgba(63,185,80,0.6)', borderColor: '#3fb950', borderWidth: 1 },
                    { type: 'bar', label: 'TX Transfer', data: deltaTx, backgroundColor: 'rgba(255,149,0,0.6)', borderColor: '#ff9500', borderWidth: 1 }
                ];
                scales = { y: { ticks: { color: '#484f58', callback: function(v) { return formatBytes(v); } }, grid: { color: '#21262d' } } };
            } else {
                datasets = [
                    { label: 'RX (Mbps)', data: rxRate, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                    { label: 'TX (Mbps)', data: txRate, borderColor: '#ff9500', backgroundColor: 'rgba(255,149,0,0.08)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y' },
                    { type: 'bar', label: 'RX Transfer', data: deltaRx, backgroundColor: 'rgba(63,185,80,0.3)', borderWidth: 0, yAxisID: 'y1' },
                    { type: 'bar', label: 'TX Transfer', data: deltaTx, backgroundColor: 'rgba(255,149,0,0.3)', borderWidth: 0, yAxisID: 'y1' }
                ];
                scales = {
                    y: { position: 'left', ticks: { color: '#484f58', callback: function(v) { return v.toFixed(1); } }, grid: { color: '#21262d' } },
                    y1: { position: 'right', grid: { display: false }, ticks: { color: '#484f58', callback: function(v) { return formatBytes(v); } } }
                };
            }

            modalChart = new Chart(canvas.getContext('2d'), {
                type: bwView === 'total' ? 'bar' : 'line',
                data: { labels: chartLabels, datasets: datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 0 },
                    interaction: { intersect: false, mode: 'index' },
                    plugins: {
                        legend: { labels: { color: '#8b949e', font: { size: 11 } } },
                        zoom: {
                            zoom: {
                                wheel: { enabled: true },
                                drag: { enabled: true },
                                mode: 'x'
                            }
                        }
                    },
                    scales: Object.assign(
                        { x: { ticks: { color: '#484f58', maxTicksLimit: 12, maxRotation: 0 }, grid: { color: '#21262d' } } },
                        scales
                    )
                }
            });
        });
    }

    // ---- Start ----
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
