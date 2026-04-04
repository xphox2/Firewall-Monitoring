// admin-main.js — Main admin page logic extracted from admin.html
(function() {
    'use strict';

    var AC = window.AdminCommon;
    var API_BASE = AC.API_BASE;
    var escapeHtml = AC.escapeHtml;
    var apiFetch = AC.apiFetch;

    var formatDate = AC.formatDate;

    // Expose apiFetch globally for diagram-panels.js interop
    window.apiFetch = apiFetch;

    var currentDevices = [];
    var currentConnections = [];
    var currentVpnMap = {};
    var currentProbes = [];
    var currentSites = [];
    var adminRefreshTimer;
    var syslogRefreshTimer;
    var syslogOffset = 0;
    var flowsOffset = 0;
    var alertsOffset = 0;
    var trapsOffset = 0;
    var chartInstances = {};
    var deviceSiteMap = {};
    var ifacePage = 1;
    var ifacePageSize = 50;
    var flowStatsHours = 24;

    // Expose globals for diagram-panels.js and other diagram modules
    window.currentConnections = currentConnections;
    window.currentDevices = currentDevices;

    var SEVERITY_NAMES = ['Emergency','Alert','Critical','Error','Warning','Notice','Info','Debug'];
    var PROTOCOL_NAMES = {0:'HOPOPT',1:'ICMP',2:'IGMP',4:'IPv4',6:'TCP',8:'EGP',17:'UDP',41:'IPv6',43:'IPv6-Route',44:'IPv6-Frag',47:'GRE',50:'ESP',51:'AH',58:'ICMPv6',59:'IPv6-NoNxt',60:'IPv6-Opts',88:'EIGRP',89:'OSPF',103:'PIM',112:'VRRP',132:'SCTP',137:'MPLS-in-IP'};

    function severityBadgeClass(sev) {
        if (sev <= 1) return 'emergency';
        if (sev === 2) return 'critical';
        if (sev === 3) return 'error';
        if (sev === 4) return 'warning';
        if (sev === 5) return 'notice';
        if (sev === 6) return 'info';
        return 'debug';
    }

    // Connection type visual style mapping
    function connStyle(type) {
        var styles = {
            ipsec:    { color: '#58a6ff', dash: null, width: 3 },
            ssl:      { color: '#d29922', dash: null, width: 3 },
            vxlan:    { color: '#8957e5', dash: '8,4', width: 3 },
            l2vlan:   { color: '#39d4e0', dash: null, width: 3 },
            l3ipvlan: { color: '#da7de8', dash: '12,4', width: 3 },
            gre:      { color: '#b392f0', dash: null, width: 3 },
            wan:      { color: '#f0883e', dash: null, width: 3 },
            lag:      { color: '#d29922', dash: null, width: 4 },
            ethernet: { color: '#6e7681', dash: null, width: 2 },
            tunnel:   { color: '#8b949e', dash: null, width: 3 }
        };
        return styles[type] || styles.tunnel;
    }
    window.connStyle = connStyle;

    function typeBadgeHtml(type) {
        var labels = {ipsec:'IPSec',vxlan:'VXLAN',ssl:'SSL VPN',wan:'WAN',l2vlan:'L2VLAN',l3ipvlan:'L3IPVLAN',gre:'GRE',lag:'LAG',ethernet:'Ethernet',tunnel:'Tunnel'};
        var cs = connStyle(type);
        return '<span class="badge" style="background:' + cs.color + '22;color:' + cs.color + ';">' + escapeHtml(labels[type] || (type || 'tunnel').toUpperCase()) + '</span>';
    }
    window.typeBadgeHtml = typeBadgeHtml;

    function matchMethodBadge(method, autoDetected) {
        if (!autoDetected) return '<span style="color:#8b949e;font-size:0.75rem;">Manual</span>';
        var badges = {
            'ip_match': '<span class="badge" style="background:#238636;font-size:0.65rem;padding:1px 5px;">Direct</span>',
            'interface_ip': '<span class="badge" style="background:#238636;font-size:0.65rem;padding:1px 5px;">Direct</span>',
            'bidirectional': '<span class="badge" style="background:#238636;font-size:0.65rem;padding:1px 5px;">Direct</span>',
            'subnet_match': '<span class="badge" style="background:#238636;font-size:0.65rem;padding:1px 5px;">Direct</span>',
            'tunnel_indirect': '<span class="badge" style="background:#f0883e;font-size:0.65rem;padding:1px 5px;">Indirect</span>',
            'wan_inferred': '<span class="badge" style="background:#f0883e;font-size:0.65rem;padding:1px 5px;">Indirect</span>',
            'name_match': '<span class="badge" style="background:#f0883e;font-size:0.65rem;padding:1px 5px;">Indirect</span>',
            'overlay_name': '<span class="badge" style="background:#f0883e;font-size:0.65rem;padding:1px 5px;">Indirect</span>'
        };
        return badges[method] || badges['ip_match'];
    }
    window.matchMethodBadge = matchMethodBadge;

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var units = ['B','KB','MB','GB','TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }
    window.formatBytes = formatBytes;

    function formatBps(bps) {
        if (!bps || bps <= 0) return '0 bps';
        if (bps < 1) return bps.toFixed(2) + ' bps';
        var units = ['bps','Kbps','Mbps','Gbps','Tbps'];
        var i = Math.floor(Math.log(bps) / Math.log(1000));
        if (i < 0) i = 0;
        if (i >= units.length) i = units.length - 1;
        return (bps / Math.pow(1000, i)).toFixed(1) + ' ' + units[i];
    }

    function formatNum(n) { return n != null ? Number(n).toLocaleString() : '0'; }
    window.formatNum = formatNum;

    function timeAgo(dateStr) {
        var d = new Date(dateStr);
        var s = Math.floor((Date.now() - d) / 1000);
        if (s < 60) return s + 's ago';
        if (s < 3600) return Math.floor(s/60) + 'm ago';
        if (s < 86400) return Math.floor(s/3600) + 'h ago';
        return Math.floor(s/86400) + 'd ago';
    }

    // ---- Navigation ----
    document.querySelectorAll('.nav-item[data-page]').forEach(function(item) {
        item.addEventListener('click', function() {
            document.querySelectorAll('.nav-item').forEach(function(i) { i.classList.remove('active'); });
            item.classList.add('active');
            document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
            var page = item.dataset.page;
            document.getElementById('page-' + page).classList.add('active');
            document.getElementById('page-title').textContent = item.textContent.trim();
            history.pushState(null, '', '/admin/' + (page === 'dashboard' ? '' : page));
            loadPageData(page);
        });
    });

    function loadPageData(page) {
        switch(page) {
            case 'dashboard': loadDashboard(); break;
            case 'devices': loadDevices(); break;
            case 'interfaces': populateIfaceFilters().then(function() { loadInterfaces(); }); break;
            case 'connections': loadConnections(); break;
            case 'syslog': loadSyslog(); break;
            case 'flows': loadFlows(); break;
            case 'settings': loadSettings(); break;
            case 'alerts': loadAlerts(); break;
            case 'traps': loadTraps(); break;
            case 'alert-policies': loadAlertPolicies(); break;
            case 'maintenance': loadMaintenance(); break;
        }
    }

    // ---- Dashboard ----
    function loadDashboard() {
        Promise.all([
            apiFetch(API_BASE + '/dashboard'),
            apiFetch(API_BASE + '/probes'),
            apiFetch(API_BASE + '/syslog/stats'),
            apiFetch(API_BASE + '/traps/stats')
        ]).then(function(results) {
            var dashResult = results[0];
            var probesResult = results[1];
            var syslogStatsResult = results[2];
            var trapStatsResult = results[3];
            if (!dashResult) return;
            var raw = dashResult.data;
            var data = raw.dashboard || raw;
            var probes = probesResult && probesResult.data ? probesResult.data : [];

            var deviceList = data.devices || [];
            document.getElementById('total-devices').textContent = deviceList.length || 0;
            document.getElementById('online-devices').textContent = deviceList.filter(function(f) { return f.status === 'online'; }).length || 0;
            document.getElementById('offline-devices').textContent = deviceList.filter(function(f) { return f.status === 'offline'; }).length || 0;

            var activeProbes = probes.filter(function(p) { return p.approval_status === 'approved' && p.status === 'online'; });
            document.getElementById('active-probes').textContent = activeProbes.length;
            document.getElementById('syslog-count').textContent = (syslogStatsResult && syslogStatsResult.data ? syslogStatsResult.data.total || 0 : 0).toLocaleString();
            document.getElementById('trap-count').textContent = (trapStatsResult && trapStatsResult.data ? trapStatsResult.data.total || 0 : 0).toLocaleString();

            // Probe health cards
            var probeContainer = document.getElementById('probe-health-cards');
            if (probes.length === 0) {
                probeContainer.innerHTML = '<div class="empty-state">No probes configured</div>';
            } else {
                probeContainer.innerHTML = probes.map(function(p) {
                    var statusClass = p.status === 'online' ? 'online' : (p.status === 'offline' ? 'offline' : 'pending');
                    var lastSeen = p.last_seen ? timeAgo(p.last_seen) : 'Never';
                    return '<div class="probe-card">' +
                        '<div class="probe-name"><span class="pulse-dot ' + statusClass + '"></span>' + escapeHtml(p.name) + '</div>' +
                        '<div class="probe-meta">' + escapeHtml(p.site ? p.site.name : 'No Site') + ' &middot; ' + escapeHtml(p.approval_status) + ' &middot; Last seen: ' + lastSeen + '</div>' +
                        '<div class="probe-stats" id="probe-stats-' + p.id + '">' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Syslog</div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Traps</div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Flows</div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Pings</div></div>' +
                        '</div></div>';
                }).join('');

                // Load stats for each probe
                probes.forEach(function(p) {
                    apiFetch(API_BASE + '/probes/' + p.id + '/stats').then(function(r) {
                        if (!r || !r.data) return;
                        var el = document.getElementById('probe-stats-' + p.id);
                        if (el) {
                            var d = r.data;
                            el.innerHTML =
                                '<div class="probe-stat"><div class="val">' + (d.syslog || 0) + '</div><div class="lbl">Syslog</div></div>' +
                                '<div class="probe-stat"><div class="val">' + (d.traps || 0) + '</div><div class="lbl">Traps</div></div>' +
                                '<div class="probe-stat"><div class="val">' + (d.flows || 0) + '</div><div class="lbl">Flows</div></div>' +
                                '<div class="probe-stat"><div class="val">' + (d.pings || 0) + '</div><div class="lbl">Pings</div></div>';
                        }
                    })['catch'](function() {});
                });
            }

            loadDashboardCharts();
        })['catch'](function(e) {
            console.error('Failed to load dashboard:', e);
        });
    }

    function loadDashboardCharts() {
        apiFetch(API_BASE + '/dashboard/stats').then(function(result) {
            if (!result || !result.data) return;
            var d = result.data;

            // Activity trend chart
            var actLabels = [];
            var actSyslog = [];
            var actTraps = [];
            var actAlerts = [];
            var allBuckets = {};
            (d.syslog_over_time || []).forEach(function(b) { allBuckets[b.bucket] = true; });
            (d.traps_over_time || []).forEach(function(b) { allBuckets[b.bucket] = true; });
            (d.alerts_over_time || []).forEach(function(b) { allBuckets[b.bucket] = true; });
            var sortedBuckets = Object.keys(allBuckets).sort();
            var sysMap = {};
            (d.syslog_over_time || []).forEach(function(b) { sysMap[b.bucket] = b.count; });
            var trapMap = {};
            (d.traps_over_time || []).forEach(function(b) { trapMap[b.bucket] = b.count; });
            var alertMap = {};
            (d.alerts_over_time || []).forEach(function(b) { alertMap[b.bucket] = b.count; });
            sortedBuckets.forEach(function(b) {
                actLabels.push(b.substring(11,16) || b);
                actSyslog.push(sysMap[b] || 0);
                actTraps.push(trapMap[b] || 0);
                actAlerts.push(alertMap[b] || 0);
            });
            createChart('dashboard-activity-chart', 'line', actLabels, [
                {label:'Syslog',data:actSyslog,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',fill:true,tension:0.3},
                {label:'Traps',data:actTraps,borderColor:'#d2992a',backgroundColor:'rgba(210,153,42,0.1)',fill:true,tension:0.3},
                {label:'Alerts',data:actAlerts,borderColor:'#f85149',backgroundColor:'rgba(248,81,73,0.1)',fill:true,tension:0.3}
            ]);

            // Device status doughnut
            var devLabels = (d.device_status || []).map(function(s) { return s.key || 'unknown'; });
            var devCounts = (d.device_status || []).map(function(s) { return s.count; });
            var devColors = devLabels.map(function(l) { return l === 'online' ? '#3fb950' : l === 'offline' ? '#f85149' : '#8b949e'; });
            createChart('dashboard-device-chart', 'doughnut', devLabels, [{data:devCounts,backgroundColor:devColors,borderWidth:0}]);
        })['catch'](function(e) { console.error('Failed to load dashboard charts:', e); });
    }

    function createChart(canvasId, type, labels, datasets, opts) {
        if (chartInstances[canvasId]) { chartInstances[canvasId].destroy(); }
        var ctx = document.getElementById(canvasId);
        if (!ctx) return;
        var defaults = {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 12, padding: 8, font: {size:11} } } },
            scales: type === 'doughnut' ? {} : {
                x: { ticks: { color: '#484f58', font:{size:10}, maxRotation: 0 }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#484f58', font:{size:10} }, grid: { color: '#21262d' }, beginAtZero: true }
            }
        };
        var mergedOpts = Object.assign({}, defaults, opts || {});
        chartInstances[canvasId] = new Chart(ctx, { type: type, data: { labels: labels, datasets: datasets }, options: mergedOpts });
    }

    // ---- Devices ----
    function loadDevices() {
        Promise.all([
            apiFetch(API_BASE + '/devices'),
            apiFetch(API_BASE + '/probes'),
            apiFetch(API_BASE + '/sites')
        ]).then(function(results) {
            var devResult = results[0];
            var probeResult = results[1];
            var siteResult = results[2];
            if (!devResult) return;
            currentDevices = devResult.data || [];
            currentProbes = probeResult && probeResult.data ? probeResult.data : [];
            currentSites = siteResult && siteResult.data ? siteResult.data : [];
            window.currentDevices = currentDevices;

            populateProbeSelect('device-probe');
            populateSiteSelect('device-site');

            var tbody = document.querySelector('#devices-table tbody');
            tbody.innerHTML = currentDevices.map(function(d) {
                return '<tr>' +
                    '<td><a href="/admin/devices/' + d.id + '" style="color:#58a6ff;text-decoration:none;font-weight:600">' + escapeHtml(d.name) + '</a>' + (d.description ? '<br><span style="color:#484f58;font-size:0.78rem;">' + escapeHtml(d.description) + '</span>' : '') + '</td>' +
                    '<td class="mono">' + escapeHtml(d.ip_address) + '</td>' +
                    '<td>' + (d.probe ? escapeHtml(d.probe.name) : '<span style="color:#484f58">-</span>') + '</td>' +
                    '<td>' + (d.site ? escapeHtml(d.site.name) : '<span style="color:#484f58">-</span>') + '</td>' +
                    '<td id="dev-cpu-' + d.id + '" style="color:#484f58">-</td>' +
                    '<td id="dev-mem-' + d.id + '" style="color:#484f58">-</td>' +
                    '<td id="dev-sess-' + d.id + '" style="color:#484f58">-</td>' +
                    '<td><span class="pulse-dot ' + (d.status === 'online' ? 'online' : 'offline') + '"></span><span class="badge ' + escapeHtml(d.status) + '">' + escapeHtml(d.status).toUpperCase() + '</span></td>' +
                    '<td>' +
                        '<button class="btn secondary sm" data-action="device-alert-config" data-id="' + d.id + '">Alerts</button> ' +
                        '<button class="btn secondary sm" data-action="edit-device" data-id="' + d.id + '">Edit</button> ' +
                        '<button class="btn danger sm" data-action="delete-device" data-id="' + d.id + '">Delete</button>' +
                    '</td>' +
                '</tr>';
            }).join('') || '<tr><td colspan="9" class="empty-state">No devices configured</td></tr>';

            loadDeviceEnrichments();
            loadDeviceAlertIndicators();
        })['catch'](function(e) {
            console.error('Failed to load devices:', e);
        });
    }

    function loadDeviceAlertIndicators() {
        currentDevices.forEach(function(d) {
            apiFetch(API_BASE + '/devices/' + d.id + '/alert-config').then(function(resp) {
                if (!resp || !resp.data || !resp.data.id) return;
                var cfg = resp.data;
                var nameCell = document.querySelector('#devices-table a[href="/admin/devices/' + d.id + '"]');
                if (!nameCell) return;
                // Remove existing indicators
                var existing = nameCell.parentNode.querySelector('.device-alert-indicator');
                if (existing) existing.remove();
                var indicator = document.createElement('span');
                indicator.className = 'device-alert-indicator';
                if (!cfg.alerts_enabled) {
                    indicator.className += ' muted';
                    indicator.title = 'Alerts disabled';
                } else {
                    indicator.className += ' custom';
                    indicator.title = 'Custom alert config';
                }
                nameCell.parentNode.insertBefore(indicator, nameCell.nextSibling);
            })['catch'](function() {});
        });
    }

    function loadDeviceEnrichments() {
        apiFetch(API_BASE + '/dashboard').then(function(r) {
            if (!r || !r.data || !r.data.enrichments) return;
            var enrichments = r.data.enrichments;
            Object.keys(enrichments).forEach(function(id) {
                var e = enrichments[id];
                var cpuEl = document.getElementById('dev-cpu-' + id);
                var memEl = document.getElementById('dev-mem-' + id);
                var sessEl = document.getElementById('dev-sess-' + id);
                var rows = e.status_rows || 0;
                if (!e.has_status) {
                    if (cpuEl) { cpuEl.textContent = 'No data'; cpuEl.title = '0 system_status records (device_id=' + id + '). Check collector logs.'; }
                    if (memEl) { memEl.textContent = 'No data'; memEl.title = '0 system_status records (device_id=' + id + ').'; }
                    if (sessEl) { sessEl.textContent = 'No data'; sessEl.title = '0 system_status records (device_id=' + id + ').'; }
                    return;
                }
                var polledInfo = e.status_time ? 'Last: ' + formatDate(e.status_time) + ' | ' + rows + ' records' : rows + ' records';
                if (cpuEl) {
                    cpuEl.textContent = e.cpu_usage.toFixed(1) + '%';
                    cpuEl.style.color = e.cpu_usage >= 80 ? '#f85149' : (e.cpu_usage >= 60 ? '#d29922' : '#3fb950');
                    cpuEl.title = polledInfo;
                }
                if (memEl) {
                    memEl.textContent = e.memory_usage.toFixed(1) + '%';
                    memEl.style.color = e.memory_usage >= 80 ? '#f85149' : (e.memory_usage >= 60 ? '#d29922' : '#3fb950');
                    memEl.title = polledInfo;
                }
                if (sessEl) {
                    sessEl.textContent = e.session_count.toLocaleString();
                    sessEl.style.color = '#c9d1d9';
                    sessEl.title = polledInfo;
                }
            });
        })['catch'](function() {});
    }

    // ---- Interfaces ----
    function loadInterfaces() {
        ifacePage = 1;
        fetchInterfaces();
    }

    function fetchInterfaces() {
        var deviceFilter = document.getElementById('iface-filter-device').value;
        var statusFilter = document.getElementById('iface-filter-status').value;
        var typeFilter = document.getElementById('iface-filter-type').value;
        var url = API_BASE + '/interfaces?page=' + ifacePage + '&page_size=' + ifacePageSize;
        if (deviceFilter) url += '&device_id=' + deviceFilter;
        if (statusFilter) url += '&status=' + statusFilter;
        if (typeFilter) url += '&type=' + encodeURIComponent(typeFilter);

        apiFetch(url).then(function(result) {
            if (!result || !result.data) return;
            var ifaces = result.data.interfaces || [];
            var total = result.data.total || 0;

            var tbody = document.querySelector('#interfaces-table tbody');
            tbody.innerHTML = ifaces.map(function(i) {
                return '<tr>' +
                    '<td><a href="/admin/devices/' + i.device_id + '" style="color:#58a6ff;text-decoration:none;font-weight:500">' + escapeHtml(i.device_name) + '</a></td>' +
                    '<td><strong>' + escapeHtml(i.name) + '</strong></td>' +
                    '<td>' + escapeHtml(i.alias || '') + '</td>' +
                    '<td>' + escapeHtml(i.type_name || String(i.type)) + '</td>' +
                    '<td>' + formatIfaceSpeed(i) + '</td>' +
                    '<td><span class="badge ' + i.status + '">' + escapeHtml(i.status) + '</span></td>' +
                    '<td><span class="badge ' + (i.admin_status === 'up' ? 'up' : 'down') + '">' + escapeHtml(i.admin_status || 'unknown') + '</span></td>' +
                    '<td>' + formatBytesShort(i.in_bytes) + '</td>' +
                    '<td>' + formatBytesShort(i.out_bytes) + '</td>' +
                    '<td>' + ((i.in_errors || 0) + (i.out_errors || 0)) + '</td>' +
                '</tr>';
            }).join('') || '<tr><td colspan="10" class="empty-state">No interfaces found</td></tr>';

            var totalPages = Math.ceil(total / ifacePageSize) || 1;
            document.getElementById('iface-page-info').textContent = 'Page ' + ifacePage + ' of ' + totalPages + ' (' + total + ' interfaces)';
            document.getElementById('iface-prev').disabled = ifacePage <= 1;
            document.getElementById('iface-next').disabled = ifacePage >= totalPages;
        })['catch'](function(e) { console.error('Failed to load interfaces:', e); });
    }

    function ifacePrevPage() { if (ifacePage > 1) { ifacePage--; fetchInterfaces(); } }
    function ifaceNextPage() { ifacePage++; fetchInterfaces(); }

    function populateIfaceFilters() {
        return apiFetch(API_BASE + '/devices').then(function(devResult) {
            if (devResult && devResult.data) {
                var sel = document.getElementById('iface-filter-device');
                sel.innerHTML = '<option value="">All Devices</option>' + devResult.data.map(function(d) {
                    return '<option value="' + d.id + '">' + escapeHtml(d.name) + '</option>';
                }).join('');
            }
            return apiFetch(API_BASE + '/interfaces?page=1&page_size=500');
        }).then(function(result) {
            if (result && result.data && result.data.interfaces) {
                var typeSet = {};
                result.data.interfaces.forEach(function(i) { if (i.type_name) typeSet[i.type_name] = true; });
                var types = Object.keys(typeSet).sort();
                var sel = document.getElementById('iface-filter-type');
                sel.innerHTML = '<option value="">All Types</option>' + types.map(function(t) {
                    return '<option value="' + encodeURIComponent(t) + '">' + escapeHtml(t) + '</option>';
                }).join('');
            }
        })['catch'](function(e) { console.error('Failed to populate interface filters:', e); });
    }

    function formatIfaceSpeed(iface) {
        if (iface.high_speed && iface.high_speed > 0) {
            if (iface.high_speed >= 1000) return (iface.high_speed / 1000).toFixed(0) + ' Gbps';
            return iface.high_speed + ' Mbps';
        }
        if (iface.speed) {
            var mbps = iface.speed / 1000000;
            if (mbps >= 1000) return (mbps / 1000).toFixed(0) + ' Gbps';
            if (mbps >= 1) return mbps.toFixed(0) + ' Mbps';
        }
        return '-';
    }

    function formatBytesShort(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0, val = bytes;
        while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
        return val.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    function populateProbeSelect(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        var current = sel.value;
        sel.innerHTML = '<option value="">None</option>' + currentProbes.map(function(p) {
            return '<option value="' + p.id + '">' + escapeHtml(p.name) + (p.site ? ' (' + escapeHtml(p.site.name) + ')' : '') + '</option>';
        }).join('');
        sel.value = current;
    }

    function populateSiteSelect(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        var current = sel.value;
        sel.innerHTML = '<option value="">None</option>' + currentSites.map(function(s) {
            return '<option value="' + s.id + '">' + escapeHtml(s.name) + (s.region ? ' - ' + escapeHtml(s.region) : '') + '</option>';
        }).join('');
        sel.value = current;
    }

    // ---- Connections ----
    function loadConnections() {
        Promise.all([
            apiFetch(API_BASE + '/devices'),
            apiFetch(API_BASE + '/connections'),
            apiFetch(API_BASE + '/connections/vpn-map').catch(function() { return {data: {}}; }),
            apiFetch(API_BASE + '/sites').catch(function() { return {data: []}; })
        ]).then(function(results) {
            var devicesResult = results[0];
            var connsResult = results[1];
            var vpnMapResult = results[2];
            var sitesResult = results[3];
            if (!devicesResult || !connsResult) return;
            currentDevices = devicesResult.data || [];
            currentConnections = connsResult.data || [];
            currentVpnMap = vpnMapResult && vpnMapResult.data ? vpnMapResult.data : {};
            currentSites = sitesResult && sitesResult.data ? sitesResult.data : [];
            window.currentConnections = currentConnections;
            window.currentDevices = currentDevices;
            deviceSiteMap = {};
            currentDevices.forEach(function(d) { deviceSiteMap[d.id] = d.site_id || null; });

            var tbody = document.querySelector('#connections-table tbody');
            tbody.innerHTML = currentConnections.map(function(c) {
                var deleteBtn = c.auto_detected
                    ? '<span style="color:#8b949e;font-size:0.8rem;">Auto-managed</span>'
                    : '<button class="btn danger sm" data-action="delete-connection" data-id="' + c.id + '">Delete</button>';
                return '<tr>' +
                    '<td>' + escapeHtml(c.name) + (c.auto_detected ? ' <span class="badge" style="background:#388bfd;font-size:0.65rem;padding:1px 5px;">AUTO</span>' : '') + '</td>' +
                    '<td>' + (escapeHtml(c.source_device ? c.source_device.name : '') || c.source_device_id) + '</td>' +
                    '<td>' + (escapeHtml(c.dest_device ? c.dest_device.name : '') || c.dest_device_id) + '</td>' +
                    '<td>' + escapeHtml(c.connection_type ? c.connection_type.toUpperCase() : 'IPSEC') + '</td>' +
                    '<td><span class="badge ' + escapeHtml(c.status) + '">' + escapeHtml(c.status).toUpperCase() + '</span></td>' +
                    '<td>' + matchMethodBadge(c.match_method, c.auto_detected) + '</td>' +
                    '<td style="font-size:0.8rem;color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(c.tunnel_names || '') + '">' + escapeHtml(c.tunnel_names || '-') + '</td>' +
                    '<td><a href="/admin/connections/' + c.id + '" style="color:#58a6ff;font-size:0.8rem;margin-right:8px;">Details</a>' + deleteBtn + '</td>' +
                '</tr>';
            }).join('') || '<tr><td colspan="8" class="empty-state">No connections configured</td></tr>';

            drawConnectionDiagram();
            populateDeviceSelects();
        })['catch'](function(e) {
            console.error('Failed to load connections:', e);
        });
    }

    // ---- Syslog ----
    function loadSyslog() {
        syslogOffset = 0;
        var p = Promise.resolve();
        if (currentProbes.length === 0) {
            p = apiFetch(API_BASE + '/probes').then(function(pr) { currentProbes = pr && pr.data ? pr.data : []; });
        }
        p.then(function() {
            if (currentDevices.length === 0) {
                return apiFetch(API_BASE + '/devices').then(function(dr) { currentDevices = dr && dr.data ? dr.data : []; });
            }
        }).then(function() {
            populateFilterProbes('syslog-filter-probe');
            populateFilterDevices('syslog-filter-device');
            var params = buildSyslogParams(100);
            return apiFetch(API_BASE + '/syslog?' + params);
        }).then(function(result) {
            if (!result) return;
            var messages = result.data || [];
            renderSyslogTable(messages, false);
            syslogOffset = messages.length;
            loadSyslogCharts();
        })['catch'](function(e) {
            console.error('Failed to load syslog:', e);
        });
    }

    function loadSyslogCharts() {
        apiFetch(API_BASE + '/syslog/stats').then(function(result) {
            if (!result || !result.data) return;
            var d = result.data;
            document.getElementById('syslog-total').textContent = (d.total || 0).toLocaleString();
            var crit = 0, warn = 0, info = 0;
            (d.by_severity || []).forEach(function(s) {
                if (['Emergency','Alert','Critical'].indexOf(s.key) !== -1) crit += s.count;
                else if (['Error','Warning'].indexOf(s.key) !== -1) warn += s.count;
                else info += s.count;
            });
            document.getElementById('syslog-critical').textContent = crit.toLocaleString();
            document.getElementById('syslog-warning').textContent = warn.toLocaleString();
            document.getElementById('syslog-info').textContent = info.toLocaleString();

            var labels = (d.over_time || []).map(function(b) { return b.bucket.substring(11,16) || b.bucket; });
            var counts = (d.over_time || []).map(function(b) { return b.count; });
            createChart('syslog-trend-chart','bar',labels,[{label:'Messages',data:counts,backgroundColor:'#58a6ff',borderRadius:3}]);

            var sevLabels = (d.by_severity || []).map(function(s) { return s.key; });
            var sevCounts = (d.by_severity || []).map(function(s) { return s.count; });
            var sevColors = sevLabels.map(function(l) {
                if (['Emergency','Alert'].indexOf(l) !== -1) return '#ff7b72';
                if (l === 'Critical') return '#f85149';
                if (l === 'Error') return '#da3633';
                if (l === 'Warning') return '#d2992a';
                if (l === 'Notice') return '#58a6ff';
                if (l === 'Info') return '#388bfd';
                return '#8b949e';
            });
            createChart('syslog-severity-chart','doughnut',sevLabels,[{data:sevCounts,backgroundColor:sevColors,borderWidth:0}]);
        })['catch'](function(e) { console.error('Failed to load syslog charts:', e); });
    }

    function buildSyslogParams(limit) {
        var parts = ['limit=' + limit];
        var probe = document.getElementById('syslog-filter-probe');
        var device = document.getElementById('syslog-filter-device');
        var severity = document.getElementById('syslog-filter-severity');
        var search = document.getElementById('syslog-filter-search');
        if (probe && probe.value) parts.push('probe_id=' + probe.value);
        if (device && device.value) parts.push('device_id=' + device.value);
        if (severity && severity.value !== '') parts.push('severity=' + severity.value);
        if (search && search.value) parts.push('search=' + encodeURIComponent(search.value));
        return parts.join('&');
    }

    function renderSyslogTable(messages, append) {
        var tbody = document.querySelector('#syslog-table tbody');
        var html = messages.map(function(m) {
            return '<tr>' +
                '<td style="white-space:nowrap;">' + formatDate(m.timestamp) + '</td>' +
                '<td class="mono">' + escapeHtml(m.source_ip) + '</td>' +
                '<td>' + escapeHtml(m.hostname) + '</td>' +
                '<td><span class="badge ' + severityBadgeClass(m.severity) + '">' + (SEVERITY_NAMES[m.severity] || m.severity) + '</span></td>' +
                '<td>' + escapeHtml(m.app_name) + '</td>' +
                '<td class="expandable-msg" data-action="toggle-expand">' + escapeHtml(m.message) + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="6" class="empty-state">No syslog messages</td></tr>';
    }

    function loadMoreSyslog() {
        var params = buildSyslogParams(100);
        apiFetch(API_BASE + '/syslog?' + params + '&offset=' + syslogOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderSyslogTable(result.data, true);
                syslogOffset += result.data.length;
            }
        });
    }

    // ---- Flows ----
    function loadFlows() {
        flowsOffset = 0;
        var p = Promise.resolve();
        if (currentProbes.length === 0) {
            p = apiFetch(API_BASE + '/probes').then(function(pr) { currentProbes = pr && pr.data ? pr.data : []; });
        }
        p.then(function() {
            if (currentDevices.length === 0) {
                return apiFetch(API_BASE + '/devices').then(function(dr) { currentDevices = dr && dr.data ? dr.data : []; });
            }
        }).then(function() {
            populateFilterProbes('flows-filter-probe');
            populateFilterDevices('flows-filter-device');
            var params = buildFlowParams(100);
            return apiFetch(API_BASE + '/flows?' + params);
        }).then(function(result) {
            if (!result) return;
            var samples = result.data || [];
            renderFlowsTable(samples, false);
            flowsOffset = samples.length;
            loadFlowCharts();
        })['catch'](function(e) {
            console.error('Failed to load flows:', e);
        });
    }

    function setFlowRange(hours) {
        flowStatsHours = hours;
        document.querySelectorAll('.flow-range-btn').forEach(function(b) { b.classList.remove('active'); });
        var activeBtn = document.querySelector('.flow-range-btn[data-hours="' + hours + '"]');
        if (activeBtn) activeBtn.classList.add('active');
        loadFlowCharts();
    }

    var bytesTickCallback = function(value) { return formatBytes(value); };
    var bytesTooltipCallback = function(ctx) { return ctx.dataset.label + ': ' + formatBytes(ctx.parsed.y || ctx.parsed.x || 0); };
    var bpsTickCallback = function(value) { return formatBps(value); };
    var bpsTooltipCallback = function(ctx) { return ctx.dataset.label + ': ' + formatBps(ctx.parsed.y || ctx.parsed.x || 0); };

    // Shared options for horizontal bar charts
    var horizBarOpts = function(color) {
        return {
            indexAxis:'y',
            scales: {
                x: { ticks: { color: '#484f58', font:{size:10}, callback: bytesTickCallback }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#484f58', font:{size:10} }, grid: { color: '#21262d' } }
            },
            plugins: { legend: { labels: { color: '#8b949e', boxWidth: 12, padding: 8, font: {size:11} } }, tooltip: { callbacks: { label: bytesTooltipCallback } } }
        };
    };

    function loadFlowCharts() {
        var statsUrl = API_BASE + '/flows/stats?hours=' + flowStatsHours;
        var deviceFilter = document.getElementById('flows-filter-device');
        if (deviceFilter && deviceFilter.value) statsUrl += '&device_id=' + deviceFilter.value;
        apiFetch(statsUrl).then(function(result) {
            if (!result || !result.data) return;
            var d = result.data;
            // 6 stat cards
            document.getElementById('flows-total').textContent = (d.total_flows || 0).toLocaleString();
            document.getElementById('flows-bytes').textContent = formatBytes(d.total_bytes || 0);
            document.getElementById('flows-throughput').textContent = formatBps(d.bits_per_second || 0);
            document.getElementById('flows-sources').textContent = (d.unique_sources || 0).toLocaleString();
            document.getElementById('flows-dests').textContent = (d.unique_dests || 0).toLocaleString();
            document.getElementById('flows-protocols').textContent = (d.protocol_count || 0).toLocaleString();

            // Local traffic info bar
            var localBar = document.getElementById('flows-local-traffic-bar');
            if (localBar && d.local_traffic && d.local_traffic.bytes > 0) {
                localBar.style.display = 'block';
                document.getElementById('flows-local-bytes').textContent = formatBytes(d.local_traffic.bytes);
                document.getElementById('flows-local-flows').textContent = (d.local_traffic.flows || 0).toLocaleString();
                document.getElementById('flows-local-packets').textContent = (d.local_traffic.packets || 0).toLocaleString();
            } else if (localBar) {
                localBar.style.display = 'none';
            }

            // Protocol doughnut
            var protoLabels = (d.by_protocol || []).map(function(p) { return p.key; });
            var protoCounts = (d.by_protocol || []).map(function(p) { return p.count; });
            var protoColors = ['#58a6ff','#3fb950','#d2992a','#f85149','#bc8cff','#8b949e','#388bfd','#da3633'];
            createChart('flows-protocol-chart','doughnut',protoLabels,[{data:protoCounts,backgroundColor:protoColors.slice(0,protoLabels.length),borderWidth:0}]);

            // Top sources bar (horizontal)
            var srcLabels = (d.top_sources || []).map(function(s) { return s.key; });
            var srcCounts = (d.top_sources || []).map(function(s) { return s.count; });
            createChart('flows-top-talkers-chart','bar',srcLabels,[{label:'Bytes',data:srcCounts,backgroundColor:'#58a6ff',borderRadius:3}], horizBarOpts('#58a6ff'));

            // Top destinations bar (horizontal)
            var dstLabels = (d.top_destinations || []).map(function(s) { return s.key; });
            var dstCounts = (d.top_destinations || []).map(function(s) { return s.count; });
            createChart('flows-top-dests-chart','bar',dstLabels,[{label:'Bytes',data:dstCounts,backgroundColor:'#3fb950',borderRadius:3}], horizBarOpts('#3fb950'));

            // Bandwidth over time (bits/sec) — use server-provided bucket interval
            var intervalSec = d.bucket_seconds || 3600;
            var timeLabels = (d.bytes_over_time || []).map(function(b) { return b.bucket.substring(11,16) || b.bucket; });
            var timeBps = (d.bytes_over_time || []).map(function(b) {
                return (b.count * 8) / intervalSec;
            });
            createChart('flows-bytes-time-chart','line',timeLabels,[{label:'Throughput',data:timeBps,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',fill:true,tension:0.3}],{
                scales: {
                    x: { ticks: { color: '#484f58', font:{size:10}, maxRotation: 0 }, grid: { color: '#21262d' } },
                    y: { ticks: { color: '#484f58', font:{size:10}, callback: bpsTickCallback }, grid: { color: '#21262d' }, beginAtZero: true }
                },
                plugins: { legend: { labels: { color: '#8b949e', boxWidth: 12, padding: 8, font: {size:11} } }, tooltip: { callbacks: { label: bpsTooltipCallback } } }
            });

            // Top conversations table
            var convTbody = document.querySelector('#flows-conversations-table tbody');
            if (convTbody) {
                var totalBytes = d.total_bytes || 1;
                var convos = d.top_conversations || [];
                convTbody.innerHTML = convos.map(function(c) {
                    var pct = ((c.bytes / totalBytes) * 100).toFixed(1);
                    return '<tr class="conv-row" style="cursor:pointer" data-src="' + escapeHtml(c.src_addr) + '" data-dst="' + escapeHtml(c.dst_addr) + '" data-dport="' + c.dst_port + '">' +
                        '<td class="mono">' + escapeHtml(c.src_addr) + '</td>' +
                        '<td>&#8594;</td>' +
                        '<td class="mono">' + escapeHtml(c.dst_addr) + ':' + c.dst_port + '</td>' +
                        '<td>' + escapeHtml(c.protocol) + '</td>' +
                        '<td>' + formatBytes(c.bytes) + '</td>' +
                        '<td>' + (c.packets || 0).toLocaleString() + '</td>' +
                        '<td>' + pct + '%</td>' +
                    '</tr>';
                }).join('') || '<tr><td colspan="7" class="empty-state">No conversations</td></tr>';
            }
        })['catch'](function(e) { console.error('Failed to load flow charts:', e); });
    }

    function buildFlowParams(limit) {
        var parts = ['limit=' + limit];
        var device = document.getElementById('flows-filter-device');
        var probe = document.getElementById('flows-filter-probe');
        var proto = document.getElementById('flows-filter-protocol');
        var src = document.getElementById('flows-filter-src');
        var dst = document.getElementById('flows-filter-dst');
        if (device && device.value) parts.push('device_id=' + device.value);
        if (probe && probe.value) parts.push('probe_id=' + probe.value);
        if (proto && proto.value) parts.push('protocol=' + proto.value);
        if (src && src.value) parts.push('src_addr=' + encodeURIComponent(src.value));
        if (dst && dst.value) parts.push('dst_addr=' + encodeURIComponent(dst.value));
        return parts.join('&');
    }

    function renderFlowsTable(samples, append) {
        var tbody = document.querySelector('#flows-table tbody');
        var html = samples.map(function(f) {
            var estBytes = f.sampling_rate ? f.bytes * f.sampling_rate : f.bytes;
            return '<tr>' +
                '<td style="white-space:nowrap;">' + formatDate(f.timestamp) + '</td>' +
                '<td class="mono">' + escapeHtml(f.src_addr) + ':' + f.src_port + '</td>' +
                '<td>&#8594;</td>' +
                '<td class="mono">' + escapeHtml(f.dst_addr) + ':' + f.dst_port + '</td>' +
                '<td>' + (PROTOCOL_NAMES[f.protocol] || f.protocol) + '</td>' +
                '<td>' + formatBytes(f.bytes) + '</td>' +
                '<td>' + formatBytes(estBytes) + '</td>' +
                '<td>' + f.packets + '</td>' +
                '<td>' + (f.sampling_rate ? '1:' + f.sampling_rate : '-') + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="9" class="empty-state">No flow samples</td></tr>';
    }

    function loadMoreFlows() {
        var params = buildFlowParams(100);
        apiFetch(API_BASE + '/flows?' + params + '&offset=' + flowsOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderFlowsTable(result.data, true);
                flowsOffset += result.data.length;
            }
        });
    }

    function populateFilterProbes(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        sel.innerHTML = '<option value="">All Probes</option>' + currentProbes.map(function(p) {
            return '<option value="' + p.id + '">' + escapeHtml(p.name) + '</option>';
        }).join('');
    }

    function populateFilterDevices(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        sel.innerHTML = '<option value="">All Devices</option>' + currentDevices.map(function(d) {
            return '<option value="' + d.id + '">' + escapeHtml(d.name) + '</option>';
        }).join('');
    }

    // Syslog auto-refresh
    var sysAutoRefreshEl = document.getElementById('syslog-auto-refresh');
    if (sysAutoRefreshEl) {
        sysAutoRefreshEl.addEventListener('change', function() {
            if (this.checked) {
                syslogRefreshTimer = setInterval(function() {
                    if (document.querySelector('#page-syslog.active')) loadSyslog();
                }, 10000);
            } else {
                clearInterval(syslogRefreshTimer);
            }
        });
    }

    // ---- Alerts ----
    function loadAlerts() {
        alertsOffset = 0;
        var params = buildAlertParams(100);
        apiFetch(API_BASE + '/alerts?' + params).then(function(result) {
            if (!result) return;
            var alerts = result.data || [];
            renderAlertsTable(alerts, false);
            alertsOffset = alerts.length;
            loadAlertCharts();
        })['catch'](function(e) {
            console.error('Failed to load alerts:', e);
        });
    }

    function buildAlertParams(limit) {
        var parts = ['limit=' + limit];
        var sev = document.getElementById('alerts-filter-severity');
        var ack = document.getElementById('alerts-filter-ack');
        if (sev && sev.value) parts.push('severity=' + sev.value);
        if (ack && ack.value) parts.push('acknowledged=' + ack.value);
        return parts.join('&');
    }

    function getDeviceName(deviceId) {
        var dev = currentDevices.find(function(d) { return d.id === deviceId; });
        return dev ? escapeHtml(dev.name) : 'DEV-' + deviceId;
    }

    function renderAlertsTable(alerts, append) {
        var tbody = document.querySelector('#alerts-full-table tbody');
        var html = alerts.map(function(a) {
            var statusCol = '';
            if (a.suppressed) {
                statusCol = '<span class="badge unknown">MAINT</span>';
            } else if (a.acknowledged) {
                statusCol = '<span class="badge info" title="' + escapeHtml((a.acknowledged_at ? formatDate(a.acknowledged_at) : '') + (a.notes ? ' — ' + a.notes : '')) + '">ACK</span>';
            } else {
                statusCol = '<button class="btn sm" data-action="show-ack-modal" data-id="' + a.id + '">Ack</button>';
            }
            return '<tr>' +
                '<td>' + formatDate(a.timestamp) + '</td>' +
                '<td>' + getDeviceName(a.device_id) + '</td>' +
                '<td>' + escapeHtml(a.alert_type) + '</td>' +
                '<td><span class="badge ' + escapeHtml(a.severity) + '">' + escapeHtml(a.severity).toUpperCase() + '</span></td>' +
                '<td>' + escapeHtml(a.message) + '</td>' +
                '<td>' + statusCol + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="6" class="empty-state">No alerts</td></tr>';
    }

    function showAckModal(id) {
        document.getElementById('ack-alert-id').value = id;
        document.getElementById('ack-notes').value = '';
        document.getElementById('ack-modal').classList.add('active');
    }

    function closeAckModal() {
        document.getElementById('ack-modal').classList.remove('active');
    }

    function acknowledgeAlert(id, notes) {
        var body = notes ? {notes: notes} : {};
        apiFetch(API_BASE + '/alerts/' + id + '/acknowledge', {method:'POST', body: body}).then(function() {
            closeAckModal();
            loadAlerts();
        })['catch'](function(e) { console.error('Failed to acknowledge alert:', e); });
    }

    var ackForm = document.getElementById('ack-form');
    if (ackForm) {
        ackForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var id = parseInt(document.getElementById('ack-alert-id').value);
            var notes = document.getElementById('ack-notes').value;
            acknowledgeAlert(id, notes);
        });
    }

    function loadMoreAlerts() {
        var params = buildAlertParams(100);
        apiFetch(API_BASE + '/alerts?' + params + '&offset=' + alertsOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderAlertsTable(result.data, true);
                alertsOffset += result.data.length;
            }
        });
    }

    function loadAlertCharts() {
        apiFetch(API_BASE + '/alerts/stats').then(function(result) {
            if (!result || !result.data) return;
            var d = result.data;
            document.getElementById('alerts-total').textContent = (d.total || 0).toLocaleString();
            var crit = 0, warn = 0, inf = 0;
            (d.by_severity || []).forEach(function(s) {
                if (s.key === 'critical') crit += s.count;
                else if (s.key === 'warning') warn += s.count;
                else inf += s.count;
            });
            document.getElementById('alerts-critical').textContent = crit.toLocaleString();
            document.getElementById('alerts-warning').textContent = warn.toLocaleString();
            document.getElementById('alerts-info').textContent = inf.toLocaleString();

            var labels = (d.over_time || []).map(function(b) { return b.bucket.substring(11,16) || b.bucket; });
            var counts = (d.over_time || []).map(function(b) { return b.count; });
            createChart('alerts-trend-chart','line',labels,[{label:'Alerts',data:counts,borderColor:'#f85149',backgroundColor:'rgba(248,81,73,0.1)',fill:true,tension:0.3}]);

            var typeLabels = (d.by_type || []).map(function(t) { return t.key || 'unknown'; });
            var typeCounts = (d.by_type || []).map(function(t) { return t.count; });
            var typeColors = ['#f85149','#d2992a','#58a6ff','#3fb950','#bc8cff','#8b949e'];
            createChart('alerts-type-chart','doughnut',typeLabels,[{data:typeCounts,backgroundColor:typeColors.slice(0,typeLabels.length),borderWidth:0}]);
        })['catch'](function(e) { console.error('Failed to load alert charts:', e); });
    }

    // ---- Traps ----
    function loadTraps() {
        trapsOffset = 0;
        var params = buildTrapParams(100);
        apiFetch(API_BASE + '/traps?' + params).then(function(result) {
            if (!result) return;
            var traps = result.data || [];
            renderTrapsTable(traps, false);
            trapsOffset = traps.length;
            loadTrapCharts();
        })['catch'](function(e) {
            console.error('Failed to load traps:', e);
        });
    }

    function buildTrapParams(limit) {
        var parts = ['limit=' + limit];
        var sev = document.getElementById('traps-filter-severity');
        var type = document.getElementById('traps-filter-type');
        if (sev && sev.value) parts.push('severity=' + sev.value);
        if (type && type.value) parts.push('trap_type=' + encodeURIComponent(type.value));
        return parts.join('&');
    }

    function renderTrapsTable(traps, append) {
        var tbody = document.querySelector('#traps-table tbody');
        var html = traps.map(function(t) {
            return '<tr>' +
                '<td>' + formatDate(t.timestamp) + '</td>' +
                '<td class="mono">' + escapeHtml(t.source_ip) + '</td>' +
                '<td>' + escapeHtml(t.trap_type) + '</td>' +
                '<td><span class="badge ' + escapeHtml(t.severity) + '">' + escapeHtml(t.severity).toUpperCase() + '</span></td>' +
                '<td>' + escapeHtml(t.message) + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="5" class="empty-state">No traps</td></tr>';
    }

    function loadMoreTraps() {
        var params = buildTrapParams(100);
        apiFetch(API_BASE + '/traps?' + params + '&offset=' + trapsOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderTrapsTable(result.data, true);
                trapsOffset += result.data.length;
            }
        });
    }

    function loadTrapCharts() {
        apiFetch(API_BASE + '/traps/stats').then(function(result) {
            if (!result || !result.data) return;
            var d = result.data;
            document.getElementById('traps-total').textContent = (d.total || 0).toLocaleString();
            var crit = 0, warn = 0, inf = 0;
            (d.by_severity || []).forEach(function(s) {
                if (s.key === 'critical') crit += s.count;
                else if (s.key === 'warning') warn += s.count;
                else inf += s.count;
            });
            document.getElementById('traps-critical').textContent = crit.toLocaleString();
            document.getElementById('traps-warning').textContent = warn.toLocaleString();
            document.getElementById('traps-info').textContent = inf.toLocaleString();

            var labels = (d.over_time || []).map(function(b) { return b.bucket.substring(11,16) || b.bucket; });
            var counts = (d.over_time || []).map(function(b) { return b.count; });
            createChart('traps-freq-chart','bar',labels,[{label:'Traps',data:counts,backgroundColor:'#d2992a',borderRadius:3}]);

            var sevLabels = (d.by_severity || []).map(function(s) { return s.key || 'unknown'; });
            var sevCounts = (d.by_severity || []).map(function(s) { return s.count; });
            var sevColors = ['#f85149','#d2992a','#58a6ff','#3fb950','#8b949e'];
            createChart('traps-severity-chart','doughnut',sevLabels,[{data:sevCounts,backgroundColor:sevColors.slice(0,sevLabels.length),borderWidth:0}]);
        })['catch'](function(e) { console.error('Failed to load trap charts:', e); });
    }

    // ---- Settings ----
    var TIMEZONE_LIST = [
        'Pacific/Midway', 'Pacific/Honolulu', 'America/Anchorage', 'America/Los_Angeles',
        'America/Phoenix', 'America/Denver', 'America/Chicago', 'America/New_York',
        'America/Halifax', 'America/St_Johns', 'America/Sao_Paulo', 'America/Argentina/Buenos_Aires',
        'Atlantic/South_Georgia', 'Atlantic/Azores', 'UTC',
        'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Helsinki',
        'Europe/Moscow', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata',
        'Asia/Dhaka', 'Asia/Bangkok', 'Asia/Shanghai', 'Asia/Tokyo',
        'Australia/Sydney', 'Pacific/Auckland', 'Pacific/Fiji'
    ];

    function populateTimezoneSelect() {
        var sel = document.getElementById('display-timezone');
        if (!sel) return;
        var current = AC.getTimezone();
        sel.innerHTML = TIMEZONE_LIST.map(function(tz) {
            var label = tz.replace(/_/g, ' ');
            try {
                var now = new Date();
                var short = now.toLocaleString('en-US', { timeZone: tz, timeZoneName: 'short' }).split(', ').pop().split(' ').pop();
                label = tz.replace(/_/g, ' ') + ' (' + short + ')';
            } catch(e) {}
            return '<option value="' + tz + '"' + (tz === current ? ' selected' : '') + '>' + label + '</option>';
        }).join('');
        sel.addEventListener('change', function() {
            AC.setTimezone(sel.value);
        });
    }

    populateTimezoneSelect();

    function loadSettings() {
        apiFetch(API_BASE + '/settings').then(function(result) {
            if (!result) return;
            var settings = result.data || [];

            // Load timezone from DB and sync to localStorage
            var tzSetting = settings.find(function(s) { return s.key === 'display_timezone'; });
            if (tzSetting && tzSetting.value) {
                AC.setTimezone(tzSetting.value);
                var tzSel = document.getElementById('display-timezone');
                if (tzSel) tzSel.value = tzSetting.value;
            }

            var alertSettings = settings.filter(function(s) { return s.category === 'alerts'; });
            var notifSettings = settings.filter(function(s) { return s.category === 'notifications'; });

            document.getElementById('settings-alerts').innerHTML = [
                { key: 'cpu_threshold', label: 'CPU Threshold (%)', value: 80, type: 'number' },
                { key: 'memory_threshold', label: 'Memory Threshold (%)', value: 80, type: 'number' },
                { key: 'disk_threshold', label: 'Disk Threshold (%)', value: 90, type: 'number' },
                { key: 'session_threshold', label: 'Session Threshold', value: 100000, type: 'number' }
            ].map(function(s) {
                var found = alertSettings.find(function(x) { return x.key === s.key; });
                return '<div class="setting-item"><label>' + s.label + '</label>' +
                    '<input type="' + s.type + '" name="' + s.key + '" value="' + escapeHtml(found ? found.value : String(s.value)) + '"></div>';
            }).join('');

            document.getElementById('settings-notifications').innerHTML = [
                { key: 'email_enabled', label: 'Enable Email', type: 'checkbox' },
                { key: 'slack_webhook', label: 'Slack Webhook URL', type: 'text' },
                { key: 'discord_webhook', label: 'Discord Webhook URL', type: 'text' },
                { key: 'webhook_url', label: 'Generic Webhook URL', type: 'text' }
            ].map(function(s) {
                var found = notifSettings.find(function(x) { return x.key === s.key; });
                var savedVal = found ? found.value : '';
                if (s.type === 'checkbox') {
                    var checked = savedVal === 'true' ? 'checked' : '';
                    return '<div class="setting-item"><label>' + s.label + '</label><input type="checkbox" name="' + s.key + '" ' + checked + '></div>';
                }
                return '<div class="setting-item"><label>' + s.label + '</label><input type="text" name="' + s.key + '" value="' + escapeHtml(savedVal) + '" autocomplete="one-time-code"></div>';
            }).join('');

            document.getElementById('settings-smtp').innerHTML = [
                { key: 'smtp_host', label: 'SMTP Host', type: 'text', placeholder: 'smtp.example.com' },
                { key: 'smtp_port', label: 'SMTP Port', type: 'number', placeholder: '587' },
                { key: 'smtp_username', label: 'SMTP Username', type: 'text', placeholder: 'user@example.com' },
                { key: 'smtp_password', label: 'SMTP Password', type: 'password', placeholder: '' },
                { key: 'smtp_from', label: 'From Address', type: 'text', placeholder: 'alerts@example.com' },
                { key: 'smtp_to', label: 'To Address', type: 'text', placeholder: 'admin@example.com' }
            ].map(function(s) {
                var found = notifSettings.find(function(x) { return x.key === s.key; });
                var savedVal = found ? found.value : '';
                return '<div class="setting-item"><label>' + s.label + '</label><input type="' + s.type + '" name="' + s.key + '" value="' + escapeHtml(savedVal) + '" placeholder="' + (s.placeholder || '') + '"></div>';
            }).join('');

            return apiFetch(API_BASE + '/display-settings');
        }).then(function(displayResult) {
            if (displayResult && displayResult.data) {
                var ds = displayResult.data;
                document.querySelectorAll('#display-settings input[type="checkbox"]').forEach(function(cb) {
                    cb.checked = ds[cb.name] !== 'false';
                });
                var refreshInput = document.querySelector('#display-settings input[name="public_refresh_interval"]');
                if (refreshInput && ds['public_refresh_interval']) refreshInput.value = ds['public_refresh_interval'];
                
                updateDisplayConfigVisibility();
            }
        })['catch'](function(e) {
            console.error('Failed to load settings:', e);
        });

        loadPublicDashboardOptions();
        loadMigrationPrecheck();
    }
    
    function updateDisplayConfigVisibility() {
        var showBandwidth = document.querySelector('input[name="public_show_bandwidth"]');
        var showVpn = document.querySelector('input[name="public_show_vpn"]');
        var bandwidthConfig = document.getElementById('bandwidth-config');
        var vpnConfig = document.getElementById('vpn-config');
        if (bandwidthConfig && showBandwidth) {
            bandwidthConfig.style.display = showBandwidth.checked ? 'block' : 'none';
        }
        if (vpnConfig && showVpn) {
            vpnConfig.style.display = showVpn.checked ? 'block' : 'none';
        }
    }
    
    function loadPublicDashboardOptions() {
        apiFetch(API_BASE + '/devices').then(function(result) {
            if (!result || !result.data || result.data.length === 0) return;
            var deviceId = result.data[0].id;
            
            apiFetch(API_BASE + '/interfaces?device_id=' + deviceId).then(function(ifResult) {
                if (!ifResult || !ifResult.data) return;
                var ifSelect = document.querySelector('select[name="public_bandwidth_interfaces"]');
                if (ifSelect) {
                    var typeGroups = {};
                    ifResult.data.forEach(function(iface) {
                        var type = iface.type_name || 'Other';
                        if (!typeGroups[type]) typeGroups[type] = [];
                        typeGroups[type].push(iface);
                    });
                    
                    Object.keys(typeGroups).sort().forEach(function(type) {
                        var groupLabel = document.createElement('optgroup');
                        groupLabel.label = type.charAt(0).toUpperCase() + type.slice(1);
                        typeGroups[type].forEach(function(iface) {
                            var opt = document.createElement('option');
                            opt.value = iface.name || 'Interface ' + iface.index;
                            opt.textContent = (iface.name || 'Interface ' + iface.index) + (iface.alias ? ' (' + iface.alias + ')' : '');
                            opt.dataset.type = type;
                            groupLabel.appendChild(opt);
                        });
                        ifSelect.appendChild(groupLabel);
                    });
                    
                    var savedIfaces = document.querySelector('#display-settings input[name="public_bandwidth_interfaces"]');
                    if (savedIfaces && savedIfaces.value) {
                        var selectedIfaces = savedIfaces.value.split(',');
                        Array.from(ifSelect.options).forEach(function(opt) {
                            opt.selected = selectedIfaces.includes(opt.value);
                        });
                    }
                }
            })['catch'](function() {});
            
            apiFetch(API_BASE + '/devices/' + deviceId + '/detail').then(function(detailResult) {
                if (!detailResult || !detailResult.data || !detailResult.data.vpn) return;
                var vpnSelect = document.querySelector('select[name="public_vpn_tunnels"]');
                if (vpnSelect) {
                    detailResult.data.vpn.forEach(function(tunnel) {
                        var opt = document.createElement('option');
                        opt.value = tunnel.tunnel_name;
                        opt.textContent = tunnel.tunnel_name || tunnel.tunnel_type || 'Tunnel';
                        vpnSelect.appendChild(opt);
                    });
                }
            })['catch'](function() {});
        })['catch'](function() {});
        
        document.querySelectorAll('#display-settings input[name="public_show_bandwidth"], #display-settings input[name="public_show_vpn"]').forEach(function(cb) {
            cb.addEventListener('change', updateDisplayConfigVisibility);
        });
    }

    // ---- Device Modal ----
    function showDeviceModal(id) {
        document.getElementById('device-modal').classList.add('active');
        document.getElementById('device-modal-title').textContent = id ? 'Edit Device' : 'Add Device';
        populateProbeSelect('device-probe');
        populateSiteSelect('device-site');

        if (id) {
            var d = currentDevices.find(function(d) { return d.id === id; });
            document.getElementById('device-id').value = d.id;
            document.getElementById('device-name').value = d.name;
            document.getElementById('device-ip').value = d.ip_address;
            document.getElementById('device-snmp-port').value = d.snmp_port || 161;
            document.getElementById('device-snmp-version').value = d.snmp_version || '2c';
            document.getElementById('device-community').value = d.snmp_community || 'public';
            document.getElementById('device-v3-username').value = d.snmpv3_username || '';
            document.getElementById('device-v3-auth-type').value = d.snmpv3_auth_type || '';
            document.getElementById('device-v3-auth-pass').value = '';
            document.getElementById('device-v3-priv-type').value = d.snmpv3_priv_type || '';
            document.getElementById('device-v3-priv-pass').value = '';
            document.getElementById('device-vendor').value = d.vendor || 'fortigate';
            document.getElementById('device-probe').value = d.probe_id || '';
            document.getElementById('device-site').value = d.site_id || '';
            document.getElementById('device-location').value = d.location || '';
            document.getElementById('device-description').value = d.description || '';
            document.getElementById('device-wan-speed').value = d.wan_speed_mbps || 1000;
        } else {
            document.getElementById('device-form').reset();
            document.getElementById('device-id').value = '';
            document.getElementById('device-snmp-port').value = '161';
            document.getElementById('device-snmp-version').value = '2c';
            document.getElementById('device-community').value = 'public';
            document.getElementById('device-wan-speed').value = '1000';
        }
        toggleV3Fields();
    }

    function closeDeviceModal() { document.getElementById('device-modal').classList.remove('active'); }

    function toggleV3Fields() {
        var ver = document.getElementById('device-snmp-version').value;
        document.getElementById('snmpv3-fields').style.display = ver === '3' ? 'block' : 'none';
        document.getElementById('community-group').style.display = ver === '3' ? 'none' : 'block';
    }

    // Listen for SNMP version change
    var snmpVersionEl = document.getElementById('device-snmp-version');
    if (snmpVersionEl) {
        snmpVersionEl.addEventListener('change', toggleV3Fields);
    }

    function testDeviceConnection(el) {
        var ip = document.getElementById('device-ip').value;
        var port = document.getElementById('device-snmp-port').value || 161;
        var community = document.getElementById('device-community').value || 'public';
        var version = document.getElementById('device-snmp-version').value || '2c';
        if (!ip) { alert('Please enter an IP address first'); return; }

        var btn = el;
        var orig = btn.textContent;
        btn.textContent = 'Testing...';
        btn.disabled = true;

        var testData = { ip_address: ip, snmp_port: parseInt(port), snmp_community: community, snmp_version: version };
        var probeVal = document.getElementById('device-probe').value;
        if (probeVal) testData.probe_id = parseInt(probeVal);
        if (version === '3') {
            testData.snmpv3_username = document.getElementById('device-v3-username').value;
            testData.snmpv3_auth_type = document.getElementById('device-v3-auth-type').value;
            testData.snmpv3_auth_pass = document.getElementById('device-v3-auth-pass').value;
            testData.snmpv3_priv_type = document.getElementById('device-v3-priv-type').value;
            testData.snmpv3_priv_pass = document.getElementById('device-v3-priv-pass').value;
        }

        apiFetch(API_BASE + '/devices/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(testData)
        }).then(function(result) {
            if (result && result.data && result.data.probe_managed) {
                alert(result.data.message);
            } else if (result && result.data && result.data.online) {
                alert('Connected!\nHostname: ' + result.data.hostname + '\nVersion: ' + result.data.version + '\nCPU: ' + result.data.cpu + '%\nMemory: ' + result.data.memory + '%');
            } else {
                alert('Failed: ' + (result && result.data ? result.data.message || 'Unknown error' : 'Unknown error'));
            }
        })['catch'](function(err) { alert('Error: ' + err.message); })
        .finally(function() { btn.textContent = orig; btn.disabled = false; });
    }

    // Device form submit
    var deviceForm = document.getElementById('device-form');
    if (deviceForm) {
        deviceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var id = document.getElementById('device-id').value;
            var snmpVersion = document.getElementById('device-snmp-version').value || '2c';
            var data = {
                name: document.getElementById('device-name').value,
                ip_address: document.getElementById('device-ip').value,
                snmp_port: parseInt(document.getElementById('device-snmp-port').value),
                snmp_version: snmpVersion,
                snmp_community: document.getElementById('device-community').value,
                vendor: document.getElementById('device-vendor').value || 'fortigate',
                location: document.getElementById('device-location').value,
                description: document.getElementById('device-description').value,
                wan_speed_mbps: parseInt(document.getElementById('device-wan-speed').value),
                enabled: true
            };
            if (snmpVersion === '3') {
                data.snmpv3_username = document.getElementById('device-v3-username').value;
                data.snmpv3_auth_type = document.getElementById('device-v3-auth-type').value;
                var authPass = document.getElementById('device-v3-auth-pass').value;
                if (authPass) data.snmpv3_auth_pass = authPass;
                data.snmpv3_priv_type = document.getElementById('device-v3-priv-type').value;
                var privPass = document.getElementById('device-v3-priv-pass').value;
                if (privPass) data.snmpv3_priv_pass = privPass;
            }
            var probeVal = document.getElementById('device-probe').value;
            var siteVal = document.getElementById('device-site').value;
            if (probeVal) data.probe_id = parseInt(probeVal);
            else data.probe_id = null;
            if (siteVal) data.site_id = parseInt(siteVal);
            else data.site_id = null;

            var method = id ? 'PUT' : 'POST';
            var url = id ? API_BASE + '/devices/' + id : API_BASE + '/devices';
            apiFetch(url, { method: method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) }).then(function() {
                closeDeviceModal();
                loadDevices();
            })['catch'](function(err) { alert('Error saving device: ' + err.message); });
        });
    }

    function editDevice(id) { showDeviceModal(id); }

    function deleteDevice(id) {
        if (!confirm('Delete this device and all its data?')) return;
        apiFetch(API_BASE + '/devices/' + id, { method: 'DELETE' }).then(function() {
            loadDevices();
        })['catch'](function(err) { alert('Error: ' + err.message); });
    }

    // ---- Connection Diagram ----
    function drawConnectionDiagram() {
        if (!FWDiagram.Panels.getCurrentPanelConnId()) {
            var panelContainer = document.getElementById('conn-detail-panel-container');
            if (panelContainer) panelContainer.innerHTML = '';
        }

        if (currentDevices.length === 0) {
            document.getElementById('connection-diagram').innerHTML =
                '<div class="loading" style="padding:60px 20px;">Add devices to see the network diagram</div>';
            return;
        }

        FWDiagram.init('connection-diagram');
        var siteNames = {};
        currentSites.forEach(function(s) { siteNames[s.id] = s.name; });
        FWDiagram.setCallbacks(
            function(conn) { FWDiagram.Panels.showRichConnDetailPanel(conn); },
            function(deviceId, offnetOnly) { FWDiagram.Panels.showRichVPNDetailPanel(deviceId, offnetOnly, currentDevices, currentVpnMap); }
        );
        FWDiagram.render(currentDevices, currentConnections, deviceSiteMap, currentVpnMap, siteNames);
    }
    window.drawConnectionDiagram = drawConnectionDiagram;

    function populateDeviceSelects() {
        ['connection-source', 'connection-dest'].forEach(function(sid) {
            var sel = document.getElementById(sid);
            sel.innerHTML = currentDevices.map(function(d) {
                return '<option value="' + d.id + '">' + escapeHtml(d.name) + ' (' + escapeHtml(d.ip_address) + ')</option>';
            }).join('');
        });
    }

    function showConnectionModal() {
        if (currentDevices.length < 2) { alert('You need at least 2 devices'); return; }
        document.getElementById('connection-modal').classList.add('active');
        document.getElementById('connection-form').reset();
        populateDeviceSelects();
    }
    function closeConnectionModal() { document.getElementById('connection-modal').classList.remove('active'); }

    // Connection form submit
    var connectionForm = document.getElementById('connection-form');
    if (connectionForm) {
        connectionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var data = {
                name: document.getElementById('connection-name').value,
                source_device_id: parseInt(document.getElementById('connection-source').value),
                dest_device_id: parseInt(document.getElementById('connection-dest').value),
                connection_type: document.getElementById('connection-type').value,
                notes: document.getElementById('connection-notes').value
            };
            apiFetch(API_BASE + '/connections', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) }).then(function() {
                closeConnectionModal();
                loadConnections();
            })['catch'](function(err) { alert('Error: ' + err.message); });
        });
    }

    function deleteConnection(id) {
        if (!confirm('Delete this connection?')) return;
        apiFetch(API_BASE + '/connections/' + id, { method: 'DELETE' }).then(function() {
            loadConnections();
        })['catch'](function(err) { alert('Error: ' + err.message); });
    }

    // ---- Settings Actions ----
    function changePassword() {
        var current = document.getElementById('current-password').value;
        var newPass = document.getElementById('new-password').value;
        var confirmPass = document.getElementById('confirm-password').value;
        if (!current || !newPass || !confirmPass) { alert('Please fill in all password fields'); return; }
        if (newPass !== confirmPass) { alert('New passwords do not match'); return; }
        if (newPass.length < 8) { alert('Password must be at least 8 characters'); return; }
        apiFetch(API_BASE + '/settings/password', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: current, new_password: newPass })
        }).then(function(result) {
            if (result && result.success) {
                alert(result.message);
                document.getElementById('current-password').value = '';
                document.getElementById('new-password').value = '';
                document.getElementById('confirm-password').value = '';
            } else { alert('Error: ' + (result && result.error ? result.error : 'Unknown error')); }
        })['catch'](function(err) { alert('Error: ' + err.message); });
    }

    function saveSettings() {
        var settings = [];
        document.querySelectorAll('#settings-alerts input').forEach(function(input) {
            settings.push({ key: input.name, value: input.type === 'checkbox' ? String(input.checked) : input.value, category: 'alerts', type: input.type === 'checkbox' ? 'bool' : 'string' });
        });
        document.querySelectorAll('#settings-notifications input').forEach(function(input) {
            settings.push({ key: input.name, value: input.type === 'checkbox' ? String(input.checked) : input.value, category: 'notifications', type: input.type === 'checkbox' ? 'bool' : 'string' });
        });
        document.querySelectorAll('#settings-smtp input').forEach(function(input) {
            if (input.type === 'password' && input.value === '********') return;
            settings.push({ key: input.name, value: input.value, category: 'notifications', type: 'string', is_secret: input.type === 'password' });
        });
        document.querySelectorAll('#display-settings input').forEach(function(input) {
            settings.push({ key: input.name, value: input.type === 'checkbox' ? String(input.checked) : input.value, category: 'display', type: input.type === 'checkbox' ? 'bool' : 'string' });
        });
        
        var bandwidthSelect = document.querySelector('select[name="public_bandwidth_interfaces"]');
        if (bandwidthSelect) {
            var selectedIfaces = Array.from(bandwidthSelect.selectedOptions).map(function(o) { return o.value; }).join(',');
            settings.push({ key: 'public_bandwidth_interfaces', value: selectedIfaces, category: 'display', type: 'string' });
        }
        
        var vpnSelect = document.querySelector('select[name="public_vpn_tunnels"]');
        if (vpnSelect) {
            var selectedVpns = Array.from(vpnSelect.selectedOptions).map(function(o) { return o.value; }).join(',');
            settings.push({ key: 'public_vpn_tunnels', value: selectedVpns, category: 'display', type: 'string' });
        }
        
        var tzSel = document.getElementById('display-timezone');
        if (tzSel && tzSel.value) {
            settings.push({ key: 'display_timezone', value: tzSel.value, category: 'display', type: 'string' });
            AC.setTimezone(tzSel.value);
        }

        apiFetch(API_BASE + '/settings', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(settings) }).then(function() {
            alert('Settings saved!');
        })['catch'](function(err) { alert('Error: ' + err.message); });
    }

    function testEmail() {
        var resultEl = document.getElementById('test-email-result');
        resultEl.textContent = 'Sending...';
        resultEl.style.color = '#8b949e';
        apiFetch(API_BASE + '/settings/test-email', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}' }).then(function(result) {
            if (result && result.data && result.data.success) {
                resultEl.textContent = result.data.message;
                resultEl.style.color = '#3fb950';
            } else {
                resultEl.textContent = (result && result.data ? result.data.message : '') || 'Failed';
                resultEl.style.color = '#f85149';
            }
        })['catch'](function(e) { resultEl.textContent = 'Error: ' + e.message; resultEl.style.color = '#f85149'; });
    }

    function testWebhook(type) {
        var resultEl = document.getElementById('test-webhook-result');
        resultEl.textContent = 'Sending...';
        resultEl.style.color = '#8b949e';
        var urlInput = document.querySelector('#settings-notifications input[name="' + type + '"]');
        var url = urlInput ? urlInput.value : '';
        apiFetch(API_BASE + '/settings/test-webhook', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type, url: url })
        }).then(function(result) {
            if (result && result.data && result.data.success) {
                resultEl.textContent = result.data.message;
                resultEl.style.color = '#3fb950';
            } else {
                resultEl.textContent = (result && result.data ? result.data.message : '') || 'Failed';
                resultEl.style.color = '#f85149';
            }
        })['catch'](function(e) { resultEl.textContent = 'Error: ' + e.message; resultEl.style.color = '#f85149'; });
    }

    // ---- Logout ----
    var logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            apiFetch('/admin/api/logout', { method: 'POST' }).then(function() {
                window.location.href = '/';
            })['catch'](function() {
                window.location.href = '/';
            });
        });
    }

    // ---- URL-based tab activation ----
    function activateTabFromUrl() {
        var path = window.location.pathname.replace(/\/$/, '');
        var segments = path.split('/');
        var lastSegment = segments[segments.length - 1];
        var pageMap = { 'dashboard':'dashboard', 'devices':'devices', 'interfaces':'interfaces', 'connections':'connections',
            'settings':'settings', 'syslog':'syslog', 'flows':'flows', 'alerts':'alerts', 'traps':'traps' };
        var page = pageMap[lastSegment];
        if (page) {
            document.querySelectorAll('.nav-item').forEach(function(i) { i.classList.remove('active'); });
            var navItem = document.querySelector('.nav-item[data-page="' + page + '"]');
            if (navItem) navItem.classList.add('active');
            document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
            var pageEl = document.getElementById('page-' + page);
            if (pageEl) pageEl.classList.add('active');
            document.getElementById('page-title').textContent = navItem ? navItem.textContent.trim() : page;
            return page;
        }
        return 'dashboard';
    }

    // ---- Migration Functions ----
    var migrationPollTimer = null;

    function loadMigrationPrecheck() {
        var card = document.getElementById('migration-card');
        if (!card) return;
        apiFetch(API_BASE + '/migrate/precheck').then(function(result) {
            if (!result || !result.data) return;
            card.style.display = '';
            var data = result.data;
            if (!data.is_postgres) {
                document.getElementById('migration-unavailable').style.display = '';
                document.getElementById('migration-form').style.display = 'none';
            } else {
                document.getElementById('migration-unavailable').style.display = 'none';
                document.getElementById('migration-form').style.display = '';
                var pathInput = document.getElementById('migration-source-path');
                if (pathInput && !pathInput.value) pathInput.value = data.default_sqlite_path || '';
                // Check if a migration is already running
                pollMigrationStatus();
            }
        })['catch'](function() {});
    }

    function startMigration() {
        var pathInput = document.getElementById('migration-source-path');
        var sourcePath = pathInput ? pathInput.value.trim() : '';
        if (!sourcePath) { alert('Please enter the SQLite database path.'); return; }

        apiFetch(API_BASE + '/migrate/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({source_path: sourcePath})
        }).then(function(result) {
            if (!result) return;
            document.getElementById('migration-form').style.display = 'none';
            document.getElementById('migration-progress').style.display = '';
            document.getElementById('migration-done').style.display = 'none';
            document.getElementById('migration-error').style.display = 'none';
            if (!migrationPollTimer) {
                migrationPollTimer = setInterval(pollMigrationStatus, 2000);
            }
        })['catch'](function(e) {
            alert('Failed to start migration: ' + (e.message || e));
        });
    }

    function pollMigrationStatus() {
        apiFetch(API_BASE + '/migrate/status').then(function(result) {
            if (!result || !result.data) return;
            var s = result.data;
            // If never started, nothing to show
            if (!s.started_at && !s.running) {
                if (migrationPollTimer) { clearInterval(migrationPollTimer); migrationPollTimer = null; }
                return;
            }
            // Show progress section
            document.getElementById('migration-form').style.display = 'none';
            var progressDiv = document.getElementById('migration-progress');
            progressDiv.style.display = '';

            var tables = s.tables || [];
            var totalRows = 0, totalMigrated = 0;
            tables.forEach(function(t) { totalRows += t.total_rows; totalMigrated += t.migrated; });
            var pct = totalRows > 0 ? Math.round((totalMigrated / totalRows) * 100) : 0;

            document.getElementById('migration-overall-pct').textContent = pct + '%';
            document.getElementById('migration-overall-bar').style.width = pct + '%';

            var tbody = document.getElementById('migration-table-body');
            tbody.innerHTML = tables.map(function(t) {
                var statusBadge = '<span style="color:' + migrationStatusColor(t.status) + ';">' + t.status + '</span>';
                var rowPct = t.total_rows > 0 ? Math.round((t.migrated / t.total_rows) * 100) : 0;
                var progressBar = '<div style="background:#21262d;border-radius:3px;height:6px;width:100px;display:inline-block;vertical-align:middle;">' +
                    '<div style="background:' + migrationStatusColor(t.status) + ';height:100%;width:' + rowPct + '%;border-radius:3px;"></div></div>' +
                    ' <span style="color:#8b949e;">' + rowPct + '%</span>';
                var errorTip = t.error ? ' <span title="' + escapeHtml(t.error) + '" style="color:#f85149;cursor:help;">(!)</span>' : '';
                return '<tr><td>' + escapeHtml(t.table_name) + '</td><td>' + statusBadge + errorTip + '</td><td>' +
                    t.migrated + ' / ' + t.total_rows + '</td><td>' + progressBar + '</td></tr>';
            }).join('');

            // Start polling if running and not already polling
            if (s.running && !migrationPollTimer) {
                migrationPollTimer = setInterval(pollMigrationStatus, 2000);
            }

            // Handle completion
            if (!s.running && s.finished_at) {
                if (migrationPollTimer) { clearInterval(migrationPollTimer); migrationPollTimer = null; }
                if (s.error) {
                    var errDiv = document.getElementById('migration-error');
                    errDiv.style.display = '';
                    errDiv.textContent = 'Migration error: ' + s.error;
                } else {
                    document.getElementById('migration-done').style.display = '';
                }
                document.getElementById('migration-overall-bar').style.background = s.error ? '#f85149' : '#3fb950';
            }
        })['catch'](function() {});
    }

    function migrationStatusColor(status) {
        switch (status) {
            case 'done': return '#3fb950';
            case 'running': return '#58a6ff';
            case 'error': return '#f85149';
            case 'skipped': return '#d29922';
            default: return '#8b949e';
        }
    }

    // ---- Alert Policies ----
    var currentPolicies = [];
    var ALERT_TYPES = ['CPU_HIGH','MEMORY_HIGH','DISK_HIGH','SESSIONS_HIGH','INTERFACE_DOWN','INTERFACE_ERRORS','VPN_TUNNEL_DOWN','DEVICE_OFFLINE','TRAFFIC_SPIKE','SYSLOG_EMERGENCY','SYSLOG_ALERT','SYSLOG_CRITICAL'];

    function loadAlertPolicies() {
        apiFetch(API_BASE + '/alert-policies').then(function(result) {
            if (!result) return;
            currentPolicies = result.data || [];
            document.getElementById('ap-total').textContent = currentPolicies.length;
            renderPoliciesTable(currentPolicies);
        })['catch'](function(e) { console.error('Failed to load policies:', e); });
    }

    function renderPoliciesTable(policies) {
        var tbody = document.querySelector('#alert-policies-table tbody');
        var html = policies.map(function(p) {
            var channels = [];
            if (p.notify_email) channels.push('Email');
            if (p.notify_slack) channels.push('Slack');
            if (p.notify_discord) channels.push('Discord');
            if (p.notify_webhook) channels.push('Webhook');
            var ruleCount = (p.rules || []).length;
            return '<tr>' +
                '<td>' + escapeHtml(p.name) + '</td>' +
                '<td>' + escapeHtml(p.description || '') + '</td>' +
                '<td>' + (p.is_default ? '<span class="badge info">DEFAULT</span>' : '') + '</td>' +
                '<td>' + ruleCount + '</td>' +
                '<td>' + (channels.length ? channels.join(', ') : '<span style="color:#484f58">Dashboard only</span>') + '</td>' +
                '<td>' + p.cooldown_minutes + 'm</td>' +
                '<td>' + (p.escalation_enabled ? p.escalation_minutes + 'm (' + p.escalation_repeat + 'x)' : 'Off') + '</td>' +
                '<td>' +
                    '<button class="btn secondary sm" data-action="edit-policy" data-id="' + p.id + '">Edit</button> ' +
                    '<button class="btn secondary sm" data-action="clone-policy" data-id="' + p.id + '">Clone</button> ' +
                    (p.is_default ? '' : '<button class="btn secondary sm" data-action="delete-policy" data-id="' + p.id + '">Delete</button>') +
                '</td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html || '<tr><td colspan="8" class="empty-state">No alert policies</td></tr>';
    }

    function showPolicyModal(id) {
        document.getElementById('policy-modal').classList.add('active');
        document.getElementById('policy-modal-title').textContent = id ? 'Edit Alert Policy' : 'Create Alert Policy';
        document.getElementById('policy-form').reset();
        document.getElementById('policy-id').value = '';

        if (id) {
            var p = currentPolicies.find(function(x) { return x.id === id; });
            if (!p) return;
            document.getElementById('policy-id').value = p.id;
            document.getElementById('policy-name').value = p.name;
            document.getElementById('policy-description').value = p.description || '';
            document.getElementById('policy-cooldown').value = p.cooldown_minutes;
            document.getElementById('policy-is-default').value = p.is_default ? 'true' : 'false';
            document.getElementById('policy-notify-email').checked = p.notify_email;
            document.getElementById('policy-notify-slack').checked = p.notify_slack;
            document.getElementById('policy-notify-discord').checked = p.notify_discord;
            document.getElementById('policy-notify-webhook').checked = p.notify_webhook;
            document.getElementById('policy-email-recipients').value = p.email_recipients || '';
            document.getElementById('policy-slack-url').value = p.slack_webhook_url || '';
            document.getElementById('policy-discord-url').value = p.discord_webhook_url || '';
            document.getElementById('policy-webhook-url').value = p.webhook_url || '';
            document.getElementById('policy-escalation-enabled').checked = p.escalation_enabled;
            document.getElementById('policy-escalation-minutes').value = p.escalation_minutes;
            document.getElementById('policy-escalation-repeat').value = p.escalation_repeat;
            populateRulesTable(p.rules || []);
        } else {
            populateRulesTable([]);
        }
    }

    function populateRulesTable(existingRules) {
        var tbody = document.getElementById('policy-rules-body');
        var ruleMap = {};
        existingRules.forEach(function(r) { ruleMap[r.alert_type] = r; });

        var html = ALERT_TYPES.map(function(type) {
            var r = ruleMap[type] || {};
            var enabled = r.alert_type ? r.enabled : true;
            var severity = r.severity || '';
            var threshold = r.threshold || '';
            var cooldown = (r.cooldown_minutes != null) ? r.cooldown_minutes : '';

            function triState(field, val) {
                if (val === true) return '<select data-field="' + field + '" class="sm"><option value="">Inherit</option><option value="true" selected>On</option><option value="false">Off</option></select>';
                if (val === false) return '<select data-field="' + field + '" class="sm"><option value="">Inherit</option><option value="true">On</option><option value="false" selected>Off</option></select>';
                return '<select data-field="' + field + '" class="sm"><option value="" selected>Inherit</option><option value="true">On</option><option value="false">Off</option></select>';
            }

            return '<tr data-alert-type="' + type + '">' +
                '<td style="font-size:12px">' + escapeHtml(type) + '</td>' +
                '<td><input type="checkbox" data-field="enabled" ' + (enabled ? 'checked' : '') + '></td>' +
                '<td><select data-field="severity" class="sm"><option value="">Inherit</option><option value="critical"' + (severity==='critical' ? ' selected' : '') + '>Critical</option><option value="warning"' + (severity==='warning' ? ' selected' : '') + '>Warning</option><option value="info"' + (severity==='info' ? ' selected' : '') + '>Info</option></select></td>' +
                '<td><input type="number" data-field="threshold" value="' + threshold + '" step="0.1" class="sm" style="width:70px"></td>' +
                '<td>' + triState('notify_email', r.notify_email) + '</td>' +
                '<td>' + triState('notify_slack', r.notify_slack) + '</td>' +
                '<td>' + triState('notify_discord', r.notify_discord) + '</td>' +
                '<td>' + triState('notify_webhook', r.notify_webhook) + '</td>' +
                '<td><input type="number" data-field="cooldown_minutes" value="' + cooldown + '" class="sm" style="width:60px" min="1"></td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html;
    }

    function collectRules() {
        var rows = document.querySelectorAll('#policy-rules-body tr');
        var rules = [];
        rows.forEach(function(row) {
            var type = row.dataset.alertType;
            var enabled = row.querySelector('[data-field="enabled"]').checked;
            var severity = row.querySelector('[data-field="severity"]').value;
            var threshold = parseFloat(row.querySelector('[data-field="threshold"]').value) || 0;
            var cooldownVal = row.querySelector('[data-field="cooldown_minutes"]').value;
            var cooldown = cooldownVal ? parseInt(cooldownVal) : null;

            function triVal(field) {
                var v = row.querySelector('[data-field="' + field + '"]').value;
                if (v === 'true') return true;
                if (v === 'false') return false;
                return null;
            }

            rules.push({
                alert_type: type,
                enabled: enabled,
                severity: severity,
                threshold: threshold,
                notify_email: triVal('notify_email'),
                notify_slack: triVal('notify_slack'),
                notify_discord: triVal('notify_discord'),
                notify_webhook: triVal('notify_webhook'),
                cooldown_minutes: cooldown
            });
        });
        return rules;
    }

    function closePolicyModal() {
        document.getElementById('policy-modal').classList.remove('active');
    }

    var policyForm = document.getElementById('policy-form');
    if (policyForm) {
        policyForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var id = document.getElementById('policy-id').value;
            var data = {
                name: document.getElementById('policy-name').value,
                description: document.getElementById('policy-description').value,
                cooldown_minutes: parseInt(document.getElementById('policy-cooldown').value) || 5,
                is_default: document.getElementById('policy-is-default').value === 'true',
                notify_email: document.getElementById('policy-notify-email').checked,
                notify_slack: document.getElementById('policy-notify-slack').checked,
                notify_discord: document.getElementById('policy-notify-discord').checked,
                notify_webhook: document.getElementById('policy-notify-webhook').checked,
                email_recipients: document.getElementById('policy-email-recipients').value,
                slack_webhook_url: document.getElementById('policy-slack-url').value,
                discord_webhook_url: document.getElementById('policy-discord-url').value,
                webhook_url: document.getElementById('policy-webhook-url').value,
                escalation_enabled: document.getElementById('policy-escalation-enabled').checked,
                escalation_minutes: parseInt(document.getElementById('policy-escalation-minutes').value) || 30,
                escalation_repeat: parseInt(document.getElementById('policy-escalation-repeat').value) || 3
            };

            var method = id ? 'PUT' : 'POST';
            var url = id ? (API_BASE + '/alert-policies/' + id) : (API_BASE + '/alert-policies');

            apiFetch(url, {method: method, body: data}).then(function(result) {
                var policyId = id || (result.data && result.data.id);
                if (policyId) {
                    var rules = collectRules();
                    return apiFetch(API_BASE + '/alert-policies/' + policyId + '/rules', {method: 'PUT', body: rules});
                }
            }).then(function() {
                closePolicyModal();
                loadAlertPolicies();
            })['catch'](function(err) { alert('Error saving policy: ' + (err.message || err)); });
        });
    }

    function clonePolicy(id) {
        apiFetch(API_BASE + '/alert-policies/' + id + '/clone', {method: 'POST'}).then(function() {
            loadAlertPolicies();
        })['catch'](function(e) { alert('Clone failed: ' + e.message); });
    }

    function deletePolicy(id) {
        if (!confirm('Delete this alert policy?')) return;
        apiFetch(API_BASE + '/alert-policies/' + id, {method: 'DELETE'}).then(function() {
            loadAlertPolicies();
        })['catch'](function(e) { alert('Delete failed: ' + e.message); });
    }

    // ---- Maintenance Windows ----
    var currentMaintenanceWindows = [];

    function loadMaintenance() {
        apiFetch(API_BASE + '/maintenance-windows').then(function(result) {
            if (!result) return;
            currentMaintenanceWindows = result.data || [];
            var now = new Date();
            var active = 0, scheduled = 0;
            currentMaintenanceWindows.forEach(function(w) {
                var start = new Date(w.start_time);
                var end = new Date(w.end_time);
                if (now >= start && now <= end) active++;
                else if (now < start) scheduled++;
            });
            document.getElementById('mw-active').textContent = active;
            document.getElementById('mw-scheduled').textContent = scheduled;
            document.getElementById('mw-total').textContent = currentMaintenanceWindows.length;
            renderMaintenanceTable(currentMaintenanceWindows);
        })['catch'](function(e) { console.error('Failed to load maintenance windows:', e); });
    }

    function renderMaintenanceTable(windows) {
        var tbody = document.querySelector('#maintenance-table tbody');
        if (!windows.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="empty-icon">&#128295;</div>No maintenance windows scheduled</td></tr>';
            return;
        }
        // Fetch device and site names for display
        Promise.all([
            apiFetch(API_BASE + '/devices'),
            apiFetch(API_BASE + '/sites')
        ]).then(function(results) {
            var deviceMap = {};
            var siteMap = {};
            if (results[0] && results[0].data) {
                results[0].data.forEach(function(d) { deviceMap[d.id] = d.name + (d.ip_address ? ' (' + d.ip_address + ')' : ''); });
            }
            if (results[1] && results[1].data) {
                results[1].data.forEach(function(s) { siteMap[s.id] = s.name; });
            }
            var now = new Date();
            var html = windows.map(function(w) {
                var start = new Date(w.start_time);
                var end = new Date(w.end_time);
                var status = 'Expired';
                var statusClass = 'unknown';
                if (now >= start && now <= end) { status = 'Active'; statusClass = 'warning'; }
                else if (now < start) { status = 'Scheduled'; statusClass = 'info'; }

                var scope = 'All Devices';
                if (w.device_id) scope = deviceMap[w.device_id] || ('Device #' + w.device_id);
                if (w.site_id) scope = siteMap[w.site_id] || ('Site #' + w.site_id);

                return '<tr>' +
                    '<td>' + escapeHtml(w.name) + '</td>' +
                    '<td>' + escapeHtml(scope) + '</td>' +
                    '<td>' + formatDate(w.start_time) + '</td>' +
                    '<td>' + formatDate(w.end_time) + '</td>' +
                    '<td>' + (w.recurring ? 'Yes' : 'No') + '</td>' +
                    '<td><span class="badge ' + statusClass + '">' + status + '</span></td>' +
                    '<td><span class="maint-table-actions">' +
                        '<button class="btn secondary sm" data-action="edit-maint" data-id="' + w.id + '">Edit</button> ' +
                        '<button class="btn secondary sm" data-action="delete-maint" data-id="' + w.id + '">Delete</button>' +
                    '</span></td>' +
                '</tr>';
            }).join('');
            tbody.innerHTML = html;
        })['catch'](function() {
            // Fallback: render with IDs if fetch fails
            var now = new Date();
            var html = windows.map(function(w) {
                var start = new Date(w.start_time);
                var end = new Date(w.end_time);
                var status = 'Expired';
                var statusClass = 'unknown';
                if (now >= start && now <= end) { status = 'Active'; statusClass = 'warning'; }
                else if (now < start) { status = 'Scheduled'; statusClass = 'info'; }
                var scope = 'All Devices';
                if (w.device_id) scope = 'Device #' + w.device_id;
                if (w.site_id) scope = 'Site #' + w.site_id;
                return '<tr>' +
                    '<td>' + escapeHtml(w.name) + '</td>' +
                    '<td>' + scope + '</td>' +
                    '<td>' + formatDate(w.start_time) + '</td>' +
                    '<td>' + formatDate(w.end_time) + '</td>' +
                    '<td>' + (w.recurring ? 'Yes' : 'No') + '</td>' +
                    '<td><span class="badge ' + statusClass + '">' + status + '</span></td>' +
                    '<td><span class="maint-table-actions">' +
                        '<button class="btn secondary sm" data-action="edit-maint" data-id="' + w.id + '">Edit</button> ' +
                        '<button class="btn secondary sm" data-action="delete-maint" data-id="' + w.id + '">Delete</button>' +
                    '</span></td>' +
                '</tr>';
            }).join('');
            tbody.innerHTML = html;
        });
    }

    function showMaintModal(id) {
        document.getElementById('maint-modal').classList.add('active');
        document.getElementById('maint-modal-title').textContent = id ? 'Edit Maintenance Window' : 'Create Maintenance Window';
        document.getElementById('maint-form').reset();
        document.getElementById('maint-id').value = '';
        document.getElementById('maint-suppress-all').checked = true;
        document.getElementById('maint-alert-types-row').style.display = 'none';
        document.getElementById('maint-scope-device').style.display = 'none';
        document.getElementById('maint-scope-site').style.display = 'none';

        // Pre-fill datetime defaults: start=now, end=now+2h
        var now = new Date();
        var end = new Date(now.getTime() + 2 * 60 * 60 * 1000);
        function toLocal(d) { return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
        document.getElementById('maint-start').value = toLocal(now);
        document.getElementById('maint-end').value = toLocal(end);

        // Populate device select from API (not currentDevices which may be empty)
        var devSelect = document.getElementById('maint-device-id');
        var siteSelect = document.getElementById('maint-site-id');
        apiFetch(API_BASE + '/devices').then(function(r) {
            if (r && r.data) {
                devSelect.innerHTML = '<option value="">Select Device</option>' + r.data.map(function(d) {
                    var label = escapeHtml(d.name);
                    if (d.ip_address) label += ' (' + escapeHtml(d.ip_address) + ')';
                    return '<option value="' + d.id + '">' + label + '</option>';
                }).join('');
                // Re-apply device selection for edit mode
                if (id) {
                    var w = currentMaintenanceWindows.find(function(x) { return x.id === id; });
                    if (w && w.device_id) devSelect.value = w.device_id;
                }
            }
        });
        apiFetch(API_BASE + '/sites').then(function(r) {
            if (r && r.data) {
                siteSelect.innerHTML = '<option value="">Select Site</option>' + r.data.map(function(s) {
                    var label = escapeHtml(s.name);
                    if (s.region) label += ' (' + escapeHtml(s.region) + ')';
                    return '<option value="' + s.id + '">' + label + '</option>';
                }).join('');
                // Re-apply site selection for edit mode
                if (id) {
                    var w = currentMaintenanceWindows.find(function(x) { return x.id === id; });
                    if (w && w.site_id) siteSelect.value = w.site_id;
                }
            }
        });

        if (id) {
            var w = currentMaintenanceWindows.find(function(x) { return x.id === id; });
            if (!w) return;
            document.getElementById('maint-id').value = w.id;
            document.getElementById('maint-name').value = w.name;
            document.getElementById('maint-suppress-all').checked = w.suppress_all;
            if (!w.suppress_all) {
                document.getElementById('maint-alert-types-row').style.display = '';
                document.getElementById('maint-alert-types').value = w.alert_types || '';
            }
            document.getElementById('maint-notes').value = w.notes || '';
            if (w.start_time) document.getElementById('maint-start').value = w.start_time.slice(0, 16);
            if (w.end_time) document.getElementById('maint-end').value = w.end_time.slice(0, 16);
            var scopeVal = 'all';
            if (w.device_id) {
                scopeVal = 'device';
                document.getElementById('maint-scope-device').style.display = '';
            } else if (w.site_id) {
                scopeVal = 'site';
                document.getElementById('maint-scope-site').style.display = '';
            }
            // Set scope toggle radio
            var scopeRadio = document.querySelector('input[name="maint-scope"][value="' + scopeVal + '"]');
            if (scopeRadio) scopeRadio.checked = true;
        }
    }

    function closeMaintModal() {
        document.getElementById('maint-modal').classList.remove('active');
    }

    // Toggle scope fields (radio buttons)
    var maintScopeToggle = document.getElementById('maint-scope-toggle');
    if (maintScopeToggle) {
        maintScopeToggle.addEventListener('change', function(e) {
            if (e.target.name !== 'maint-scope') return;
            document.getElementById('maint-scope-device').style.display = e.target.value === 'device' ? '' : 'none';
            document.getElementById('maint-scope-site').style.display = e.target.value === 'site' ? '' : 'none';
        });
    }

    var maintSuppressAll = document.getElementById('maint-suppress-all');
    if (maintSuppressAll) {
        maintSuppressAll.addEventListener('change', function() {
            document.getElementById('maint-alert-types-row').style.display = this.checked ? 'none' : '';
        });
    }

    var maintForm = document.getElementById('maint-form');
    if (maintForm) {
        maintForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var id = document.getElementById('maint-id').value;
            var scopeRadio = document.querySelector('input[name="maint-scope"]:checked');
            var scope = scopeRadio ? scopeRadio.value : 'all';
            var data = {
                name: document.getElementById('maint-name').value,
                start_time: new Date(document.getElementById('maint-start').value).toISOString(),
                end_time: new Date(document.getElementById('maint-end').value).toISOString(),
                suppress_all: document.getElementById('maint-suppress-all').checked,
                alert_types: document.getElementById('maint-alert-types').value,
                notes: document.getElementById('maint-notes').value
            };
            if (scope === 'device') data.device_id = parseInt(document.getElementById('maint-device-id').value) || null;
            if (scope === 'site') data.site_id = parseInt(document.getElementById('maint-site-id').value) || null;

            var method = id ? 'PUT' : 'POST';
            var url = id ? (API_BASE + '/maintenance-windows/' + id) : (API_BASE + '/maintenance-windows');

            apiFetch(url, {method: method, body: data}).then(function() {
                closeMaintModal();
                loadMaintenance();
            })['catch'](function(err) { alert('Error: ' + (err.message || err)); });
        });
    }

    function deleteMaintWindow(id) {
        if (!confirm('Delete this maintenance window?')) return;
        apiFetch(API_BASE + '/maintenance-windows/' + id, {method: 'DELETE'}).then(function() {
            loadMaintenance();
        })['catch'](function(e) { alert('Delete failed: ' + e.message); });
    }

    // ---- Device Alert Config Modal ----
    function showDeviceAlertModal(deviceId) {
        var device = currentDevices.find(function(d) { return d.id === deviceId; });
        var title = device ? 'Alert Configuration: ' + device.name : 'Device Alert Configuration';
        document.getElementById('device-alert-modal-title').textContent = title;
        document.getElementById('device-alert-device-id').value = deviceId;

        // Reset form
        document.getElementById('device-alert-enabled').checked = true;
        document.getElementById('device-alert-cpu').value = '';
        document.getElementById('device-alert-memory').value = '';
        document.getElementById('device-alert-disk').value = '';
        document.getElementById('device-alert-sessions').value = '';
        document.getElementById('device-alert-cooldown').value = '';

        // Load policies for dropdown
        var policySelect = document.getElementById('device-alert-policy');
        policySelect.innerHTML = '<option value="">— Inherit from site/global —</option>';

        Promise.all([
            apiFetch(API_BASE + '/devices/' + deviceId + '/alert-config'),
            apiFetch(API_BASE + '/alert-policies')
        ]).then(function(results) {
            var configResp = results[0];
            var policiesResp = results[1];

            // Populate policy dropdown
            if (policiesResp && policiesResp.data) {
                policiesResp.data.forEach(function(p) {
                    var opt = document.createElement('option');
                    opt.value = p.id;
                    opt.textContent = p.name;
                    policySelect.appendChild(opt);
                });
            }

            // Populate config values
            if (configResp && configResp.data) {
                var cfg = configResp.data;
                document.getElementById('device-alert-enabled').checked = cfg.alerts_enabled !== false;
                if (cfg.policy_id) policySelect.value = cfg.policy_id;
                if (cfg.cpu_threshold) document.getElementById('device-alert-cpu').value = cfg.cpu_threshold;
                if (cfg.memory_threshold) document.getElementById('device-alert-memory').value = cfg.memory_threshold;
                if (cfg.disk_threshold) document.getElementById('device-alert-disk').value = cfg.disk_threshold;
                if (cfg.session_threshold) document.getElementById('device-alert-sessions').value = cfg.session_threshold;
                if (cfg.cooldown_minutes) document.getElementById('device-alert-cooldown').value = cfg.cooldown_minutes;
            }

            document.getElementById('device-alert-modal').classList.add('active');
        })['catch'](function(e) {
            alert('Failed to load alert config: ' + e.message);
        });
    }

    function closeDeviceAlertModal() {
        document.getElementById('device-alert-modal').classList.remove('active');
    }

    function resetDeviceAlertConfig() {
        var deviceId = document.getElementById('device-alert-device-id').value;
        if (!deviceId) return;
        if (!confirm('Reset alert configuration to defaults? This removes all overrides for this device.')) return;
        apiFetch(API_BASE + '/devices/' + deviceId + '/alert-config', { method: 'DELETE' }).then(function() {
            closeDeviceAlertModal();
            loadDevices();
        })['catch'](function(e) { alert('Reset failed: ' + e.message); });
    }

    var deviceAlertForm = document.getElementById('device-alert-form');
    if (deviceAlertForm) {
        deviceAlertForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var deviceId = document.getElementById('device-alert-device-id').value;
            if (!deviceId) return;

            var data = {
                device_id: parseInt(deviceId),
                alerts_enabled: document.getElementById('device-alert-enabled').checked
            };

            var policyVal = document.getElementById('device-alert-policy').value;
            if (policyVal) data.policy_id = parseInt(policyVal);
            else data.policy_id = null;

            var cpu = document.getElementById('device-alert-cpu').value;
            var mem = document.getElementById('device-alert-memory').value;
            var disk = document.getElementById('device-alert-disk').value;
            var sess = document.getElementById('device-alert-sessions').value;
            var cool = document.getElementById('device-alert-cooldown').value;

            data.cpu_threshold = cpu !== '' ? parseFloat(cpu) : 0;
            data.memory_threshold = mem !== '' ? parseFloat(mem) : 0;
            data.disk_threshold = disk !== '' ? parseFloat(disk) : 0;
            data.session_threshold = sess !== '' ? parseInt(sess) : 0;
            data.cooldown_minutes = cool !== '' ? parseInt(cool) : 0;

            apiFetch(API_BASE + '/devices/' + deviceId + '/alert-config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            }).then(function() {
                closeDeviceAlertModal();
                loadDevices();
            })['catch'](function(err) { alert('Error saving alert config: ' + err.message); });
        });
    }

    // ---- Event Delegation (click) ----
    AC.delegateEvent('click', {
        'show-device-modal': function() { showDeviceModal(); },
        'load-interfaces': function() { loadInterfaces(); },
        'iface-prev-page': function() { ifacePrevPage(); },
        'iface-next-page': function() { ifaceNextPage(); },
        'show-connection-modal': function() { showConnectionModal(); },
        'load-syslog': function() { loadSyslog(); },
        'load-more-syslog': function() { loadMoreSyslog(); },
        'set-flow-range': function(el) {
            var hours = parseInt(el.dataset.hours);
            setFlowRange(hours);
        },
        'load-flows': function() { loadFlows(); },
        'load-more-flows': function() { loadMoreFlows(); },
        'load-alerts': function() { loadAlerts(); },
        'load-more-alerts': function() { loadMoreAlerts(); },
        'load-traps': function() { loadTraps(); },
        'load-more-traps': function() { loadMoreTraps(); },
        'change-password': function() { changePassword(); },
        'save-settings': function() { saveSettings(); },
        'start-migration': function() { startMigration(); },
        'test-email': function() { testEmail(); },
        'test-webhook': function(el) { testWebhook(el.dataset.type); },
        'close-device-modal': function() { closeDeviceModal(); },
        'device-alert-config': function(el) { showDeviceAlertModal(parseInt(el.dataset.id)); },
        'close-device-alert-modal': function() { closeDeviceAlertModal(); },
        'reset-device-alert-config': function() { resetDeviceAlertConfig(); },
        'test-device-connection': function(el) { testDeviceConnection(el); },
        'close-connection-modal': function() { closeConnectionModal(); },
        'edit-device': function(el) { editDevice(parseInt(el.dataset.id)); },
        'delete-device': function(el) { deleteDevice(parseInt(el.dataset.id)); },
        'delete-connection': function(el) { deleteConnection(parseInt(el.dataset.id)); },
        'show-ack-modal': function(el) { showAckModal(parseInt(el.dataset.id)); },
        'close-ack-modal': function() { closeAckModal(); },
        'show-policy-modal': function() { showPolicyModal(); },
        'close-policy-modal': function() { closePolicyModal(); },
        'edit-policy': function(el) { showPolicyModal(parseInt(el.dataset.id)); },
        'clone-policy': function(el) { clonePolicy(parseInt(el.dataset.id)); },
        'delete-policy': function(el) { deletePolicy(parseInt(el.dataset.id)); },
        'show-maint-modal': function() { showMaintModal(); },
        'close-maint-modal': function() { closeMaintModal(); },
        'edit-maint': function(el) { showMaintModal(parseInt(el.dataset.id)); },
        'delete-maint': function(el) { deleteMaintWindow(parseInt(el.dataset.id)); },
        'toggle-expand': function(el) { el.classList.toggle('expanded'); }
    });

    // Click-to-filter: clicking a conversation row populates src/dst filters and reloads flow table
    document.addEventListener('click', function(e) {
        var row = e.target.closest('.conv-row');
        if (!row) return;
        var srcInput = document.getElementById('flows-filter-src');
        var dstInput = document.getElementById('flows-filter-dst');
        if (srcInput) srcInput.value = row.dataset.src || '';
        if (dstInput) dstInput.value = row.dataset.dst || '';
        loadFlows();
    });

    // ---- Init ----
    var initialPage = activateTabFromUrl();
    AC.fetchCsrfToken().then(function() { loadPageData(initialPage); });

    adminRefreshTimer = setInterval(function() {
        var activePage = document.querySelector('.page.active');
        if (activePage && activePage.id === 'page-dashboard') loadDashboard();
    }, 30000);
})();
