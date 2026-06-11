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
    var connRefreshTimer;
    var syslogRefreshTimer;
    var syslogOffset = 0;
    var flowsOffset = 0;
    // v0.10.212 (bundle A2) — per-analytics-page state. Initialized from URL
    // on first tab activation by wireSyslog/Alerts/TrapsAnalyticsPage(). The
    // `hours` value drives both the stats fetch and is mirrored back to the
    // pill bar via FwmonControls. Sentinel of 0/'' means "default" and is
    // stripped from the URL by FwmonControls.syncURL.
    var analyticsPages = { syslog: null, alerts: null, traps: null, audit: null };
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

    // Shared utilities imported from admin-common.js
    var connStyle = AC.connStyle;
    var matchMethodBadge = AC.matchMethodBadge;
    var typeBadgeHtml = AC.typeBadgeHtml;
    var formatBytes = AC.formatBytes;

    function formatBps(bps) {
        if (!bps || bps <= 0) return '0 bps';
        if (bps < 1) return bps.toFixed(2) + ' bps';
        var units = ['bps','Kbps','Mbps','Gbps','Tbps'];
        var i = Math.floor(Math.log(bps) / Math.log(1000));
        if (i < 0) i = 0;
        if (i >= units.length) i = units.length - 1;
        return (bps / Math.pow(1000, i)).toFixed(1) + ' ' + units[i];
    }

    var formatNum = AC.formatNum;

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
            if (page !== 'connections') stopConnRefresh();
            loadPageData(page);
        });
    });

    function loadPageData(page) {
        switch(page) {
            case 'dashboard': loadDashboard(); break;
            case 'devices': loadDevices(); break;
            case 'interfaces': populateIfaceFilters().then(function() { loadInterfaces(); }); break;
            case 'connections': loadConnections(); break;
            case 'syslog': wireSyslogAnalyticsPage(); loadSyslog(); break;
            case 'flows':
                // v0.10.211: the Flows tab is owned by FwmonFlows (admin-flows.js).
                // It binds its own controls, syncs filters with the URL, and
                // handles uPlot rendering. The legacy loadFlows()/loadFlowCharts()
                // path is left below as a fallback in case admin-flows.js fails
                // to load. Devices + probes lists are populated for the filter
                // dropdowns first so FwmonFlows.applyStateToControls() can label
                // any pre-applied filter chips.
                ensureFlowFilterLists().then(function() {
                    if (window.FwmonFlows && window.FwmonFlows.init) {
                        window.FwmonFlows.init();
                    } else {
                        loadFlows();
                    }
                });
                break;
            case 'settings': loadSettings(); break;
            case 'reports': if (window.AdminReports && window.AdminReports.init) window.AdminReports.init(); break;
            case 'alerts': wireAlertsAnalyticsPage(); loadAlerts(); break;
            case 'traps': wireTrapsAnalyticsPage(); loadTraps(); break;
            case 'alert-policies': loadAlertPolicies(); break;
            case 'maintenance': loadMaintenance(); break;
            case 'audit': wireAuditAnalyticsPage(); loadAuditLogs(); break;
        }
    }

    // ---- Dashboard ----
    // ---- Stale-device card (v0.10.216, bundle F3) ----
    //
    // The dashboard card lists every device whose last successful poll is
    // older than the operator-selected threshold. Useful for catching the
    // "device says online, but we haven't actually heard from it in 3
    // hours" failure mode — a stuck poller, broken probe, mid-firmware
    // upgrade, etc.
    //
    // Threshold is operator-controllable (15m / 30m / 1h / 3h / 12h / 24h)
    // via the in-card <select>; default 1h. The selection is persisted in
    // localStorage so the operator's preferred sensitivity sticks across
    // reloads.
    var STALE_THRESHOLD_KEY = 'fwmon-stale-threshold-min';
    var staleDeviceListCache = [];

    function getStaleThresholdMin() {
        var sel = document.getElementById('stale-threshold-select');
        if (sel && sel.value) return parseInt(sel.value, 10) || 60;
        try {
            var saved = localStorage.getItem(STALE_THRESHOLD_KEY);
            if (saved) return parseInt(saved, 10) || 60;
        } catch (e) { /* localStorage blocked — fall through */ }
        return 60;
    }

    function renderStaleDevices(deviceList) {
        staleDeviceListCache = deviceList || [];
        var card  = document.getElementById('stale-devices-card');
        var host  = document.getElementById('stale-devices-list');
        var count = document.getElementById('stale-devices-count');
        if (!card || !host) return;

        var sel = document.getElementById('stale-threshold-select');
        if (sel && !sel.__fwmonBound) {
            sel.__fwmonBound = true;
            try {
                var saved = localStorage.getItem(STALE_THRESHOLD_KEY);
                if (saved) sel.value = saved;
            } catch (e) { /* ignore */ }
            sel.addEventListener('change', function() {
                try { localStorage.setItem(STALE_THRESHOLD_KEY, sel.value); } catch (e) { /* ignore */ }
                renderStaleDevices(staleDeviceListCache);
            });
        }

        var thresholdMs = getStaleThresholdMin() * 60 * 1000;
        var now = Date.now();
        var stale = staleDeviceListCache.filter(function(d) {
            if (!d.last_polled) return true; // never polled → always stale
            var t = new Date(d.last_polled).getTime();
            if (!isFinite(t)) return true;
            return (now - t) > thresholdMs;
        });

        if (stale.length === 0) {
            card.style.display = 'none';
            return;
        }

        // Sort: oldest last_polled first (most concerning).
        stale.sort(function(a, b) {
            var ta = a.last_polled ? new Date(a.last_polled).getTime() : 0;
            var tb = b.last_polled ? new Date(b.last_polled).getTime() : 0;
            return ta - tb;
        });

        card.style.display = '';
        if (count) count.textContent = stale.length + ' stale';

        host.innerHTML =
            '<table style="width:100%;border-collapse:collapse;">' +
                '<thead><tr>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Device</th>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">IP</th>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Last polled</th>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Status</th>' +
                    '<th></th>' +
                '</tr></thead>' +
                '<tbody>' +
                stale.map(function(d) {
                    var lastSeen = d.last_polled ? timeAgo(d.last_polled) : 'never';
                    var statusBadge = '<span class="badge ' + escapeHtml(d.status || 'unknown') + '">' +
                        escapeHtml((d.status || 'unknown').toUpperCase()) + '</span>';
                    return '<tr>' +
                        '<td style="padding:8px;border-bottom:1px solid #21262d;">' +
                            AC.deviceLink(d.id, d.name) +
                        '</td>' +
                        '<td class="mono" style="padding:8px;border-bottom:1px solid #21262d;color:#8b949e;">' + escapeHtml(d.ip_address || '-') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #21262d;color:#8b949e;">' + lastSeen + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #21262d;">' + statusBadge + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #21262d;text-align:right;">' +
                            AC.sshLaunchButton(d) +
                        '</td>' +
                    '</tr>';
                }).join('') +
                '</tbody>' +
            '</table>';
    }

    // ---- Noisy-device leaderboard (v0.10.218, bundle G1) ----
    //
    // Ranks devices by recent alert + syslog volume so an operator can
    // spot the top offenders that are filling the queue. Uses the
    // `device_id` filter on /alerts/stats + /syslog/stats added in D4
    // (v0.10.217) — without that filter we'd need an N+1 pattern.
    //
    // The naive query pattern is still N+1 *across the device list*:
    // one /alerts/stats and one /syslog/stats call per device. Bounded
    // by the dashboard's existing device cap (1000, per D3). We fire
    // them in parallel and accept the request fan-out as the cost of
    // staying frontend-only — a proper per-device aggregate endpoint
    // could replace this in a future bundle if the request count
    // becomes a problem.
    var NOISY_WINDOW_KEY = 'fwmon-noisy-window-hours';
    var noisyDeviceListCache = [];

    function getNoisyWindowHours() {
        var sel = document.getElementById('noisy-window-select');
        if (sel && sel.value) return parseInt(sel.value, 10) || 24;
        try {
            var saved = localStorage.getItem(NOISY_WINDOW_KEY);
            if (saved) return parseInt(saved, 10) || 24;
        } catch (e) { /* ignore */ }
        return 24;
    }

    function renderNoisyDevices(deviceList) {
        noisyDeviceListCache = deviceList || [];
        var card  = document.getElementById('noisy-devices-card');
        var host  = document.getElementById('noisy-devices-list');
        var count = document.getElementById('noisy-devices-count');
        if (!card || !host) return;

        var sel = document.getElementById('noisy-window-select');
        if (sel && !sel.__fwmonBound) {
            sel.__fwmonBound = true;
            try {
                var saved = localStorage.getItem(NOISY_WINDOW_KEY);
                if (saved) sel.value = saved;
            } catch (e) { /* ignore */ }
            sel.addEventListener('change', function() {
                try { localStorage.setItem(NOISY_WINDOW_KEY, sel.value); } catch (e) { /* ignore */ }
                renderNoisyDevices(noisyDeviceListCache);
            });
        }

        if (noisyDeviceListCache.length === 0) {
            card.style.display = 'none';
            return;
        }

        host.innerHTML = '<div class="loading" style="padding:24px;color:#8b949e;">Loading top message producers…</div>';
        card.style.display = '';

        var hours = getNoisyWindowHours();
        // Concurrent fetch — one /alerts/stats and one /syslog/stats per
        // device, parameterized by ?device_id=. Promise.all collects them.
        var promises = noisyDeviceListCache.map(function(d) {
            return Promise.all([
                apiFetch(API_BASE + '/alerts/stats?hours=' + hours + '&device_id=' + d.id).catch(function() { return null; }),
                apiFetch(API_BASE + '/syslog/stats?hours=' + hours + '&device_id=' + d.id).catch(function() { return null; })
            ]).then(function(results) {
                var alertTotal  = (results[0] && results[0].data && results[0].data.total) || 0;
                var syslogTotal = (results[1] && results[1].data && results[1].data.total) || 0;
                return {
                    device: d,
                    alerts: alertTotal,
                    syslog: syslogTotal,
                    total:  alertTotal + syslogTotal
                };
            });
        });

        Promise.all(promises).then(function(rows) {
            // Drop devices with zero messages — the leaderboard is for
            // "noisy" devices, not a sparse list of silent ones.
            rows = rows.filter(function(r) { return r.total > 0; });
            if (rows.length === 0) {
                card.style.display = 'none';
                return;
            }
            // Sort descending by total volume, show top 10.
            rows.sort(function(a, b) { return b.total - a.total; });
            var topN = rows.slice(0, 10);
            if (count) count.textContent = 'top ' + topN.length;

            // Maximum value for bar widths (relative scale).
            var maxTotal = topN[0].total;

            host.innerHTML =
                '<table style="width:100%;border-collapse:collapse;">' +
                    '<thead><tr>' +
                        '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Device</th>' +
                        '<th style="text-align:right;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Alerts</th>' +
                        '<th style="text-align:right;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;">Syslog</th>' +
                        '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #30363d;width:40%;">Volume</th>' +
                    '</tr></thead>' +
                    '<tbody>' +
                    topN.map(function(r) {
                        var d = r.device;
                        var pct = Math.max(2, Math.round((r.total / maxTotal) * 100));
                        var alertsCell = r.alerts > 0
                            ? AC.filterLink('alerts', { device_id: d.id, hours: hours }, r.alerts.toLocaleString(),
                                { title: 'Show alerts from this device' })
                            : '<span style="color:#8b949e;">0</span>';
                        var syslogCell = r.syslog > 0
                            ? AC.filterLink('syslog', { device_id: d.id, hours: hours }, r.syslog.toLocaleString(),
                                { title: 'Show syslog from this device' })
                            : '<span style="color:#8b949e;">0</span>';
                        return '<tr>' +
                            '<td style="padding:8px;border-bottom:1px solid #21262d;">' +
                                AC.deviceLink(d.id, d.name) +
                            '</td>' +
                            '<td class="mono" style="padding:8px;border-bottom:1px solid #21262d;text-align:right;">' + alertsCell + '</td>' +
                            '<td class="mono" style="padding:8px;border-bottom:1px solid #21262d;text-align:right;">' + syslogCell + '</td>' +
                            '<td style="padding:8px;border-bottom:1px solid #21262d;">' +
                                '<div style="background:rgba(125,211,252,0.15);height:10px;border-radius:5px;width:' + pct + '%;min-width:20px;"' +
                                ' title="' + r.total.toLocaleString() + ' total"></div>' +
                            '</td>' +
                        '</tr>';
                    }).join('') +
                    '</tbody>' +
                '</table>';
        }).catch(function(err) {
            console.error('Noisy-device leaderboard failed:', err);
            host.innerHTML = '<div class="error" style="padding:16px;color:#f85149;">Failed to load leaderboard</div>';
        });
    }

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

            // Stale-device card (v0.10.216, bundle F3). Compares each
            // device's last_polled to the operator-chosen threshold and
            // surfaces anything past the cutoff. Hidden entirely when
            // nothing is stale.
            renderStaleDevices(deviceList);

            // Noisy-device leaderboard (v0.10.218, bundle G1). Ranks
            // devices by recent alert + syslog volume; fired after the
            // dashboard renders so the slower per-device stats fetches
            // don't block the initial paint.
            renderNoisyDevices(deviceList);

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
                    return '<div class="probe-card clickable" data-probe-id="' + escapeHtml(p.id) + '" data-probe-name="' + escapeHtml(p.name) + '">' +
                        '<div class="probe-name"><span class="pulse-dot ' + statusClass + '"></span>' + escapeHtml(p.name) + '</div>' +
                        '<div class="probe-meta">' + escapeHtml(p.site ? p.site.name : 'No Site') + ' &middot; ' + escapeHtml(p.approval_status) + ' &middot; Last seen: ' + lastSeen + '</div>' +
                        '<div class="probe-stats" id="probe-stats-' + p.id + '">' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Syslog<div class="last-hour">loading...</div></div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Traps<div class="last-hour">loading...</div></div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Flows<div class="last-hour">loading...</div></div></div>' +
                            '<div class="probe-stat"><div class="val">-</div><div class="lbl">Pings<div class="last-hour">loading...</div></div></div>' +
                        '</div></div>';
                }).join('');

                // Load stats for each probe
                probes.forEach(function(p) {
                    apiFetch(API_BASE + '/probes/' + p.id + '/stats').then(function(r) {
                        if (!r || !r.data) return;
                        var el = document.getElementById('probe-stats-' + p.id);
                        if (el) {
                            var d = r.data;
                            var lh = d.last_hour || {};
                            el.innerHTML =
                                '<div class="probe-stat"><div class="lbl">Syslog<div class="last-hour">+' + (lh.syslog || 0).toLocaleString() + ' / hr</div></div></div>' +
                                '<div class="probe-stat"><div class="lbl">Traps<div class="last-hour">+' + (lh.traps || 0).toLocaleString() + ' / hr</div></div></div>' +
                                '<div class="probe-stat"><div class="lbl">Flows<div class="last-hour">+' + (lh.flows || 0).toLocaleString() + ' / hr</div></div></div>' +
                                '<div class="probe-stat"><div class="lbl">Pings<div class="last-hour">+' + (lh.pings || 0).toLocaleString() + ' / hr</div></div></div>';
                        }
                    }).catch(function(err) {
                        console.error('Failed to load probe stats:', err);
                    });
                });

                // Click handler for probe cards to show detail modal
                document.querySelectorAll('.probe-card.clickable').forEach(function(card) {
                    card.addEventListener('click', function() {
                        var probeId = parseInt(this.dataset.probeId);
                        var probeName = this.dataset.probeName;
                        showProbeDetailModal(probeId, probeName);
                    });
                });
            }

            // Probe detail modal functions
            window.showProbeDetailModal = function(probeId, probeName) {
                var modal = document.getElementById('probe-detail-modal');
                if (!modal) return;
                document.getElementById('probe-detail-name').textContent = probeName;
                document.getElementById('probe-detail-body').innerHTML = '<div class="loading">Loading...</div>';
                AC.openModal('probe-detail-modal');

                apiFetch(API_BASE + '/probes/' + probeId + '/stats').then(function(r) {
                    if (!r || !r.data) {
                        document.getElementById('probe-detail-body').innerHTML = '<div class="error">Failed to load stats</div>';
                        return;
                    }
                    var d = r.data;
                    var lh = d.last_hour || {};

                    var html = '<div class="probe-detail-totals">' +
                        '<div class="detail-stat"><div class="detail-val">' + (d.syslog || 0).toLocaleString() + '</div><div class="detail-lbl">Syslog Received<span class="last-hour">+' + (lh.syslog || 0).toLocaleString() + ' / hr</span></div></div>' +
                        '<div class="detail-stat"><div class="detail-val">' + (d.traps || 0).toLocaleString() + '</div><div class="detail-lbl">Traps Received<span class="last-hour">+' + (lh.traps || 0).toLocaleString() + ' / hr</span></div></div>' +
                        '<div class="detail-stat"><div class="detail-val">' + (d.flows || 0).toLocaleString() + '</div><div class="detail-lbl">Flows Sampled<span class="last-hour">+' + (lh.flows || 0).toLocaleString() + ' / hr</span></div></div>' +
                        '<div class="detail-stat"><div class="detail-val">' + (d.pings || 0).toLocaleString() + '</div><div class="detail-lbl">Pings Sent<span class="last-hour">+' + (lh.pings || 0).toLocaleString() + ' / hr</span></div></div>' +
                        '</div>';

                    // Hourly breakdown table
                    var breakdown = d.hourly_breakdown || [];
                    if (breakdown.length > 0) {
                        html += '<div class="probe-detail-breakdown"><h4>Hourly Breakdown (Last 24 Hours)</h4>' +
                            '<div class="detail-table-wrap"><table class="detail-table"><thead><tr><th>Hour</th><th>Syslog</th><th>Traps</th><th>Flows</th><th>Pings</th><th>Total</th></tr></thead><tbody>';
                        breakdown.forEach(function(h) {
                            var hourLabel = '';
                            if (h.timestamp) {
                                var d = new Date(h.timestamp);
                                var tz = AC.getTimezone();
                                hourLabel = d.toLocaleString('en-US', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
                            } else {
                                hourLabel = h.hour || '';
                            }
                            html += '<tr><td>' + escapeHtml(hourLabel) + '</td><td>' + (h.syslog || 0).toLocaleString() + '</td><td>' + (h.traps || 0).toLocaleString() + '</td><td>' + (h.flows || 0).toLocaleString() + '</td><td>' + (h.pings || 0).toLocaleString() + '</td><td>' + (h.total || 0).toLocaleString() + '</td></tr>';
                        });
                        html += '</tbody></table></div></div>';
                    }

                    document.getElementById('probe-detail-body').innerHTML = html;
                }).catch(function(err) {
                    console.error('Failed to load probe detail:', err);
                    document.getElementById('probe-detail-body').innerHTML = '<div class="error">Failed to load stats</div>';
                    AC.showError('Failed to load probe statistics');
                });
            };

            window.closeProbeDetailModal = function() {
                AC.closeModal('probe-detail-modal');
            };

            loadDashboardCharts();
        }).catch(function(e) {
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
        }).catch(function(e) { console.error('Failed to load dashboard charts:', e); });
    }

    function createChart(canvasId, type, labels, datasets, opts) {
        if (chartInstances[canvasId]) { chartInstances[canvasId].destroy(); }
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        var ctx2d = canvas.getContext('2d');
        var isDoughnut = type === 'doughnut' || type === 'pie';

        // Enhance datasets with area gradients if it's a line chart
        if (type === 'line' && ctx2d) {
            datasets.forEach(function(ds) {
                var color = ds.borderColor || '#58a6ff';
                var gradient = ctx2d.createLinearGradient(0, 0, 0, 250);
                // Convert hexadecimal or standard color formats to translucent gradients
                var startColor = 'rgba(88, 166, 255, 0.25)';
                if (color === '#d2992a') startColor = 'rgba(210, 153, 42, 0.25)';
                else if (color === '#f85149') startColor = 'rgba(248, 81, 73, 0.25)';
                else if (color === '#3fb950') startColor = 'rgba(63, 185, 80, 0.25)';
                
                gradient.addColorStop(0, startColor);
                gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
                ds.backgroundColor = gradient;
                ds.fill = true;
                ds.pointBackgroundColor = color;
                ds.pointBorderColor = '#0d1117';
                ds.pointBorderWidth = 2;
                ds.pointRadius = 4;
                ds.pointHoverRadius = 6;
                ds.tension = 0.4; // smooth curve
            });
        } else if (isDoughnut) {
            datasets.forEach(function(ds) {
                ds.borderWidth = 3;
                ds.borderColor = '#161b22';
                ds.hoverBorderWidth = 0;
            });
        }

        var defaults = {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: {
                    position: isDoughnut ? 'bottom' : 'top',
                }
            },
            scales: isDoughnut ? {} : {
                x: { ticks: { maxRotation: 0, maxTicksLimit: 8 } },
                y: { beginAtZero: true }
            }
        };
        
        var mergedOpts = Object.assign({}, defaults, opts || {});
        if (isDoughnut) {
            mergedOpts.cutout = '75%';
        }

        chartInstances[canvasId] = new Chart(canvas, { type: type, data: { labels: labels, datasets: datasets }, options: mergedOpts });
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
                    '<td><a href="/admin/devices/' + d.id + '" style="color:#58a6ff;text-decoration:none;font-weight:600">' + escapeHtml(d.name) + '</a>' + (d.description ? '<br><span style="color:#768390;font-size:0.78rem;">' + escapeHtml(d.description) + '</span>' : '') + '</td>' +
                    '<td class="mono">' + escapeHtml(d.ip_address) + '</td>' +
                    '<td>' + (d.probe ? escapeHtml(d.probe.name) : '<span style="color:#768390">-</span>') + '</td>' +
                    '<td>' + (d.site ? escapeHtml(d.site.name) : '<span style="color:#768390">-</span>') + '</td>' +
                    '<td id="dev-cpu-' + d.id + '" style="color:#768390">-</td>' +
                    '<td id="dev-mem-' + d.id + '" style="color:#768390">-</td>' +
                    '<td id="dev-sess-' + d.id + '" style="color:#768390">-</td>' +
                    '<td><span class="pulse-dot ' + (d.status === 'online' ? 'online' : 'offline') + '"></span><span class="badge ' + escapeHtml(d.status) + '">' + escapeHtml(d.status).toUpperCase() + '</span></td>' +
                    '<td><input type="checkbox" ' + (d.public_visible ? 'checked ' : '') + 'data-action="toggle-public-visible" data-id="' + d.id + '"></td>' +
                    '<td>' +
                        AC.sshLaunchButton(d) +
                        '<button class="btn secondary sm" data-action="device-alert-config" data-id="' + d.id + '">Alerts</button> ' +
                        '<button class="btn secondary sm" data-action="edit-device" data-id="' + d.id + '">Edit</button> ' +
                        '<button class="btn danger sm" data-action="delete-device" data-id="' + d.id + '">Delete</button>' +
                    '</td>' +
                '</tr>';
            }).join('') || '<tr><td colspan="10" class="empty-state">No devices configured</td></tr>';

            loadDeviceEnrichments();
            loadDeviceAlertIndicators();
        }).catch(function(e) {
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
            }).catch(function(err) {
                console.error('Failed to load device alert indicators:', err);
            });
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
        }).catch(function(err) {
            console.error('Failed to load device enrichments:', err);
        });
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
        }).catch(function(e) { console.error('Failed to load interfaces:', e); });
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
        }).catch(function(e) { console.error('Failed to populate interface filters:', e); });
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

    function formatBucketTime(bucket, hours) {
        if (!bucket) return '';
        var d = new Date(bucket);
        if (isNaN(d.getTime())) return bucket.substring(11,16) || bucket;
        var tz = AC.getTimezone();
        if (!hours || hours <= 24) {
            return d.toLocaleString('en-US', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
        } else if (hours <= 168) {
            return d.toLocaleString('en-US', { timeZone: tz, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
        } else {
            return d.toLocaleString('en-US', { timeZone: tz, month: '2-digit', day: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
        }
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
                    ? '<span style="color:#8b949e;font-size:0.75rem;">Auto-managed</span>'
                    : '<button class="btn danger sm" data-action="delete-connection" data-id="' + c.id + '">Delete</button>';
                var editBtn = '<button class="btn secondary sm" data-action="edit-connection" data-id="' + c.id + '">Edit</button>';
                // Cross-page nav (v0.10.215, bundle E2): source + dest
                // device names link straight to each device's detail page.
                var srcName = c.source_device ? c.source_device.name : ('DEV-' + c.source_device_id);
                var dstName = c.dest_device   ? c.dest_device.name   : ('DEV-' + c.dest_device_id);
                var srcCell = AC.deviceLink(c.source_device_id, srcName);
                var dstCell = AC.deviceLink(c.dest_device_id,   dstName);
                return '<tr>' +
                    '<td>' + escapeHtml(c.name) + (c.auto_detected ? ' <span class="badge" style="background:#388bfd;font-size:0.65rem;padding:1px 5px;">AUTO</span>' : '') + '</td>' +
                    '<td>' + srcCell + '</td>' +
                    '<td>' + dstCell + '</td>' +
                    '<td>' + escapeHtml(c.connection_type ? c.connection_type.toUpperCase() : 'IPSEC') + '</td>' +
                    '<td><span class="badge ' + escapeHtml(c.status) + '">' + escapeHtml(c.status).toUpperCase() + '</span></td>' +
                    '<td>' + matchMethodBadge(c.match_method, c.auto_detected) + '</td>' +
                    '<td style="font-size:0.8rem;color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(c.tunnel_names || '') + '">' + escapeHtml(c.tunnel_names || '-') + '</td>' +
                    '<td><a href="/admin/connections/' + c.id + '" style="color:#58a6ff;font-size:0.8rem;margin-right:8px;">Details</a>' + editBtn + ' ' + deleteBtn + '</td>' +
                '</tr>';
            }).join('') || '<tr><td colspan="8" class="empty-state">No connections configured</td></tr>';

            drawConnectionDiagram();
            populateDeviceSelects();
            startConnRefresh();
        }).catch(function(e) {
            console.error('Failed to load connections:', e);
        });
    }

    function startConnRefresh() {
        stopConnRefresh();
        // Visibility-gated (v0.10.214, bundle C2). The previous setInterval
        // hit the status-summary endpoint every 15s even when the admin
        // tab was hidden — meaningless work in a background tab.
        connRefreshTimer = AC.pollWhenVisible(pollConnectionStatuses, 15000, { immediate: false });
    }

    function stopConnRefresh() {
        if (connRefreshTimer) {
            if (typeof connRefreshTimer.stop === 'function') connRefreshTimer.stop();
            else clearInterval(connRefreshTimer);
            connRefreshTimer = null;
        }
    }

    function pollConnectionStatuses() {
        apiFetch(API_BASE + '/connections/status-summary').then(function(res) {
            if (!res || !res.data) return;
            var data = res.data;

            // Diff connection statuses
            var connChanges = [];
            var connMap = {};
            (data.connections || []).forEach(function(c) { connMap[c.id] = c.status; });
            currentConnections.forEach(function(c) {
                var newStatus = connMap[c.id];
                if (newStatus && newStatus !== c.status) {
                    connChanges.push({ id: c.id, status: newStatus, oldStatus: c.status });
                    c.status = newStatus; // update in-memory
                }
            });

            // Diff device statuses
            var deviceChanges = [];
            var devMap = {};
            (data.devices || []).forEach(function(d) { devMap[d.id] = d.status; });
            currentDevices.forEach(function(d) {
                var newStatus = devMap[d.id];
                if (newStatus && newStatus !== d.status) {
                    deviceChanges.push({ id: d.id, status: newStatus, oldStatus: d.status });
                    d.status = newStatus;
                }
            });

            // FWDiagram may not be loaded yet — diagram is lazy-loaded
            // (v0.10.214, bundle C3). Status updates only run if the
            // operator has actually opened the Connections tab.
            if ((connChanges.length > 0 || deviceChanges.length > 0) && window.FWDiagram) {
                FWDiagram.updateStatuses(connChanges, deviceChanges);
            }

            // Refresh VPN badges on device nodes
            apiFetch(API_BASE + '/connections/vpn-map').then(function(vpnRes) {
                if (vpnRes && vpnRes.data) {
                    currentVpnMap = vpnRes.data;
                    if (window.FWDiagram) FWDiagram.updateVPNBadges(currentVpnMap);
                }
            }).catch(function(err) {
                console.error('Failed to refresh VPN badges:', err);
            });

            if (connChanges.length > 0) {
                // Re-render table for simplicity
                if (connChanges.length > 0) {
                    var tbody = document.querySelector('#connections-table tbody');
                    if (tbody) {
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
                    }
                }
            }
        }).catch(function(err) {
            console.error('Failed to poll connection statuses:', err);
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
            var params = buildSyslogParams(10);
            return apiFetch(API_BASE + '/syslog?' + params);
        }).then(function(result) {
            if (!result) return;
            var messages = (result.data && result.data.messages) ? result.data.messages : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            renderSyslogTable(messages, false);
            syslogOffset = messages.length;
            updateSyslogPagination(messages.length, total);
            loadSyslogCharts();
        }).catch(function(e) {
            console.error('Failed to load syslog:', e);
        });
    }

    var syslogTotalCount = 0;

    function updateSyslogPagination(count, total) {
        syslogTotalCount = total;
        var container = document.getElementById('syslog-pagination');
        if (!container) return;
        if (total === 0) {
            container.innerHTML = '';
            return;
        }
        var from = syslogOffset - count + 1;
        var to = syslogOffset;
        var totalPages = Math.ceil(total / 10);
        var currentPage = Math.ceil(syslogOffset / 10);
        container.innerHTML =
            '<span style="color:#8b949e;">Showing ' + from + '-' + to + ' of ' + total.toLocaleString() + ' &nbsp;|&nbsp; </span>' +
            '<button class="btn secondary sm" data-action="prev-syslog"' + (currentPage <= 1 ? ' disabled' : '') + '>Prev</button> ' +
            '<span style="color:#8b949e;">Page ' + currentPage + ' of ' + totalPages + ' &nbsp;</span>' +
            '<button class="btn secondary sm" data-action="next-syslog"' + (syslogOffset >= total ? ' disabled' : '') + '>Next</button>';
    }

    function prevSyslog() {
        if (syslogOffset <= 10) return;
        syslogOffset -= 20;
        if (syslogOffset < 0) syslogOffset = 0;
        var params = buildSyslogParams(10);
        apiFetch(API_BASE + '/syslog?' + params + '&offset=' + syslogOffset).then(function(result) {
            if (!result) return;
            var messages = (result.data && result.data.messages) ? result.data.messages : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            renderSyslogTable(messages, false);
            syslogOffset += messages.length;
            updateSyslogPagination(messages.length, total);
        }).catch(function(e) {
            console.error('Failed to load prev syslog:', e);
        });
    }

    function nextSyslog() {
        var params = buildSyslogParams(10);
        apiFetch(API_BASE + '/syslog?' + params + '&offset=' + syslogOffset).then(function(result) {
            if (!result) return;
            var messages = (result.data && result.data.messages) ? result.data.messages : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            if (messages.length > 0) {
                renderSyslogTable(messages, false);
                syslogOffset += messages.length;
                updateSyslogPagination(messages.length, total);
            }
        }).catch(function(e) {
            console.error('Failed to load next syslog:', e);
        });
    }

    function loadSyslogCharts() {
        var s = analyticsPages.syslog && analyticsPages.syslog.getState();
        var hoursParam = (s && s.hours) ? ('?hours=' + s.hours) : '';
        apiFetch(API_BASE + '/syslog/stats' + hoursParam).then(function(result) {
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

            var labels = (d.over_time || []).map(function(b) { return formatBucketTime(b.bucket); });
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
        }).catch(function(e) { console.error('Failed to load syslog charts:', e); });
    }

    function buildSyslogParams(limit) {
        var parts = ['limit=' + limit];
        var s = analyticsPages.syslog && analyticsPages.syslog.getState();
        var probe = document.getElementById('syslog-filter-probe');
        var device = document.getElementById('syslog-filter-device');
        var severity = document.getElementById('syslog-filter-severity');
        var search = document.getElementById('syslog-filter-search');
        if (s && s.hours && Number(s.hours) !== 24) parts.push('hours=' + s.hours);
        if (probe && probe.value) parts.push('probe_id=' + probe.value);
        if (device && device.value) parts.push('device_id=' + device.value);
        if (severity && severity.value !== '') parts.push('severity=' + severity.value);
        if (search && search.value) parts.push('search=' + encodeURIComponent(search.value));
        return parts.join('&');
    }

    function renderSyslogTable(messages, append) {
        var tbody = document.querySelector('#syslog-table tbody');
        var html = messages.map(function(m) {
            var typeBadge = '';
            if (m.message) {
                var typeMatch = m.message.match(/type=(\w+)/);
                var subMatch = m.message.match(/subtype=(\w+)/);
                if (typeMatch) {
                    var t = typeMatch[1];
                    typeBadge = '<span class="badge ' + (t === 'TRAFFIC' ? 'info' : (t === 'IPS' ? 'error' : (t === 'AV' ? 'critical' : 'warning'))) + '">' + t + '</span>';
                }
            }
            // Cross-page nav (v0.10.215, bundle E2): source IP filters the
            // syslog page to "all entries from this device"; hostname does
            // the same via its column. Both stay on the same page (no full
            // reload — admin SPA picks up the ?search param on load).
            var srcIpCell = m.source_ip
                ? AC.filterLink('syslog', { search: m.source_ip }, m.source_ip,
                    { title: 'Show all syslog entries from ' + m.source_ip })
                : '';
            var hostnameCell = m.hostname
                ? AC.filterLink('syslog', { search: m.hostname }, m.hostname,
                    { title: 'Show all syslog entries from ' + m.hostname })
                : '';
            return '<tr class="syslog-row" data-id="' + m.id + '">' +
                '<td style="white-space:nowrap;">' + formatDate(m.timestamp) + '</td>' +
                '<td class="mono">' + srcIpCell + '</td>' +
                '<td>' + hostnameCell + '</td>' +
                '<td><span class="badge ' + severityBadgeClass(m.severity) + '">' + (SEVERITY_NAMES[m.severity] || m.severity) + '</span></td>' +
                '<td>' + typeBadge + '</td>' +
                '<td class="expandable-msg">' + escapeHtml(m.message) + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="6" class="empty-state">No syslog messages</td></tr>';
    }

    function showSyslogDetail(id) {
        apiFetch(API_BASE + '/syslog/' + id).then(function(result) {
            if (!result || !result.data) return;
            var m = result.data;
            var body = document.getElementById('syslog-detail-body');
            var parsedHtml = '';
            if (typeof window.formatFortiGateLogHtml === 'function' && m.message) {
                parsedHtml = window.formatFortiGateLogHtml(m.message);
            } else {
                parsedHtml =
                    '<div style="margin-bottom:16px;">' +
                        '<div style="margin-bottom:8px;"><span style="color:#8b949e;">Time:</span> ' + formatDate(m.timestamp) + '</div>' +
                        '<div style="margin-bottom:8px;"><span style="color:#8b949e;">Severity:</span> <span class="badge ' + severityBadgeClass(m.severity) + '">' + (SEVERITY_NAMES[m.severity] || m.severity) + '</span></div>' +
                        '<div style="margin-bottom:8px;"><span style="color:#8b949e;">Source IP:</span> <span style="font-family:monospace;color:#58a6ff;">' + escapeHtml(m.source_ip) + '</span></div>' +
                        '<div style="margin-bottom:8px;"><span style="color:#8b949e;">Hostname:</span> ' + escapeHtml(m.hostname) + '</div>' +
                        '<div style="margin-bottom:8px;"><span style="color:#8b949e;">App Name:</span> ' + escapeHtml(m.app_name) + '</div>' +
                    '</div>' +
                    '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-family:monospace;font-size:0.85rem;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(m.message) + '</div>';
            }
            body.innerHTML = parsedHtml;
            AC.openModal('syslog-detail-modal');
        }).catch(function(err) {
            console.error('Failed to load syslog detail:', err);
            AC.showError('Failed to load syslog detail');
        });
    }
    function closeSyslogDetail() { AC.closeModal('syslog-detail-modal'); }

    function loadMoreSyslog() {
        var params = buildSyslogParams(100);
        apiFetch(API_BASE + '/syslog?' + params + '&offset=' + syslogOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderSyslogTable(result.data, true);
                syslogOffset += result.data.length;
            }
        }).catch(function(err) {
            console.error('Failed to load more syslog:', err);
            AC.showError('Failed to load more syslog');
        });
    }

    // ---- Audit Logs ----
    var auditOffset = 0;
    var auditTotalCount = 0;
    var currentAuditLogs = [];

    function wireAuditAnalyticsPage() {
        if (!window.FwmonControls) return;
        if (analyticsPages.audit) {
            analyticsPages.audit.refresh();
            return;
        }
        analyticsPages.audit = FwmonControls.attachAnalyticsPage({
            page: 'audit',
            rangePillsId: 'audit-range-pills',
            chipsId: 'audit-active-chips',
            defaults: { hours: 24, actor: '', action: '' },
            inputs: [
                { id: 'audit-filter-actor',  stateKey: 'actor',  chipKey: 'actor' },
                { id: 'audit-filter-action', stateKey: 'action', chipKey: 'action' }
            ],
            selects: [],
            onChange: function() { loadAuditLogs(); }
        });
    }

    function loadAuditLogs() {
        auditOffset = 0;
        var params = buildAuditParams(10);
        apiFetch(API_BASE + '/audit?' + params).then(function(result) {
            if (!result) return;
            var logs = (result.data && result.data.audit_logs) ? result.data.audit_logs : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            currentAuditLogs = logs;
            renderAuditTable(logs, false);
            auditOffset = logs.length;
            updateAuditPagination(logs.length, total);
        }).catch(function(e) {
            fwmonLog.error('Failed to load audit logs:', e);
            AC.showError('Failed to load audit logs');
        });
    }

    function buildAuditParams(limit) {
        var parts = ['limit=' + limit];
        var s = analyticsPages.audit && analyticsPages.audit.getState();
        var actor = document.getElementById('audit-filter-actor');
        var action = document.getElementById('audit-filter-action');
        if (s && s.hours && Number(s.hours) !== 24) parts.push('hours=' + s.hours);
        if (actor && actor.value) parts.push('actor=' + encodeURIComponent(actor.value.trim()));
        if (action && action.value) parts.push('action=' + encodeURIComponent(action.value.trim()));
        return parts.join('&');
    }

    function renderAuditTable(logs, append) {
        var tbody = document.querySelector('#audit-table tbody');
        if (!tbody) return;
        
        var html = logs.map(function(log) {
            var statusClass = 'unknown';
            if (log.status >= 200 && log.status < 300) {
                statusClass = 'online';
            } else if (log.status >= 400) {
                statusClass = 'offline';
            }
            
            return '<tr class="audit-row" data-id="' + log.id + '">' +
                '<td>' + formatDate(log.created_at) + '</td>' +
                '<td><span style="font-weight:600;color:#e6edf3;">' + escapeHtml(log.actor) + '</span></td>' +
                '<td><span class="badge ' + (log.method === 'DELETE' ? 'error' : (log.method === 'POST' ? 'success' : 'info')) + '">' + escapeHtml(log.method) + '</span></td>' +
                '<td style="font-family:monospace;color:#8b949e;font-size:0.82rem;">' + escapeHtml(log.action) + '</td>' +
                '<td style="font-family:monospace;font-size:0.82rem;">' + escapeHtml(log.target || '—') + '</td>' +
                '<td><span class="badge ' + statusClass + '">' + log.status + '</span></td>' +
                '<td>' + escapeHtml(log.ip_address) + '</td>' +
                '</tr>';
        }).join('');
        
        if (append) {
            tbody.innerHTML += html;
        } else {
            tbody.innerHTML = html || '<tr><td colspan="7" style="text-align:center;color:#8b949e;padding:24px;">No audit records found</td></tr>';
        }
        
        tbody.querySelectorAll('.audit-row').forEach(function(row) {
            row.addEventListener('click', function() {
                var id = row.getAttribute('data-id');
                showAuditDetail(id);
            });
            row.style.cursor = 'pointer';
        });
    }

    function updateAuditPagination(count, total) {
        auditTotalCount = total;
        var info = document.getElementById('audit-page-info');
        var prevBtn = document.getElementById('audit-prev');
        var nextBtn = document.getElementById('audit-next');
        if (!info || !prevBtn || !nextBtn) return;
        
        if (total === 0) {
            info.textContent = 'No records';
            prevBtn.disabled = true;
            nextBtn.disabled = true;
            return;
        }
        
        var from = auditOffset - count + 1;
        var to = auditOffset;
        var totalPages = Math.ceil(total / 10);
        var currentPage = Math.ceil(auditOffset / 10);
        
        info.innerHTML = 'Showing ' + from + '-' + to + ' of ' + total.toLocaleString();
        prevBtn.disabled = (currentPage <= 1);
        nextBtn.disabled = (auditOffset >= total);
    }

    function prevAudit() {
        if (auditOffset <= 10) return;
        auditOffset -= 20;
        if (auditOffset < 0) auditOffset = 0;
        var params = buildAuditParams(10);
        apiFetch(API_BASE + '/audit?' + params + '&offset=' + auditOffset).then(function(result) {
            if (!result) return;
            var logs = (result.data && result.data.audit_logs) ? result.data.audit_logs : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            currentAuditLogs = logs;
            renderAuditTable(logs, false);
            auditOffset += logs.length;
            updateAuditPagination(logs.length, total);
        }).catch(function(e) {
            fwmonLog.error('Failed to load prev audit logs:', e);
            AC.showError('Failed to load prev audit logs');
        });
    }

    function nextAudit() {
        var params = buildAuditParams(10);
        apiFetch(API_BASE + '/audit?' + params + '&offset=' + auditOffset).then(function(result) {
            if (!result) return;
            var logs = (result.data && result.data.audit_logs) ? result.data.audit_logs : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            if (logs.length > 0) {
                currentAuditLogs = logs;
                renderAuditTable(logs, false);
                auditOffset += logs.length;
                updateAuditPagination(logs.length, total);
            }
        }).catch(function(e) {
            fwmonLog.error('Failed to load next audit logs:', e);
            AC.showError('Failed to load next audit logs');
        });
    }

    function showAuditDetail(id) {
        var log = currentAuditLogs.find(function(l) { return String(l.id) === String(id); });
        if (!log) return;
        
        var body = document.getElementById('audit-detail-body');
        if (!body) return;
        
        var parsedHtml = 
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">Timestamp</span>' + formatDate(log.created_at) + '</div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">Actor</span>' + escapeHtml(log.actor) + ' (ID: ' + log.actor_id + ')</div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">Action Route</span><span style="font-family:monospace;font-size:0.85rem;color:#58a6ff;">' + escapeHtml(log.method) + ' ' + escapeHtml(log.action) + '</span></div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">Target Parameters</span><div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px;font-family:monospace;font-size:0.85rem;white-space:pre-wrap;word-break:break-all;">' + (log.target ? escapeHtml(log.target) : 'None') + '</div></div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">Status</span><span class="badge ' + (log.status >= 200 && log.status < 300 ? 'online' : 'offline') + '">' + log.status + '</span></div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">IP Address</span>' + escapeHtml(log.ip_address) + '</div>' +
            '<div style="margin-bottom:12px;"><span style="color:#8b949e;display:block;font-size:0.75rem;text-transform:uppercase;">User Agent</span><div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px;font-size:0.85rem;word-break:break-all;color:#8b949e;">' + escapeHtml(log.user_agent) + '</div></div>';
            
        body.innerHTML = parsedHtml;
        AC.openModal('audit-detail-modal');
    }

    function closeAuditDetail() { AC.closeModal('audit-detail-modal'); }

    // ---- Flows ----
    // ensureFlowFilterLists — populate the device + probe <select> dropdowns
    // and expose the cached lists to FwmonFlows via window.adminMainState
    // (so chip rendering can resolve `device_id=42` to "fw-edge-01"). Cached
    // after first fetch like the original loadFlows() did.
    function ensureFlowFilterLists() {
        var p = Promise.resolve();
        if (currentProbes.length === 0) {
            p = apiFetch(API_BASE + '/probes').then(function(pr) {
                currentProbes = pr && pr.data ? pr.data : [];
            });
        }
        return p.then(function() {
            if (currentDevices.length === 0) {
                return apiFetch(API_BASE + '/devices').then(function(dr) {
                    currentDevices = dr && dr.data ? dr.data : [];
                });
            }
        }).then(function() {
            populateFilterProbes('flows-filter-probe');
            populateFilterDevices('flows-filter-device');
            // Surface to admin-flows.js for chip labels.
            window.adminMainState = window.adminMainState || {};
            window.adminMainState.devices = currentDevices;
            window.adminMainState.probes = currentProbes;
        });
    }

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
        }).catch(function(e) {
            console.error('Failed to load flows:', e);
        });
    }

    function setFlowRange(hours) {
        flowStatsHours = hours;
        document.querySelectorAll('.flow-range-btn').forEach(function(b) { b.classList.remove('active'); });
        var activeBtn = document.querySelector('.flow-range-btn[data-hours="' + hours + '"]');
        if (activeBtn) activeBtn.classList.add('active');
        var label = document.getElementById('flow-range-label');
        if (label) label.textContent = activeBtn ? activeBtn.textContent : hours + 'h';
        var select = document.getElementById('flow-range-select');
        if (select) select.value = hours;
        loadFlowCharts();
    }

    // Initialize flows range select dropdown
    var flowRangeSelect = document.getElementById('flow-range-select');
    if (flowRangeSelect) {
        flowRangeSelect.addEventListener('change', function() {
            setFlowRange(parseFloat(this.value));
        });
    }

    var bytesTickCallback = function(value) { return formatBytes(value); };
    var bytesTooltipCallback = function(ctx) { var v = ctx.chart.options.indexAxis === 'y' ? ctx.parsed.x : ctx.parsed.y; return ctx.dataset.label + ': ' + formatBytes(v != null ? v : 0); };
    var bpsTickCallback = function(value) { return formatBps(value); };
    var bpsTooltipCallback = function(ctx) { var v = ctx.chart.options.indexAxis === 'y' ? ctx.parsed.x : ctx.parsed.y; return ctx.dataset.label + ': ' + formatBps(v != null ? v : 0); };

    // Shared options for horizontal bar charts
    var horizBarOpts = function(color) {
        return {
            indexAxis:'y',
            scales: {
                x: { beginAtZero: true, ticks: { color: '#484f58', font:{size:10}, callback: bytesTickCallback }, grid: { color: '#21262d' } },
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
            // 5 stat cards
            document.getElementById('flows-total').textContent = (d.total_flows || 0).toLocaleString();
            document.getElementById('flows-bytes').textContent = formatBytes(d.total_bytes || 0);
            document.getElementById('flows-throughput').textContent = formatBps(d.bits_per_second || 0);
            document.getElementById('flows-sources').textContent = (d.unique_sources || 0).toLocaleString();
            document.getElementById('flows-dests').textContent = (d.unique_dests || 0).toLocaleString();
            document.getElementById('flows-protocols').textContent = (d.protocol_count || 0).toLocaleString();
            document.getElementById('flows-sampling-rate').textContent = d.avg_sampling_rate > 1 ? '1:' + Math.round(d.avg_sampling_rate) : 'None';
            document.getElementById('flows-packets').textContent = (d.total_packets || 0).toLocaleString();

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

            // Top ports bar (horizontal)
            var portLabels = (d.top_ports || []).map(function(s) { return s.key; });
            var portCounts = (d.top_ports || []).map(function(s) { return s.count; });
            createChart('flows-top-ports-chart','bar',portLabels,[{label:'Bytes',data:portCounts,backgroundColor:'#d2992a',borderRadius:3}], horizBarOpts('#d2992a'));

            // Bandwidth over time (bits/sec) — use server-provided bucket interval
            var intervalSec = d.bucket_seconds || 3600;
            var timeLabels = (d.bytes_over_time || []).map(function(b) { return formatBucketTime(b.bucket, flowStatsHours); });
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
        }).catch(function(e) { console.error('Failed to load flow charts:', e); });
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
            return '<tr>' +
                '<td style="white-space:nowrap;">' + formatDate(f.timestamp) + '</td>' +
                '<td class="mono">' + escapeHtml(f.src_addr) + ':' + f.src_port + '</td>' +
                '<td>&#8594;</td>' +
                '<td class="mono">' + escapeHtml(f.dst_addr) + ':' + f.dst_port + '</td>' +
                '<td>' + (PROTOCOL_NAMES[f.protocol] || f.protocol) + '</td>' +
                '<td>' + formatBytes(f.bytes) + '</td>' +
                '<td>' + f.packets + '</td>' +
                '<td>' + (f.sampling_rate ? '1:' + f.sampling_rate : '-') + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="8" class="empty-state">No flow samples</td></tr>';
    }

    function loadMoreFlows() {
        var params = buildFlowParams(100);
        apiFetch(API_BASE + '/flows?' + params + '&offset=' + flowsOffset).then(function(result) {
            if (result && result.data && result.data.length) {
                renderFlowsTable(result.data, true);
                flowsOffset += result.data.length;
            }
        }).catch(function(err) {
            console.error('Failed to load more flows:', err);
            AC.showError('Failed to load more flows');
        });
    }

    function populateFilterProbes(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        var currentVal = sel.value;
        sel.innerHTML = '<option value="">All Probes</option>' + currentProbes.map(function(p) {
            return '<option value="' + p.id + '"' + (p.id == currentVal ? ' selected' : '') + '>' + escapeHtml(p.name) + '</option>';
        }).join('');
    }

    function populateFilterDevices(selectId) {
        var sel = document.getElementById(selectId);
        if (!sel) return;
        var currentVal = sel.value;
        sel.innerHTML = '<option value="">All Devices</option>' + currentDevices.map(function(d) {
            return '<option value="' + d.id + '"' + (d.id == currentVal ? ' selected' : '') + '>' + escapeHtml(d.name) + '</option>';
        }).join('');
    }

    // Syslog auto-refresh — visibility-gated (v0.10.214, bundle C2). The
    // page-active check still applies so we don't run when on a different
    // admin tab, plus the new gate suspends when the whole browser tab is
    // hidden.
    var sysAutoRefreshEl = document.getElementById('syslog-auto-refresh');
    if (sysAutoRefreshEl) {
        sysAutoRefreshEl.addEventListener('change', function() {
            if (this.checked) {
                syslogRefreshTimer = AC.pollWhenVisible(function() {
                    if (document.querySelector('#page-syslog.active')) loadSyslog();
                }, 10000, { immediate: false });
            } else if (syslogRefreshTimer) {
                if (typeof syslogRefreshTimer.stop === 'function') syslogRefreshTimer.stop();
                else clearInterval(syslogRefreshTimer);
                syslogRefreshTimer = null;
            }
        });
    }

    // ---- Alerts ----
    var ALERTS_PAGE_SIZE = 10;
    var alertSelection = {}; // map id (string) -> true for currently-selected rows on the current page
    var selectAllMatchingMode = false; // true when user clicked "Select all N matching" — bulk-ack uses filter, not IDs

    function loadAlerts() {
        alertsOffset = 0;
        clearAlertSelection();
        var p = Promise.resolve();
        if (currentDevices.length === 0) {
            p = apiFetch(API_BASE + '/devices').then(function(dr) { currentDevices = dr && dr.data ? dr.data : []; });
        }
        p.then(function() {
            var params = buildAlertParams(ALERTS_PAGE_SIZE);
            return apiFetch(API_BASE + '/alerts?' + params);
        }).then(function(result) {
            if (!result) return;
            var alerts = (result.data && result.data.alerts) ? result.data.alerts : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            renderAlertsTable(alerts, false);
            alertsOffset = alerts.length;
            updateAlertPagination(alerts.length, total);
            loadAlertCharts();
        }).catch(function(e) {
            console.error('Failed to load alerts:', e);
        });
    }

    // refreshAlertsAtCurrentPage re-fetches the same page the user is currently
    // viewing. Used after single-ack and bulk-ack so the user doesn't get
    // bounced back to page 1. If the current page would be empty after the
    // refresh (because every visible row got acked and the filter is "unack"),
    // step back one page until we find content or hit page 1.
    function refreshAlertsAtCurrentPage() {
        var pageSize = ALERTS_PAGE_SIZE;
        var pageEnd = alertsOffset; // current offset == end of current page
        var pageStart = Math.max(0, pageEnd - pageSize);

        function tryLoad(offset) {
            var params = buildAlertParams(pageSize);
            return apiFetch(API_BASE + '/alerts?' + params + '&offset=' + offset).then(function(result) {
                if (!result) return;
                var alerts = (result.data && result.data.alerts) ? result.data.alerts : [];
                var total = (result.data && result.data.total) ? result.data.total : 0;
                if (alerts.length === 0 && offset > 0) {
                    // Page got empty (all rows acked). Try the previous page.
                    return tryLoad(Math.max(0, offset - pageSize));
                }
                renderAlertsTable(alerts, false);
                alertsOffset = offset + alerts.length;
                updateAlertPagination(alerts.length, total);
                loadAlertCharts();
            });
        }
        tryLoad(pageStart).catch(function(e) {
            console.error('Failed to refresh alerts at current page:', e);
        });
    }

    function clearAlertSelection() {
        alertSelection = {};
        updateAlertBulkToolbar();
    }

    function updateAlertBulkToolbar() {
        var ids = Object.keys(alertSelection).filter(function(k) { return alertSelection[k]; });
        var count = ids.length;
        var summary = document.getElementById('alerts-bulk-summary');
        var ackBtn = document.getElementById('alerts-bulk-ack-btn');
        var clearBtn = document.getElementById('alerts-bulk-clear-btn');
        var pageBox = document.getElementById('alerts-select-page');
        if (summary) {
            if (selectAllMatchingMode) {
                summary.textContent = 'All ' + alertTotalCount.toLocaleString() + ' matching alerts selected';
            } else {
                summary.textContent = count === 0 ? 'No alerts selected' : (count + ' alert' + (count === 1 ? '' : 's') + ' selected');
            }
        }
        if (ackBtn) ackBtn.disabled = count === 0 && !selectAllMatchingMode;
        if (clearBtn) clearBtn.disabled = count === 0 && !selectAllMatchingMode;
        // Sync the page-select checkbox state with row checkboxes on this page.
        if (pageBox) {
            var rowBoxes = document.querySelectorAll('#alerts-full-table tbody input[data-action="toggle-alert-selection"]');
            var checkedCount = 0;
            rowBoxes.forEach(function(b) { if (b.checked) checkedCount++; });
            pageBox.checked = rowBoxes.length > 0 && checkedCount === rowBoxes.length;
            pageBox.indeterminate = checkedCount > 0 && checkedCount < rowBoxes.length;
        }
        updateSelectAllMatchingBanner();
    }

    // updateSelectAllMatchingBanner shows the GitHub-style "Select all N matching"
    // prompt when the page-select checkbox is fully checked AND there are more
    // matching rows than fit on this page. Hides when no longer applicable.
    function updateSelectAllMatchingBanner() {
        var banner = document.getElementById('alerts-select-all-matching');
        if (!banner) return;
        var pageBox = document.getElementById('alerts-select-page');
        var pageFullySelected = pageBox && pageBox.checked && !pageBox.indeterminate;
        var hasMoreMatching = alertTotalCount > ALERTS_PAGE_SIZE;

        if (selectAllMatchingMode) {
            banner.style.display = '';
            banner.innerHTML =
                'All <strong>' + alertTotalCount.toLocaleString() + '</strong> matching alerts are selected. ' +
                '<a href="#" data-action="cancel-select-all-matching" style="color:#58a6ff;text-decoration:underline">Clear selection</a>';
            return;
        }
        if (pageFullySelected && hasMoreMatching) {
            banner.style.display = '';
            banner.innerHTML =
                Object.keys(alertSelection).length + ' selected on this page. ' +
                '<a href="#" data-action="select-all-matching" style="color:#58a6ff;text-decoration:underline">' +
                'Select all ' + alertTotalCount.toLocaleString() + ' matching the current filter</a>';
            return;
        }
        banner.style.display = 'none';
        banner.innerHTML = '';
    }

    function enableSelectAllMatching() {
        selectAllMatchingMode = true;
        updateAlertBulkToolbar();
    }

    function cancelSelectAllMatching() {
        selectAllMatchingMode = false;
        // Also clear the per-row selection so the user starts fresh.
        var rowBoxes = document.querySelectorAll('#alerts-full-table tbody input[data-action="toggle-alert-selection"]');
        rowBoxes.forEach(function(b) { b.checked = false; });
        clearAlertSelection();
    }

    function bulkAckSelected() {
        var ids = Object.keys(alertSelection).filter(function(k) { return alertSelection[k]; }).map(function(k) { return parseInt(k, 10); });
        var count = selectAllMatchingMode ? alertTotalCount : ids.length;
        if (count === 0) return;
        var modal = document.getElementById('alerts-bulk-ack-modal');
        var label = 'Acknowledging ' + count.toLocaleString() + ' alert' + (count === 1 ? '' : 's');
        if (selectAllMatchingMode) label += ' (all matching the current filter)';
        document.getElementById('alerts-bulk-ack-count').textContent = label;
        document.getElementById('alerts-bulk-ack-notes').value = '';
        AC.openModal('alerts-bulk-ack-modal');
    }

    function confirmBulkAck() {
        var notes = document.getElementById('alerts-bulk-ack-notes').value || '';
        var btn = document.getElementById('alerts-bulk-ack-confirm');
        if (btn) btn.disabled = true;

        var promise;
        if (selectAllMatchingMode) {
            // Filter-based ack: server walks every row matching the current filter
            // (potentially thousands), so we don't have to ship IDs. The server
            // requires at least one filter as a safety guard against accidental
            // "ack everything in the DB" calls. When the user is bulk-acking from
            // the unfiltered view, default to acknowledged=false — the natural
            // meaning of "clear all alerts" is "ack the unacknowledged ones."
            // Re-acking already-acked rows would overwrite their existing notes,
            // which is rarely what an operator wants.
            var params = buildAlertParams(0); // limit/offset are irrelevant for the UPDATE
            if (params.indexOf('acknowledged=') === -1) {
                params += '&acknowledged=false';
            }
            promise = apiFetch(API_BASE + '/alerts/bulk-acknowledge-filter?' + params, {
                method: 'POST',
                body: { notes: notes }
            });
        } else {
            var ids = Object.keys(alertSelection).filter(function(k) { return alertSelection[k]; }).map(function(k) { return parseInt(k, 10); });
            if (ids.length === 0) {
                if (btn) btn.disabled = false;
                return;
            }
            promise = apiFetch(API_BASE + '/alerts/bulk-acknowledge', {
                method: 'POST',
                body: { ids: ids, notes: notes }
            });
        }

        promise.then(function(result) {
            AC.closeModal('alerts-bulk-ack-modal');
            selectAllMatchingMode = false;
            clearAlertSelection();
            var n = (result && result.data && result.data.acknowledged) || 0;
            AC.showSuccess(n + ' alert' + (n === 1 ? '' : 's') + ' acknowledged');
            refreshAlertsAtCurrentPage();
        }).catch(function(e) {
            console.error('Bulk ack failed:', e);
            // Surface the server's error message if apiFetch attached one to
            // the rejection (e.g. "at least one filter is required"). Falls
            // back to the generic toast for opaque network errors.
            var detail = (e && (e.message || e.error)) || '';
            AC.showError(detail ? 'Bulk acknowledge failed: ' + detail : 'Bulk acknowledge failed');
        }).finally(function() {
            if (btn) btn.disabled = false;
        });
    }

    var alertTotalCount = 0;

    function updateAlertPagination(count, total) {
        alertTotalCount = total;
        var container = document.getElementById('alerts-pagination');
        if (!container) return;
        if (total === 0) {
            container.innerHTML = '';
            return;
        }
        var from = alertsOffset - count + 1;
        var to = alertsOffset;
        var totalPages = Math.ceil(total / 10);
        var currentPage = Math.ceil(alertsOffset / 10);
        container.innerHTML =
            '<span style="color:#8b949e;">Showing ' + from + '-' + to + ' of ' + total.toLocaleString() + ' &nbsp;|&nbsp; </span>' +
            '<button class="btn secondary sm" data-action="prev-alerts"' + (currentPage <= 1 ? ' disabled' : '') + '>Prev</button> ' +
            '<span style="color:#8b949e;">Page ' + currentPage + ' of ' + totalPages + ' &nbsp;</span>' +
            '<button class="btn secondary sm" data-action="next-alerts"' + (alertsOffset >= total ? ' disabled' : '') + '>Next</button>';
    }

    function prevAlerts() {
        if (alertsOffset <= 10) return;
        alertsOffset -= 20;
        if (alertsOffset < 0) alertsOffset = 0;
        var params = buildAlertParams(10);
        apiFetch(API_BASE + '/alerts?' + params + '&offset=' + alertsOffset).then(function(result) {
            if (!result) return;
            var alerts = (result.data && result.data.alerts) ? result.data.alerts : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            renderAlertsTable(alerts, false);
            alertsOffset += alerts.length;
            updateAlertPagination(alerts.length, total);
        }).catch(function(e) {
            console.error('Failed to load prev alerts:', e);
        });
    }

    function nextAlerts() {
        var params = buildAlertParams(10);
        apiFetch(API_BASE + '/alerts?' + params + '&offset=' + alertsOffset).then(function(result) {
            if (!result) return;
            var alerts = (result.data && result.data.alerts) ? result.data.alerts : [];
            var total = (result.data && result.data.total) ? result.data.total : 0;
            if (alerts.length > 0) {
                renderAlertsTable(alerts, false);
                alertsOffset += alerts.length;
                updateAlertPagination(alerts.length, total);
            }
        }).catch(function(e) {
            console.error('Failed to load next alerts:', e);
        });
    }

    function buildAlertParams(limit) {
        var parts = ['limit=' + limit];
        var s = analyticsPages.alerts && analyticsPages.alerts.getState();
        var dev = document.getElementById('alerts-filter-device');
        var type = document.getElementById('alerts-filter-type');
        var sev = document.getElementById('alerts-filter-severity');
        var ack = document.getElementById('alerts-filter-ack');
        if (s && s.hours && Number(s.hours) !== 24) parts.push('hours=' + s.hours);
        if (dev && dev.value) parts.push('device_id=' + dev.value);
        if (type && type.value) parts.push('alert_type=' + encodeURIComponent(type.value));
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
        // Reset selection state and the header checkbox state. Do this BEFORE
        // setting innerHTML so the header `pageBox` doesn't carry its previous
        // checked state across page navigations (which is visually wrong —
        // none of the *new* row checkboxes are checked).
        if (!append) {
            alertSelection = {};
            // Don't try to read row boxes here — they're about to be replaced.
            // Just force the header to a known state.
            var pageBox = document.getElementById('alerts-select-page');
            if (pageBox) { pageBox.checked = false; pageBox.indeterminate = false; }
            selectAllMatchingMode = false;
            updateSelectAllMatchingBanner();
        }
        var html = alerts.map(function(a) {
            var statusCol = '';
            // Already-acked rows can't be re-selected from the bulk toolbar (but
            // appear in the page so the user can still see notes/timestamps).
            var canSelect = !a.acknowledged && !a.suppressed;
            var checkboxCell = canSelect
                ? '<td><input type="checkbox" data-action="toggle-alert-selection" data-id="' + a.id + '"></td>'
                : '<td></td>';
            // Snooze badge (v0.10.218, bundle G2): operator sees at-a-
            // glance which rows are currently snoozed. Hovering reveals
            // the wake-up timestamp. Snoozed rows are only visible if
            // the operator opted in via the "Show snoozed" toggle (the
            // server default filters them out).
            var snoozedActive = !!(a.snoozed_until && (new Date(a.snoozed_until).getTime() > Date.now()));
            if (a.suppressed) {
                statusCol = '<span class="badge unknown">MAINT</span>';
            } else if (snoozedActive) {
                statusCol = '<span class="badge warning" title="Until ' + escapeHtml(formatDate(a.snoozed_until)) + '">SNOOZED</span>';
            } else if (a.resolved_at) {
                // Auto-cleared by a recovery signal (device back online, interface up,
                // etc.). These rows are also acknowledged, so this branch MUST precede
                // the acknowledged branch to show RESOLVED instead of a generic ACK.
                statusCol = '<span class="badge online" title="' + escapeHtml('Auto-cleared ' + formatDate(a.resolved_at) + (a.notes ? ' — ' + a.notes : '')) + '">RESOLVED</span>';
            } else if (a.acknowledged) {
                statusCol = '<span class="badge info" title="' + escapeHtml((a.acknowledged_at ? formatDate(a.acknowledged_at) : '') + (a.notes ? ' — ' + a.notes : '')) + '">ACK</span>';
            } else {
                statusCol = '<button class="btn sm" data-action="show-ack-modal" data-id="' + a.id + '">Ack</button>';
            }
            // Cross-page nav (v0.10.215, bundle E2): the device cell links
            // straight to that device's detail page so an alerts triage
            // session is one click to context.
            var dev = currentDevices.find(function(d) { return d.id === a.device_id; });
            var deviceCell = a.device_id
                ? AC.deviceLink(a.device_id, dev ? dev.name : ('DEV-' + a.device_id))
                : '';
            return '<tr class="alert-row" data-id="' + a.id + '">' +
                checkboxCell +
                '<td style="white-space:nowrap;">' + formatDate(a.timestamp) + '</td>' +
                '<td>' + deviceCell + '</td>' +
                '<td><span class="badge ' + escapeHtml(a.severity) + '">' + escapeHtml(a.alert_type) + '</span></td>' +
                '<td><span class="badge ' + escapeHtml(a.severity) + '">' + escapeHtml(a.severity).toUpperCase() + '</span></td>' +
                '<td class="expandable-msg">' + escapeHtml(a.message) + '</td>' +
                '<td>' + statusCol + '</td>' +
            '</tr>';
        }).join('');
        if (append) tbody.innerHTML += html;
        else tbody.innerHTML = html || '<tr><td colspan="6" class="empty-state">No alerts</td></tr>';
    }

    function showAlertDetail(id) {
        apiFetch(API_BASE + '/alerts/' + id).then(function(result) {
            if (!result || !result.data) return;
            var a = result.data;
            var body = document.getElementById('alert-detail-body');
            var sevClass = (a.severity || 'info').toLowerCase();
            var statusHtml = '';
            // Snoozed state (v0.10.218, bundle G2) — surface as its own
            // status, with an Unsnooze button. Snooze is orthogonal to
            // acknowledged: a snoozed-then-acked alert is still acked.
            var snoozedActive = !!(a.snoozed_until && (new Date(a.snoozed_until).getTime() > Date.now()));
            if (a.suppressed) {
                statusHtml = '<span class="badge unknown">SUPPRESSED (MAINT)</span>';
            } else if (snoozedActive) {
                statusHtml =
                    '<span class="badge warning">SNOOZED until ' + escapeHtml(formatDate(a.snoozed_until)) + '</span>' +
                    '<button class="btn secondary sm" style="margin-left:8px;" data-action="unsnooze-alert" data-id="' + a.id + '">Unsnooze</button>';
                if (a.snoozed_by || a.snoozed_reason) {
                    statusHtml += '<div style="margin-top:8px;font-size:0.8rem;color:#8b949e;">';
                    if (a.snoozed_by) statusHtml += 'By: ' + escapeHtml(a.snoozed_by);
                    if (a.snoozed_reason) statusHtml += '<br>Reason: ' + escapeHtml(a.snoozed_reason);
                    statusHtml += '</div>';
                }
            } else if (a.resolved_at) {
                // Auto-cleared by a recovery signal — no operator action needed.
                // Precedes the acknowledged branch because auto-resolved rows are
                // also acknowledged.
                statusHtml = '<span class="badge online">RESOLVED (AUTO-CLEARED)</span>';
                statusHtml += '<div style="margin-top:8px;font-size:0.8rem;color:#8b949e;">';
                statusHtml += 'Resolved at: ' + formatDate(a.resolved_at);
                if (a.notes) statusHtml += '<br>' + escapeHtml(a.notes);
                statusHtml += '</div>';
            } else if (a.acknowledged) {
                statusHtml = '<span class="badge info">ACKNOWLEDGED</span>';
                if (a.acknowledged_at || a.notes) {
                    statusHtml += '<div style="margin-top:8px;font-size:0.8rem;color:#8b949e;">';
                    if (a.acknowledged_at) statusHtml += 'At: ' + formatDate(a.acknowledged_at);
                    if (a.notes) statusHtml += '<br>Notes: ' + escapeHtml(a.notes);
                    statusHtml += '</div>';
                }
            } else {
                // Open alert — offer both Acknowledge (close it) and
                // Snooze (postpone surfacing).
                statusHtml =
                    '<button class="btn sm" data-action="show-ack-modal" data-id="' + a.id + '">Acknowledge</button>' +
                    ' <button class="btn secondary sm" data-action="snooze-alert" data-id="' + a.id + '">Snooze</button>';
            }

            var isSyslogAlert = a.metric_name === 'syslog';
            var parsedMsg = null;
            if (isSyslogAlert && a.message) {
                parsedMsg = parseFortiGateLog(a.message);
            }

            // Cross-page nav (v0.10.215, bundle E3): the device row in the
            // alert-detail modal is a link to the device-detail page, and
            // we surface two extra context-jumps so an operator triaging
            // an alert can pivot to "all alerts for this device" or "all
            // syslog around this time" in one click.
            var devForAlert = currentDevices.find(function(d) { return d.id === a.device_id; });
            var devLinkHtml = a.device_id
                ? AC.deviceLink(a.device_id, devForAlert ? devForAlert.name : ('DEV-' + a.device_id))
                : 'Unknown';
            // The analytics pages use device_id (not device) as their state
            // key — see FwmonControls.attachAnalyticsPage descriptors below.
            var deviceAlertsLink = a.device_id
                ? ' ' + AC.filterLink('alerts', { device_id: a.device_id }, 'All alerts',
                    { title: 'Show all alerts from this device' })
                : '';
            var deviceSyslogLink = (a.device_id && devForAlert)
                ? ' ' + AC.filterLink('syslog', { device_id: a.device_id }, 'Related syslog',
                    { title: 'Show syslog entries from this device' })
                : '';
            var headerHtml =
                '<div style="margin-bottom:16px;">' +
                    '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">' +
                        '<span class="badge ' + sevClass + '" style="font-size:0.9rem;padding:4px 12px;">' + (a.severity || 'UNKNOWN').toUpperCase() + '</span>' +
                        '<span style="color:#58a6ff;font-weight:600;">' + escapeHtml(a.alert_type || 'ALERT') + '</span>' +
                    '</div>' +
                    '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px 16px;">' +
                        '<div><span style="color:#8b949e;">Time:</span> ' + formatDate(a.timestamp) + '</div>' +
                        '<div><span style="color:#8b949e;">Device:</span> ' + devLinkHtml + '</div>' +
                        '<div><span style="color:#8b949e;">Policy:</span> ' + (a.policy_id ? 'ID ' + a.policy_id : 'N/A') + '</div>' +
                    '</div>' +
                    (deviceAlertsLink || deviceSyslogLink ?
                        '<div style="margin-top:10px;font-size:0.8rem;color:#8b949e;display:flex;gap:14px;flex-wrap:wrap;">' +
                        '<span>Drill into:</span>' +
                        deviceAlertsLink + deviceSyslogLink +
                        '</div>' : '') +
                '</div>';

            var metricHtml = '';
            if (a.metric_name || a.threshold || a.current_value) {
                metricHtml =
                    '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin-bottom:12px;">' +
                        '<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;margin-bottom:8px;">Metric Info</div>' +
                        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:4px 16px;">' +
                            (a.metric_name ? '<div><span style="color:#8b949e;">Metric:</span> <span style="font-family:monospace;">' + escapeHtml(a.metric_name) + '</span></div>' : '') +
                            (a.threshold ? '<div><span style="color:#8b949e;">Threshold:</span> ' + a.threshold + '</div>' : '') +
                            (a.current_value ? '<div><span style="color:#8b949e;">Current:</span> <span style="color:#f85149;font-weight:600;">' + a.current_value + '</span></div>' : '') +
                        '</div>' +
                    '</div>';
            }

            var msgHtml = '';
            if (isSyslogAlert && parsedMsg && parsedMsg.type) {
                var f = parsedMsg.fields;
                var typeBadge = '<span class="badge ' + (parsedMsg.type === 'TRAFFIC' ? 'info' : (parsedMsg.type === 'IPS' ? 'error' : (parsedMsg.type === 'AV' ? 'critical' : 'warning'))) + '">' + escapeHtml(parsedMsg.type) + '</span>';
                msgHtml =
                    '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;margin-bottom:12px;">' +
                        '<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;margin-bottom:8px;">Parsed Syslog Fields</div>' +
                        '<div style="margin-bottom:8px;">' + typeBadge +
                            (parsedMsg.subtype ? ' <span style="color:#8b949e;">/ ' + escapeHtml(parsedMsg.subtype) + '</span>' : '') +
                        '</div>' +
                        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:4px 16px;">';
                var keyFields = ['srcip', 'srcport', 'dstip', 'dstport', 'proto', 'action', 'sentbyte', 'rcvdbyte', 'duration', 'iface', 'policyid', 'vd', 'sessionid', 'srcintf', 'dstintf', 'hostname', 'logid', 'app', 'appid', 'apprisk', 'virus', 'file', 'sig_name', 'service', 'ha_role'];
                var fieldLabels = {'srcip':'Src IP','srcport':'Src Port','dstip':'Dst IP','dstport':'Dst Port','proto':'Protocol','action':'Action','sentbyte':'Sent Bytes','rcvdbyte':'Rcvd Bytes','duration':'Duration (s)','iface':'Interface','policyid':'Policy ID','vd':'VDOM','sessionid':'Session ID','srcintf':'Src Intf','dstintf':'Dst Intf','hostname':'Hostname','logid':'Log ID','app':'Application','appid':'App ID','apprisk':'App Risk','virus':'Virus','file':'File','sig_name':'Signature','service':'Service','ha_role':'HA Role'};
                keyFields.forEach(function(key) {
                    if (f[key] !== undefined && f[key] !== '') {
                        var label = fieldLabels[key] || key;
                        var val = f[key];
                        var valHtml = '';
                        if (key === 'srcip' || key === 'dstip') {
                            valHtml = '<span style="font-family:monospace;color:#58a6ff;">' + escapeHtml(val) + '</span>';
                        } else if (key === 'action') {
                            var actClass = val === 'accept' || val === 'pass' || val === 'detected' ? 'up' : (val === 'deny' || val === 'drop' || val === 'blocked' ? 'down' : 'warning');
                            valHtml = '<span class="badge ' + actClass + '">' + escapeHtml(val.toUpperCase()) + '</span>';
                        } else if (key === 'apprisk') {
                            var riskClass = val === 'very-high' || val === 'high' ? 'down' : (val === 'medium' ? 'warning' : 'up');
                            valHtml = '<span class="badge ' + riskClass + '">' + escapeHtml(val.toUpperCase()) + '</span>';
                        } else {
                            valHtml = escapeHtml(val);
                        }
                        msgHtml += '<div><span style="color:#8b949e;">' + escapeHtml(label) + ':</span> ' + valHtml + '</div>';
                    }
                });
                msgHtml += '</div></div>';
                msgHtml +=
                    '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;">' +
                        '<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;margin-bottom:6px;">Raw Syslog Message</div>' +
                        '<div style="font-family:monospace;font-size:0.85rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(a.message || '') + '</div>' +
                    '</div>';
            } else {
                msgHtml =
                    '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin-bottom:12px;">' +
                        '<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;margin-bottom:6px;">Message</div>' +
                        '<div style="font-family:monospace;font-size:0.85rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(a.message || '') + '</div>' +
                    '</div>';
            }

            body.innerHTML = headerHtml + metricHtml + msgHtml +
                '<div style="margin-top:12px;">' + statusHtml + '</div>';
            AC.openModal('alert-detail-modal');
        }).catch(function(err) {
            console.error('Failed to load alert detail:', err);
            AC.showError('Failed to load alert detail');
        });
    }
    function closeAlertDetail() { AC.closeModal('alert-detail-modal'); }

    function showAckModal(id) {
        document.getElementById('ack-alert-id').value = id;
        document.getElementById('ack-notes').value = '';
        AC.openModal('ack-modal');
    }

    function closeAckModal() {
        AC.closeModal('ack-modal');
    }

    function acknowledgeAlert(id, notes) {
        var body = notes ? {acknowledged: true, notes: notes} : {acknowledged: true};
        apiFetch(API_BASE + '/alerts/' + id + '/acknowledge', {method:'POST', body: body}).then(function() {
            closeAckModal();
            // Stay on the user's current page rather than bouncing to page 1.
            refreshAlertsAtCurrentPage();
            AC.showSuccess('Alert acknowledged');
        }).catch(function(e) {
            console.error('Failed to acknowledge alert:', e);
            AC.showError('Failed to acknowledge alert');
        });
    }

    // Snooze flow (v0.10.218, bundle G2). Uses prompt() rather than a
    // dedicated modal — the friction is intentional, snooze is a self-
    // serve action and a full modal is overkill. Hours are clamped
    // server-side to [1, 720]; we accept anything parseable here.
    function showSnoozePrompt(id) {
        var hoursStr = window.prompt('Snooze this alert for how many hours?\n(1 hour to 720 hours / 30 days)', '4');
        if (hoursStr == null) return; // operator cancelled
        var hours = parseInt(hoursStr, 10);
        if (!isFinite(hours) || hours < 1) {
            AC.showError('Enter a positive number of hours');
            return;
        }
        var reason = window.prompt('Optional reason for the audit log (leave blank to skip):', '') || '';
        apiFetch(API_BASE + '/alerts/' + id + '/snooze', {
            method: 'POST',
            body: { hours: hours, reason: reason }
        }).then(function(res) {
            closeAlertDetail();
            refreshAlertsAtCurrentPage();
            var until = res && res.data && res.data.snoozed_until;
            AC.showSuccess('Alert snoozed' + (until ? ' until ' + formatDate(until) : ''));
        }).catch(function(e) {
            console.error('Failed to snooze alert:', e);
            AC.showError('Failed to snooze alert: ' + (e.message || ''));
        });
    }

    function unsnoozeAlert(id) {
        apiFetch(API_BASE + '/alerts/' + id + '/unsnooze', { method: 'POST' }).then(function() {
            closeAlertDetail();
            refreshAlertsAtCurrentPage();
            AC.showSuccess('Alert unsnoozed');
        }).catch(function(e) {
            console.error('Failed to unsnooze alert:', e);
            AC.showError('Failed to unsnooze alert');
        });
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
        }).catch(function(err) {
            console.error('Failed to load more alerts:', err);
            AC.showError('Failed to load more alerts');
        });
    }

    function loadAlertCharts() {
        var s = analyticsPages.alerts && analyticsPages.alerts.getState();
        var hoursParam = (s && s.hours) ? ('?hours=' + s.hours) : '';
        apiFetch(API_BASE + '/alerts/stats' + hoursParam).then(function(result) {
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

            var labels = (d.over_time || []).map(function(b) { return formatBucketTime(b.bucket); });
            var counts = (d.over_time || []).map(function(b) { return b.count; });
            createChart('alerts-trend-chart','line',labels,[{label:'Alerts',data:counts,borderColor:'#f85149',backgroundColor:'rgba(248,81,73,0.1)',fill:true,tension:0.3}]);

            var typeLabels = (d.by_type || []).map(function(t) { return t.key || 'unknown'; });
            var typeCounts = (d.by_type || []).map(function(t) { return t.count; });
            var typeColors = ['#f85149','#d2992a','#58a6ff','#3fb950','#bc8cff','#8b949e'];
            createChart('alerts-type-chart','doughnut',typeLabels,[{data:typeCounts,backgroundColor:typeColors.slice(0,typeLabels.length),borderWidth:0}]);
        }).catch(function(e) { console.error('Failed to load alert charts:', e); });
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
        }).catch(function(e) {
            console.error('Failed to load traps:', e);
        });
    }

    function buildTrapParams(limit) {
        var parts = ['limit=' + limit];
        var s = analyticsPages.traps && analyticsPages.traps.getState();
        var sev = document.getElementById('traps-filter-severity');
        var type = document.getElementById('traps-filter-type');
        if (s && s.hours && Number(s.hours) !== 24) parts.push('hours=' + s.hours);
        if (sev && sev.value) parts.push('severity=' + sev.value);
        if (type && type.value) parts.push('trap_type=' + encodeURIComponent(type.value));
        return parts.join('&');
    }

    function renderTrapsTable(traps, append) {
        var tbody = document.querySelector('#traps-table tbody');
        var html = traps.map(function(t) {
            // Source-IP cross-pivot (v0.10.215, bundle E2): traps page has
            // no search filter today, so the IP cell pivots to /admin/syslog
            // filtered by the same source instead — operators triaging a
            // trap usually want the surrounding syslog context anyway.
            var srcCell = t.source_ip
                ? AC.filterLink('syslog', { search: t.source_ip }, t.source_ip,
                    { title: 'Show syslog entries from ' + t.source_ip })
                : '';
            return '<tr>' +
                '<td>' + formatDate(t.timestamp) + '</td>' +
                '<td class="mono">' + srcCell + '</td>' +
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
        }).catch(function(err) {
            console.error('Failed to load more traps:', err);
            AC.showError('Failed to load more traps');
        });
    }

    function loadTrapCharts() {
        var s = analyticsPages.traps && analyticsPages.traps.getState();
        var hoursParam = (s && s.hours) ? ('?hours=' + s.hours) : '';
        apiFetch(API_BASE + '/traps/stats' + hoursParam).then(function(result) {
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

            var labels = (d.over_time || []).map(function(b) { return formatBucketTime(b.bucket); });
            var counts = (d.over_time || []).map(function(b) { return b.count; });
            createChart('traps-freq-chart','bar',labels,[{label:'Traps',data:counts,backgroundColor:'#d2992a',borderRadius:3}]);

            var sevLabels = (d.by_severity || []).map(function(s) { return s.key || 'unknown'; });
            var sevCounts = (d.by_severity || []).map(function(s) { return s.count; });
            var sevColors = ['#f85149','#d2992a','#58a6ff','#3fb950','#8b949e'];
            createChart('traps-severity-chart','doughnut',sevLabels,[{data:sevCounts,backgroundColor:sevColors.slice(0,sevLabels.length),borderWidth:0}]);
        }).catch(function(e) { console.error('Failed to load trap charts:', e); });
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
            var savedReportVals = {};
            settings.filter(function(s) { return s.category === 'reports'; }).forEach(function(s) { savedReportVals[s.key] = s.value; });

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
                    return '<div class="toggle-row"><label>' + s.label + '</label><input type="checkbox" name="' + s.key + '" ' + checked + '></div>';
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

            // Report scheduling settings
            var reportTimeOptions = '';
            for (var h = 0; h < 24; h++) {
                for (var m = 0; m < 60; m += 30) {
                    var t = ('0'+h).slice(-2) + ':' + ('0'+m).slice(-2);
                    var sel = savedReportVals && savedReportVals['report_daily_time'] === t ? ' selected' : '';
                    reportTimeOptions += '<option value="' + t + '"' + sel + '>' + t + '</option>';
                }
            }
            var reportDayOptions = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'].map(function(d) {
                var sel = savedReportVals && savedReportVals['report_weekly_day'] === d.toLowerCase() ? ' selected' : '';
                return '<option value="' + d.toLowerCase() + '"' + sel + '>' + d + '</option>';
            }).join('');
            document.getElementById('settings-reports').innerHTML = [
                { key: 'report_daily_enabled', label: 'Enable Daily Report', type: 'checkbox' },
                { key: 'report_weekly_enabled', label: 'Enable Weekly Report', type: 'checkbox' },
                { key: 'report_recipients', label: 'Report Recipients (emails)', type: 'text', placeholder: 'admin@example.com' },
                { key: 'report_timezone', label: 'Report Timezone', type: 'text', placeholder: 'America/New_York' }
            ].map(function(s) {
                var found = settings.find(function(x) { return x.key === s.key; });
                var savedVal = found ? found.value : '';
                if (s.type === 'checkbox') {
                    var checked = savedVal === 'true' ? 'checked' : '';
                    return '<div class="toggle-row"><label>' + s.label + '</label><input type="checkbox" name="' + s.key + '" ' + checked + '></div>';
                }
                return '<div class="setting-item"><label>' + s.label + '</label><input type="text" name="' + s.key + '" value="' + escapeHtml(savedVal) + '" placeholder="' + (s.placeholder || '') + '"></div>';
            }).join('') +
            '<div class="setting-item"><label>Daily Report Time (HH:MM)</label><select name="report_daily_time" class="report-time-select">' + reportTimeOptions + '</select></div>' +
            '<div class="setting-item"><label>Weekly Report Day</label><select name="report_weekly_day" class="report-day-select"><option value="">-- Select --</option>' + reportDayOptions + '</select></div>';

            // Spike detection settings
            document.getElementById('settings-spike').innerHTML = [
                { key: 'spike_alert_enabled', label: 'Enable Spike Alerts', type: 'checkbox' },
                { key: 'spike_stddev_threshold', label: 'Standard Deviation Threshold (1.0-10.0)', type: 'number', value: '3.0' }
            ].map(function(s) {
                var found = settings.find(function(x) { return x.key === s.key; });
                var savedVal = found ? found.value : (s.value || '');
                if (s.type === 'checkbox') {
                    return '<div class="toggle-row"><label>' + s.label + '</label><input type="checkbox" name="' + s.key + '" ' + (savedVal === 'true' ? 'checked' : '') + '></div>';
                }
                return '<div class="setting-item"><label>' + s.label + '</label><input type="number" name="' + s.key + '" value="' + escapeHtml(savedVal) + '" step="0.1" min="1" max="10"></div>';
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
            }
        }).catch(function(e) {
            console.error('Failed to load settings:', e);
        });

    }

    // ---- Device Modal ----
    function showDeviceModal(id) {
        AC.openModal('device-modal');
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
            document.getElementById('device-enabled').checked = d.enabled !== false;
            document.getElementById('device-public-visible').checked = d.public_visible !== false;
            document.getElementById('device-ssh-username').value = d.ssh_username || '';
            document.getElementById('device-ssh-password').value = '';
            document.getElementById('device-ssh-port').value = d.ssh_port || 22;
            document.getElementById('device-ssh-poll-interval').value = d.ssh_poll_interval || 900;
            document.getElementById('device-ssh-poll-enabled').checked = d.ssh_poll_enabled === true;
        } else {
            document.getElementById('device-form').reset();
            document.getElementById('device-id').value = '';
            document.getElementById('device-snmp-port').value = '161';
            document.getElementById('device-snmp-version').value = '2c';
            document.getElementById('device-community').value = 'public';
            document.getElementById('device-wan-speed').value = '1000';
            document.getElementById('device-ssh-port').value = '22';
            document.getElementById('device-ssh-poll-interval').value = '900';
        }
        toggleV3Fields();
    }

    function closeDeviceModal() { AC.closeModal('device-modal'); }

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
        }).catch(function(err) {
            console.error('Device connection test failed:', err);
            AC.showError('Error: ' + err.message);
        })
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
                enabled: document.getElementById('device-enabled').checked,
                public_visible: document.getElementById('device-public-visible').checked
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

            var sshUsername = document.getElementById('device-ssh-username').value;
            var sshPassword = document.getElementById('device-ssh-password').value;
            if (sshUsername) data.ssh_username = sshUsername;
            if (sshPassword && !/^\*+$/.test(sshPassword)) data.ssh_password = sshPassword;
            data.ssh_port = parseInt(document.getElementById('device-ssh-port').value) || 22;
            data.ssh_poll_interval = parseInt(document.getElementById('device-ssh-poll-interval').value) || 900;
            data.ssh_poll_enabled = document.getElementById('device-ssh-poll-enabled').checked;

            // Validate SSH polling requires credentials
            if (data.ssh_poll_enabled) {
                var existingPw = document.getElementById('device-ssh-password').value;
                var isMasked = /^\*+$/.test(existingPw);
                // Need either new password entered OR existing username (implies password already set)
                if (!sshUsername) {
                    alert('SSH Username is required when SSH polling is enabled');
                    return;
                }
                if (!sshPassword && !isMasked && id) {
                    alert('SSH Password is required when SSH polling is enabled');
                    return;
                }
            }

            var method = id ? 'PUT' : 'POST';
            var url = id ? API_BASE + '/devices/' + id : API_BASE + '/devices';
            apiFetch(url, { method: method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) }).then(function() {
                closeDeviceModal();
                loadDevices();
                AC.showSuccess(id ? 'Device updated' : 'Device created');
            }).catch(function(err) {
                console.error('Error saving device:', err);
                AC.showError('Error saving device: ' + err.message);
            });
        });
    }

    function editDevice(id) { showDeviceModal(id); }

    function deleteDevice(id) {
        AC.confirm('Delete this device and all its data?', {
            title: 'Delete device?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            apiFetch(API_BASE + '/devices/' + id, { method: 'DELETE' }).then(function() {
                loadDevices();
                AC.showSuccess('Device deleted');
            }).catch(function(err) {
                console.error('Error deleting device:', err);
                AC.showError('Error deleting device: ' + err.message);
            });
        });
    }

    // ---- Connection Diagram ----
    // Cytoscape is lazy-loaded (v0.10.214, bundle C3). The diagram bundle
    // (~421 KB) only fetches the first time an operator opens the
    // Connections tab. Subsequent draws are cached.
    function drawConnectionDiagram() {
        if (currentDevices.length === 0) {
            var host = document.getElementById('connection-diagram');
            if (host) {
                host.innerHTML =
                    '<div class="loading" style="padding:60px 20px;">Add devices to see the network diagram</div>';
            }
            return;
        }

        var diagramHost = document.getElementById('connection-diagram');
        if (diagramHost && !window.FWDiagram) {
            diagramHost.innerHTML =
                '<div class="loading" style="padding:60px 20px;">Loading network diagram…</div>';
        }

        AC.loadCytoscape().then(function() {
            if (!window.FWDiagram) return;
            if (!FWDiagram.Panels.getCurrentPanelConnId()) {
                var panelContainer = document.getElementById('conn-detail-panel-container');
                if (panelContainer) panelContainer.innerHTML = '';
            }
            FWDiagram.init('connection-diagram');
            var siteNames = {};
            currentSites.forEach(function(s) { siteNames[s.id] = s.name; });
            FWDiagram.setCallbacks(
                function(conn) { FWDiagram.Panels.showRichConnDetailPanel(conn); },
                function(deviceId, offnetOnly) { FWDiagram.Panels.showRichVPNDetailPanel(deviceId, offnetOnly, currentDevices, currentVpnMap); }
            );
            FWDiagram.render(currentDevices, currentConnections, deviceSiteMap, currentVpnMap, siteNames);
        }).catch(function(err) {
            console.error('Failed to load network diagram bundle:', err);
            if (diagramHost) {
                diagramHost.innerHTML =
                    '<div class="error" style="padding:60px 20px;color:#f85149;">Failed to load network diagram. Try refreshing the page.</div>';
            }
        });
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

    function showConnectionModal(id) {
        if (currentDevices.length < 2) { alert('You need at least 2 devices'); return; }
        AC.openModal('connection-modal');
        document.getElementById('connection-form').reset();
        document.getElementById('connection-id').value = id || '';
        populateDeviceSelects();
        if (id) {
            var conn = null;
            for (var i = 0; i < currentConnections.length; i++) {
                if (currentConnections[i].id === id) { conn = currentConnections[i]; break; }
            }
            if (conn) {
                document.getElementById('connection-name').value = conn.name;
                document.getElementById('connection-type').value = conn.connection_type || 'ipsec';
                document.getElementById('connection-notes').value = conn.notes || '';
                document.getElementById('connection-source').value = conn.source_device_id;
                document.getElementById('connection-dest').value = conn.dest_device_id;
                document.querySelector('#connection-modal h2').textContent = 'Edit Connection';
            }
        } else {
            document.querySelector('#connection-modal h2').textContent = 'Add Connection';
        }
    }
    function closeConnectionModal() { AC.closeModal('connection-modal'); }

    // Connection form submit
    var connectionForm = document.getElementById('connection-form');
    if (connectionForm) {
        connectionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var id = document.getElementById('connection-id').value;
            var data = {
                name: document.getElementById('connection-name').value,
                source_device_id: parseInt(document.getElementById('connection-source').value),
                dest_device_id: parseInt(document.getElementById('connection-dest').value),
                connection_type: document.getElementById('connection-type').value,
                notes: document.getElementById('connection-notes').value
            };
            var method = id ? 'PUT' : 'POST';
            var url = id ? API_BASE + '/connections/' + id : API_BASE + '/connections';
            apiFetch(url, { method: method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) }).then(function() {
                closeConnectionModal();
                loadConnections();
                AC.showSuccess(id ? 'Connection updated' : 'Connection created');
            }).catch(function(err) {
                console.error('Error saving connection:', err);
                AC.showError('Error saving connection: ' + err.message);
            });
        });
    }

    function deleteConnection(id) {
        AC.confirm('Delete this connection?', {
            title: 'Delete connection?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            apiFetch(API_BASE + '/connections/' + id, { method: 'DELETE' }).then(function() {
                loadConnections();
                AC.showSuccess('Connection deleted');
            }).catch(function(err) {
                console.error('Error deleting connection:', err);
                AC.showError('Error deleting connection: ' + err.message);
            });
        });
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
        }).catch(function(err) {
            console.error('Password change failed:', err);
            AC.showError('Error: ' + err.message);
        });
    }

    function saveSettings() {
        var settings = [];
        var hasError = false;
        
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
            if (input.name === 'display_timezone') return; // skip, added explicitly below
            settings.push({ key: input.name, value: input.type === 'checkbox' ? String(input.checked) : input.value, category: 'display', type: input.type === 'checkbox' ? 'bool' : 'string' });
        });
        var reportsSection = document.getElementById('settings-reports');
        var dailyEnabled = reportsSection.querySelector('input[name="report_daily_enabled"]') && reportsSection.querySelector('input[name="report_daily_enabled"]').checked;
        var weeklyEnabled = reportsSection.querySelector('input[name="report_weekly_enabled"]') && reportsSection.querySelector('input[name="report_weekly_enabled"]').checked;
        document.querySelectorAll('#settings-reports input, #settings-reports select').forEach(function(el) {
            if (el.tagName === 'INPUT' && el.name === 'report_daily_time') {
                if (dailyEnabled && el.value && !/^\d{2}:\d{2}$/.test(el.value)) {
                    AC.showError('Daily report time must be in HH:MM format (e.g., 08:00)');
                    hasError = true;
                    return;
                }
            }
            if (el.tagName === 'INPUT' && el.name === 'report_weekly_day') {
                if (weeklyEnabled && el.value) {
                    var validDays = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'];
                    if (validDays.indexOf(el.value.toLowerCase()) === -1) {
                        AC.showError('Weekly report day must be a day of the week (e.g., Monday)');
                        hasError = true;
                        return;
                    }
                }
            }
            settings.push({ key: el.name, value: el.type === 'checkbox' ? String(el.checked) : el.value, category: 'reports', type: el.type === 'checkbox' ? 'bool' : 'string' });
        });
        if (hasError) return;
        document.querySelectorAll('#settings-spike input').forEach(function(input) {
            settings.push({ key: input.name, value: input.type === 'checkbox' ? String(input.checked) : input.value, category: 'spike', type: input.type === 'checkbox' ? 'bool' : 'string' });
        });
        
        var tzSel = document.getElementById('display-timezone');
        if (tzSel && tzSel.value) {
            settings.push({ key: 'display_timezone', value: tzSel.value, category: 'display', type: 'string' });
            AC.setTimezone(tzSel.value);
        }

        apiFetch(API_BASE + '/settings', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(settings) }).then(function(result) {
            AC.showSuccess('Settings saved!');
            // v0.10.224: surface server-side mutation warnings (e.g.
            // "Trimmed leading/trailing whitespace from smtp_password
            // before encrypting"). These previously happened silently;
            // the operator had no way to tell whether their stored
            // password matched what they typed. Each warning becomes
            // its own toast so they can't be missed even with a busy
            // save flow.
            var warnings = (result && result.data && Array.isArray(result.data.warnings)) ? result.data.warnings : [];
            warnings.forEach(function(w) { AC.showError(w); });
        }).catch(function(err) {
            console.error('Settings save failed:', err);
            AC.showError('Error: ' + err.message);
        });
    }

    function testEmail() {
        var resultEl = document.getElementById('test-email-result');
        resultEl.innerHTML = '<div style="color:#8b949e;font-size:0.85rem;">Running diagnostic… (this can take a few seconds)</div>';
        var toOverride = document.getElementById('test-email-to-override');
        var body = toOverride && toOverride.value.trim()
            ? JSON.stringify({ to: toOverride.value.trim() })
            : '{}';

        apiFetch(API_BASE + '/settings/test-email', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: body
        }).then(function(result) {
            var d = (result && result.data) || {};
            renderSMTPTrace(resultEl, d);
        }).catch(function(e) {
            resultEl.innerHTML = '<div style="color:#f85149;font-weight:500;">Request failed: ' + escapeHtml(e.message || 'unknown') + '</div>';
        });
    }

    // renderSMTPTrace — pretty-print the verbose SMTP trace returned by
    // /api/settings/test-email (v0.10.220, bundle I). Each step renders
    // as a row with status pill, timing, detail (what we tried) and the
    // server's response. Failed step is anchored top.
    function renderSMTPTrace(host, d) {
        var ok = !!d.success;
        var trace = Array.isArray(d.trace) ? d.trace : [];
        var headerColor = ok ? '#3fb950' : '#f85149';
        var headerIcon = ok ? '✓' : '✗';

        // v0.10.224: reverted v0.10.223's username/length metadata.
        // swaks' --auth-hide-password convention explicitly keeps
        // credential data out of test transcripts; mail-admin UIs
        // (Mailcow, Mailu, Postal) follow the same line. The "did your
        // password get mutated?" signal that password_len was trying
        // to provide is now surfaced at SAVE time as a warning toast
        // when TrimSpace actually changes the value — see
        // UpdateSettings in handlers_settings.go.
        var meta =
            '<div style="display:flex;gap:14px;flex-wrap:wrap;font-size:0.78rem;color:#8b949e;margin-bottom:6px;">' +
            '<span><strong>Host:</strong> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(d.host || '') + ':' + escapeHtml(String(d.port || '')) + '</span></span>' +
            '<span><strong>From:</strong> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(d.from || '') + '</span></span>' +
            '<span><strong>To:</strong> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(d.to || '') + '</span></span>' +
            '<span><strong>Auth:</strong> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(d.auth_method || 'none') + '</span></span>' +
            '<span><strong>Total:</strong> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(String(d.total_ms || 0)) + ' ms</span></span>' +
            '</div>';

        var summary =
            '<div style="font-size:0.95rem;font-weight:500;color:' + headerColor + ';margin-bottom:8px;">' +
            headerIcon + ' ' + escapeHtml(d.message || (ok ? 'OK' : 'Failed')) + '</div>';

        var rows = trace.map(function(s) {
            var statusColor, statusBg, statusLabel;
            if (s.status === 'ok') {
                statusColor = '#3fb950'; statusBg = 'rgba(63,185,80,0.15)'; statusLabel = 'OK';
            } else if (s.status === 'skipped') {
                statusColor = '#8b949e'; statusBg = 'rgba(139,148,158,0.15)'; statusLabel = 'SKIP';
            } else {
                statusColor = '#f85149'; statusBg = 'rgba(248,81,73,0.15)'; statusLabel = 'FAIL';
            }
            var responseRow = s.response
                ? '<div style="color:#8b949e;font-size:0.78rem;margin-top:4px;"><span style="color:#8b949e;">response:</span> <span class="mono" style="color:#c9d1d9;">' + escapeHtml(s.response) + '</span></div>'
                : '';
            var errorRow = s.error
                ? '<div style="color:#f85149;font-size:0.82rem;margin-top:4px;font-family:monospace;background:rgba(248,81,73,0.08);padding:6px 8px;border-radius:4px;border-left:3px solid #f85149;">' + escapeHtml(s.error) + '</div>'
                : '';
            // v0.10.224: operator-facing remediation hint. Distinct
            // styling from the error row so the operator can scan past
            // the wire-protocol error and land on the actionable next
            // step (e.g. "check Dovecot auth log on the mail server").
            var hintRow = s.hint
                ? '<div style="color:#79c0ff;font-size:0.8rem;margin-top:6px;background:rgba(56,139,253,0.08);padding:6px 8px;border-radius:4px;border-left:3px solid #1f6feb;line-height:1.5;"><strong style="color:#58a6ff;">Next step:</strong> ' + escapeHtml(s.hint) + '</div>'
                : '';
            return '<tr>' +
                '<td style="padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top;">' +
                    '<span style="background:' + statusBg + ';color:' + statusColor + ';padding:2px 8px;border-radius:10px;font-size:0.7rem;font-weight:600;letter-spacing:0.4px;">' + statusLabel + '</span>' +
                '</td>' +
                '<td class="mono" style="padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top;font-size:0.82rem;color:#c9d1d9;font-weight:600;">' +
                    escapeHtml(s.step) +
                '</td>' +
                '<td style="padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top;">' +
                    '<div style="color:#c9d1d9;font-size:0.82rem;">' + escapeHtml(s.detail || '') + '</div>' +
                    responseRow + errorRow + hintRow +
                '</td>' +
                '<td class="mono" style="padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top;text-align:right;color:#8b949e;font-size:0.78rem;">' +
                    escapeHtml(String(s.duration_ms || 0)) + ' ms' +
                '</td>' +
            '</tr>';
        }).join('');

        var table = trace.length === 0 ? '' :
            '<table style="width:100%;border-collapse:collapse;background:#0d1117;border:1px solid #30363d;border-radius:6px;overflow:hidden;">' +
                '<thead><tr>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 10px;border-bottom:1px solid #30363d;background:#161b22;width:60px;"></th>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 10px;border-bottom:1px solid #30363d;background:#161b22;width:110px;">Step</th>' +
                    '<th style="text-align:left;color:#8b949e;font-weight:500;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 10px;border-bottom:1px solid #30363d;background:#161b22;">Action / Server response</th>' +
                    '<th style="text-align:right;color:#8b949e;font-weight:500;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;padding:6px 10px;border-bottom:1px solid #30363d;background:#161b22;width:70px;">Time</th>' +
                '</tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
            '</table>';

        host.innerHTML = summary + meta + table;
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
        }).catch(function(e) { resultEl.textContent = 'Error: ' + e.message; resultEl.style.color = '#f85149'; });
    }

    // ---- Logout ----
    var logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            apiFetch('/admin/api/logout', { method: 'POST' }).then(function() {
                window.location.href = '/';
            }).catch(function() {
                window.location.href = '/';
            });
        });
    }

    // ---- URL-based tab activation ----
    function activateTabFromUrl() {
        var path = window.location.pathname.replace(/\/$/, '');
        var segments = path.split('/');
        var lastSegment = segments[segments.length - 1];
        // Only SPA tabs hosted inside admin.html. Standalone pages (probes,
        // sites, probe-pending, irc) are served as their own HTML documents and
        // never reach this code, so they must NOT be mapped here (see SPA_PAGES).
        var pageMap = { 'dashboard':'dashboard', 'devices':'devices', 'interfaces':'interfaces', 'connections':'connections',
            'settings':'settings', 'reports':'reports', 'syslog':'syslog', 'flows':'flows', 'alerts':'alerts', 'traps':'traps',
            'alert-policies':'alert-policies', 'maintenance':'maintenance', 'audit':'audit' };
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

    // ---- Alert Policies ----
    var currentPolicies = [];
    var ALERT_TYPES = ['CPU_HIGH','MEMORY_HIGH','DISK_HIGH','SESSIONS_HIGH','INTERFACE_DOWN','INTERFACE_ERRORS','VPN_TUNNEL_DOWN','DEVICE_OFFLINE','TRAFFIC_SPIKE','SYSLOG_EMERGENCY','SYSLOG_ALERT','SYSLOG_CRITICAL'];

    function loadAlertPolicies() {
        apiFetch(API_BASE + '/alert-policies').then(function(result) {
            if (!result) return;
            currentPolicies = result.data || [];
            document.getElementById('ap-total').textContent = currentPolicies.length;
            renderPoliciesTable(currentPolicies);
        }).catch(function(e) { console.error('Failed to load policies:', e); });
    }

    function renderPoliciesTable(policies) {
        var grid = document.getElementById('alert-policies-grid');
        if (!grid) return;
        var html = policies.map(function(p) {
            var ruleCount = (p.rules || []).length;
            
            var emailClass = p.notify_email ? 'active email' : 'inactive';
            var slackClass = p.notify_slack ? 'active slack' : 'inactive';
            var discordClass = p.notify_discord ? 'active discord' : 'inactive';
            var webhookClass = p.notify_webhook ? 'active webhook' : 'inactive';
            
            var escVal = p.escalation_enabled ? p.escalation_minutes + 'm (' + p.escalation_repeat + 'x)' : 'Disabled';
            var desc = p.description ? escapeHtml(p.description) : '<span style="color:#475569;font-style:italic">No description provided</span>';
            
            return '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:240px;padding:20px;">' +
                '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">' +
                    '<h3 style="font-size:1.1rem;font-weight:600;color:#f8fafc;margin:0;font-family:\'Outfit\',sans-serif;">' + escapeHtml(p.name) + '</h3>' +
                    (p.is_default ? '<span class="badge info">DEFAULT</span>' : '') +
                '</div>' +
                '<div style="font-size:0.82rem;color:#94a3b8;margin-bottom:16px;min-height:38px;line-height:1.4;">' + desc + '</div>' +
                '<div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:10px;margin-bottom:20px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);border-radius:8px;padding:10px;">' +
                    '<div style="display:flex;flex-direction:column;align-items:center;text-align:center;">' +
                        '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;margin-bottom:2px;">Rules</span>' +
                        '<span style="font-size:0.85rem;font-weight:600;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + ruleCount + '</span>' +
                    '</div>' +
                    '<div style="display:flex;flex-direction:column;align-items:center;text-align:center;">' +
                        '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;margin-bottom:2px;">Cooldown</span>' +
                        '<span style="font-size:0.85rem;font-weight:600;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + p.cooldown_minutes + 'm</span>' +
                    '</div>' +
                    '<div style="display:flex;flex-direction:column;align-items:center;text-align:center;">' +
                        '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;margin-bottom:2px;">Escalate</span>' +
                        '<span style="font-size:0.78rem;font-weight:600;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + escVal + '</span>' +
                    '</div>' +
                '</div>' +
                '<div class="policy-card-channels" style="display:flex;gap:8px;margin-bottom:20px;align-items:center;">' +
                    '<span class="policy-channel-tag ' + emailClass + '">Email</span>' +
                    '<span class="policy-channel-tag ' + slackClass + '">Slack</span>' +
                    '<span class="policy-channel-tag ' + discordClass + '">Discord</span>' +
                    '<span class="policy-channel-tag ' + webhookClass + '">Webhook</span>' +
                '</div>' +
                '<div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid rgba(255,255,255,0.05);padding-top:14px;">' +
                    '<button class="btn secondary sm" data-action="edit-policy" data-id="' + p.id + '">Edit</button>' +
                    '<button class="btn secondary sm" data-action="clone-policy" data-id="' + p.id + '">Clone</button>' +
                    (p.is_default ? '' : '<button class="btn secondary sm" data-action="delete-policy" data-id="' + p.id + '">Delete</button>') +
                '</div>' +
            '</div>';
        }).join('');
        grid.innerHTML = html || '<div class="col-span-full card text-center p-8 text-[#8b949e]">No alert policies configured</div>';
    }

    function showPolicyModal(id) {
        AC.openModal('policy-modal');
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
        AC.closeModal('policy-modal');
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
                AC.showSuccess(id ? 'Policy updated' : 'Policy created');
            }).catch(function(err) {
                console.error('Error saving policy:', err);
                AC.showError('Error saving policy: ' + (err.message || err));
            });
        });
    }

    function clonePolicy(id) {
        apiFetch(API_BASE + '/alert-policies/' + id + '/clone', {method: 'POST'}).then(function() {
            loadAlertPolicies();
            AC.showSuccess('Policy cloned');
        }).catch(function(e) {
            console.error('Clone failed:', e);
            AC.showError('Clone failed: ' + e.message);
        });
    }

    function deletePolicy(id) {
        AC.confirm('Delete this alert policy?', {
            title: 'Delete alert policy?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            apiFetch(API_BASE + '/alert-policies/' + id, {method: 'DELETE'}).then(function() {
                loadAlertPolicies();
                AC.showSuccess('Policy deleted');
            }).catch(function(e) {
                console.error('Delete policy failed:', e);
                AC.showError('Delete failed: ' + e.message);
            });
        });
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
        }).catch(function(e) { console.error('Failed to load maintenance windows:', e); });
    }

    function renderMaintenanceTable(windows) {
        var grid = document.getElementById('maintenance-grid');
        if (!grid) return;
        if (!windows.length) {
            grid.innerHTML = '<div class="col-span-full card text-center p-8 text-[#8b949e]"><div style="font-size:2rem;margin-bottom:8px;">🔧</div>No maintenance windows scheduled</div>';
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

                return '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:220px;padding:20px;">' +
                    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">' +
                        '<h3 style="font-size:1.1rem;font-weight:600;color:#f8fafc;margin:0;font-family:\'Outfit\',sans-serif;">' + escapeHtml(w.name) + '</h3>' +
                        '<span class="badge ' + statusClass + '">' + status + '</span>' +
                    '</div>' +
                    '<div style="font-size:0.82rem;color:#e2e8f0;margin-bottom:16px;">' +
                        '<span style="color:#64748b;font-size:0.72rem;text-transform:uppercase;display:block;margin-bottom:2px;">Scope</span>' +
                        '<strong>' + escapeHtml(scope) + '</strong>' +
                    '</div>' +
                    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);border-radius:8px;padding:10px;">' +
                        '<div>' +
                            '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;display:block;margin-bottom:2px;">Start</span>' +
                            '<span style="font-size:0.78rem;font-weight:500;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + formatDate(w.start_time) + '</span>' +
                        '</div>' +
                        '<div>' +
                            '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;display:block;margin-bottom:2px;">End</span>' +
                            '<span style="font-size:0.78rem;font-weight:500;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + formatDate(w.end_time) + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid rgba(255,255,255,0.05);padding-top:14px;">' +
                        '<button class="btn secondary sm" data-action="edit-maint" data-id="' + w.id + '">Edit</button>' +
                        '<button class="btn secondary sm" data-action="delete-maint" data-id="' + w.id + '">Delete</button>' +
                    '</div>' +
                '</div>';
            }).join('');
            grid.innerHTML = html;
        }).catch(function() {
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

                return '<div class="policy-card card" style="display:flex;flex-direction:column;justify-content:space-between;min-height:220px;padding:20px;">' +
                    '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">' +
                        '<h3 style="font-size:1.1rem;font-weight:600;color:#f8fafc;margin:0;font-family:\'Outfit\',sans-serif;">' + escapeHtml(w.name) + '</h3>' +
                        '<span class="badge ' + statusClass + '">' + status + '</span>' +
                    '</div>' +
                    '<div style="font-size:0.82rem;color:#e2e8f0;margin-bottom:16px;">' +
                        '<span style="color:#64748b;font-size:0.72rem;text-transform:uppercase;display:block;margin-bottom:2px;">Scope</span>' +
                        '<strong>' + escapeHtml(scope) + '</strong>' +
                    '</div>' +
                    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);border-radius:8px;padding:10px;">' +
                        '<div>' +
                            '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;display:block;margin-bottom:2px;">Start</span>' +
                            '<span style="font-size:0.78rem;font-weight:500;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + formatDate(w.start_time) + '</span>' +
                        '</div>' +
                        '<div>' +
                            '<span style="font-size:0.65rem;text-transform:uppercase;color:#64748b;letter-spacing:0.5px;display:block;margin-bottom:2px;">End</span>' +
                            '<span style="font-size:0.78rem;font-weight:500;color:#e2e8f0;font-family:var(--fwmon-font-mono);">' + formatDate(w.end_time) + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid rgba(255,255,255,0.05);padding-top:14px;">' +
                        '<button class="btn secondary sm" data-action="edit-maint" data-id="' + w.id + '">Edit</button>' +
                        '<button class="btn secondary sm" data-action="delete-maint" data-id="' + w.id + '">Delete</button>' +
                    '</div>' +
                '</div>';
            }).join('');
            grid.innerHTML = html;
        });
    }

    function showMaintModal(id) {
        AC.openModal('maint-modal');
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
        AC.closeModal('maint-modal');
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
                AC.showSuccess(id ? 'Maintenance window updated' : 'Maintenance window created');
            }).catch(function(err) {
                console.error('Error saving maintenance window:', err);
                AC.showError('Error: ' + (err.message || err));
            });
        });
    }

    function deleteMaintWindow(id) {
        AC.confirm('Delete this maintenance window?', {
            title: 'Delete maintenance window?',
            confirmLabel: 'Delete',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            apiFetch(API_BASE + '/maintenance-windows/' + id, {method: 'DELETE'}).then(function() {
                loadMaintenance();
                AC.showSuccess('Maintenance window deleted');
            }).catch(function(e) {
                console.error('Delete maintenance window failed:', e);
                AC.showError('Delete failed: ' + e.message);
            });
        });
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

            AC.openModal('device-alert-modal');
        }).catch(function(e) {
            console.error('Failed to load alert config:', e);
            AC.showError('Failed to load alert config: ' + e.message);
        });
    }

    function closeDeviceAlertModal() {
        AC.closeModal('device-alert-modal');
    }

    function resetDeviceAlertConfig() {
        var deviceId = document.getElementById('device-alert-device-id').value;
        if (!deviceId) return;
        AC.confirm('Reset alert configuration to defaults? This removes all overrides for this device.', {
            title: 'Reset alert config?',
            confirmLabel: 'Reset',
            danger: true,
        }).then(function(ok) {
            if (!ok) return;
            apiFetch(API_BASE + '/devices/' + deviceId + '/alert-config', { method: 'DELETE' }).then(function() {
                closeDeviceAlertModal();
                loadDevices();
                AC.showSuccess('Alert config reset to defaults');
            }).catch(function(e) {
                console.error('Reset alert config failed:', e);
                AC.showError('Reset failed: ' + e.message);
            });
        });
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
                AC.showSuccess('Alert config saved');
            }).catch(function(err) {
                console.error('Error saving alert config:', err);
                AC.showError('Error saving alert config: ' + err.message);
            });
        });
    }

    // ---- Event Delegation (click) ----
    AC.delegateEvent('click', {
        'show-device-modal': function() { showDeviceModal(); },
        'load-interfaces': function() { loadInterfaces(); },
        'iface-prev-page': function() { ifacePrevPage(); },
        'iface-next-page': function() { ifaceNextPage(); },
        'show-connection-modal': function(el) { showConnectionModal(el && el.dataset.id ? parseInt(el.dataset.id) : null); },
        'edit-connection': function(el) { showConnectionModal(parseInt(el.dataset.id)); },
        'load-syslog': function() { loadSyslog(); },
        'load-more-syslog': function() { loadMoreSyslog(); },
        'set-flow-range': function(el) {
            var hours = parseInt(el.dataset.hours);
            // v0.10.211: range is now driven by FwmonFlows.setFilter('hours',...).
            // The legacy data-action handler stays for any external deep-link.
            if (window.FwmonFlows && window.FwmonFlows.setFilter) {
                window.FwmonFlows.setFilter('hours', hours);
            } else {
                setFlowRange(hours);
            }
        },
        'load-flows': function() {
            if (window.FwmonFlows && window.FwmonFlows.refresh) {
                window.FwmonFlows.refresh();
            } else {
                loadFlows();
            }
        },
        'load-more-flows': function() {
            // FwmonFlows binds its own "load more" button directly; this
            // handler stays for the legacy fallback path.
            if (!window.FwmonFlows) loadMoreFlows();
        },
        'load-alerts': function() { loadAlerts(); },
        'load-more-alerts': function() { loadMoreAlerts(); },
        'prev-alerts': function() { prevAlerts(); },
        'next-alerts': function() { nextAlerts(); },
        'load-traps': function() { loadTraps(); },
        'load-more-traps': function() { loadMoreTraps(); },
        'prev-syslog': function() { prevSyslog(); },
        'next-syslog': function() { nextSyslog(); },
        'prev-audit': function() { prevAudit(); },
        'next-audit': function() { nextAudit(); },
        'refresh-audit': function() { loadAuditLogs(); },
        'close-audit-detail': function() { closeAuditDetail(); },
        'change-password': function() { changePassword(); },
        'save-settings': function() { saveSettings(); },
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
        'toggle-public-visible': function(el) {
            var id = parseInt(el.dataset.id);
            var checked = el.checked;
            apiFetch(API_BASE + '/devices/' + id, {
                method: 'PUT',
                body: { public_visible: checked }
            }).then(function() {
                AC.showSuccess('Public visibility updated');
            }).catch(function() {
                el.checked = !checked;
                AC.showError('Failed to update public visibility');
            });
        },
        'delete-connection': function(el) { deleteConnection(parseInt(el.dataset.id)); },
        'show-ack-modal':  function(el) { showAckModal(parseInt(el.dataset.id)); },
        'close-ack-modal': function() { closeAckModal(); },
        // Snooze handlers (v0.10.218, bundle G2).
        'snooze-alert':    function(el) { showSnoozePrompt(parseInt(el.dataset.id)); },
        'unsnooze-alert':  function(el) { unsnoozeAlert(parseInt(el.dataset.id)); },
        'show-policy-modal': function() { showPolicyModal(); },
        'close-policy-modal': function() { closePolicyModal(); },
        'edit-policy': function(el) { showPolicyModal(parseInt(el.dataset.id)); },
        'clone-policy': function(el) { clonePolicy(parseInt(el.dataset.id)); },
        'delete-policy': function(el) { deletePolicy(parseInt(el.dataset.id)); },
        'show-maint-modal': function() { showMaintModal(); },
        'close-maint-modal': function() { closeMaintModal(); },
        'edit-maint': function(el) { showMaintModal(parseInt(el.dataset.id)); },
        'delete-maint': function(el) { deleteMaintWindow(parseInt(el.dataset.id)); },
        'close-probe-detail-modal': function() { closeProbeDetailModal(); },
        'toggle-expand': function(el) { el.classList.toggle('expanded'); },
        'close-syslog-detail': function() { closeSyslogDetail(); },
        'close-alert-detail': function() { closeAlertDetail(); },
        'toggle-alert-selection': function(el) {
            var id = el.dataset.id;
            if (el.checked) alertSelection[id] = true;
            else delete alertSelection[id];
            updateAlertBulkToolbar();
        },
        'toggle-page-selection': function(el) {
            var rowBoxes = document.querySelectorAll('#alerts-full-table tbody input[data-action="toggle-alert-selection"]');
            rowBoxes.forEach(function(b) {
                b.checked = el.checked;
                if (el.checked) alertSelection[b.dataset.id] = true;
                else delete alertSelection[b.dataset.id];
            });
            updateAlertBulkToolbar();
        },
        'clear-alert-selection': function() {
            var rowBoxes = document.querySelectorAll('#alerts-full-table tbody input[data-action="toggle-alert-selection"]');
            rowBoxes.forEach(function(b) { b.checked = false; });
            clearAlertSelection();
        },
        'bulk-ack-alerts': function() { bulkAckSelected(); },
        'close-bulk-ack': function() { AC.closeModal('alerts-bulk-ack-modal'); },
        'confirm-bulk-ack': function() { confirmBulkAck(); },
        'select-all-matching': function(el, e) {
            if (e && e.preventDefault) e.preventDefault();
            enableSelectAllMatching();
        },
        'cancel-select-all-matching': function(el, e) {
            if (e && e.preventDefault) e.preventDefault();
            cancelSelectAllMatching();
        }
    });

    // Click on syslog row to show detail
    document.addEventListener('click', function(e) {
        // Ignore clicks on form controls or data-action elements — they have
        // their own handlers (selection checkboxes, ack button, etc.). Also
        // skip <a> clicks (v0.10.215, bundle E2): syslog/alert rows now
        // contain inline filter-links, and we don't want clicking those
        // links to *also* open the row detail modal.
        if (e.target.closest('a, input, button, select, textarea, [data-action]')) return;
        var row = e.target.closest('.syslog-row');
        if (row) { showSyslogDetail(parseInt(row.dataset.id)); return; }
        var row2 = e.target.closest('.alert-row');
        if (row2) { showAlertDetail(parseInt(row2.dataset.id)); return; }
        var cell = e.target.closest('.expandable-msg');
        if (cell && cell.classList.contains('expanded')) { cell.classList.remove('expanded'); return; }
        if (cell) { cell.classList.add('expanded'); }
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
    // v0.10.212 (bundle A2) — wire range pills + auto-apply + URL state for
    // the three analytics tabs. These helpers are idempotent (FwmonControls
    // primitives guard with one-shot binding flags), so calling them on
    // every tab activation is cheap. The first call hydrates the page state
    // from the URL; subsequent calls only paint the chip strip.
    function wireSyslogAnalyticsPage() {
        if (!window.FwmonControls) return;
        if (analyticsPages.syslog) {
            analyticsPages.syslog.refresh();
            return;
        }
        analyticsPages.syslog = FwmonControls.attachAnalyticsPage({
            page: 'syslog',
            rangePillsId: 'syslog-range-pills',
            chipsId: 'syslog-active-chips',
            defaults: { hours: 24, device_id: '', probe_id: '', severity: '', search: '' },
            inputs: [
                { id: 'syslog-filter-search', stateKey: 'search', chipKey: 'search' }
            ],
            selects: [
                { id: 'syslog-filter-device',   stateKey: 'device_id', chipKey: 'device',
                  chipLabel: function(v) { return deviceLabel(v); } },
                { id: 'syslog-filter-probe',    stateKey: 'probe_id',  chipKey: 'probe',
                  chipLabel: function(v) { return probeLabel(v); } },
                { id: 'syslog-filter-severity', stateKey: 'severity',  chipKey: 'sev' }
            ],
            onChange: function() { loadSyslog(); }
        });
    }

    function wireAlertsAnalyticsPage() {
        if (!window.FwmonControls) return;
        if (analyticsPages.alerts) {
            analyticsPages.alerts.refresh();
            return;
        }
        analyticsPages.alerts = FwmonControls.attachAnalyticsPage({
            page: 'alerts',
            rangePillsId: 'alerts-range-pills',
            chipsId: 'alerts-active-chips',
            defaults: { hours: 24, device_id: '', alert_type: '', severity: '', acknowledged: '' },
            inputs: [],
            selects: [
                { id: 'alerts-filter-device',   stateKey: 'device_id',    chipKey: 'device',
                  chipLabel: function(v) { return deviceLabel(v); } },
                { id: 'alerts-filter-type',     stateKey: 'alert_type',   chipKey: 'type' },
                { id: 'alerts-filter-severity', stateKey: 'severity',     chipKey: 'sev' },
                { id: 'alerts-filter-ack',      stateKey: 'acknowledged', chipKey: 'ack' }
            ],
            onChange: function() { loadAlerts(); }
        });
    }

    function wireTrapsAnalyticsPage() {
        if (!window.FwmonControls) return;
        if (analyticsPages.traps) {
            analyticsPages.traps.refresh();
            return;
        }
        analyticsPages.traps = FwmonControls.attachAnalyticsPage({
            page: 'traps',
            rangePillsId: 'traps-range-pills',
            chipsId: 'traps-active-chips',
            defaults: { hours: 24, severity: '', trap_type: '' },
            inputs: [],
            selects: [
                { id: 'traps-filter-severity', stateKey: 'severity',  chipKey: 'sev' },
                { id: 'traps-filter-type',     stateKey: 'trap_type', chipKey: 'type' }
            ],
            onChange: function() { loadTraps(); }
        });
    }

    // deviceLabel / probeLabel — used by the analytics-page chip formatter
    // to render `device: prod-edge-01` instead of `device: 42`.
    function deviceLabel(id) {
        for (var i = 0; i < currentDevices.length; i++) {
            if (String(currentDevices[i].id) === String(id)) return currentDevices[i].name || ('dev:' + id);
        }
        return 'dev:' + id;
    }
    function probeLabel(id) {
        for (var i = 0; i < currentProbes.length; i++) {
            if (String(currentProbes[i].id) === String(id)) return currentProbes[i].name || ('probe:' + id);
        }
        return 'probe:' + id;
    }

    // SPA-aware filter-link interceptor (v0.10.219, bundle H2).
    //
    // Bundles E and G added filter-links like /admin/alerts?device_id=42
    // throughout the admin (alert detail modal, noisy-device leaderboard,
    // device-detail "view all" link, etc). Clicking those links from
    // inside the SPA used to do a full page reload — visible flash, lost
    // scroll position, every chart re-initialised. This handler catches
    // those clicks and applies the new filter via history.pushState +
    // the analytics-page reseedFromURL helper added in H2.
    //
    // Only same-origin /admin/* links are intercepted. Modifier-key
    // clicks (Ctrl/Cmd-click for new tab, Shift-click for new window,
    // middle-click via the button check) bypass the handler so the
    // browser keeps its native open-in-new-tab affordance — which is
    // critical for the multi-tab triage flow.
    // ONLY the tabs that actually exist as `page-<name>` divs inside admin.html
    // (and have a loadPageData() case) belong here. Probes, Sites, Pending and
    // IRC are STANDALONE HTML documents (probes.html, sites.html,
    // probe-pending.html, irc.html) — they do not load admin-main.js and have no
    // page div here. Listing them caused the click interceptor below to
    // preventDefault() the real navigation and call loadPageData() with no
    // matching case, so the page went blank until a manual refresh did the true
    // full-page navigation. Keep this set in sync with the page divs + the
    // loadPageData() switch.
    var SPA_PAGES = { dashboard:1, devices:1, interfaces:1, connections:1,
        settings:1, reports:1, syslog:1, flows:1, alerts:1, traps:1,
        'alert-policies':1, maintenance:1, audit:1 };

    document.addEventListener('click', function(ev) {
        if (ev.button !== 0) return;                        // not a primary click
        if (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey) return;
        var a = ev.target && ev.target.closest && ev.target.closest('a[href]');
        if (!a) return;
        if (a.target && a.target !== '' && a.target !== '_self') return;
        // Same-origin admin route?
        var href = a.getAttribute('href') || '';
        if (!href || href[0] === '#') return;
        var url;
        try { url = new URL(href, window.location.href); } catch (e) { return; }
        if (url.origin !== window.location.origin) return;
        // Filter to admin page navigations; skip admin API and non-admin
        // URLs. Earlier code had a precedence bug —
        //   if (!url.pathname.indexOf('/admin/api/') === 0 && ...)
        // evaluates as (!indexOf) === 0, which is always false, so the
        // early return never fired. Fixed in v0.10.225.
        if (url.pathname.indexOf('/admin/') !== 0) return;       // not an admin page
        if (url.pathname.indexOf('/admin/api/') === 0) return;   // admin API call, not a page
        // Split off the segments under /admin/. If there's more than one
        // segment (e.g. /admin/devices/123, /admin/connections/42), this
        // is a DETAIL page served from a separate HTML document
        // (device-detail.html, connection-detail.html — see cmd/api/main.go
        // routes 409-414). Earlier code only checked the FIRST segment
        // against SPA_PAGES, so /admin/devices/123 matched 'devices', the
        // interceptor preventDefault()'d the click, pushed the URL onto
        // history, and called loadPageData('devices') — which reloads the
        // devices LIST. URL bar said /admin/devices/123, page showed the
        // list. That was the reported bug. Fix: bail out the moment we
        // see a deep path so the browser navigates natively.
        var pathSegs = url.pathname.replace(/^\/admin\/?/, '').replace(/\/$/, '').split('/').filter(Boolean);
        if (pathSegs.length > 1) return;
        var seg = pathSegs[0] || '';
        if (!SPA_PAGES[seg || 'dashboard']) return;

        ev.preventDefault();
        var page = seg || 'dashboard';
        // Push the new URL so future refresh / back-button preserves the
        // filter exactly.
        history.pushState(null, '', url.pathname + url.search);

        // If already on the target page, just re-seed filters in place.
        var currentActive = document.querySelector('.page.active');
        var alreadyOnPage = currentActive && currentActive.id === ('page-' + page);
        if (alreadyOnPage) {
            // The analytics-page handles (when present) own URL state for
            // syslog / alerts / traps. Re-seed from URL and let them
            // refresh the data + chips.
            if (analyticsPages[page] && analyticsPages[page].reseedFromURL) {
                analyticsPages[page].reseedFromURL();
            } else {
                loadPageData(page);
            }
            return;
        }

        // Switch tabs via the same path nav-item clicks use, then load.
        document.querySelectorAll('.nav-item').forEach(function(i) { i.classList.remove('active'); });
        var navItem = document.querySelector('.nav-item[data-page="' + page + '"]');
        if (navItem) navItem.classList.add('active');
        document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
        var pageEl = document.getElementById('page-' + page);
        if (pageEl) pageEl.classList.add('active');
        var titleEl = document.getElementById('page-title');
        if (titleEl) titleEl.textContent = navItem ? navItem.textContent.trim() : page;
        if (page !== 'connections') stopConnRefresh();
        loadPageData(page);
    });

    var initialPage = activateTabFromUrl();
    AC.fetchCsrfToken().then(function() { loadPageData(initialPage); });

    // popstate — re-derive page from the URL after browser back/forward.
    // Without this, every sidebar tab click pushed a history entry but
    // the back button only changed the URL bar — the view stayed put
    // because nothing was listening for the transition. Now back/forward
    // re-runs activateTabFromUrl() (which switches the active page +
    // nav-item) and then reseeds analytics pages from URL query string
    // or calls loadPageData for non-analytics pages. Added v0.10.225.
    window.addEventListener('popstate', function() {
        var page = activateTabFromUrl();
        if (page !== 'connections') stopConnRefresh();
        if (analyticsPages[page] && analyticsPages[page].reseedFromURL) {
            analyticsPages[page].reseedFromURL();
        } else {
            loadPageData(page);
        }
    });

    // Dashboard refresh — visibility-gated (v0.10.214, bundle C2). Page-
    // active check stays so we don't refresh when on syslog/alerts/etc;
    // the new gate also pauses when the whole browser tab is hidden.
    adminRefreshTimer = AC.pollWhenVisible(function() {
        var activePage = document.querySelector('.page.active');
        if (activePage && activePage.id === 'page-dashboard') loadDashboard();
    }, 30000, { immediate: false });
})();
