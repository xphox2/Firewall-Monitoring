// admin-dashboard-modules.js — FwmonDashboard: the customizable system-health
// dashboard. Renders modules from the cached /api/dashboard/health composite;
// per-user layout (show/hide + order) persists via /api/me/dashboard. Distinct
// from the NOC (real-time site/device view) — this summarizes PLATFORM health.
(function () {
    'use strict';
    var AC = window.AdminCommon;
    if (!AC) return;
    var API = AC.API_BASE;
    var esc = AC.escapeHtml;

    // ---- helpers -------------------------------------------------------------
    function sevColor(sev) {
        return AC.cssVar(
            sev === 'crit' ? '--fwmon-sig-crit' : sev === 'warn' ? '--fwmon-sig-warn' : '--fwmon-sig-ok',
            sev === 'crit' ? '#f2555a' : sev === 'warn' ? '#e7b53c' : '#36c98a'
        );
    }
    function pctSev(p) { return p >= 80 ? 'crit' : p >= 60 ? 'warn' : 'ok'; }
    function num(n) { return (n == null ? 0 : Number(n)).toLocaleString(); }

    function tile(label, value, sev) {
        var color = sev ? 'color:' + sevColor(sev) + ';' : '';
        return '<div class="sys-metric"><div class="sys-metric-lbl">' + esc(label) + '</div>' +
            '<div class="sys-metric-val" style="' + color + '">' + value + '</div></div>';
    }
    function tiles(inner) {
        return '<div class="dash-tiles">' + inner + '</div>';
    }
    function fmtUptime(sec) {
        sec = Math.floor(sec || 0);
        var d = Math.floor(sec / 86400); sec -= d * 86400;
        var h = Math.floor(sec / 3600); sec -= h * 3600;
        var m = Math.floor(sec / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }
    function fmtBytes(b) { return AC.formatBytes ? AC.formatBytes(b) : (b || 0) + ' B'; }
    function fmtAgo(sec) {
        if (sec == null) return 'n/a';
        if (sec < 90) return Math.max(0, Math.round(sec)) + 's ago';
        if (sec < 5400) return Math.round(sec / 60) + 'm ago';
        if (sec < 172800) return Math.round(sec / 3600) + 'h ago';
        return Math.round(sec / 86400) + 'd ago';
    }
    // Inline sparkline from an array of {count} or numbers.
    function spark(series, sev) {
        var vals = (series || []).map(function (p) { return typeof p === 'number' ? p : (p.count || 0); });
        if (vals.length < 2) return '<div class="dash-spark-empty">no data</div>';
        var max = Math.max.apply(null, vals) || 1;
        var w = 100, hgt = 28, step = w / (vals.length - 1);
        var pts = vals.map(function (v, i) {
            return (i * step).toFixed(1) + ',' + (hgt - (v / max) * (hgt - 3) - 1).toFixed(1);
        }).join(' ');
        var c = sevColor(sev || 'ok');
        return '<svg class="dash-spark" viewBox="0 0 ' + w + ' ' + hgt + '" preserveAspectRatio="none" aria-hidden="true">' +
            '<polyline points="' + pts + '" fill="none" stroke="' + c + '" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';
    }

    // ---- module definitions --------------------------------------------------
    // Each: { id, title, sev(data)->'ok'|'warn'|'crit', body(data)->html }
    var MODULES = [
        {
            id: 'platform', title: 'Platform',
            sev: function (d) {
                var h = (d.platform || {}).host || {};
                // data_disk_percent is the volume holding the database. It is
                // usually NOT the root filesystem, and it is the one that takes
                // the system down: a full PGDATA crash-loops Postgres on
                // "No space left on device". Omitting it here is why a 98% data
                // volume showed as a healthy 83% platform tile.
                return pctSev(Math.max(h.cpu_percent || 0, h.mem_percent || 0,
                    h.disk_percent || 0, h.data_disk_percent || 0));
            },
            body: function (d) {
                var p = d.platform || {}, host = p.host || {}, rt = p.runtime || {};
                function pc(v) { return v == null ? 'n/a' : Math.round(v) + '%'; }
                return tiles(
                    tile('CPU', pc(host.cpu_percent), host.cpu_percent != null ? pctSev(host.cpu_percent) : null) +
                    tile('Memory', pc(host.mem_percent), host.mem_percent != null ? pctSev(host.mem_percent) : null) +
                    tile('Disk', pc(host.disk_percent), host.disk_percent != null ? pctSev(host.disk_percent) : null) +
                    // Shown separately rather than folded into Disk: an operator
                    // needs to know WHICH volume is filling to act on it.
                    (host.data_disk_percent != null
                        ? tile('DB volume', pc(host.data_disk_percent), pctSev(host.data_disk_percent))
                        : '') +
                    tile('Load 1m', host.load1 != null ? host.load1.toFixed(2) : 'n/a') +
                    tile('Uptime', fmtUptime(p.uptime_seconds)) +
                    tile('Goroutines', num(rt.goroutines)) +
                    tile('Heap', rt.heap_alloc_mb != null ? Math.round(rt.heap_alloc_mb) + ' MB' : 'n/a') +
                    tile('Version', '<span style="font-size:0.9rem">' + esc(p.version || '—') + '</span>')
                );
            }
        },
        {
            id: 'database', title: 'Database',
            sev: function (d) {
                var pool = ((d.platform || {}).db || {}).pool || {};
                if (!((d.platform || {}).db || {}).reachable) return 'crit';
                if (pool.max_open && pool.in_use / pool.max_open >= 0.8) return 'warn';
                return 'ok';
            },
            body: function (d) {
                var db = (d.platform || {}).db || {}, pool = db.pool || {};
                var poolTxt = pool.in_use != null ? pool.in_use + ' / ' + (pool.max_open || pool.open || 0) : 'n/a';
                var poolSev = (pool.max_open && pool.in_use / pool.max_open >= 0.8) ? 'warn' : null;
                return tiles(
                    tile('Reachable', db.reachable ? 'Yes' : 'No', db.reachable ? 'ok' : 'crit') +
                    tile('Size', db.size_bytes != null ? fmtBytes(db.size_bytes) : 'n/a') +
                    tile('Pool in-use', poolTxt, poolSev) +
                    tile('Idle conns', num(pool.idle)) +
                    tile('Waits', num(pool.wait_count))
                );
            }
        },
        {
            id: 'ingestion', title: 'Ingestion Rates',
            sev: function (d) {
                var f = (d.ingestion || {}).freshness_seconds;
                return f != null && f > 1800 ? 'warn' : 'ok';
            },
            body: function (d) {
                var g = d.ingestion || {};
                function row(label, total, lh) {
                    return tile(label, '<span>' + num(total) + '</span>' +
                        '<span class="dash-rate">+' + num(lh) + '/hr</span>');
                }
                return tiles(
                    row('Syslog', g.syslog, g.syslog_last_hour) +
                    row('Traps', g.traps, g.traps_last_hour) +
                    row('Flows', g.flows, g.flows_last_hour) +
                    row('Pings', g.pings, g.pings_last_hour) +
                    tile('Last poll', fmtAgo(g.freshness_seconds), g.freshness_seconds > 1800 ? 'warn' : null)
                );
            }
        },
        {
            id: 'collectors', title: 'Collector Health',
            sev: function (d) {
                var c = d.collectors || {};
                if (c.offline > 0) return 'crit';
                if (c.pending > 0) return 'warn';
                return 'ok';
            },
            body: function (d) {
                var c = d.collectors || {}, probes = c.probes || [];
                var head = tiles(
                    tile('Online', num(c.online), c.online > 0 ? 'ok' : null) +
                    tile('Offline', num(c.offline), c.offline > 0 ? 'crit' : null) +
                    tile('Pending', num(c.pending), c.pending > 0 ? 'warn' : null)
                );
                if (!probes.length) return head + '<div class="dash-empty">No probes configured</div>';
                var rows = probes.slice(0, 8).map(function (p) {
                    var s = p.status === 'online' ? 'ok' : (p.approval_status === 'pending' ? 'warn' : 'crit');
                    return '<div class="dash-row"><span class="dash-dot" style="background:' + sevColor(s) + '"></span>' +
                        '<span class="dash-row-name">' + esc(p.name) + '</span>' +
                        '<span class="dash-row-meta">' + esc(p.site || 'no site') + '</span></div>';
                }).join('');
                return head + '<div class="dash-list">' + rows + '</div>';
            }
        },
        {
            id: 'fleet', title: 'Fleet Summary',
            sev: function (d) { return (d.fleet || {}).offline > 0 ? 'crit' : 'ok'; },
            body: function (d) {
                var f = d.fleet || {};
                var total = f.total || 0, online = f.online || 0;
                var pct = total ? Math.round((online / total) * 100) : 0;
                return tiles(
                    tile('Devices', num(total)) +
                    tile('Online', num(online), 'ok') +
                    tile('Offline', num(f.offline), f.offline > 0 ? 'crit' : null)
                ) + '<div class="dash-barwrap"><div class="dash-bar" style="width:' + pct + '%;background:' +
                    sevColor(f.offline > 0 ? 'warn' : 'ok') + '"></div></div>' +
                    '<div class="dash-caption">' + pct + '% of the fleet online</div>';
            }
        },
        {
            id: 'alerts', title: 'Alerts Summary',
            sev: function (d) {
                var s = (d.alerts || {}).open_by_severity || {};
                if (s.critical > 0 || s.emergency > 0) return 'crit';
                if (s.warning > 0 || s.error > 0) return 'warn';
                return 'ok';
            },
            body: function (d) {
                var a = d.alerts || {}, s = a.open_by_severity || {};
                var trend = (a.trend || {}).alerts_over_time || [];
                var tsev = (s.critical > 0) ? 'crit' : (s.warning > 0 ? 'warn' : 'ok');
                return tiles(
                    tile('Open', num(a.open_total), a.open_total > 0 ? tsev : null) +
                    tile('Critical', num(s.critical), s.critical > 0 ? 'crit' : null) +
                    tile('Warning', num(s.warning), s.warning > 0 ? 'warn' : null) +
                    tile('Info', num(s.info))
                ) + '<div class="dash-caption">Alerts, last 24h</div>' + spark(trend, tsev);
            }
        },
        {
            id: 'dataquality', title: 'Data Quality',
            sev: function (d) {
                var q = d.data_quality || {};
                return (q.stale || []).length > 0 ? 'warn' : 'ok';
            },
            body: function (d) {
                var q = d.data_quality || {}, stale = q.stale || [], noisy = q.noisy || [];
                var out = '<div class="dash-subhead">Stale devices <span class="dash-count">' + stale.length + '</span></div>';
                if (!stale.length) {
                    out += '<div class="dash-empty">All devices polled recently</div>';
                } else {
                    out += '<div class="dash-list">' + stale.slice(0, 5).map(function (dev) {
                        return '<div class="dash-row"><span class="dash-dot" style="background:' + sevColor('warn') + '"></span>' +
                            '<span class="dash-row-name">' + AC.deviceLink(dev.id, dev.name) + '</span></div>';
                    }).join('') + '</div>';
                }
                out += '<div class="dash-subhead" style="margin-top:12px;">Noisiest devices</div>';
                if (!noisy.length) {
                    out += '<div class="dash-empty">Quiet — no notable volume</div>';
                } else {
                    var max = noisy[0].total || 1;
                    out += '<div class="dash-list">' + noisy.slice(0, 5).map(function (r) {
                        var w = Math.max(4, Math.round((r.total / max) * 100));
                        return '<div class="dash-row"><span class="dash-row-name">' + AC.deviceLink(r.device_id, r.name) + '</span>' +
                            '<span class="dash-row-meta mono">' + num(r.total) + '</span>' +
                            '<span class="dash-minibar"><span style="width:' + w + '%"></span></span></div>';
                    }).join('') + '</div>';
                }
                return out;
            }
        },
        {
            id: 'services', title: 'Services & Feeds',
            sev: function (d) {
                var down = (d.services || []).some(function (s) { return s.status === 'down'; });
                return down ? 'crit' : 'ok';
            },
            body: function (d) {
                var svcs = d.services || [], tf = d.threat_feeds || {};
                function statSev(st) { return st === 'down' ? 'crit' : (st === 'idle' || st === 'off') ? 'warn' : 'ok'; }
                var rows = svcs.map(function (s) {
                    return '<div class="dash-row"><span class="dash-dot" style="background:' + sevColor(statSev(s.status)) + '"></span>' +
                        '<span class="dash-row-name">' + esc(s.name) + '</span>' +
                        '<span class="dash-row-meta">' + esc(s.status) + '</span></div>';
                }).join('');
                var feedTxt = tf.enabled
                    ? num(tf.indicator_count) + ' IPs · ' + num(tf.active_sources) + ' sources'
                    : 'disabled';
                rows += '<div class="dash-row"><span class="dash-dot" style="background:' +
                    sevColor(tf.enabled ? 'ok' : 'warn') + '"></span>' +
                    '<span class="dash-row-name">Threat feeds</span>' +
                    '<span class="dash-row-meta">' + esc(feedTxt) + '</span></div>';
                return '<div class="dash-list">' + rows + '</div>';
            }
        }
    ];
    var MODULE_INDEX = {};
    MODULES.forEach(function (m) { MODULE_INDEX[m.id] = m; });
    var DEFAULT_LAYOUT = MODULES.map(function (m) { return { id: m.id, visible: true }; });

    // ---- state ---------------------------------------------------------------
    var layout = null;        // [{id, visible}]
    var savedLayout = null;   // last-persisted snapshot (for Cancel)
    var data = null;          // last health payload
    var customizing = false;
    var loaded = false;
    var pollStarted = false;
    var dragId = null;

    function reconcile(saved) {
        var out = [], seen = {};
        (saved || []).forEach(function (e) {
            if (e && MODULE_INDEX[e.id] && !seen[e.id]) {
                seen[e.id] = true;
                out.push({ id: e.id, visible: e.visible !== false });
            }
        });
        // Append any modules not in the saved layout (e.g. newly shipped ones).
        MODULES.forEach(function (m) { if (!seen[m.id]) out.push({ id: m.id, visible: true }); });
        return out;
    }
    function clone(l) { return l.map(function (e) { return { id: e.id, visible: e.visible }; }); }

    // ---- rendering -----------------------------------------------------------
    function render() {
        var host = document.getElementById('dashboard-modules');
        if (!host) return;
        if (!data) { host.innerHTML = '<div class="loading" style="padding:32px;">Loading system health…</div>'; return; }
        var html = layout.map(function (e) {
            var m = MODULE_INDEX[e.id];
            if (!m) return '';
            if (!e.visible && !customizing) return '';
            var sev = 'ok';
            try { sev = m.sev(data) || 'ok'; } catch (err) { sev = 'ok'; }
            var cls = 'dash-module' + (customizing ? ' editing' : '') + (!e.visible ? ' hidden-mod' : '');
            var controls = customizing
                ? '<div class="dash-mod-controls">' +
                '<button class="dash-eye" type="button" data-eye="' + e.id + '" title="' + (e.visible ? 'Hide' : 'Show') + '" aria-label="' + (e.visible ? 'Hide module' : 'Show module') + '">' + (e.visible ? '👁' : '🚫') + '</button>' +
                '<span class="dash-grip" title="Drag to reorder" aria-hidden="true">⠿</span></div>'
                : '';
            var body = '';
            try { body = m.body(data); } catch (err) { body = '<div class="dash-empty">unavailable</div>'; }
            return '<section class="' + cls + '" data-mod-id="' + e.id + '"' + (customizing ? ' draggable="true"' : '') + '>' +
                '<div class="dash-module-header"><span class="dash-dot" style="background:' + sevColor(sev) + '"></span>' +
                '<h3>' + esc(m.title) + '</h3>' + controls + '</div>' +
                '<div class="dash-module-body">' + body + '</div></section>';
        }).join('');
        host.innerHTML = html || '<div class="dash-empty" style="padding:32px;">All modules hidden — click Customize to add some.</div>';
        if (customizing) wireDnd(host);
    }

    // ---- drag & drop reorder (customize mode) --------------------------------
    function wireDnd(host) {
        host.querySelectorAll('.dash-module').forEach(function (el) {
            el.addEventListener('dragstart', function (e) {
                dragId = el.dataset.modId; el.classList.add('dragging');
                if (e.dataTransfer) { e.dataTransfer.effectAllowed = 'move'; try { e.dataTransfer.setData('text/plain', dragId); } catch (x) {} }
            });
            el.addEventListener('dragend', function () { dragId = null; el.classList.remove('dragging'); });
            el.addEventListener('dragover', function (e) { e.preventDefault(); });
            el.addEventListener('drop', function (e) {
                e.preventDefault();
                var targetId = el.dataset.modId;
                if (!dragId || dragId === targetId) return;
                var from = layout.findIndex(function (x) { return x.id === dragId; });
                var to = layout.findIndex(function (x) { return x.id === targetId; });
                if (from < 0 || to < 0) return;
                var moved = layout.splice(from, 1)[0];
                layout.splice(to, 0, moved);
                render();
            });
        });
    }

    // ---- customize toolbar ---------------------------------------------------
    function setCustomize(on) {
        customizing = on;
        ['dash-save-btn', 'dash-cancel-btn', 'dash-reset-btn', 'dash-customize-hint'].forEach(function (id) {
            var el = document.getElementById(id); if (el) el.style.display = on ? '' : 'none';
        });
        var cbtn = document.getElementById('dash-customize-btn');
        if (cbtn) cbtn.style.display = on ? 'none' : '';
        render();
    }
    function wireToolbar() {
        var cbtn = document.getElementById('dash-customize-btn');
        if (cbtn && !cbtn.__wired) {
            cbtn.__wired = true;
            cbtn.addEventListener('click', function () { savedLayout = clone(layout); setCustomize(true); });
            document.getElementById('dash-cancel-btn').addEventListener('click', function () {
                if (savedLayout) layout = clone(savedLayout); setCustomize(false);
            });
            document.getElementById('dash-reset-btn').addEventListener('click', function () {
                layout = clone(DEFAULT_LAYOUT); render();
            });
            document.getElementById('dash-save-btn').addEventListener('click', saveLayout);
            // Eye toggles are delegated (re-rendered each time).
            document.getElementById('dashboard-modules').addEventListener('click', function (e) {
                var b = e.target.closest ? e.target.closest('[data-eye]') : null;
                if (!b) return;
                var id = b.getAttribute('data-eye');
                var entry = layout.find(function (x) { return x.id === id; });
                if (entry) { entry.visible = !entry.visible; render(); }
            });
        }
    }

    function saveLayout() {
        var body = JSON.stringify({ modules: layout });
        AC.apiFetch(API + '/me/dashboard', { method: 'PUT', body: JSON.stringify({ prefs: body }) })
            .then(function () { savedLayout = clone(layout); setCustomize(false); if (AC.showSuccess) AC.showSuccess('Dashboard layout saved'); })
            .catch(function () { if (AC.showError) AC.showError('Failed to save layout'); });
    }

    // ---- data + lifecycle ----------------------------------------------------
    function fetchData() {
        return AC.apiFetch(API + '/dashboard/health').then(function (r) {
            data = (r && r.data) ? r.data : null;
            render();
        }).catch(function () { /* keep last data */ });
    }
    function loadLayout() {
        return AC.apiFetch(API + '/me/dashboard').then(function (r) {
            var prefs = (r && r.data && r.data.prefs) ? r.data.prefs : '';
            var parsed = null;
            if (prefs) { try { parsed = JSON.parse(prefs).modules; } catch (e) { parsed = null; } }
            layout = reconcile(parsed);
        }).catch(function () { layout = clone(DEFAULT_LAYOUT); });
    }

    // load() runs on every navigation to the dashboard: refresh data, and on the
    // first visit also load the saved layout, wire the toolbar, and start the
    // (page-guarded) poll. The server caches /dashboard/health ~10s, so polling
    // from many workstations stays flat.
    function load() {
        if (!loaded) {
            loaded = true;
            layout = clone(DEFAULT_LAYOUT);
            wireToolbar();
            loadLayout().then(fetchData);
            if (!pollStarted && AC.pollWhenVisible) {
                pollStarted = true;
                AC.pollWhenVisible(function () {
                    var pg = document.getElementById('page-dashboard');
                    if (pg && pg.classList.contains('active') && !customizing) fetchData();
                }, 30000, { immediate: false });
            }
        } else {
            fetchData();
        }
    }

    window.FwmonDashboard = { load: load };
})();
