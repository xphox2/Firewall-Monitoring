/*
 * admin-noc.js — NOC operations breakdown (per-site → per-device).
 *
 * Subscribes to the server's Server-Sent Events stream (/admin/api/noc/stream),
 * which pushes a fresh snapshot every few seconds. The snapshot carries fleet
 * vitals, a live per-site/device health breakdown (snapshot.sites) and the
 * last minute's threat lists; a named "feed" event carries the live alert and
 * detection ticker. The whole page renders from that ONE stream (no extra poll).
 *
 * Every site/device card is a link into Alert History, filtered to that entity:
 *   - site card    → /admin/alerts?site_id=ID   (or ?site_id=unassigned)
 *   - device card  → /admin/alerts?device_id=ID
 * so a click lands on the live alerts for that site/device. Navigation is plain
 * <a href>, handled by the SPA click-interceptor (no router code here).
 *
 * Public API (window.FwmonNOC):
 *   init()  — open the stream and start rendering (called when the NOC page opens)
 *   stop()  — close the stream (called when navigating away)
 */
(function () {
    'use strict';

    var STREAM_URL = '/admin/api/noc/stream';
    var es = null;
    var latest = null;               // most recent snapshot object
    var mode = 'site';               // 'site' | 'device'
    var wired = false;

    var SEV_RANK = { critical: 0, warning: 1, info: 2 };

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function fmtCount(n) {
        n = Number(n) || 0;
        if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
        return String(n);
    }
    function fmtBytes(n) {
        n = Number(n) || 0;
        var u = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return n.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
    }
    function fmtBps(bits) {
        bits = Number(bits) || 0;
        var u = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
        var i = 0;
        while (bits >= 1000 && i < u.length - 1) { bits /= 1000; i++; }
        return bits.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
    }
    function ago(iso) {
        if (!iso) return '';
        var t = new Date(iso).getTime();
        if (!isFinite(t)) return '';
        var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
        if (s < 60) return s + 's';
        if (s < 3600) return Math.floor(s / 60) + 'm';
        if (s < 86400) return Math.floor(s / 3600) + 'h';
        return Math.floor(s / 86400) + 'd';
    }
    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }
    function sevClass(sev) {
        return sev ? ('sev-' + sev) : '';
    }
    // siteKey maps a SiteBreakdown to the token used in ?site_id=KEY: the numeric
    // site id, or 'unassigned' for the null bucket (the alerts filter understands
    // both — see applyAlertFilters).
    function siteKey(s) {
        return (s && s.site_id != null) ? String(s.site_id) : 'unassigned';
    }

    // ── render entry point ──────────────────────────────────────────────────

    function render(d) {
        if (!d) return;
        latest = d;
        renderVitals(d);
        renderThreats(d);
        renderBreakdown(d);
        // The one-shot fallback carries the feed inline; the stream sends it as
        // its own event. Between feed frames, each snapshot re-renders the feed
        // so its relative times stay current (rows whose text is unchanged are
        // not touched).
        if (d.feed) onFeed(d.feed);
        else if (feedState.feed && !isPaused()) renderFeed();
    }

    function renderVitals(d) {
        setText('noc-bps', fmtBps(d.bits_per_second));
        setText('noc-flows', fmtCount(d.total_flows) + ' / ' + fmtBytes(d.total_bytes));
        setText('noc-srcs', fmtCount(d.unique_sources) + ' → ' + fmtCount(d.unique_dests));
        setText('noc-threat-flows', fmtCount(d.threat_flows));
        setText('noc-ti', fmtCount(d.active_threat_intel));
        var winHint = document.getElementById('noc-window-hint');
        if (winHint) winHint.textContent = 'last ' + Math.round((d.window_seconds || 300) / 60) + ' min · live';
    }

    function renderBreakdown(d) {
        var sites = d.sites || [];
        var sitesGrid = document.getElementById('noc-sites-grid');
        var devGrid = document.getElementById('noc-devices-grid');
        if (sitesGrid) sitesGrid.hidden = mode !== 'site';
        if (devGrid) devGrid.hidden = mode !== 'device';
        if (mode === 'site') renderSiteCards(sites);
        else renderDeviceCards(sites);
    }

    // ── By Site: one card per site (links to Alert History for that site) ────

    function sevBadges(critical, warning) {
        var out = '';
        if (critical > 0) out += '<span class="fwmon-noc-badge crit">' + critical + ' crit</span>';
        if (warning > 0) out += '<span class="fwmon-noc-badge warn">' + warning + ' warn</span>';
        if (!out) out += '<span class="fwmon-noc-badge ok">no alerts</span>';
        return out;
    }

    function renderSiteCards(sites) {
        var el = document.getElementById('noc-sites-grid');
        if (!el) return;
        if (!sites.length) {
            el.innerHTML = '<div class="fwmon-noc-empty">No sites or devices yet. Add devices under Infrastructure → Sites.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < sites.length; i++) {
            var s = sites[i];
            var key = siteKey(s);
            var sc = sevClass(s.worst_severity);
            var total = (s.devices_online || 0) + (s.devices_offline || 0);
            var probeWarn = s.probe_offline ? '<span class="fwmon-noc-badge crit">probe down</span>' : '';
            html += '<a class="fwmon-noc-card ' + sc + '" href="/admin/alerts?site_id=' + encodeURIComponent(key) + '&acknowledged=false"' +
                ' title="View open alerts for ' + esc(s.site_name || 'this site') + '">' +
                '<div class="fwmon-noc-card-head">' +
                    '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                    '<span class="fwmon-noc-card-title">' + esc(s.site_name || 'Site') + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-badges">' + sevBadges(s.alerts_critical || 0, s.alerts_warning || 0) + probeWarn + '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span>' + (s.devices_online || 0) + '/' + total + ' up</span>' +
                    '<span class="bps">' + fmtBps(s.bits_per_second) + '</span>' +
                '</div>' +
            '</a>';
        }
        el.innerHTML = html;
    }

    // ── By Device: flat device grid, each card links to that device's alerts ─

    function flattenDevices(sites) {
        var out = [];
        for (var i = 0; i < sites.length; i++) {
            var s = sites[i];
            var devs = s.devices || [];
            for (var j = 0; j < devs.length; j++) {
                // The snapshot is server-scoped to active devices
                // (GetDeviceStatusRows applies ActiveDevices), so retired
                // devices never reach this list: no card, no count.
                out.push({ dev: devs[j], siteName: s.site_name || 'Unassigned' });
            }
        }
        // Worst severity first, then by bps desc.
        out.sort(function (a, b) {
            var ra = SEV_RANK[a.dev.worst_severity] != null ? SEV_RANK[a.dev.worst_severity] : 9;
            var rb = SEV_RANK[b.dev.worst_severity] != null ? SEV_RANK[b.dev.worst_severity] : 9;
            if (ra !== rb) return ra - rb;
            return (b.dev.bits_per_second || 0) - (a.dev.bits_per_second || 0);
        });
        return out;
    }

    function renderDeviceCards(sites) {
        var el = document.getElementById('noc-devices-grid');
        if (!el) return;
        var rows = flattenDevices(sites);
        if (!rows.length) {
            el.innerHTML = '<div class="fwmon-noc-empty">No devices yet.</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var dev = rows[i].dev;
            var sc = sevClass(dev.worst_severity);
            var online = dev.status === 'online' || dev.status === 'up';
            html += '<a class="fwmon-noc-card ' + sc + '" href="/admin/alerts?device_id=' + encodeURIComponent(dev.id) + '&acknowledged=false"' +
                ' title="View open alerts for ' + esc(dev.name || ('DEV-' + dev.id)) + '">' +
                '<div class="fwmon-noc-card-head">' +
                    '<span class="fwmon-noc-dot ' + sc + '"></span>' +
                    '<span class="fwmon-noc-card-title">' + esc(dev.name || ('DEV-' + dev.id)) + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span class="site">' + esc(rows[i].siteName) + '</span>' +
                    '<span>' + (online ? 'online' : esc(dev.status || 'offline')) + '</span>' +
                '</div>' +
                '<div class="fwmon-noc-card-meta">' +
                    '<span class="ip">' + esc(dev.ip || '') + '</span>' +
                    '<span class="bps">' + fmtBps(dev.bits_per_second) + '</span>' +
                '</div>' +
            '</a>';
        }
        el.innerHTML = html;
    }

    // ipRef renders an IP as a threat-intel-enrichable reference (populated by
    // AdminCommon.enrichIps after paint), falling back to plain text.
    function ipRef(addr) {
        if (!addr) return '';
        var AC = window.AdminCommon;
        return (AC && AC.ipRef) ? AC.ipRef(addr) : esc(addr);
    }

    // ── Live feed (v0.11.269) ───────────────────────────────────────────────
    //
    // The stream's named "feed" event carries three capped lists (alerts, live
    // detections, silenced detections); this merges, filters and slices them.
    // The list is diffed in place — never rebuilt — so a new item can slide in
    // and a screen reader is not read the whole list every few seconds.

    var FEED_COUNTS = [10, 20, 50, 100];
    var FEED_KINDS = ['all', 'alerts', 'detections'];
    var NEW_WINDOW_MS = 20 * 60 * 1000;   // "new" and "still firing" horizon
    var ANNOUNCE_EVERY_MS = 15 * 1000;
    var PREF = { count: 'fwmon.noc.feed.count', kind: 'fwmon.noc.feed.kind', silenced: 'fwmon.noc.feed.silenced' };

    var feedState = {
        count: 20, kind: 'all', silenced: false,
        feed: null,            // latest feed frame received
        prevKeys: null,        // keys of the last RENDERED frame (all lists); null = nothing rendered yet
        paused: false, hoverPaused: false, focusPaused: false,
        pendingAnnounce: 0, lastAnnounce: 0, announceTimer: null
    };

    function prefGet(key) {
        try { return window.localStorage.getItem(key); } catch (e) { return null; }
    }
    function prefSet(key, val) {
        try { window.localStorage.setItem(key, String(val)); } catch (e) { /* private mode */ }
    }
    // Stored preferences are read through whitelists: a tampered or stale value
    // falls back to the default instead of slicing to nothing.
    function loadFeedPrefs() {
        var c = parseInt(prefGet(PREF.count), 10);
        feedState.count = FEED_COUNTS.indexOf(c) !== -1 ? c : 20;
        var k = prefGet(PREF.kind);
        feedState.kind = FEED_KINDS.indexOf(k) !== -1 ? k : 'all';
        feedState.silenced = prefGet(PREF.silenced) === '1';
        var el;
        if ((el = document.getElementById('noc-feed-count'))) el.value = String(feedState.count);
        if ((el = document.getElementById('noc-feed-kind'))) el.value = feedState.kind;
        if ((el = document.getElementById('noc-feed-silenced'))) el.checked = feedState.silenced;
    }

    // itemKey identifies a feed item across frames. A detection episode that
    // was already running when the window began ("truncated") is keyed on its
    // dedup key alone, so it keeps its identity as its oldest rows age out; an
    // alert re-fired in place (same id, new timestamp) gets a new key.
    function itemKey(it, list) {
        if (it.kind === 'alert') return 'alert|' + it.id + '|' + it.at;
        return list + '|' + it.dedup_key + '|' + (it.truncated ? 'old' : it.at);
    }

    function allFeedItems(feed) {
        var out = [];
        var add = function (arr, list) {
            (arr || []).forEach(function (it) { out.push({ it: it, list: list, key: itemKey(it, list) }); });
        };
        add(feed.alerts, 'alert');
        add(feed.detections, 'detection');
        add(feed.silenced, 'silenced');
        return out;
    }

    function tms(iso) { var t = new Date(iso).getTime(); return isFinite(t) ? t : 0; }

    // Newest first; ties (a detector cycle stamps all its findings alike) break
    // the same way as on the server, so the order never shuffles.
    function feedOrder(a, b) {
        var d = tms(b.it.at) - tms(a.it.at);
        if (d !== 0) return d;
        if (a.list !== b.list) return a.list < b.list ? -1 : 1;
        if (a.list === 'alert') return b.it.id - a.it.id;
        return a.it.dedup_key < b.it.dedup_key ? -1 : (a.it.dedup_key > b.it.dedup_key ? 1 : 0);
    }

    function visibleFeed(all) {
        var k = feedState.kind;
        return all.filter(function (e) {
            if (e.list === 'silenced' && !feedState.silenced) return false;
            if (k === 'alerts') return e.list === 'alert';
            if (k === 'detections') return e.list !== 'alert';
            return true;
        }).sort(feedOrder).slice(0, feedState.count);
    }

    function feedHref(e) {
        if (e.list === 'alert') return '#alert/' + encodeURIComponent(e.it.id);
        var q = 'hours=6&tab=samples';
        if (e.it.src) q += '&src=' + encodeURIComponent(e.it.src);
        if (e.it.dst) q += '&dst=' + encodeURIComponent(e.it.dst);
        return '/admin/flows?' + q;
    }

    function feedRowHTML(e, genMs) {
        var it = e.it;
        var sev = FEED_SEVS[it.severity] ? it.severity : 'info';
        var route = '';
        if (it.src || it.dst) {
            route = (it.src ? ipRef(it.src) : '—') + (it.dst ? ' → ' + ipRef(it.dst) + (it.dst_port ? ':' + esc(it.dst_port) : '') : '');
        }
        var dev = it.device_name || (it.device_id ? 'DEV-' + it.device_id : '');
        if (dev && it.site_name) dev += ' · ' + it.site_name;
        var firing = e.list !== 'alert' && genMs - tms(it.last_seen) <= NEW_WINDOW_MS;
        var when = it.truncated ? '> 6h' : ago(it.at);
        return '<a class="fwmon-noc-feed-row" href="' + esc(feedHref(e)) + '"' + (e.list === 'alert' ? ' data-noc-alert="' + esc(it.id) + '"' : '') + '>' +
            '<span class="fwmon-det-sev fwmon-det-sev-' + esc(sev) + '">' + esc(sev) + '</span>' +
            '<span class="fwmon-noc-feed-type">' + esc(it.type || '') +
                (it.repeat > 1 ? ' <span class="fwmon-noc-feed-rep" title="times seen"><span aria-hidden="true">×' + esc(it.repeat) + '</span><span class="fwmon-sr-only">seen ' + esc(it.repeat) + ' times</span></span>' : '') +
                (firing ? ' <span class="fwmon-noc-feed-firing" title="still firing"><span aria-hidden="true">●</span><span class="fwmon-sr-only">still firing</span></span>' : '') +
                (e.list === 'silenced' ? ' <span class="fwmon-noc-feed-tag">silenced</span>' : '') +
            '</span>' +
            '<span class="fwmon-noc-feed-dev">' + esc(dev) + '</span>' +
            '<span class="fwmon-noc-feed-route">' + route + '</span>' +
            '<span class="fwmon-noc-feed-msg">' + esc(it.message || '') + '</span>' +
            '<span class="fwmon-noc-feed-when" title="' + esc(it.at || '') + '">' + esc(when) + '</span>' +
        '</a>';
    }
    var FEED_SEVS = { critical: 1, warning: 1, info: 1 };

    function isPaused() { return feedState.paused || feedState.hoverPaused || feedState.focusPaused; }

    function onFeed(feed) {
        if (!feed) return;
        feedState.feed = feed;
        if (isPaused()) { showPausedBadge(); return; }
        renderFeed();
    }

    function showPausedBadge() {
        var badge = document.getElementById('noc-feed-paused');
        if (!badge) return;
        if (!isPaused()) { badge.hidden = true; return; }
        var n = 0;
        if (feedState.feed && feedState.prevKeys) {
            allFeedItems(feedState.feed).forEach(function (e) { if (!feedState.prevKeys[e.key]) n++; });
        }
        // A manual pause says so; hover/focus only holds the list while it is read.
        badge.textContent = (feedState.paused ? 'paused' : 'held while reading') + (n ? ' · ' + n + ' new' : '');
        badge.hidden = false;
    }

    function renderFeed() {
        var list = document.getElementById('noc-feed-list');
        var feed = feedState.feed;
        if (!list || !feed) return;
        var genMs = tms(feed.generated_at) || Date.now();
        var all = allFeedItems(feed);
        var shown = visibleFeed(all);
        var prev = feedState.prevKeys;
        var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        // Existing nodes by key. Departed rows are removed FIRST, so a departure
        // never displaces (and so never moves or re-animates) the rows below it;
        // the loop then moves only rows whose rank genuinely changed.
        var keep = {};
        shown.forEach(function (e) { keep[e.key] = true; });
        var byKey = {};
        Array.prototype.slice.call(list.children).forEach(function (li) {
            var k = li.getAttribute('data-key');
            if (keep[k]) byKey[k] = li;
            else list.removeChild(li);
        });
        var fresh = 0;
        shown.forEach(function (e, i) {
            var html = feedRowHTML(e, genMs);
            var li = byKey[e.key];
            if (!li) {
                li = document.createElement('li');
                li.setAttribute('data-key', e.key);
                // New only if absent from the last rendered frame AND recent: the
                // first frame, a re-keyed old episode and a toggle animate nothing.
                if (prev && !prev[e.key] && genMs - tms(e.it.at) <= NEW_WINDOW_MS) {
                    fresh++;
                    if (!reduce) {
                        li.className = 'fwmon-noc-feed-new';
                        // One slide-in only: a later move must not replay it.
                        li.addEventListener('animationend', function () { li.className = ''; }, { once: true });
                    }
                }
            }
            if (li.getAttribute('data-html') !== html) {
                li.innerHTML = html;
                li.setAttribute('data-html', html);
            }
            if (list.children[i] !== li) list.insertBefore(li, list.children[i] || null);
        });

        var next = {};
        all.forEach(function (e) { next[e.key] = true; });
        feedState.prevKeys = next;

        renderFeedEmpty(shown.length, feed);
        if (fresh) announce(fresh);
        if (window.AdminCommon && window.AdminCommon.enrichIps) window.AdminCommon.enrichIps(list);
        var badge = document.getElementById('noc-feed-paused');
        if (badge) badge.hidden = true;
    }

    function renderFeedEmpty(shown, feed) {
        var el = document.getElementById('noc-feed-empty');
        if (!el) return;
        var hidden = !feedState.silenced && (feed.silenced_total || 0) > 0 && feedState.kind !== 'alerts';
        var msg = '';
        if (!shown) msg = feedState.kind === 'alerts' ? 'No alerts in the last 7 days.' : 'No events to show.';
        if (hidden) {
            el.innerHTML = esc(msg ? msg + ' ' : '') + esc(fmtCount(feed.silenced_total)) +
                ' silenced or dismissed detections hidden — <button type="button" class="fwmon-link-btn" data-noc-show-silenced>Show silenced</button>';
            el.hidden = false;
        } else if (msg) {
            el.textContent = msg;
            el.hidden = false;
        } else {
            el.hidden = true;
        }
    }

    // announce tells a screen reader how many events arrived, at most every
    // ANNOUNCE_EVERY_MS, instead of a live region on the whole list.
    function announce(n) {
        feedState.pendingAnnounce += n;
        var wait = feedState.lastAnnounce + ANNOUNCE_EVERY_MS - Date.now();
        if (feedState.announceTimer) return;
        feedState.announceTimer = setTimeout(function () {
            feedState.announceTimer = null;
            var el = document.getElementById('noc-feed-status');
            if (el && feedState.pendingAnnounce) {
                el.textContent = feedState.pendingAnnounce + ' new event' + (feedState.pendingAnnounce === 1 ? '' : 's');
            }
            feedState.pendingAnnounce = 0;
            feedState.lastAnnounce = Date.now();
        }, Math.max(0, wait));
    }

    function setPaused(on) {
        feedState.paused = on;
        var btn = document.getElementById('noc-feed-pause');
        if (btn) {
            btn.textContent = on ? 'Resume' : 'Pause';
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        }
        afterPauseChange();
    }
    function afterPauseChange() {
        if (isPaused()) showPausedBadge();
        else renderFeed();
    }

    function wireFeed() {
        var list = document.getElementById('noc-feed-list');
        var count = document.getElementById('noc-feed-count');
        var kind = document.getElementById('noc-feed-kind');
        var sil = document.getElementById('noc-feed-silenced');
        var pause = document.getElementById('noc-feed-pause');
        if (count) count.addEventListener('change', function () {
            var c = parseInt(count.value, 10);
            feedState.count = FEED_COUNTS.indexOf(c) !== -1 ? c : 20;
            prefSet(PREF.count, feedState.count);
            renderFeed();
        });
        if (kind) kind.addEventListener('change', function () {
            feedState.kind = FEED_KINDS.indexOf(kind.value) !== -1 ? kind.value : 'all';
            prefSet(PREF.kind, feedState.kind);
            renderFeed();
        });
        if (sil) sil.addEventListener('change', function () {
            feedState.silenced = !!sil.checked;
            prefSet(PREF.silenced, feedState.silenced ? '1' : '0');
            renderFeed();
        });
        if (pause) pause.addEventListener('click', function () { setPaused(!feedState.paused); });
        if (list) {
            // Hover-pause only where hovering exists: on touch a tap fires
            // mouseenter with no mouseleave and would freeze the feed.
            if (window.matchMedia && window.matchMedia('(hover: hover)').matches) {
                list.addEventListener('mouseenter', function () { feedState.hoverPaused = true; afterPauseChange(); });
                list.addEventListener('mouseleave', function () { feedState.hoverPaused = false; afterPauseChange(); });
            }
            list.addEventListener('focusin', function () { feedState.focusPaused = true; afterPauseChange(); });
            list.addEventListener('focusout', function (ev) {
                if (ev.relatedTarget && list.contains(ev.relatedTarget)) return;
                feedState.focusPaused = false;
                afterPauseChange();
            });
            // A repeat click on the same alert: clear the hash first so the
            // hashchange route opens the detail again.
            list.addEventListener('click', function (ev) {
                var a = ev.target.closest && ev.target.closest('a[data-noc-alert]');
                if (a && location.hash === a.getAttribute('href')) {
                    history.replaceState(null, '', location.pathname + location.search);
                }
            });
        }
    }

    // ── Threats — last 60 s ─────────────────────────────────────────────────

    var PROTO = { 1: 'icmp', 6: 'tcp', 17: 'udp' };

    function threatRowHTML(e, outbound) {
        var svc = e.service ? esc(e.service) + '/' + esc(PROTO[e.protocol] || e.protocol) : '—';
        var marks = '';
        if (e.inferred) marks += ' <span class="fwmon-noc-feed-tag" title="direction inferred from a guessed service port">inferred</span>';
        if (!e.ip_match) marks += ' <span class="fwmon-noc-feed-tag" title="only the address’s network (ASN) is on the threat list">ASN</span>';
        if (e.blocked) marks += ' <span class="fwmon-noc-feed-tag">' + esc(fmtCount(e.blocked)) + ' blocked</span>';
        var hosts = (e.internal_hosts || []).map(ipRef).join(', ');
        if (e.internal_count > (e.internal_hosts || []).length) hosts += ' +' + esc(e.internal_count - e.internal_hosts.length);
        var href = '/admin/flows?hours=1&tab=samples&' + (outbound ? 'dst=' : 'src=') + encodeURIComponent(e.addr);
        return '<li><a class="fwmon-noc-threat-row" href="' + esc(href) + '">' +
            '<span class="addr">' + ipRef(e.addr) + marks + '</span>' +
            '<span class="svc">' + svc + '</span>' +
            '<span class="req" title="request records">' + esc(fmtCount(e.requests)) + ' req · ' + esc(fmtBytes(e.bytes)) + '</span>' +
            '<span class="hosts">' + (outbound ? 'from ' : 'to ') + (hosts || '—') + '</span>' +
        '</a></li>';
    }

    function renderThreats(d) {
        var top = d && d.threat_top;
        var sum = document.getElementById('noc-threat-summary');
        var outEl = document.getElementById('noc-threat-out');
        var inEl = document.getElementById('noc-threat-in');
        if (!sum || !outEl || !inEl) return;
        if (!top) { sum.textContent = ''; outEl.innerHTML = inEl.innerHTML = ''; return; }
        var s = top.summary || {};
        sum.innerHTML =
            '<span class="out"><b>' + esc(fmtCount(s.outbound)) + '</b> outbound req</span>' +
            '<span class="in"><b>' + esc(fmtCount(s.inbound)) + '</b> inbound req</span>' +
            '<span><b>' + esc(fmtCount(s.unclassified)) + '</b> unclassified</span>' +
            '<span><b>' + esc(fmtCount(s.other)) + '</b> other</span>' +
            '<span><b>' + esc(fmtCount(s.blocked)) + '</b> blocked</span>';
        var empty = '<li class="fwmon-noc-threat-empty">No threat-intel matches in the last minute.</li>';
        outEl.innerHTML = (top.outbound || []).length ? top.outbound.map(function (e) { return threatRowHTML(e, true); }).join('') : empty;
        inEl.innerHTML = (top.inbound || []).length ? top.inbound.map(function (e) { return threatRowHTML(e, false); }).join('') : empty;
        if (window.AdminCommon && window.AdminCommon.enrichIps) {
            window.AdminCommon.enrichIps(outEl);
            window.AdminCommon.enrichIps(inEl);
        }
    }

    // ── mode toggle / interaction ───────────────────────────────────────────

    function setMode(m) {
        if (m !== 'site' && m !== 'device') return;
        mode = m;
        var btns = document.querySelectorAll('.fwmon-noc-mode');
        for (var i = 0; i < btns.length; i++) {
            var on = btns[i].getAttribute('data-noc-mode') === m;
            btns[i].classList.toggle('active', on);
            btns[i].setAttribute('aria-selected', on ? 'true' : 'false');
        }
        if (latest) renderBreakdown(latest);
    }

    function onClick(ev) {
        var t = ev.target;
        // Mode toggle (By Site / By Device). Cards are plain <a> links and fall
        // through to the SPA click-interceptor, so no card handling is needed here.
        var modeBtn = t.closest && t.closest('.fwmon-noc-mode');
        if (modeBtn) { setMode(modeBtn.getAttribute('data-noc-mode')); return; }
        if (t.closest && t.closest('[data-noc-show-silenced]')) {
            var sil = document.getElementById('noc-feed-silenced');
            if (sil) { sil.checked = true; sil.dispatchEvent(new Event('change')); }
        }
    }

    function setStatus(txt, cls) {
        var el = document.getElementById('noc-conn-status');
        if (!el) return;
        el.textContent = txt;
        el.className = 'fwmon-noc-status' + (cls ? ' ' + cls : '');
    }

    function wire() {
        if (wired) return;
        var page = document.getElementById('page-noc');
        if (page) page.addEventListener('click', onClick);
        wireFeed();
        wired = true;
    }

    function init() {
        stop(); // never stack streams on re-entry
        wire();
        loadFeedPrefs();
        // A fresh visit animates nothing on its first frame, and no hover/focus
        // hold survives leaving the page.
        feedState.prevKeys = null;
        feedState.feed = null;
        feedState.hoverPaused = false;
        feedState.focusPaused = false;

        if (typeof EventSource === 'undefined') {
            setStatus('live updates unsupported', 'bad');
            if (window.AdminCommon && window.AdminCommon.apiFetch) {
                window.AdminCommon.apiFetch('/admin/api/noc/snapshot')
                    .then(function (res) { render(res && res.data); })
                    .catch(function () {});
            }
            return;
        }
        setStatus('connecting…');
        es = new EventSource(STREAM_URL);
        es.onopen = function () { setStatus('● live', 'ok'); };
        es.onmessage = function (ev) {
            setStatus('● live', 'ok');
            try { render(JSON.parse(ev.data)); }
            catch (e) { if (window.fwmonLog) window.fwmonLog.error('FwmonNOC: bad frame', e); }
        };
        es.addEventListener('feed', function (ev) {
            try { onFeed(JSON.parse(ev.data)); }
            catch (e) { if (window.fwmonLog) window.fwmonLog.error('FwmonNOC: bad feed frame', e); }
        });
        es.onerror = function () { setStatus('reconnecting…', 'warn'); };
    }

    function stop() {
        if (es) { es.close(); es = null; }
    }

    window.FwmonNOC = { init: init, stop: stop };
})();
