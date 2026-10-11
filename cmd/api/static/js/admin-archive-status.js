// admin-archive-status.js — the Raw Archive status card on Settings →
// Retention (admins). admin-main.js fetches GET /archive/status (admin-only)
// and hands the result to render(); watch() keeps it current while the card
// is on screen: a refetch every 15 s (paused while the browser tab is hidden
// — AdminCommon.pollWhenVisible), and a 1 s tick that only rewrites the
// countdown and "x ago" texts. The card is a list of sections and a refetch
// rewrites only those whose HTML changed: an unchanged banner or button keeps
// its DOM and keyboard focus, and <details> keep their open state.
//
// What it shows, top to bottom (v0.11.317):
//   1. the health banner — the server's verdict (data.health, computed once
//      in internal/archive/status/health.go for this page, the CLI and the
//      alerts): colour, icon AND words, the one-line summary, the last
//      successful backup, how far behind, the target;
//   2. "Action needed": the errors and warnings, most severe first, each
//      with what it means, what is at risk, what to do and a button to the
//      setting or control that does it; then the notes (information);
//   3. the per-stream table: state, verified through, backlog, stored,
//      compression (a phone shows each stream as a card);
//   4. the details: current activity, recently verified chunks, retries and
//      parked chunks (Reset), months with their seal badges, the last
//      failure of each stage.
// It also tells the Raw Archive Settings card the verdict (the
// fwmon:archive-health event) for its badge.
//
// CSP: no inline handlers. The buttons carry data-action (admin-main.js
// dispatches archive-refresh / archive-reset-chunk / archive-reengage /
// archive-jump / archive-open-settings / archive-test-connection). Every
// server string goes through escapeHtml. Styles are classes in
// admin-settings.css on the theme tokens (light and dark).
(function () {
    'use strict';

    var AC = window.AdminCommon;
    var esc = AC.escapeHtml;
    var REFRESH_MS = 15000;

    var poller = null;        // AdminCommon.pollWhenVisible handle
    var ticker = null;        // the 1 s countdown timer
    var lastVerdict = null;   // the last data.health rendered (lastHealth)

    // ---- formatting -----------------------------------------------------

    // dur: a duration in seconds, coarse ("45 s", "12 min", "3.4 h", "2.1 days").
    function dur(sec) {
        if (sec == null || !isFinite(sec)) return '&mdash;';
        sec = Math.max(0, sec);
        if (sec < 60) return Math.round(sec) + ' s';
        if (sec < 3600) return Math.round(sec / 60) + ' min';
        if (sec < 48 * 3600) return (sec / 3600).toFixed(1) + ' h';
        return (sec / 86400).toFixed(1) + ' days';
    }

    // clock: a countdown, "m:ss" (or "h:mm:ss").
    function clock(sec) {
        sec = Math.max(0, Math.round(sec));
        var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
        var mm = (h ? (m < 10 ? '0' : '') : '') + m;
        return (h ? h + ':' : '') + mm + ':' + (s < 10 ? '0' : '') + s;
    }

    function when(t) { return t ? esc(AC.formatDate(t)) : '<span class="arch-faint">never</span>'; }

    function label(v) { return String(v || '').split('_').join(' '); }

    function badge(cls, text) { return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }

    // utc: an instant as "2026-10-04 07:00 UTC" (the archive's periods are UTC).
    function utc(t) { return t ? esc(String(t).slice(0, 16).replace('T', ' ')) + ' UTC' : '&mdash;'; }

    // period: a chunk's UTC day ("2026-10-04") or hour ("2026-10-04 07:00").
    function period(start, end) {
        if (!start) return '';
        var s = String(start), daily = end && (new Date(end) - new Date(start)) >= 86400000;
        return esc(daily ? s.slice(0, 10) : s.slice(0, 10) + ' ' + s.slice(11, 16)) + (daily ? '' : ' UTC');
    }

    // live: a span the 1 s tick fills in — a countdown to until, or the age
    // of since. Written empty, so the page's HTML does not change from one
    // second to the next (render compares it to skip unchanged refreshes).
    function liveUntil(until) { return '<span data-arch-until="' + esc(until) + '"></span>'; }

    function liveSince(since) { return '<span data-arch-since="' + esc(since) + '"></span>'; }

    // bar: a progress bar, fraction 0..1, with an accessible label.
    function bar(fraction, text) {
        var pct = Math.max(0, Math.min(100, (fraction || 0) * 100));
        return '<div class="arch-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + Math.round(pct) + '" aria-label="' + esc(text) + '">' +
            '<div class="arch-bar-fill" style="width:' + pct.toFixed(1) + '%;"></div></div>';
    }

    function section(title, body, id) {
        return '<h3 class="arch-h3"' + (id ? ' id="' + id + '"' : '') + '>' + esc(title) + '</h3>' + body;
    }

    function streamName(s) {
        return { syslog: 'Syslog', sflow: 'sFlow', netflow: 'NetFlow', 'sflow-counters': 'sFlow counters' }[s] || s;
    }

    // VERDICT: tone, icon, heading per health verdict. The heading carries
    // the state in words, so colour is never the only signal.
    var VERDICT = {
        healthy: ['ok', 'check-circle', 'Healthy'],
        warning: ['warn', 'alert-triangle', 'Warning — check below'],
        error: ['crit', 'x-octagon', 'Error — action needed'],
        disabled: ['neutral', 'pause-circle', 'Archiving is off'],
        not_configured: ['neutral', 'minus-circle', 'Not configured']
    };

    var NOTE = ['neutral', 'info-circle', 'Note'];
    var SEVERITY = {
        error: ['crit', 'x-octagon', 'Error'],
        warning: ['warn', 'alert-triangle', 'Warning'],
        info: NOTE
    };

    // STREAM_STATE: tone of each per-stream state (its text is the server's).
    var STREAM_STATE = { ok: 'ok', catching_up: 'info', warning: 'warn', error: 'crit', stalled: 'crit', idle: 'neutral', pending: 'info', off: 'neutral' };

    var STAGE = { start: 'Starting', export: 'Exporting', upload: 'Uploading', verify: 'Reading back', count: 'Recounting', manifest: 'Writing chunk.json' };

    function pill(tone, text) {
        return '<span class="arch-pill is-' + tone + '"><span class="arch-pill-dot" aria-hidden="true"></span>' + esc(text) + '</span>';
    }

    // ---- 1. banner ------------------------------------------------------

    function target(st) {
        var c = st.config || {};
        if (c.target === 'local') return 'Directory <code>' + esc(c.local_dir || '') + '</code>' + (c.prefix ? ' / <code>' + esc(c.prefix) + '</code>' : '');
        if (!c.bucket) return '<span class="arch-faint">none</span>';
        return 'Bucket <code>' + esc(c.bucket) + '</code>' + (c.prefix ? ' / <code>' + esc(c.prefix) + '</code>' : '') +
            '<div class="arch-faint">' + (c.object_lock_days ? 'Object Lock ' + esc(c.object_lock_mode || '') + ' ' + c.object_lock_days + ' days' : 'no Object Lock') + '</div>';
    }

    function behind(h) {
        if (h.verdict === 'disabled' || h.verdict === 'not_configured') return '&mdash;';
        if (h.backlog_chunks > 0) {
            return '<strong>' + AC.formatNum(h.backlog_chunks) + ' chunk' + (h.backlog_chunks === 1 ? '' : 's') + ' to catch up</strong>' +
                (h.eta_seconds != null ? '<div class="arch-faint">about ' + dur(h.eta_seconds) + ' of work</div>' : '');
        }
        if (!h.verified_through) return '<span class="arch-faint">nothing verified yet</span>';
        return 'Up to date<div class="arch-faint">through ' + utc(h.verified_through) + '</div>';
    }

    function banner(st) {
        var h = st.health || {};
        var v = VERDICT[h.verdict] || ['neutral', 'info-circle', 'Unknown'];
        var counts = [];
        if (h.errors) counts.push(h.errors + ' error' + (h.errors === 1 ? '' : 's'));
        if (h.warnings) counts.push(h.warnings + ' warning' + (h.warnings === 1 ? '' : 's'));
        var facts = [
            ['Last successful backup', h.last_success_at ? when(h.last_success_at) + '<div class="arch-faint">' + liveSince(h.last_success_at) + ' ago</div>' : '<span class="arch-faint">none yet</span>'],
            ['Behind', behind(h)],
            ['Target', target(st)]
        ];
        return '<div class="arch-banner is-' + v[0] + '" role="status">' +
            '<div class="arch-banner-icon">' + AC.icon(v[1]) + '</div>' +
            '<div class="arch-banner-main"><div class="arch-banner-title">' + esc(v[2]) +
            (counts.length ? ' <span class="arch-banner-counts">' + esc(counts.join(', ')) + '</span>' : '') + '</div>' +
            '<p class="arch-banner-summary">' + esc(h.summary || '') + '</p>' +
            '<dl class="arch-facts">' + facts.map(function (f) { return '<div><dt>' + esc(f[0]) + '</dt><dd>' + f[1] + '</dd></div>'; }).join('') + '</dl></div></div>';
    }

    // controls: the "updated" line (Refresh is in the card's header). Its
    // own section, which never changes.
    function controls() {
        return '<p class="arch-controls">Updated <span data-arch-updated></span> ago &middot; refreshed every 15 s while this page is open</p>';
    }

    // ---- 2. action needed -----------------------------------------------

    var JUMP = { needs_attention: 'arch-sec-problems', retrying: 'arch-sec-problems', months: 'arch-sec-months' };

    function fixButton(f) {
        if (!f) return '';
        var lab = esc(f.label || 'Open');
        switch (f.kind) {
        case 'test': return '<button type="button" class="btn sm" data-action="archive-test-connection">' + lab + '</button>';
        case 'settings': return '<button type="button" class="btn sm secondary" data-action="archive-open-settings" data-key="' + esc(f.target || '') + '">' + lab + '</button>';
        case 'reengage': return '<button type="button" class="btn sm" data-action="archive-reengage" data-min-role="admin" data-stream="' + esc(f.target || '') + '">' + lab + '</button>';
        }
        if (JUMP[f.kind]) return '<button type="button" class="btn sm secondary" data-action="archive-jump" data-target="' + JUMP[f.kind] + '">' + lab + '</button>';
        return '';
    }

    function issueHtml(is) {
        var s = SEVERITY[is.severity] || NOTE;
        var about = is.stream ? streamName(is.stream) : (is.table || '');
        var html = '<li class="arch-issue is-' + s[0] + '">' +
            '<div class="arch-issue-head"><span class="arch-sev is-' + s[0] + '">' + AC.icon(s[1]) + esc(s[2]) + '</span>' +
            '<strong class="arch-issue-title">' + esc(is.title) + '</strong>' +
            (about ? '<span class="arch-faint arch-mono">' + esc(about) + '</span>' : '') +
            (is.since ? '<span class="arch-faint" title="' + esc(AC.formatDate(is.since)) + '">for ' + liveSince(is.since) + '</span>' : '') + '</div>' +
            '<p class="arch-issue-text">' + esc(is.meaning || '') + '</p>';
        if (is.risk) html += '<p class="arch-issue-text"><span class="arch-issue-label">At risk:</span> ' + esc(is.risk) + '</p>';
        if (is.action) html += '<p class="arch-issue-text"><span class="arch-issue-label">What to do:</span> ' + esc(is.action) + '</p>';
        var fix = fixButton(is.fix);
        if (is.detail || fix) {
            html += '<div class="arch-issue-foot">' + fix +
                (is.detail ? '<details class="arch-issue-detail" data-arch-details="issue-' + esc(is.code + '-' + (is.table || '') + (is.stream || '')) + '"><summary>Details</summary><code>' + esc(is.detail) + '</code></details>' : '') +
                '</div>';
        }
        return html + '</li>';
    }

    function actions(st) {
        var issues = (st.health && st.health.issues) || [];
        var act = issues.filter(function (i) { return i.severity !== 'info'; });
        var notes = issues.filter(function (i) { return i.severity === 'info'; });
        var html = '';
        if (act.length) {
            html += section('Action needed', '<ul class="arch-issues">' + act.map(issueHtml).join('') + '</ul>');
        } else if (st.health && st.health.verdict === 'healthy') {
            html += '<p class="arch-allclear">' + AC.icon('check-circle') + ' Nothing needs your attention.</p>';
        }
        if (notes.length) {
            html += '<details class="arch-notes" data-arch-details="notes"><summary>Notes (' + notes.length + ')</summary>' +
                '<ul class="arch-issues">' + notes.map(issueHtml).join('') + '</ul></details>';
        }
        return html;
    }

    // ---- 3. per-stream table --------------------------------------------

    function streamsTable(st) {
        var rows = ((st.health && st.health.streams) || []).filter(function (s) { return s.enabled || s.archived_rows > 0; });
        if (!rows.length) return '';
        var tables = {};
        (st.tables || []).forEach(function (t) { tables[t.table] = t; });
        var body = rows.map(function (s) {
            var b = (tables[s.table] || {}).backlog;
            var backlog = '<span class="arch-faint">&mdash;</span>';
            if (b && s.state !== 'idle' && s.state !== 'off') {
                if (b.state === 'catching_up' && b.remaining > 1) {
                    backlog = '<strong>' + AC.formatNum(b.remaining) + ' chunks</strong>' +
                        bar(b.chunks ? b.verified / b.chunks : 1, b.verified + ' of ' + b.chunks + ' chunks verified') +
                        '<div class="arch-faint">' + (b.rate_rows_per_sec != null ? AC.formatNum(Math.round(b.rate_rows_per_sec)) + ' rows/s' : 'rate not measured yet') +
                        (b.eta_seconds != null ? ' &middot; ~' + dur(b.eta_seconds) : '') + '</div>';
                } else {
                    backlog = b.remaining ? 'current period only' : 'none';
                }
            }
            var ratio = s.compression_ratio != null ? s.compression_ratio.toFixed(1) + '&times;' : '<span class="arch-faint">&mdash;</span>';
            var verified = s.verified_through
                ? utc(s.verified_through) + (s.last_verified_at ? '<div class="arch-faint">checked ' + liveSince(s.last_verified_at) + ' ago</div>' : '')
                : '<span class="arch-faint">not yet</span>';
            return '<tr>' +
                '<th scope="row" data-label="Stream">' + esc(streamName(s.stream)) + '<div class="arch-faint arch-mono">' + esc(s.table) + '</div></th>' +
                '<td data-label="State">' + pill(STREAM_STATE[s.state] || 'neutral', s.label || label(s.state)) + '</td>' +
                '<td data-label="Verified through">' + verified + '</td>' +
                '<td data-label="Backlog">' + backlog + '</td>' +
                '<td data-label="Stored">' + AC.formatNum(s.archived_rows) + ' rows<div class="arch-faint">' + AC.formatBytes(s.archived_bytes) + '</div></td>' +
                '<td data-label="Compression">' + ratio + '</td></tr>';
        }).join('');
        return section('Streams', '<div class="arch-table-wrap"><table class="data-table arch-table"><thead><tr><th scope="col">Stream</th><th scope="col">State</th>' +
            '<th scope="col">Verified through</th><th scope="col">Backlog</th><th scope="col">Stored</th><th scope="col">Compression</th></tr></thead><tbody>' +
            body + '</tbody></table></div>');
    }

    // ---- 4. details -----------------------------------------------------

    function now(st) {
        var w = st.worker;
        var html = '<div class="arch-panel">';
        var a = w && w.activity;
        if (a) {
            var what = STAGE[a.stage] || 'Working on';
            var detail = '';
            if (a.stage === 'export') {
                detail = AC.formatNum(a.rows_done) + ' rows read' + (a.id_span ? ' of up to ' + AC.formatNum(a.id_span) : '');
            } else if (a.objects_total) {
                detail = a.objects_done + ' of ' + a.objects_total + ' objects, ' + AC.formatBytes(a.bytes_done) + ' of ' + AC.formatBytes(a.bytes_total);
            }
            var pct = a.fraction != null ? Math.round(a.fraction * 100) + '%' : '';
            html += '<div class="arch-panel-title">' + esc(what) + ' ' + esc(a.table) + ' chunk ' + a.seq + ' &middot; ' + period(a.period_start, a.period_end) +
                (pct ? ' <span class="arch-faint">' + pct + '</span>' : '') + '</div>';
            if (a.fraction != null) html += bar(a.fraction, what + ' ' + pct);
            html += '<div class="arch-faint">' + (detail ? esc(detail) + ' &middot; ' : '') + 'this stage ' + liveSince(a.stage_started_at || a.started_at) +
                ', chunk started ' + when(a.started_at) + ' (' + liveSince(a.started_at) + ' ago)</div>';
        } else {
            var waits = (st.tables || []).filter(function (t) { return t.unsettled; });
            var settling = waits.filter(function (t) { return t.unsettled.reason === 'settling' && t.unsettled.until; });
            if (settling.length) {
                html += settling.map(function (t) {
                    return '<div><strong>' + esc(t.table) + '</strong>: ' + esc(t.unsettled.detail || 'the cut is settling') + ' &mdash; exported once it has, ' + liveUntil(t.unsettled.until) + '</div>';
                }).join('');
            } else if (w && w.pass_running) {
                html += '<div class="arch-panel-title">Planning the next chunk</div>';
            } else if (w && !w.stale && w.runner !== 'not running') {
                html += '<div class="arch-panel-title">Idle &mdash; waiting for the next period to close</div>';
            } else {
                html += '<div class="arch-faint">No current activity is known.</div>';
            }
            waits.filter(function (t) { return t.unsettled.reason !== 'settling'; }).forEach(function (t) {
                html += '<div class="arch-warn-text" title="' + esc(t.unsettled.detail || '') + '">' + esc(t.table) + ' waits: ' +
                    esc(label(t.unsettled.reason)) + ' for ' + dur(t.unsettled.for_seconds) + '</div>';
            });
        }
        if (w && (a || w.pass_running) && w.last_pass_at) {
            html += '<div class="arch-faint arch-gap">Pass running since ' + when(w.last_pass_at) + '</div>';
        } else if (w && w.next_pass_at) {
            html += '<div class="arch-faint arch-gap">Last pass ' + when(w.last_pass_at) + '; next ' + liveUntil(w.next_pass_at) + '</div>';
        }
        if (w) {
            var stg = w.staging || {};
            var free = stg.error ? 'free space unknown' : stg.free_bytes != null ? AC.formatBytes(stg.free_bytes) + ' free' : '';
            html += '<div class="arch-faint arch-gap">Worker <span class="arch-mono">' + esc(w.runner || '') + '</span>, reported ' + liveSince(w.seen_at) + ' ago' +
                ' &middot; staging <code>' + esc(stg.dir || '') + '</code>' + (free ? ' ' + free : '') + '</div>';
        } else if (st.worker_error) {
            html += '<div class="arch-warn-text arch-gap">The worker&rsquo;s state could not be read: ' + esc(st.worker_error) + '</div>';
        }
        return section('Current activity', html + '</div>');
    }

    function chunkTable(rows, cols) {
        return '<div class="arch-table-wrap"><table class="data-table arch-table"><thead><tr>' + cols.map(function (c) { return '<th scope="col">' + esc(c[0]) + '</th>'; }).join('') +
            '</tr></thead><tbody>' + rows.map(function (r) {
                return '<tr>' + cols.map(function (c) { return '<td data-label="' + esc(c[0]) + '">' + c[1](r) + '</td>'; }).join('') + '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function recent(st) {
        var rs = st.recent || [];
        if (!rs.length) return section('Recent activity', '<p class="arch-empty">No chunk verified yet.</p>');
        return section('Recent activity', chunkTable(rs, [
            ['Verified', function (r) { return when(r.verified_at); }],
            ['Chunk', function (r) { return esc(r.table) + ' ' + r.seq + '<div class="arch-faint">' + period(r.period_start, r.period_end) + '</div>'; }],
            ['Rows', function (r) { return AC.formatNum(r.rows); }],
            ['Objects', function (r) { return AC.formatNum(r.objects) + ' &middot; ' + AC.formatBytes(r.object_bytes); }],
            ['Took', function (r) { return dur(r.duration_seconds) + (r.duration_seconds && r.rows ? '<div class="arch-faint">' + AC.formatNum(Math.round(r.rows / Math.max(1, r.duration_seconds))) + ' rows/s</div>' : ''); }]
        ]));
    }

    function problems(st) {
        var html = '';
        var rt = st.retrying || [];
        if (rt.length) {
            html += section('Waiting for a retry', chunkTable(rt, [
                ['Chunk', function (r) { return esc(r.table) + ' ' + r.seq + '<div class="arch-faint">' + period(r.period_start, r.period_end) + '</div>'; }],
                ['Attempts', function (r) { return r.attempts; }],
                ['Retry', function (r) { return r.retry_at ? liveUntil(r.retry_at) + '<div class="arch-faint">then on the next pass</div>' : '&mdash;'; }],
                ['Error', function (r) { return '<span class="arch-break">' + esc(r.error || '') + '</span>'; }]
            ]), 'arch-sec-problems');
        }
        var na = st.needs_attention || [];
        html += section('Needs attention', !na.length ? '<p class="arch-empty">No chunk is parked.</p>' :
            chunkTable(na, [
                ['Chunk', function (p) { return p.id + ' &middot; ' + esc(p.table) + ' seq ' + p.seq + (p.holds_gate ? ' ' + badge('offline', 'holds deletes') : ''); }],
                ['Period', function (p) { return when(p.period_start); }],
                ['Mismatches', function (p) { return p.mismatches; }],
                ['Error', function (p) { return '<span class="arch-break">' + esc(p.error || '') + '</span>'; }],
                ['Action', function (p) { return '<button type="button" class="btn sm secondary" data-action="archive-reset-chunk" data-min-role="admin" data-id="' + p.id + '">Reset</button>'; }]
            ]), rt.length ? '' : 'arch-sec-problems');
        return html;
    }

    function monthBadge(m) {
        var cls = m.status === 'sealed' ? 'online' : m.status === 'seal_failed' ? 'offline' : m.due ? 'warning' : 'info';
        var out = badge(cls, m.status === 'open' ? (m.due ? 'due, not sealed' : 'open') : label(m.status));
        if (m.partial) out += ' ' + badge('warning', 'partial');
        if (m.degraded && m.degraded.length) out += ' ' + badge('warning', m.degraded.length + ' gate event' + (m.degraded.length === 1 ? '' : 's'));
        return out;
    }

    function months(st) {
        var html = '';
        (st.streams || []).forEach(function (s) {
            if (!s.enabled && !(s.months || []).length) return;
            var cells = (s.months || []).map(function (m) {
                var tip = [m.partial_note, m.error].filter(Boolean).join(' — ');
                return '<li class="arch-month"><div class="arch-month-head"><strong>' + esc(m.month) + '</strong> ' + monthBadge(m) + '</div>' +
                    '<div class="arch-faint">' + AC.formatNum(m.archived_rows) + ' rows &middot; ' + AC.formatBytes(m.archived_object_bytes) + '</div>' +
                    (tip ? '<div class="arch-faint arch-break">' + esc(tip) + '</div>' : '') + '</li>';
            }).join('');
            var seal = '';
            if (s.next_seal) {
                seal = 'Next seal ' + esc(s.next_seal.month) + (s.next_seal.due ? ' &mdash; due since ' + when(s.next_seal.due_at) + ', sealed once its chunks are verified'
                    : ' at ' + when(s.next_seal.due_at));
            }
            html += '<div class="arch-stream-months"><div><strong>' + esc(streamName(s.stream)) + '</strong> <span class="arch-faint">' +
                AC.formatNum(s.archived_rows) + ' rows, ' + AC.formatBytes(s.archived_object_bytes) + ' stored</span>' +
                (s.oldest_unsealed ? ' <span class="arch-warn-text">' + esc(s.oldest_unsealed) + ' is ' + Number(s.unsealed_days).toFixed(1) + ' days past its seal time</span>' : '') + '</div>' +
                (seal ? '<div class="arch-faint">' + seal + '</div>' : '') +
                (cells ? '<ul class="arch-months">' + cells + '</ul>' : '<p class="arch-empty">No month yet.</p>') + '</div>';
        });
        return section('Months', html || '<p class="arch-empty">Nothing archived yet.</p>', 'arch-sec-months');
    }

    function failures(st) {
        var stages = (st.worker && st.worker.stages) || [];
        if (!stages.length) return '';
        return '<details class="arch-notes" data-arch-details="failures"><summary>Last failure of each stage (' + stages.length + ')</summary>' +
            '<ul class="arch-stage-list">' + stages.map(function (e) {
                return '<li><strong>' + esc(e.stage) + '</strong> ' + when(e.at) + ' (' + e.count + '&times;' + (e.since ? ', first ' + when(e.since) : '') + ')' +
                    '<div class="arch-break arch-faint">' + esc(e.error || '') + '</div></li>';
            }).join('') + '</ul></details>';
    }

    // sections: the card as [key, html] pairs, top to bottom. render
    // rewrites only the sections whose HTML changed, so the banners and
    // buttons of an unchanged section keep their DOM (and keyboard focus).
    function sections(st) {
        var out = [['banner', banner(st)], ['controls', controls()]];
        var used = (st.tables || []).some(function (t) { return t.has_chunks; });
        if (!st.enabled && !used) {
            return out.concat([['off', '<p class="arch-empty">Set the archive up in <button type="button" class="btn sm secondary" data-action="archive-open-settings">Raw Archive Settings</button> ' +
                '(or the <code>ARCHIVE_*</code> environment keys; see docs/OPERATIONS.md).</p>']]);
        }
        return out.concat([
            ['actions', actions(st)], ['streams', streamsTable(st)], ['now', now(st)],
            ['recent', recent(st)], ['problems', problems(st)], ['months', months(st)], ['failures', failures(st)]
        ]);
    }

    function page(st) { return sections(st).map(function (s) { return s[1]; }).join(''); }

    // ---- life cycle -----------------------------------------------------

    // tick rewrites the live texts (countdowns, ages) in host.
    function tick(host) {
        host.querySelectorAll('[data-arch-until]').forEach(function (el) {
            var left = (new Date(el.getAttribute('data-arch-until')) - Date.now()) / 1000;
            var text = left > 0 ? clock(left) + ' left' : 'due now';
            if (el.textContent !== text) el.textContent = text;
        });
        host.querySelectorAll('[data-arch-since]').forEach(function (el) {
            var text = dur((Date.now() - new Date(el.getAttribute('data-arch-since'))) / 1000).replace('&mdash;', '—');
            if (el.textContent !== text) el.textContent = text;
        });
    }

    // render writes st into host, unless the page is unchanged; <details>
    // keep their open state. It also tells the settings card the verdict
    // (fwmon:archive-health).
    function render(host, st) {
        st = st || {};
        var secs = sections(st);
        var keys = secs.map(function (s) { return s[0]; }).join(',');
        var els = host.querySelectorAll(':scope > [data-arch-sec]');
        // What was last written is kept on the host itself (a card rebuilt
        // by the settings page starts afresh).
        var last = host.fwmonArchiveLast;
        if (!last || last.keys !== keys || els.length !== secs.length) {
            // A different layout (archiving switched on or off): rebuild.
            host.innerHTML = secs.map(function (s) { return '<div data-arch-sec="' + s[0] + '"></div>'; }).join('');
            els = host.querySelectorAll(':scope > [data-arch-sec]');
            last = host.fwmonArchiveLast = { keys: keys, html: {} };
        }
        var lastHtml = last.html;
        secs.forEach(function (s, i) {
            if (lastHtml[s[0]] !== s[1]) {
                write(els[i], s[1]);
                lastHtml[s[0]] = s[1];
            }
        });
        var up = host.querySelector('[data-arch-updated]');
        if (up) up.setAttribute('data-arch-since', new Date().toISOString());
        tick(host);
        if (st.health) {
            lastVerdict = st.health;
            document.dispatchEvent(new CustomEvent('fwmon:archive-health', { detail: st.health }));
        }
    }

    // write replaces one section's content; its <details> keep their
    // open/closed state.
    function write(el, html) {
        var open = {};
        el.querySelectorAll('details[data-arch-details]').forEach(function (d) { open[d.getAttribute('data-arch-details')] = d.open; });
        el.innerHTML = html;
        el.querySelectorAll('details[data-arch-details]').forEach(function (d) {
            var k = d.getAttribute('data-arch-details');
            if (k in open) d.open = open[k];
        });
    }

    function visible(host) { return host.isConnected && host.offsetParent !== null; }

    // watch keeps host current: load() (which fetches and calls render) every
    // 15 s while the page shows the card and the browser tab is visible, and
    // the live texts every second. Idempotent.
    function watch(host, load) {
        if (!poller) {
            poller = AC.pollWhenVisible(function () {
                var h = document.getElementById(host.id);
                if (h && visible(h)) load();
            }, REFRESH_MS, { immediate: false });
        }
        if (!ticker) {
            ticker = setInterval(function () {
                var h = document.getElementById(host.id);
                if (!document.hidden && h && visible(h)) tick(h);
            }, 1000);
        }
    }

    // verdictBadge: the verdict as a small pill (icon + words) for the
    // settings card.
    function verdictBadge(h) {
        var v = VERDICT[(h || {}).verdict] || ['neutral', 'info-circle', 'Unknown'];
        return '<span class="arch-pill is-' + v[0] + '">' + AC.icon(v[1]) + esc(v[2]) + '</span>';
    }

    window.FwmonArchiveStatus = { render: render, watch: watch, html: page, verdictBadge: verdictBadge,
        lastHealth: function () { return lastVerdict; } };
})();
