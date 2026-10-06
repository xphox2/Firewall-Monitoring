// admin-archive-status.js — the Raw Archive status card on Settings →
// Retention (admins). admin-main.js fetches GET /archive/status (admin-only)
// and hands the result to render(); watch() keeps it current while the card
// is on screen: a refetch every 15 s (paused while the browser tab is hidden
// — AdminCommon.pollWhenVisible), and a 1 s tick that only rewrites the
// countdown and "x ago" texts. A refetch whose page is unchanged touches
// nothing, and the open/closed state of the card's <details> survives a
// change, so the card does not flicker.
//
// What it shows, top to bottom: anything that needs the operator (a released
// gate, a gate that cannot read its switches, parked or retrying chunks, a
// stale worker, a failed preflight, a full staging directory); what the
// worker is doing now (the chunk, its stage and progress, or the settle
// countdown, and the next pass); per table the planned work verified, what
// is left, the rate and the time left; the recently verified chunks; the
// chunks waiting for a retry and those parked; per stream the archived
// totals and month folders with the next seal; the last failure of each
// stage.
//
// CSP: no inline handlers. The buttons carry data-action (admin-main.js
// dispatches archive-refresh / archive-reset-chunk / archive-reengage).
// Every server string goes through escapeHtml. Styles use the theme tokens
// (light and dark) and the existing badge / data-table / btn classes.
(function () {
    'use strict';

    var AC = window.AdminCommon;
    var esc = AC.escapeHtml;
    var faint = 'color:var(--fwmon-text-faint);';
    var small = 'font-size:0.82rem;';
    var REFRESH_MS = 15000;

    var lastHtml = null;      // the last page written into the host
    var poller = null;        // AdminCommon.pollWhenVisible handle
    var ticker = null;        // the 1 s countdown timer

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

    function when(t) { return t ? esc(AC.formatDate(t)) : '<span style="' + faint + '">never</span>'; }

    function label(v) { return String(v || '').split('_').join(' '); }

    function badge(cls, text) { return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }

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
    function bar(fraction, text, color) {
        var pct = Math.max(0, Math.min(100, (fraction || 0) * 100));
        return '<div role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + Math.round(pct) + '" aria-label="' + esc(text) + '"' +
            ' style="height:8px;border-radius:4px;background:var(--fwmon-border);overflow:hidden;margin:6px 0;">' +
            '<div style="height:100%;width:' + pct.toFixed(1) + '%;background:' + (color || 'var(--fwmon-accent)') + ';"></div></div>';
    }

    function notice(level, html) {
        var c = level === 'crit' ? 'var(--fwmon-sig-crit)' : 'var(--fwmon-sig-warn)';
        return '<div role="alert" style="border:1px solid ' + c + ';border-left-width:4px;border-radius:6px;padding:8px 12px;margin-bottom:8px;' + small + '">' + html + '</div>';
    }

    function section(title, body) {
        return '<h3 style="font-size:0.95rem;margin:18px 0 6px;">' + esc(title) + '</h3>' + body;
    }

    var STATE = {
        caught_up: ['online', 'caught up'],
        current: ['online', 'up to date'],
        catching_up: ['warning', 'catching up']
    };

    var STAGE = { start: 'Starting', export: 'Exporting', upload: 'Uploading', verify: 'Reading back', count: 'Recounting', manifest: 'Writing chunk.json' };

    // ---- sections -------------------------------------------------------

    function attention(st) {
        var html = '';
        (st.gates || []).forEach(function (g) {
            if (!g.override_active) return;
            html += notice('crit', '<strong style="color:var(--fwmon-sig-crit);">Retention gate of ' + esc(g.stream) + ' RELEASED</strong> until ' + when(g.override_until) +
                ': raw rows are deleted whether or not they are archived, and the archive alerts keep firing. ' +
                '<button type="button" class="btn sm secondary" data-action="archive-reengage" data-min-role="admin" data-stream="' + esc(g.stream) + '">Re-engage now</button>');
        });
        var gr = st.gate_read;
        if (gr) {
            html += notice('crit', '<strong style="color:var(--fwmon-sig-crit);">The retention gate cannot read the archive&rsquo;s stream switches</strong> since ' +
                when(gr.failing_since) + ' (' + liveSince(gr.failing_since) + '): ' +
                (gr.holding_all ? 'every archived table&rsquo;s deletes are held until a read succeeds.' : 'it keeps the switches it read last; a change saved below is not applied yet.') +
                ' <span style="' + faint + '">' + esc(gr.error || '') + '</span>');
        }
        var na = st.needs_attention || [];
        if (na.length) {
            var holding = na.filter(function (p) { return p.holds_gate; }).length;
            html += notice('crit', '<strong style="color:var(--fwmon-sig-crit);">' + na.length + ' chunk' + (na.length === 1 ? ' is' : 's are') +
                ' parked in needs attention</strong>' + (holding ? ' (' + holding + ' hold' + (holding === 1 ? 's' : '') + ' deletes)' : '') +
                ': no longer retried until reset. See <em>Needs attention</em> below.');
        }
        var rt = st.retrying || [];
        if (rt.length) {
            html += notice('warn', '<strong style="color:var(--fwmon-sig-warn);">' + rt.length + ' chunk' + (rt.length === 1 ? '' : 's') +
                ' failed and will be retried</strong>: ' + esc(rt[0].table) + ' ' + period(rt[0].period_start, rt[0].period_end) + ' &mdash; ' + esc(rt[0].error || '') +
                (rt.length > 1 ? ' (and ' + (rt.length - 1) + ' more below)' : ''));
        }
        var w = st.worker;
        if (w && w.stale) {
            html += notice('warn', '<strong>The archive worker&rsquo;s state is stale</strong>: last written ' + when(w.seen_at) + '. Is the poller running?');
        } else if (w && !w.preflight_ok) {
            html += notice('crit', '<strong style="color:var(--fwmon-sig-crit);">The bucket preflight has not passed</strong>: nothing is archived until it does.');
        }
        var stg = (w && w.staging) || {};
        if (w && stg.free_bytes != null && stg.free_bytes < stg.min_free_bytes) {
            html += notice('crit', 'Staging <code>' + esc(stg.dir || '') + '</code> has ' + AC.formatBytes(stg.free_bytes) +
                ' free, below the ' + AC.formatBytes(stg.min_free_bytes) + ' floor: nothing is exported.');
        }
        return html;
    }

    function header(st) {
        var c = st.config || {};
        var html = '<p style="' + small + 'margin:0 0 4px;">Bucket <code>' + esc(c.bucket || '') + '</code> prefix <code>' + esc(c.prefix || '') + '</code>' +
            (c.endpoint ? ' at ' + esc(c.endpoint) : '') + (c.access_key_id ? ', key ' + esc(c.access_key_id) : '') +
            (c.object_lock_days ? ', Object Lock ' + esc(c.object_lock_mode || '') + ' ' + c.object_lock_days + ' days' : ', no Object Lock') + '.</p>';
        var w = st.worker;
        if (!w) {
            html += '<p style="' + small + 'color:var(--fwmon-sig-warn);margin:0 0 4px;">' + (st.worker_error
                ? 'The archive worker&rsquo;s state could not be read: ' + esc(st.worker_error)
                : 'The poller&rsquo;s archive worker has not recorded any state yet.') + '</p>';
        } else {
            var stg = w.staging || {};
            var free = stg.error ? 'free space unknown (' + esc(stg.error) + ')' : stg.free_bytes != null ? AC.formatBytes(stg.free_bytes) + ' free' : '';
            html += '<p style="' + small + 'margin:0 0 4px;' + faint + '">Worker ' + esc(w.runner || '') + ', state written ' + liveSince(w.seen_at) + ' ago' +
                '. Staging <code>' + esc(stg.dir || '') + '</code>: ' + free + '.</p>';
        }
        html += '<p style="' + small + 'margin:0 0 8px;' + faint + '">Updated <span data-arch-updated></span> ago' +
            ', refreshed every 15 s while this page is open. <button type="button" class="btn sm secondary" data-action="archive-refresh">Refresh</button></p>';
        return html;
    }

    function now(st) {
        var w = st.worker;
        var html = '<div style="border:1px solid var(--fwmon-border);border-radius:6px;padding:10px 12px;background:var(--fwmon-panel-bg);">';
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
            html += '<div style="font-weight:600;">' + esc(what) + ' ' + esc(a.table) + ' chunk ' + a.seq + ' &middot; ' + period(a.period_start, a.period_end) +
                (pct ? ' <span style="' + faint + 'font-weight:400;">' + pct + '</span>' : '') + '</div>';
            if (a.fraction != null) html += bar(a.fraction, what + ' ' + pct);
            html += '<div style="' + small + faint + '">' + (detail ? esc(detail) + ' &middot; ' : '') + 'this stage ' + liveSince(a.stage_started_at || a.started_at) +
                ', chunk started ' + when(a.started_at) + ' (' + liveSince(a.started_at) + ' ago)</div>';
        } else {
            var waits = (st.tables || []).filter(function (t) { return t.unsettled; });
            var settling = waits.filter(function (t) { return t.unsettled.reason === 'settling' && t.unsettled.until; });
            if (settling.length) {
                html += settling.map(function (t) {
                    return '<div><strong>' + esc(t.table) + '</strong>: ' + esc(t.unsettled.detail || 'the cut is settling') + ' &mdash; exported once it has, ' + liveUntil(t.unsettled.until) + '</div>';
                }).join('');
            } else if (w && !w.stale) {
                html += '<div style="font-weight:600;">Idle</div>';
            } else {
                html += '<div style="' + faint + '">No current activity is known.</div>';
            }
            waits.filter(function (t) { return t.unsettled.reason !== 'settling'; }).forEach(function (t) {
                html += '<div style="' + small + 'color:var(--fwmon-sig-warn);" title="' + esc(t.unsettled.detail || '') + '">' + esc(t.table) + ' waits: ' +
                    esc(label(t.unsettled.reason)) + ' for ' + dur(t.unsettled.for_seconds) + '</div>';
            });
        }
        if (w && a && w.last_pass_at) {
            html += '<div style="' + small + faint + 'margin-top:4px;">Pass running since ' + when(w.last_pass_at) + '</div>';
        } else if (w && w.next_pass_at) {
            html += '<div style="' + small + faint + 'margin-top:4px;">Last pass ' + when(w.last_pass_at) + '; next ' + liveUntil(w.next_pass_at) + '</div>';
        }
        return section('Now', html + '</div>');
    }

    function tableCard(t) {
        var b = t.backlog;
        var st = b ? STATE[b.state] || ['info', label(b.state)] : ['info', t.has_chunks ? 'no backlog' : 'no chunk yet'];
        var html = '<div style="flex:1 1 280px;min-width:0;border:1px solid var(--fwmon-border);border-radius:6px;padding:10px 12px;background:var(--fwmon-card-bg);">' +
            '<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline;"><strong style="overflow-wrap:anywhere;">' + esc(t.table) + '</strong>' +
            (t.enabled ? badge(st[0], st[1]) : badge('', 'archiving off')) + '</div>' +
            '<div style="' + small + faint + '">' + esc((t.streams || []).join(', ')) + '</div>';
        if (b) {
            var f = b.chunks ? b.verified / b.chunks : 1;
            html += bar(f, b.verified + ' of ' + b.chunks + ' chunks verified', b.remaining ? 'var(--fwmon-accent)' : 'var(--fwmon-sig-ok)');
            html += '<div style="' + small + '">' + AC.formatNum(b.verified) + ' of ' + AC.formatNum(b.chunks) + ' chunks verified';
            if (b.remaining) {
                html += ' &middot; ' + AC.formatNum(b.remaining) + ' left from ' + (b.oldest_remaining ? esc(String(b.oldest_remaining).slice(0, 10)) : '?') +
                    ' (up to ' + AC.formatNum(b.remaining_rows) + ' rows)';
            }
            html += '</div><div style="' + small + faint + '">';
            html += b.rate_rows_per_sec != null ? AC.formatNum(Math.round(b.rate_rows_per_sec)) + ' rows/s' : 'rate not measured yet';
            if (b.eta_seconds != null) html += ' &middot; about ' + dur(b.eta_seconds) + ' of work left';
            html += '</div>';
        }
        html += '<div style="' + small + 'margin-top:6px;">Lag ' + dur(t.lag_seconds) + ' &middot; verified through ' +
            (t.verified_through_end ? esc(String(t.verified_through_end).slice(0, 16).replace('T', ' ')) + ' UTC' : '&mdash;') +
            ' &middot; last verified ' + when(t.last_verified_at) + '</div>';
        if (t.unsettled) {
            var u = t.unsettled;
            html += '<div style="' + small + (u.reason === 'settling' ? faint : 'color:var(--fwmon-sig-warn);') + '" title="' + esc(u.detail || '') + '">Waiting: ' +
                esc(label(u.reason)) + ' for ' + dur(u.for_seconds) + (u.until ? ', ' + liveUntil(u.until) : '') + '</div>';
        }
        if (t.retention && t.retention.held_seconds > 0) {
            html += '<div style="' + small + 'color:var(--fwmon-sig-warn);">Deletes held ' + dur(t.retention.held_seconds) + ' past ' + esc(t.retention.window) + '</div>';
        }
        return html + '</div>';
    }

    function chunkTable(rows, cols) {
        return '<div style="overflow-x:auto;"><table class="data-table"><thead><tr>' + cols.map(function (c) { return '<th>' + esc(c[0]) + '</th>'; }).join('') +
            '</tr></thead><tbody>' + rows.map(function (r) {
                return '<tr>' + cols.map(function (c) { return '<td style="' + small + '">' + c[1](r) + '</td>'; }).join('') + '</tr>';
            }).join('') + '</tbody></table></div>';
    }

    function recent(st) {
        var rs = st.recent || [];
        if (!rs.length) return section('Recently verified', '<p style="' + faint + small + 'margin:0;">No chunk verified yet.</p>');
        return section('Recently verified', chunkTable(rs, [
            ['Verified', function (r) { return when(r.verified_at); }],
            ['Chunk', function (r) { return esc(r.table) + ' ' + r.seq + '<div style="' + faint + '">' + period(r.period_start, r.period_end) + '</div>'; }],
            ['Rows', function (r) { return AC.formatNum(r.rows); }],
            ['Objects', function (r) { return AC.formatNum(r.objects) + ' &middot; ' + AC.formatBytes(r.object_bytes); }],
            ['Took', function (r) { return dur(r.duration_seconds) + (r.duration_seconds && r.rows ? '<div style="' + faint + '">' + AC.formatNum(Math.round(r.rows / Math.max(1, r.duration_seconds))) + ' rows/s</div>' : ''); }]
        ]));
    }

    function problems(st) {
        var html = '';
        var rt = st.retrying || [];
        if (rt.length) {
            html += section('Waiting for a retry', chunkTable(rt, [
                ['Chunk', function (r) { return esc(r.table) + ' ' + r.seq + '<div style="' + faint + '">' + period(r.period_start, r.period_end) + '</div>'; }],
                ['Attempts', function (r) { return r.attempts; }],
                ['Retry', function (r) { return r.retry_at ? liveUntil(r.retry_at) + '<div style="' + faint + '">then on the next pass</div>' : '&mdash;'; }],
                ['Error', function (r) { return '<span style="word-break:break-word;">' + esc(r.error || '') + '</span>'; }]
            ]));
        }
        var na = st.needs_attention || [];
        html += section('Needs attention', !na.length ? '<p style="' + faint + small + 'margin:0;">No chunk is parked.</p>' :
            '<div style="overflow-x:auto;"><table class="data-table"><thead><tr><th>Chunk</th><th>Period</th><th>Mismatches</th><th>Error</th><th></th></tr></thead><tbody>' +
            na.map(function (p) {
                return '<tr><td>' + p.id + ' &middot; ' + esc(p.table) + ' seq ' + p.seq + (p.holds_gate ? ' ' + badge('offline', 'holds deletes') : '') + '</td>' +
                    '<td style="' + small + '">' + when(p.period_start) + '</td><td>' + p.mismatches + '</td>' +
                    '<td style="' + small + 'word-break:break-word;">' + esc(p.error || '') + '</td>' +
                    '<td><button type="button" class="btn sm secondary" data-action="archive-reset-chunk" data-min-role="admin" data-id="' + p.id + '">Reset</button></td></tr>';
            }).join('') + '</tbody></table></div>');
        return html;
    }

    function monthBadge(m) {
        var cls = m.status === 'sealed' ? 'online' : m.status === 'seal_failed' ? 'offline' : m.due ? 'warning' : 'info';
        var out = badge(cls, m.status === 'open' ? (m.due ? 'due, not sealed' : 'pending') : label(m.status));
        if (m.partial) out += ' ' + badge('warning', 'partial');
        if (m.degraded && m.degraded.length) out += ' ' + badge('warning', m.degraded.length + ' gate event' + (m.degraded.length === 1 ? '' : 's'));
        return out;
    }

    function streams(st) {
        var html = '';
        (st.streams || []).forEach(function (s) {
            if (!s.enabled && !(s.months || []).length) return;
            var months = (s.months || []).map(function (m) {
                var tip = [m.partial_note, m.error].filter(Boolean).join(' — ');
                return '<div style="display:inline-block;margin:2px 12px 4px 0;vertical-align:top;" title="' + esc(tip) + '"><strong>' + esc(m.month) + '</strong> ' + monthBadge(m) +
                    '<div style="' + faint + 'font-size:0.78rem;">' + AC.formatNum(m.archived_rows) + ' rows &middot; ' + AC.formatBytes(m.archived_object_bytes) + '</div></div>';
            }).join('') || '<span style="' + faint + '">no month yet</span>';
            var seal = '';
            if (s.next_seal) {
                seal = 'next seal ' + esc(s.next_seal.month) + (s.next_seal.due ? ' &mdash; due since ' + when(s.next_seal.due_at) + ', sealed once its chunks are verified'
                    : ' at ' + when(s.next_seal.due_at));
            }
            html += '<div style="' + small + 'margin-bottom:10px;"><strong>' + esc(s.stream) + '</strong> &middot; ' + AC.formatNum(s.archived_rows) + ' rows in ' +
                AC.formatNum(s.archived_objects) + ' objects, ' + AC.formatBytes(s.archived_object_bytes) + ' stored (' + AC.formatBytes(s.archived_raw_bytes) + ' raw)' +
                (s.oldest_unsealed ? ' <span style="color:var(--fwmon-sig-warn);">' + esc(s.oldest_unsealed) + ' is ' + Number(s.unsealed_days).toFixed(1) + ' days past its seal time</span>' : '') +
                (seal ? '<div style="' + faint + '">' + seal + '</div>' : '') + '<div>' + months + '</div></div>';
        });
        return section('Streams and months', html || '<p style="' + faint + small + 'margin:0;">Nothing archived yet.</p>');
    }

    function failures(st) {
        var stages = (st.worker && st.worker.stages) || [];
        var html = '';
        if (stages.length) {
            html += '<details data-arch-details="failures" style="margin-top:14px;"><summary style="cursor:pointer;font-size:0.95rem;font-weight:600;">Last failure of each stage (' + stages.length + ')</summary>' +
                '<ul style="' + small + 'margin:6px 0 0;padding-left:18px;">' + stages.map(function (e) {
                    return '<li><strong>' + esc(e.stage) + '</strong> ' + when(e.at) + ' (' + e.count + '&times;): ' + esc(e.error || '') + '</li>';
                }).join('') + '</ul></details>';
        }
        (st.problems || []).forEach(function (p) {
            html += '<p style="color:var(--fwmon-sig-warn);' + small + '">Could not read: ' + esc(p) + '</p>';
        });
        return html;
    }

    function page(st) {
        var html = attention(st);
        if (!st.enabled && !(st.tables || []).some(function (t) { return t.has_chunks; })) {
            return html + '<p style="' + faint + 'font-size:0.85rem;">Archiving is off. Configure it in Raw Archive Settings below (or the <code>ARCHIVE_*</code> environment keys; see docs/OPERATIONS.md).</p>';
        }
        html += header(st) + now(st);
        var cards = (st.tables || []).filter(function (t) { return t.enabled || t.has_chunks; }).map(tableCard).join('');
        html += section('Tables', '<div style="display:flex;flex-wrap:wrap;gap:10px;">' + cards + '</div>');
        html += recent(st) + problems(st) + streams(st) + failures(st);
        return html;
    }

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
    // keep their open state.
    function render(host, st) {
        var html = page(st || {});
        if (html !== lastHtml || !host.innerHTML) {
            write(host, html);
        }
        var up = host.querySelector('[data-arch-updated]');
        if (up) up.setAttribute('data-arch-since', new Date().toISOString());
        tick(host);
    }

    function write(host, html) {
        var open = {};
        host.querySelectorAll('details[data-arch-details]').forEach(function (d) { open[d.getAttribute('data-arch-details')] = d.open; });
        host.innerHTML = html;
        lastHtml = html;
        host.querySelectorAll('details[data-arch-details]').forEach(function (d) {
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

    window.FwmonArchiveStatus = { render: render, watch: watch, html: page };
})();
