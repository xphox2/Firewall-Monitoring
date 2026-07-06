// admin-common.js — Shared utilities for admin pages
//
// AUDIT-151: this file owns the `fwmonLog` wrapper. The audit
// flagged 100+ `console.*` calls across the admin JS as "no
// level control, no prod silencing, no structured output".
// The wrapper is the single source of truth: every call site
// should use `fwmonLog.debug` / `.info` / `.warn` / `.error`
// instead of `console.log` / etc. directly. The wrapper
// supports a per-session toggle (so an operator can enable
// debug logging for a single session without restarting the
// browser) and a future build step (AUDIT-139's esbuild
// migration) can minify / tree-shake the .debug calls
// entirely for production.
//
// Currently the wrapper just forwards to console.*. The
// migration to fwmonLog.* in other files is deferred (the
// audit's call-site count is the source of truth for the
// migration's progress; see
// TestConsoleCalls_DeferringToFwmonLog_AUDIT151 in
// internal/shell/).
(function() {
    'use strict';

    var API_BASE = '/admin/api';
    var csrfTokenCache = '';

    // fwmonLog is the only blessed path for log output from
    // the admin JS. Levels: debug (silenced unless explicitly
    // enabled), info (always on), warn (always on), error
    // (always on). The debug switch is read from
    // localStorage on every call so a reload picks up changes.
    var fwmonLog = {
        debug: function() {
            if (typeof localStorage !== 'undefined' && localStorage.getItem('fwmonLog.debug') === '1') {
                console.log.apply(console, ['[fwmon:debug]'].concat(Array.prototype.slice.call(arguments)));
            }
        },
        info: function() {
            console.log.apply(console, ['[fwmon:info]'].concat(Array.prototype.slice.call(arguments)));
        },
        warn: function() {
            console.warn.apply(console, ['[fwmon:warn]'].concat(Array.prototype.slice.call(arguments)));
        },
        error: function() {
            console.error.apply(console, ['[fwmon:error]'].concat(Array.prototype.slice.call(arguments)));
        },
    };
    // Expose globally so other admin JS files can use it
    // without re-defining. (No `AC.log` namespace — keeping the
    // name short to match existing conventions like
    // `window.AdminCommon`.)
    if (typeof window !== 'undefined') {
        window.fwmonLog = fwmonLog;
    }

    function fetchCsrfToken() {
        return fetch(API_BASE + '/csrf-token', { credentials: 'same-origin' })
            .then(function(res) { return res.json(); })
            .then(function(data) {
                csrfTokenCache = data.csrf_token || '';
                return csrfTokenCache;
            }).catch(function(err) {
                fwmonLog.error('Failed to fetch CSRF token:', err);
                return '';
            });
    }

    function getCsrfToken() {
        return csrfTokenCache;
    }

    var DEFAULT_TIMEZONE = 'America/New_York';

    function getTimezone() {
        return localStorage.getItem('display_timezone') || DEFAULT_TIMEZONE;
    }

    function setTimezone(tz) {
        localStorage.setItem('display_timezone', tz);
    }

    // AUDIT-128: locale was hardcoded to 'en-US', which made
    // the admin UI display US-format dates (MM/DD/YYYY) to
    // every operator regardless of their actual locale. The
    // fix uses the browser's navigator.language with a
    // fallback to 'en-US' for the (rare) case where the
    // browser doesn't expose a language. The format
    // (year/month/day hour:minute:second, 12-hour) is
    // preserved so existing screenshots and tests still
    // look right; only the *order* of year/month/day and
    // the *separator* are now locale-aware. Operators who
    // prefer the old en-US format can pin
    // `navigator.language = 'en-US'` in their browser.
    function getBrowserLocale() {
        var lang = (navigator && navigator.language) || 'en-US';
        // Strip the region tag (e.g. 'en-US' from 'en-US-CA')
        // so Intl.DateTimeFormat still recognizes the
        // language. Without this, a locale like 'en-US-CA'
        // would fall back to en-US anyway (silently).
        return lang;
    }

    function formatDate(dateStr) {
        if (!dateStr) return '-';
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        var tz = getTimezone();
        return d.toLocaleString(getBrowserLocale(), { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    }

    function formatDateShort(dateStr) {
        if (!dateStr) return '-';
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        var tz = getTimezone();
        return d.toLocaleString(getBrowserLocale(), { timeZone: tz, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true });
    }

    function escapeHtml(str) {
        // AUDIT-059: nullish check, not falsy — `if (!str)` blanked numeric 0,
        // false, and '' alike, so a "0 bytes" field rendered empty.
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // AUDIT-133: NaN / Infinity / non-numeric inputs used to fall
    // through to `Math.log(NaN) / Math.log(1024) = NaN`, which the
    // chart then rendered as "NaN.0 undefined" — a real failure mode
    // when an upstream counter (e.g. a misbehaving device's interface
    // byte count, or a freshly-reset probe that hasn't reported
    // yet) returns a non-finite value. Guard at the top of the
    // function so the operator sees an em-dash (consistent with the
    // "no data" rendering style used elsewhere in the dashboards)
    // rather than a NaN string.
    function formatBytes(bytes) {
        if (!isFinite(bytes) || bytes == null) return '—';
        if (bytes === 0) return '0 B';
        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024));
        if (i >= sizes.length) i = sizes.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
    }

    function formatNum(n) { return n != null ? Number(n).toLocaleString() : '0'; }

    function connStyle(type) {
        var styles = {
            ipsec: { color: '#58a6ff', dash: null, width: 3 },
            ssl: { color: '#d29922', dash: null, width: 3 },
            vxlan: { color: '#8957e5', dash: '8,4', width: 3 },
            l2vlan: { color: '#39d4e0', dash: null, width: 3 },
            l3ipvlan: { color: '#da7de8', dash: '12,4', width: 3 },
            gre: { color: '#b392f0', dash: null, width: 3 },
            wan: { color: '#f0883e', dash: null, width: 3 },
            lag: { color: '#d29922', dash: null, width: 4 },
            ethernet: { color: '#6e7681', dash: null, width: 2 },
            tunnel: { color: '#8b949e', dash: null, width: 3 }
        };
        return styles[type] || styles.tunnel;
    }

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

    function typeBadgeHtml(type) {
        var labels = {ipsec:'IPSec',vxlan:'VXLAN',ssl:'SSL VPN',wan:'WAN',l2vlan:'L2VLAN',l3ipvlan:'L3IPVLAN',gre:'GRE',lag:'LAG',ethernet:'Ethernet',tunnel:'Tunnel'};
        var cs = connStyle(type);
        return '<span class="badge" style="background:' + cs.color + ';font-size:0.65rem;padding:1px 5px;">' + (labels[type] || type || 'Unknown') + '</span>';
    }

    function showError(msg, duration) {
        showToast(msg, 'error', duration);
    }

    function showSuccess(msg, duration) {
        showToast(msg, 'success', duration);
    }

    function showToast(msg, type, duration) {
        duration = duration || 5000;
        var existing = document.querySelector('.toast-container');
        if (existing) existing.remove();
        var container = document.createElement('div');
        container.className = 'toast-container';
        container.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:9999;';
        // a11y (v0.10.213, bundle B4): toasts are announced to screen readers.
        // Errors are assertive (interrupt); success/warning are polite (queued).
        // role=status + aria-live duplicates intentionally — Safari/iOS VO
        // sometimes ignores one or the other.
        if (type === 'error') {
            container.setAttribute('role', 'alert');
            container.setAttribute('aria-live', 'assertive');
        } else {
            container.setAttribute('role', 'status');
            container.setAttribute('aria-live', 'polite');
        }
        container.setAttribute('aria-atomic', 'true');
        var toast = document.createElement('div');
        toast.className = 'toast-message ' + (type || 'error');
        toast.textContent = msg;
        toast.style.cssText = 'padding:14px 24px;border-radius:8px;font-size:0.9rem;font-weight:500;box-shadow:0 4px 12px rgba(0,0,0,0.3);' +
            (type === 'success' ? 'background:#3fb950;color:#fff;' : type === 'warning' ? 'background:#d2992a;color:#fff;' : 'background:#f85149;color:#fff;') +
            'animation:toastSlideIn 0.3s ease';
        container.appendChild(toast);
        document.body.appendChild(container);
        if (duration > 0) {
            setTimeout(function() {
                toast.style.opacity = '0';
                toast.style.transition = 'opacity 0.3s';
                setTimeout(function() { container.remove(); }, 300);
            }, duration);
        }
    }

    function clearToasts() {
        var existing = document.querySelector('.toast-container');
        if (existing) existing.remove();
    }

    // forcePasswordChange renders a one-time, non-dismissable overlay that makes
    // the operator rotate the auto-generated bootstrap admin password before the
    // console is usable. It POSTs to the change-password endpoint (which the
    // server leaves reachable while must_change_password is set); on success the
    // server bumps the token version, so we send the user back to /admin/login.
    var forcePwOpen = false;
    function forcePasswordChange() {
        if (forcePwOpen) return;
        forcePwOpen = true;

        var overlay = document.createElement('div');
        overlay.id = 'force-pw-overlay';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,0.75);display:flex;align-items:center;justify-content:center;';

        var card = document.createElement('div');
        card.style.cssText = 'background:var(--fwmon-bg-primary,#161b22);color:var(--fwmon-text-primary,#e6edf3);border:1px solid var(--fwmon-border,#30363d);border-radius:10px;max-width:420px;width:92%;padding:24px;box-shadow:0 10px 40px rgba(0,0,0,0.5);font-family:inherit;';

        var title = document.createElement('h2');
        title.textContent = 'Change your password';
        title.style.cssText = 'margin:0 0 8px;font-size:18px;';

        var intro = document.createElement('p');
        intro.textContent = 'This account was created with an auto-generated password (written to the server log). Set your own password to continue.';
        intro.style.cssText = 'margin:0 0 16px;font-size:13px;color:var(--fwmon-text-muted,#8b949e);line-height:1.5;';

        function field(labelText, id, placeholder) {
            var wrap = document.createElement('div');
            wrap.style.cssText = 'margin-bottom:12px;';
            var lbl = document.createElement('label');
            lbl.textContent = labelText;
            lbl.setAttribute('for', id);
            lbl.style.cssText = 'display:block;font-size:12px;margin-bottom:4px;';
            var inp = document.createElement('input');
            inp.type = 'password';
            inp.id = id;
            inp.placeholder = placeholder || '';
            inp.autocomplete = 'new-password';
            inp.style.cssText = 'width:100%;box-sizing:border-box;padding:8px 10px;border-radius:6px;border:1px solid var(--fwmon-border,#30363d);background:var(--fwmon-bg-secondary,#21262d);color:inherit;';
            wrap.appendChild(lbl);
            wrap.appendChild(inp);
            return { wrap: wrap, input: inp };
        }

        var cur = field('Current (generated) password', 'force-pw-current');
        var next = field('New password (min 8 characters)', 'force-pw-new');
        var conf = field('Confirm new password', 'force-pw-confirm');

        var errBox = document.createElement('div');
        errBox.style.cssText = 'color:var(--fwmon-danger,#f85149);font-size:12px;min-height:16px;margin-bottom:8px;';

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = 'Change password';
        btn.style.cssText = 'width:100%;padding:10px;border:none;border-radius:6px;background:var(--fwmon-accent,#238636);color:#fff;font-weight:600;cursor:pointer;';

        function submit() {
            errBox.textContent = '';
            var c = cur.input.value, n = next.input.value, cf = conf.input.value;
            if (!c || !n || !cf) { errBox.textContent = 'Please fill in all fields.'; return; }
            if (n !== cf) { errBox.textContent = 'New passwords do not match.'; return; }
            if (n.length < 8) { errBox.textContent = 'New password must be at least 8 characters.'; return; }
            btn.disabled = true; btn.textContent = 'Changing...';
            fetch(API_BASE + '/settings/password', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ current_password: c, new_password: n })
            }).then(function(res) {
                return res.json().then(function(body) { return { ok: res.ok, body: body }; });
            }).then(function(r) {
                if (r.ok && r.body && r.body.success !== false) {
                    (window.top || window).location.href = '/admin/login';
                } else {
                    errBox.textContent = (r.body && r.body.error) || 'Password change failed.';
                    btn.disabled = false; btn.textContent = 'Change password';
                }
            }).catch(function() {
                errBox.textContent = 'Connection error. Please try again.';
                btn.disabled = false; btn.textContent = 'Change password';
            });
        }
        btn.addEventListener('click', submit);
        conf.input.addEventListener('keydown', function(e) { if (e.key === 'Enter') submit(); });

        card.appendChild(title);
        card.appendChild(intro);
        card.appendChild(cur.wrap);
        card.appendChild(next.wrap);
        card.appendChild(conf.wrap);
        card.appendChild(errBox);
        card.appendChild(btn);
        overlay.appendChild(card);
        document.body.appendChild(overlay);
        cur.input.focus();
    }

    function apiFetch(url, options) {
        options = options || {};
        var headers = Object.assign({
            'X-CSRF-Token': getCsrfToken(),
            'Content-Type': 'application/json'
        }, options.headers || {});
        // AUDIT-130: retry transient gateway errors (502/503/504) with
        // exponential backoff + jitter, up to 3 attempts total, before
        // surfacing them as an error toast. A brief proxy/DB hiccup or a
        // rolling restart no longer shows the operator a hard failure.
        var maxAttempts = 3;
        function doFetch(attempt) {
            return fetch(url, {
                method: options.method || 'GET',
                headers: headers,
                body: options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : undefined,
                credentials: 'same-origin'
            }).then(function(res) {
            if ((res.status === 502 || res.status === 503 || res.status === 504) && attempt < maxAttempts) {
                var delay = Math.pow(2, attempt - 1) * 200 + Math.floor(Math.random() * 150);
                return new Promise(function(resolve) { setTimeout(resolve, delay); })
                    .then(function() { return doFetch(attempt + 1); });
            }
            if (res.status === 401 || res.status === 302) {
                // v0.11.18: while the MFA wizard is showing the once-only
                // recovery codes, the session is ALREADY revoked by design —
                // background pollers (dashboard/vitals timers) start 401ing,
                // and this redirect was yanking the whole tab to the login
                // page before the user could save their codes. The wizard
                // raises the hold flag for exactly that window; failed
                // background calls just reject quietly.
                if (window.__fwmonAuthRedirectHold) {
                    return Promise.reject(new Error('Not authenticated'));
                }
                // AUDIT-058: redirect the TOP frame, not the current one. A 401
                // inside the Reports preview iframe would otherwise render the
                // login page inside the report frame instead of navigating the
                // whole tab to /login.
                (window.top || window).location.href = '/admin/login';
                return Promise.reject(new Error('Not authenticated'));
            }
            if (res.status === 403) {
                return res.json().then(function(err) {
                    // Forced first-login password change: the server blocks all
                    // admin API until the auto-generated password is rotated.
                    // Pop a blocking modal instead of a generic error toast.
                    if (err && err.code === 'password_change_required') {
                        forcePasswordChange();
                        throw new Error('Password change required');
                    }
                    // RBAC (T2-8b): a viewer/operator hit a control above their
                    // role — say so plainly instead of a bare "Forbidden".
                    if (err && err.code === 'insufficient_role') {
                        throw new Error('Your role (' + (window.AdminCommon && AdminCommon.sessionRole || 'viewer') + ") doesn't allow this action");
                    }
                    var msg = err.error || 'Forbidden';
                    if (msg.indexOf('CSRF') !== -1) {
                        msg += ' - please refresh the page and try again';
                    }
                    throw new Error(msg);
                });
            }
            if (!res.ok) {
                return res.json().then(function(err) { throw new Error(err.error || 'Request failed'); });
            }
            return res.json();
            });
        }
        return doFetch(1);
    }

    /* ------------------------------------------------------------------
     * Cross-page link helpers (v0.10.215, bundle E2).
     *
     * Operators frequently need to drill from a row in one table to the
     * detail page or filtered list of a related entity:
     *   - Alert row → device-detail page (already know device_id)
     *   - Syslog row → /admin/syslog filtered by hostname
     *   - Trap row → /admin/traps filtered by source IP
     *   - Connections row → /admin/devices/:id (both source + dest cells)
     *   - VPN tunnel row → /admin/devices/:remote-id if known
     *
     * Pre-E2 every operator copied the device name and pasted it into a
     * search bar. These helpers emit a properly-escaped <a href> so the
     * navigation is one click + keyboard reachable + bookmarkable + right-
     * click-openable in a new tab.
     *
     * The targets are real URLs, not hash routes. The admin SPA picks them
     * up via activateTabFromUrl() on load + the FwmonControls.stateFromURL
     * machinery wired in v0.10.212. Server-side this routes to admin.html.
     *
     * All helpers escape their inputs so callers don't need to.
     * ------------------------------------------------------------------ */

    function deviceLink(id, label, opts) {
        opts = opts || {};
        if (id == null || id === '' || id === 0) return escapeHtml(label || '');
        var displayLabel = label != null ? label : ('DEV-' + id);
        var extraAttrs = opts.title ? ' title="' + escapeHtml(opts.title) + '"' : '';
        var extraClass = opts.className ? ' ' + opts.className : '';
        return '<a href="/admin/devices/' + encodeURIComponent(id) +
               '" class="fwmon-link' + extraClass + '"' + extraAttrs + '>' +
               escapeHtml(displayLabel) + '</a>';
    }

    function connectionLink(id, label, opts) {
        opts = opts || {};
        if (id == null || id === '' || id === 0) return escapeHtml(label || '');
        return '<a href="/admin/connections/' + encodeURIComponent(id) +
               '" class="fwmon-link' + (opts.className ? ' ' + opts.className : '') + '">' +
               escapeHtml(label != null ? label : id) + '</a>';
    }

    // Filter-link: deep-links into a list page with a query param so the
    // page boots with that filter already applied. Used to jump from an
    // alert/syslog/trap detail back to "show everything for this device".
    //
    // page: 'syslog' | 'alerts' | 'traps' | 'flows'
    // params: { key: value, ... } — encoded into the query string
    function filterLink(page, params, label, opts) {
        opts = opts || {};
        if (!page) return escapeHtml(label || '');
        var qs = [];
        Object.keys(params || {}).forEach(function(k) {
            var v = params[k];
            if (v === '' || v == null) return;
            qs.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        });
        var href = '/admin/' + page + (qs.length ? '?' + qs.join('&') : '');
        return '<a href="' + href + '" class="fwmon-link' +
               (opts.className ? ' ' + opts.className : '') + '"' +
               (opts.title ? ' title="' + escapeHtml(opts.title) + '"' : '') + '>' +
               escapeHtml(label != null ? label : '') + '</a>';
    }

    /* ------------------------------------------------------------------
     * sshLaunchButton — render a small "SSH" affordance for a device row
     * (v0.10.216, bundle F2).
     *
     * The button is just an <a href="ssh://user@host[:port]"> — the operator's
     * OS hands the URL to their registered SSH handler (PuTTY, Terminal,
     * iTerm2, Windows Terminal, etc.). No backend support needed and no
     * extra credentials flow through the admin server.
     *
     * Inputs:
     *   device — the Device JSON (ip_address, ssh_username, ssh_port).
     *
     * Behavior:
     *   - If `ip_address` is missing, returns an empty string (no button).
     *   - If `ssh_username` is set, includes it in the URL.
     *   - If `ssh_port` is set and isn't 22, appends `:port`.
     *   - The host segment is URI-encoded to keep names with `@` or `:`
     *     out of the wrong slot.
     * ------------------------------------------------------------------ */
    function sshLaunchButton(device) {
        if (!device || !device.ip_address) return '';
        var user = device.ssh_username ? String(device.ssh_username).trim() : '';
        var port = device.ssh_port && device.ssh_port !== 22 ? device.ssh_port : '';
        var host = encodeURIComponent(device.ip_address);
        var url  = 'ssh://' + (user ? encodeURIComponent(user) + '@' : '') + host +
                   (port ? ':' + port : '');
        var title = 'Launch SSH to ' + (user ? (user + '@') : '') +
                    device.ip_address + (port ? (':' + port) : '');
        return '<a href="' + url + '" class="btn secondary sm" title="' +
               escapeHtml(title) + '" aria-label="' + escapeHtml(title) +
               '" style="margin-right:6px;">SSH</a>';
    }

    function doLogout() {
        apiFetch(API_BASE + '/logout', { method: 'POST' }).then(function() {
            window.location.href = '/admin/login';
        }).catch(function() {
            window.location.href = '/admin/login';
        });
    }

    /* ------------------------------------------------------------------
     * loadCytoscape — lazy-load the Cytoscape network-diagram bundle
     * (v0.10.214, bundle C3).
     *
     * Why: ~421 KB across 4 files (cytoscape + layout-base + cose-base +
     * cytoscape-fcose) plus our 2 wrappers (diagram-cytoscape + diagram-
     * panels) used to load eagerly on every admin page even when the
     * operator never opened the Connections tab. This loader injects
     * them on first use and caches the resulting promise so subsequent
     * calls are free.
     *
     * Returns a Promise that resolves when `window.FWDiagram` is ready
     * to use. Safe to call repeatedly.
     * ------------------------------------------------------------------ */
    var __fwmonCytoscapePromise = null;
    function loadCytoscape() {
        if (window.FWDiagram && window.FWDiagram.Panels) {
            return Promise.resolve(window.FWDiagram);
        }
        if (__fwmonCytoscapePromise) return __fwmonCytoscapePromise;

        function inject(src) {
            return new Promise(function(resolve, reject) {
                var s = document.createElement('script');
                s.src = src;
                s.async = false; // preserve execution order
                s.onload = function() { resolve(); };
                s.onerror = function() { reject(new Error('Failed to load ' + src)); };
                document.head.appendChild(s);
            });
        }

        // Load order matters: core library, then layout deps, then fcose
        // extension, then our wrappers.
        __fwmonCytoscapePromise = inject('/static/js/cytoscape.min.js')
            .then(function() { return inject('/static/js/layout-base.js'); })
            .then(function() { return inject('/static/js/cose-base.js'); })
            .then(function() { return inject('/static/js/cytoscape-fcose.js'); })
            .then(function() { return inject('/static/js/diagram-cytoscape.js'); })
            .then(function() { return inject('/static/js/diagram-panels.js'); })
            .then(function() { return window.FWDiagram; })
            .catch(function(err) {
                __fwmonCytoscapePromise = null; // allow retry
                throw err;
            });
        return __fwmonCytoscapePromise;
    }

    /* ------------------------------------------------------------------
     * pollWhenVisible — visibility-gated refresher (v0.10.214, bundle C2).
     *
     * Drop-in replacement for `setInterval(fn, ms)` patterns used to refresh
     * dashboards / lists / charts. The difference is that the timer is
     * suspended whenever `document.hidden` is true (tab in another window,
     * browser minimised, mobile screen off, etc.) — and resumes the moment
     * the tab is visible again, optionally firing immediately on resume so
     * the user doesn't see stale data after switching back.
     *
     * Why this matters:
     *   - Before C2, every admin tab kept hammering /api endpoints even
     *     when the operator was on another tab. On a fleet of 100 admin
     *     browsers, that's hundreds of needless requests per minute.
     *   - The connection-detail page's 30s chart refresh re-created the
     *     uPlot canvas in a hidden tab — wasted CPU and memory pressure.
     *   - Switching back to a tab that had been polling stale data was
     *     also confusing: the first frame the user saw was an old number
     *     until the next setInterval tick.
     *
     * Usage:
     *   var handle = AdminCommon.pollWhenVisible(refreshFn, 15000);
     *   // ... later ...
     *   handle.stop();      // permanently cancels
     *   handle.runNow();    // optional: trigger an immediate refresh
     *
     * Options:
     *   { immediate: false }   skip the initial call (default true)
     *   { onResume: false }    don't fire on visibilitychange→visible
     *                          (default true)
     * ------------------------------------------------------------------ */
    function pollWhenVisible(fn, intervalMs, opts) {
        opts = opts || {};
        if (typeof fn !== 'function' || !(intervalMs > 0)) return { stop: function() {} };

        var timer = null;
        var stopped = false;
        var lastRun = 0;

        function safeFn() {
            lastRun = Date.now();
            try { fn(); } catch (e) { fwmonLog.error('pollWhenVisible callback threw:', e); }
        }

        function schedule() {
            if (stopped || timer != null) return;
            timer = setInterval(function() {
                if (document.hidden) return;
                safeFn();
            }, intervalMs);
        }

        function pause() {
            if (timer != null) { clearInterval(timer); timer = null; }
        }

        function onVis() {
            if (document.hidden) {
                pause();
            } else {
                // If we've been hidden longer than the interval, fire once
                // immediately so the user doesn't see stale data on tab return.
                if (opts.onResume !== false && (Date.now() - lastRun) >= intervalMs) {
                    safeFn();
                }
                schedule();
            }
        }

        document.addEventListener('visibilitychange', onVis);

        // Initial behaviour.
        if (opts.immediate !== false) {
            // Run immediately if we're visible right now, otherwise wait
            // for visibilitychange.
            if (!document.hidden) safeFn();
        }
        if (!document.hidden) schedule();

        return {
            stop: function() {
                stopped = true;
                pause();
                document.removeEventListener('visibilitychange', onVis);
            },
            runNow: function() {
                if (!stopped && !document.hidden) safeFn();
            }
        };
    }

    function delegateEvent(eventType, actionMap) {
        document.addEventListener(eventType, function(e) {
            var el = e.target.closest('[data-action]');
            if (!el) return;
            var handler = actionMap[el.dataset.action];
            if (handler) handler(el, e);
        });
    }

    // Log running server version once on every admin page load. Lets the
    // operator instantly verify whether their last redeploy actually shipped:
    // open dev tools → Console → look for "Firewall-Mon vX.Y.Z". If the
    // version doesn't match the CHANGELOG, the binary or docker image was
    // not rebuilt after the source pull.
    fetch('/api/version').then(function(r) { return r.json(); }).then(function(v) {
        if (v && v.version) {
            fwmonLog.info('%cFirewall-Mon v' + v.version, 'color:#58a6ff;font-weight:bold');
        }
    }).catch(function() { /* version endpoint not exposed — old build */ });

    /* ------------------------------------------------------------------
     * confirmModal — accessible replacement for window.confirm().
     *
     * Usage:
     *   AdminCommon.confirm("Delete this device and all its data?", {
     *       title: "Delete device?",
     *       confirmLabel: "Delete",
     *       danger: true
     *   }).then(function(ok) { if (ok) doDelete(); });
     *
     * Why this exists (v0.10.212, bundle A3):
     *   - Native confirm() is unstyled, blocking, and has no operator
     *     branding — jarring next to the rest of the admin UI.
     *   - Accessibility audit flagged native confirm() as not respecting
     *     keyboard navigation conventions (no focus return, no aria).
     *   - Destructive ops (delete device / connection / policy / etc.)
     *     deserve a danger-styled red Confirm button operators can't
     *     mistake for a benign action.
     *
     * Accessibility:
     *   - role="dialog" + aria-modal + aria-labelledby
     *   - Focus moves into the dialog on open (Cancel by default; Confirm
     *     if `defaultButton: 'confirm'` is passed)
     *   - Tab cycles between Cancel and Confirm (focus trap)
     *   - Escape resolves false; Enter on focused Confirm resolves true
     *   - Focus restored to the triggering element on close
     *
     * Falls back to window.confirm() if document is not available
     * (defensive — shouldn't happen in browser code).
     */
    function confirmModal(message, opts) {
        opts = opts || {};
        if (typeof document === 'undefined') {
            return Promise.resolve(window.confirm(message));
        }
        return new Promise(function(resolve) {
            var trigger = document.activeElement;
            var titleId = 'fwmon-confirm-title-' + Math.random().toString(36).slice(2, 8);
            var overlay = document.createElement('div');
            overlay.className = 'fwmon-confirm-overlay';
            overlay.setAttribute('role', 'presentation');

            var dialog = document.createElement('div');
            dialog.className = 'fwmon-confirm-dialog' + (opts.danger ? ' danger' : '');
            dialog.setAttribute('role', 'dialog');
            dialog.setAttribute('aria-modal', 'true');
            dialog.setAttribute('aria-labelledby', titleId);

            var title = document.createElement('h2');
            title.id = titleId;
            title.className = 'fwmon-confirm-title';
            title.textContent = opts.title || (opts.danger ? 'Are you sure?' : 'Confirm');

            var body = document.createElement('div');
            body.className = 'fwmon-confirm-body';
            body.textContent = message;

            var actions = document.createElement('div');
            actions.className = 'fwmon-confirm-actions';

            var cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'fwmon-confirm-btn cancel';
            cancelBtn.textContent = opts.cancelLabel || 'Cancel';

            var confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = 'fwmon-confirm-btn confirm' + (opts.danger ? ' danger' : '');
            confirmBtn.textContent = opts.confirmLabel || (opts.danger ? 'Delete' : 'OK');

            actions.appendChild(cancelBtn);
            actions.appendChild(confirmBtn);
            dialog.appendChild(title);
            dialog.appendChild(body);
            dialog.appendChild(actions);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);

            function cleanup(result) {
                document.removeEventListener('keydown', onKey, true);
                if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
                if (trigger && trigger.focus) {
                    try { trigger.focus(); } catch (e) { /* ignore */ }
                }
                resolve(result);
            }

            function onKey(ev) {
                if (ev.key === 'Escape') {
                    ev.preventDefault();
                    cleanup(false);
                } else if (ev.key === 'Tab') {
                    // 2-element focus trap.
                    var focusables = [cancelBtn, confirmBtn];
                    var idx = focusables.indexOf(document.activeElement);
                    if (idx === -1) {
                        ev.preventDefault();
                        focusables[0].focus();
                        return;
                    }
                    var next = (idx + (ev.shiftKey ? -1 : 1) + focusables.length) % focusables.length;
                    ev.preventDefault();
                    focusables[next].focus();
                }
            }

            cancelBtn.addEventListener('click', function() { cleanup(false); });
            confirmBtn.addEventListener('click', function() { cleanup(true); });
            overlay.addEventListener('click', function(ev) {
                if (ev.target === overlay) cleanup(false);
            });
            document.addEventListener('keydown', onKey, true);

            // Initial focus — Cancel by default so the user can't Enter-spam
            // through a destructive prompt.
            setTimeout(function() {
                var initial = opts.defaultButton === 'confirm' ? confirmBtn : cancelBtn;
                if (initial.focus) initial.focus();
            }, 0);
        });
    }

    /* ------------------------------------------------------------------
     * Shared modal a11y wrapper (v0.10.213, bundle B2).
     *
     * The admin UI has 10+ `<div class="modal" id="…">` dialogs that all
     * toggle visibility via `.modal.active`. Pre-B2 none had `role=dialog`,
     * `aria-modal`, `aria-labelledby`, focus management, or ESC handling.
     * This wrapper adds all of those without touching the existing markup —
     * just call openModal('device-modal') instead of (or in addition to)
     * the legacy `.classList.add('active')`. closeModal() restores focus to
     * whatever element was active when openModal() ran.
     *
     * Designed to coexist with the legacy open paths: if a caller forgets
     * and uses `.classList.add('active')` directly, the modal still renders
     * — it just won't be screen-reader-announced or focus-trapped. That
     * graceful degradation matters because some open paths are deep in
     * legacy code we won't migrate in this bundle.
     *
     * Idempotent: calling openModal() on an already-open modal re-enters
     * cleanly (rebinds the trap to whatever focusables exist now — useful
     * when modal contents are populated async).
     * ------------------------------------------------------------------ */

    // Internal registry: modalId → { closeHandler, prevFocus, keyHandler }
    var __fwmonOpenModals = {};

    function focusableWithin(root) {
        if (!root) return [];
        var sel = 'a[href], button:not([disabled]), textarea:not([disabled]), ' +
                  'input:not([disabled]):not([type="hidden"]), select:not([disabled]), ' +
                  '[tabindex]:not([tabindex="-1"])';
        var nodes = root.querySelectorAll(sel);
        var out = [];
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            // skip elements inside aria-hidden subtrees or invisible
            if (n.offsetParent === null && n.tagName !== 'AREA') continue;
            out.push(n);
        }
        return out;
    }

    function openModal(modalId, opts) {
        opts = opts || {};
        var modal = (typeof modalId === 'string') ? document.getElementById(modalId) : modalId;
        if (!modal) return null;
        var id = modal.id || ('fwmon-modal-' + Math.random().toString(36).slice(2, 8));
        modal.id = id;

        // Tag for assistive tech.
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');

        // Derive a label target. Preference order:
        //   1. opts.labelledBy (caller-supplied element id)
        //   2. existing heading with class .modal-title or h2/h3 inside
        //   3. auto-injected hidden span with title text
        if (opts.labelledBy) {
            modal.setAttribute('aria-labelledby', opts.labelledBy);
        } else if (!modal.getAttribute('aria-labelledby')) {
            var heading = modal.querySelector('.modal-title, .modal-header h2, .modal-header h3, h2, h3');
            if (heading) {
                if (!heading.id) heading.id = id + '-title';
                modal.setAttribute('aria-labelledby', heading.id);
            }
        }

        // Tag every close button so it has a name.
        var closeBtns = modal.querySelectorAll('.modal-close, [data-action^="close-"]');
        for (var i = 0; i < closeBtns.length; i++) {
            if (!closeBtns[i].hasAttribute('aria-label')) {
                closeBtns[i].setAttribute('aria-label', 'Close dialog');
            }
        }

        // Show via the legacy mechanism (add .active) so existing CSS works.
        modal.classList.add('active');

        // If already open in our registry, re-bind without duplicating handlers.
        if (__fwmonOpenModals[id]) {
            return __fwmonOpenModals[id];
        }

        var prevFocus = document.activeElement;

        function onKey(ev) {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                closeModal(id);
                return;
            }
            if (ev.key === 'Tab') {
                var focusables = focusableWithin(modal);
                if (!focusables.length) return;
                var first = focusables[0];
                var last  = focusables[focusables.length - 1];
                if (ev.shiftKey && document.activeElement === first) {
                    ev.preventDefault();
                    last.focus();
                } else if (!ev.shiftKey && document.activeElement === last) {
                    ev.preventDefault();
                    first.focus();
                }
            }
        }

        document.addEventListener('keydown', onKey, true);

        // Move initial focus into the dialog. Caller can opt out (e.g. for
        // form modals where the first input is also the labelled element).
        if (opts.focus !== false) {
            setTimeout(function() {
                var focusables = focusableWithin(modal);
                // Skip the close button as the first focus target — operators
                // typing into a form would otherwise close immediately on Esc-misfire.
                var target = null;
                for (var j = 0; j < focusables.length; j++) {
                    if (!focusables[j].classList.contains('modal-close')) {
                        target = focusables[j];
                        break;
                    }
                }
                if (!target && focusables.length) target = focusables[0];
                if (target && target.focus) {
                    try { target.focus(); } catch (e) { /* ignore */ }
                }
            }, 0);
        }

        var record = {
            id: id,
            modal: modal,
            prevFocus: prevFocus,
            keyHandler: onKey
        };
        __fwmonOpenModals[id] = record;
        return record;
    }

    function closeModal(modalId) {
        var modal = (typeof modalId === 'string') ? document.getElementById(modalId) : modalId;
        if (!modal) return;
        var id = modal.id;
        modal.classList.remove('active');
        var record = __fwmonOpenModals[id];
        if (!record) return;
        document.removeEventListener('keydown', record.keyHandler, true);
        delete __fwmonOpenModals[id];
        if (record.prevFocus && record.prevFocus.focus) {
            try { record.prevFocus.focus(); } catch (e) { /* ignore */ }
        }
    }

    // On page load, retroactively tag every .modal in the DOM. This lets
    // legacy code that still calls .classList.add('active') directly at
    // least benefit from role/aria-labelledby/close-btn label, even if it
    // misses focus trap + ESC.
    function tagStaticModals() {
        var modals = document.querySelectorAll('.modal');
        for (var i = 0; i < modals.length; i++) {
            var m = modals[i];
            if (!m.hasAttribute('role')) m.setAttribute('role', 'dialog');
            if (!m.hasAttribute('aria-modal')) m.setAttribute('aria-modal', 'true');
            if (!m.hasAttribute('aria-labelledby')) {
                var heading = m.querySelector('.modal-title, .modal-header h2, .modal-header h3, h2, h3');
                if (heading) {
                    if (!heading.id) heading.id = (m.id || 'fwmon-modal') + '-title';
                    m.setAttribute('aria-labelledby', heading.id);
                }
            }
            var closes = m.querySelectorAll('.modal-close, [data-action^="close-"]');
            for (var j = 0; j < closes.length; j++) {
                if (!closes[j].hasAttribute('aria-label')) {
                    closes[j].setAttribute('aria-label', 'Close dialog');
                }
            }
        }
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', tagStaticModals);
        } else {
            tagStaticModals();
        }
    }

    /* ------------------------------------------------------------------
     * Day / Night theme (Console design system)
     *
     * The token sets live in admin-design-system.css under
     * :root[data-theme="dark"] (default) / [data-theme="light"]. We only
     * flip the attribute on <html> and persist the choice; CSS does the
     * rest. A pre-paint inline script in admin.html applies the saved
     * theme before first paint to avoid a flash; initTheme() re-applies it
     * (covering pages without that snippet) and wires the footer switch.
     * ------------------------------------------------------------------ */
    function getTheme() {
        try { return localStorage.getItem('fwmon-theme') === 'light' ? 'light' : 'dark'; }
        catch (e) { return 'dark'; }
    }
    function applyTheme(theme) {
        var t = theme === 'light' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', t);
        var icon = document.getElementById('ts-icon');
        var label = document.getElementById('ts-label');
        if (icon) icon.innerHTML = (t === 'light') ? '&#9728;' : '&#9790;'; // ☀ / ☾
        if (label) label.textContent = (t === 'light') ? 'Day' : 'Night';
        // Let charts re-read the CSS-var axis colors for the new theme.
        try { window.dispatchEvent(new CustomEvent('fwmon:themechange', { detail: { theme: t } })); }
        catch (e) { /* CustomEvent unsupported — charts refresh on next reload */ }
    }
    function setTheme(theme) {
        var t = theme === 'light' ? 'light' : 'dark';
        try { localStorage.setItem('fwmon-theme', t); } catch (e) { /* storage blocked */ }
        applyTheme(t);
    }
    function initTheme() {
        applyTheme(getTheme());
        var sw = document.getElementById('theme-switch');
        if (sw && !sw.dataset.wired) {
            sw.dataset.wired = '1';
            sw.addEventListener('click', function () {
                setTheme(getTheme() === 'light' ? 'dark' : 'light');
            });
        }
    }

    /* ------------------------------------------------------------------
     * Vitals rail — persistent network instrument (admin.html shell).
     *
     * Reads the same endpoints the dashboard uses (/dashboard, /probes,
     * /syslog/stats) and drives the rail's ambient warming edge via the
     * data-sev attribute. No-op on pages without #vitals-rail.
     * ------------------------------------------------------------------ */
    function setVital(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }
    function refreshVitals() {
        var rail = document.getElementById('vitals-rail');
        if (!rail) return;
        Promise.all([
            apiFetch(API_BASE + '/dashboard').catch(function () { return null; }),
            apiFetch(API_BASE + '/probes').catch(function () { return null; }),
            apiFetch(API_BASE + '/syslog/stats').catch(function () { return null; })
        ]).then(function (r) {
            var dash = (r[0] && r[0].data) ? (r[0].data.dashboard || r[0].data) : null;
            if (!dash) return;
            var devices = dash.devices || [];
            var online = devices.filter(function (d) { return d.status === 'online'; }).length;
            var offline = devices.filter(function (d) { return d.status === 'offline'; }).length;
            var total = devices.length;

            var allProbes = (r[1] && r[1].data) ? r[1].data : [];
            var probes = allProbes.filter(function (p) { return !p.decommissioned_at; });
            var activeProbes = probes.filter(function (p) {
                return p.approval_status === 'approved' && p.status === 'online';
            }).length;
            var staleProbes = probes.filter(function (p) {
                return p.approval_status === 'approved' && p.status !== 'online';
            }).length;
            var pendingProbes = probes.filter(function (p) { return p.approval_status === 'pending'; }).length;

            var syslog = (r[2] && r[2].data) ? (r[2].data.total || 0) : 0;

            setVital('vital-online', online);
            setVital('vital-total', total);
            setVital('vital-offline', offline);
            setVital('vital-probes', activeProbes);
            setVital('vital-syslog', Number(syslog).toLocaleString());

            // Single worst-severity readout drives the thermal edge.
            var sev = 'ok', label = 'NOMINAL';
            if (offline > 0 || staleProbes > 0) {
                sev = 'crit';
                label = (offline > 0) ? (offline + ' DOWN') : (staleProbes + ' PROBE' + (staleProbes > 1 ? 'S' : '') + ' DOWN');
            } else if (pendingProbes > 0) {
                sev = 'warn';
                label = pendingProbes + ' PENDING';
            }
            rail.setAttribute('data-sev', sev);
            setVital('vital-worst', label);
        });
    }

    // Apply theme on every admin page; start the vitals poller where the
    // rail exists. Mirrors the tagStaticModals auto-init above.
    function initConsoleChrome() {
        initTheme();
        if (document.getElementById('vitals-rail')) {
            pollWhenVisible(refreshVitals, 30000);
        }
    }
    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initConsoleChrome);
        } else {
            initConsoleChrome();
        }
    }

    /* ------------------------------------------------------------------
     * Session role bootstrap (T2-8b / LC-18).
     *
     * Lives HERE (not admin-users.js) because every admin page loads
     * admin-common.js while only admin.html loads admin-users.js — the
     * standalone pages (probes/sites/irc/device-detail/connection-detail)
     * previously never stamped <html data-role>, so their [data-min-role]
     * controls rendered for every role and dead-ended in a 403, and the
     * insufficient_role message fell back to the wrong role ("viewer").
     *
     * whenMe() fetches /admin/api/me exactly once per page, publishes
     * AdminCommon.sessionRole / sessionMe, stamps the role on <html> (the
     * CSS attribute rules in admin-design-system.css hide any
     * [data-min-role] control the session can't use — the server enforces
     * regardless), badges the sidebar for non-admins, and dispatches
     * fwmon:role-resolved + fwmon:me-resolved for page modules. The fetch
     * starts at DOMContentLoaded so every deferred page script has already
     * registered its event listeners by the time the events fire.
     * ------------------------------------------------------------------ */
    var sessionMePromise = null;

    function whenMe() {
        if (!sessionMePromise) {
            sessionMePromise = apiFetch(API_BASE + '/me').then(function (res) {
                var me = (res && res.data) || null;
                window.AdminCommon.sessionRole = me ? me.role : null;
                window.AdminCommon.sessionMe = me;
                if (me && me.role) {
                    document.documentElement.dataset.role = me.role;
                    document.dispatchEvent(new CustomEvent('fwmon:role-resolved', { detail: { role: me.role } }));
                    if (me.role !== 'admin') {
                        var sub = document.querySelector('.sidebar-header .subtitle');
                        if (sub && !document.getElementById('role-badge')) {
                            var badge = document.createElement('span');
                            badge.id = 'role-badge';
                            badge.className = 'role-badge';
                            badge.textContent = me.role + ' · ' + (me.username || '');
                            sub.appendChild(document.createElement('br'));
                            sub.appendChild(badge);
                        }
                    }
                }
                document.dispatchEvent(new CustomEvent('fwmon:me-resolved', { detail: me }));
                return me;
            }).catch(function () { return null; });
        }
        return sessionMePromise;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { whenMe(); });
    } else {
        whenMe();
    }

    // Export to window for use by other scripts and diagram modules
    window.AdminCommon = {
        API_BASE: API_BASE,
        sessionRole: null,
        sessionMe: null,
        whenMe: whenMe,
        fetchCsrfToken: fetchCsrfToken,
        getCsrfToken: getCsrfToken,
        escapeHtml: escapeHtml,
        formatBytes: formatBytes,
        formatNum: formatNum,
        connStyle: connStyle,
        matchMethodBadge: matchMethodBadge,
        typeBadgeHtml: typeBadgeHtml,
        showError: showError,
        showSuccess: showSuccess,
        showToast: showToast,
        clearToasts: clearToasts,
        confirm: confirmModal,
        openModal: openModal,
        closeModal: closeModal,
        pollWhenVisible: pollWhenVisible,
        loadCytoscape: loadCytoscape,
        deviceLink: deviceLink,
        connectionLink: connectionLink,
        filterLink: filterLink,
        sshLaunchButton: sshLaunchButton,
        apiFetch: apiFetch,
        doLogout: doLogout,
        delegateEvent: delegateEvent,
        getTimezone: getTimezone,
        setTimezone: setTimezone,
        formatDate: formatDate,
        formatDateShort: formatDateShort,
        renderSidebar: renderSidebar,
        renderMobileChrome: renderMobileChrome,
        getTheme: getTheme,
        setTheme: setTheme,
        applyTheme: applyTheme,
        initTheme: initTheme,
        refreshVitals: refreshVitals,
        cssVar: cssVar,
        hexToRgb: hexToRgb,
        fillGradient: fillGradient
    };

    function renderSidebar(currentPage) {
        if (!currentPage) {
            var path = window.location.pathname.replace(/\/$/, '');
            var segments = path.split('/');
            var lastSegment = segments[segments.length - 1];
            var pageMap = { 'dashboard':'', 'devices':'devices', 'connections':'connections',
                'settings':'settings', 'reports':'reports', 'syslog':'syslog', 'flows':'flows', 'noc':'noc', 'alerts':'alerts', 'traps':'traps',
                'alert-policies':'alert-policies', 'maintenance':'maintenance', 'probes':'probes', 'sites':'sites',
                'irc':'irc', 'audit':'audit', 'profile':'profile', 'threat-intel':'threat-intel' };
            currentPage = pageMap[lastSegment] || 'dashboard';
        }

        var pageIcons = {
            'dashboard': '&#9632;', 'devices': '&#9881;', 'connections': '&#8644;',
            'syslog': '&#9993;', 'flows': '&#8674;', 'noc': '&#9788;', 'alerts': '&#9888;', 'traps': '&#9889;',
            'alert-policies': '&#9881;', 'maintenance': '&#128295;', 'settings': '&#9881;', 'reports': '&#128202;',
            'probes': '&#9678;', 'sites': '&#9962;', 'irc': '&#128172;', 'audit': '&#128203;',
            'threat-intel': '&#128737;'
        };
        // AUDIT-057: the active link gets aria-current="page" (so screen readers
        // announce the current page) and every nav icon gets aria-hidden="true"
        // (so the Unicode glyph isn't read out as gibberish before the label).
        var navHtml = '<div class="nav-section"><div class="nav-section-title">Monitoring</div>' +
            '<a class="nav-item' + (currentPage === 'dashboard' ? ' active" aria-current="page' : '') + '" href="/admin"><span class="nav-icon" aria-hidden="true">' + pageIcons['dashboard'] + '</span> Dashboard</a>' +
            '<a class="nav-item' + (currentPage === 'devices' ? ' active" aria-current="page' : '') + '" href="/admin/devices"><span class="nav-icon" aria-hidden="true">' + pageIcons['devices'] + '</span> Devices</a>' +
            '<a class="nav-item' + (currentPage === 'connections' ? ' active" aria-current="page' : '') + '" href="/admin/connections"><span class="nav-icon" aria-hidden="true">' + pageIcons['connections'] + '</span> Connections</a>' +
            '<a class="nav-item' + (currentPage === 'noc' ? ' active" aria-current="page' : '') + '" href="/admin/noc"><span class="nav-icon" aria-hidden="true">' + pageIcons['noc'] + '</span> NOC</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">Data</div>' +
            '<a class="nav-item' + (currentPage === 'syslog' ? ' active" aria-current="page' : '') + '" href="/admin/syslog"><span class="nav-icon" aria-hidden="true">' + pageIcons['syslog'] + '</span> Syslog</a>' +
            '<a class="nav-item' + (currentPage === 'flows' ? ' active" aria-current="page' : '') + '" href="/admin/flows"><span class="nav-icon" aria-hidden="true">' + pageIcons['flows'] + '</span> Flows</a>' +
            '<a class="nav-item' + (currentPage === 'alerts' ? ' active" aria-current="page' : '') + '" href="/admin/alerts"><span class="nav-icon" aria-hidden="true">' + pageIcons['alerts'] + '</span> Alerts</a>' +
            '<a class="nav-item' + (currentPage === 'threat-intel' ? ' active" aria-current="page' : '') + '" href="/admin/threat-intel"><span class="nav-icon" aria-hidden="true">' + pageIcons['threat-intel'] + '</span> Threat Intel</a>' +
            '<a class="nav-item' + (currentPage === 'traps' ? ' active" aria-current="page' : '') + '" href="/admin/traps"><span class="nav-icon" aria-hidden="true">' + pageIcons['traps'] + '</span> Traps</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">Infrastructure</div>' +
            '<a class="nav-item' + (currentPage === 'probes' ? ' active" aria-current="page' : '') + '" href="/admin/probes"><span class="nav-icon" aria-hidden="true">' + pageIcons['probes'] + '</span> Probes</a>' +
            '<a class="nav-item' + (currentPage === 'sites' ? ' active" aria-current="page' : '') + '" href="/admin/sites"><span class="nav-icon" aria-hidden="true">' + pageIcons['sites'] + '</span> Sites</a>' +
            // The standalone "Pending" page/link was removed (v0.10.419): the
            // Probes page covers the full approve/reject workflow via its
            // "Pending" filter tab, making a separate page redundant.
            '</div><div class="nav-section"><div class="nav-section-title">Configuration</div>' +
            '<a class="nav-item' + (currentPage === 'alert-policies' ? ' active" aria-current="page' : '') + '" href="/admin/alert-policies"><span class="nav-icon" aria-hidden="true">' + pageIcons['alert-policies'] + '</span> Alert Policies</a>' +
            '<a class="nav-item' + (currentPage === 'maintenance' ? ' active" aria-current="page' : '') + '" href="/admin/maintenance"><span class="nav-icon" aria-hidden="true">' + pageIcons['maintenance'] + '</span> Maintenance</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">System</div>' +
            '<a class="nav-item' + (currentPage === 'reports' ? ' active" aria-current="page' : '') + '" href="/admin/reports"><span class="nav-icon" aria-hidden="true">' + pageIcons['reports'] + '</span> Reports</a>' +
            '<a class="nav-item' + (currentPage === 'settings' ? ' active" aria-current="page' : '') + '" href="/admin/settings"><span class="nav-icon" aria-hidden="true">' + pageIcons['settings'] + '</span> Settings</a>' +
            '<a class="nav-item' + (currentPage === 'audit' ? ' active" aria-current="page' : '') + '" href="/admin/audit"><span class="nav-icon" aria-hidden="true">' + pageIcons['audit'] + '</span> Audit Logs</a>' +
            '<a class="nav-item' + (currentPage === 'irc' ? ' active" aria-current="page' : '') + '" href="/admin/irc"><span class="nav-icon" aria-hidden="true">' + pageIcons['irc'] + '</span> IRC</a>' +
            '</div>';

        var sidebarNav = document.querySelector('.sidebar-nav');
        if (sidebarNav) {
            sidebarNav.innerHTML = navHtml;
        }
        // The Profile link lives in the static sidebar-footer (above Logout)
        // on every admin page; highlight it when the profile page is current.
        var profileLink = document.getElementById('profile-link');
        if (profileLink) {
            profileLink.classList.toggle('active', currentPage === 'profile');
            if (currentPage === 'profile') {
                profileLink.setAttribute('aria-current', 'page');
            } else {
                profileLink.removeAttribute('aria-current');
            }
        }
    }

    // AUDIT-055: inject the mobile header + sidebar overlay on every admin page
    // and wire the open/close toggle. Previously only admin.html had this
    // (inline markup + inline <script>); the other pages had a fixed 240px
    // sidebar covering half a phone viewport with no way to collapse it. The
    // CSS lives in admin-shared.css (the shared "Mobile chrome" section).
    // Idempotent — safe to call once per page after renderSidebar().
    function renderMobileChrome() {
        if (document.querySelector('.mobile-header')) return;
        var sidebar = document.querySelector('.sidebar');
        if (!sidebar || !sidebar.parentNode) return;
        if (!sidebar.id) sidebar.id = 'sidebar';

        var overlay = document.createElement('div');
        overlay.className = 'sidebar-overlay';
        overlay.id = 'sidebar-overlay';

        var header = document.createElement('div');
        header.className = 'mobile-header';
        header.innerHTML = '<button class="mobile-menu-btn" id="mobile-menu-btn" type="button" ' +
            'aria-label="Open navigation menu" aria-expanded="false" aria-controls="' + sidebar.id + '">&#9776;</button>' +
            '<span class="text-[#58a6ff] font-semibold">Firewall Monitor</span>';

        sidebar.parentNode.insertBefore(overlay, sidebar);
        sidebar.parentNode.insertBefore(header, sidebar);

        var menuBtn = header.querySelector('#mobile-menu-btn');
        function setOpen(open) {
            sidebar.classList.toggle('open', open);
            overlay.classList.toggle('open', open);
            // AUDIT-070: keep the hamburger's aria-expanded in sync with the
            // sidebar state (the old inline admin.html toggle never updated it;
            // this centralized handler, added in AUDIT-055, does).
            menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        }
        menuBtn.addEventListener('click', function() {
            setOpen(!sidebar.classList.contains('open'));
        });
        overlay.addEventListener('click', function() { setOpen(false); });
    }

    // ---- FortiGate Log Parser ----
    function getFortiGuardUrl(keyword) {
        return 'https://www.fortiguard.com/search?q=' + encodeURIComponent(keyword || '');
    }

    function parseFortiGateLog(msg) {
        var parsed = { raw: msg, type: '', subtype: '', severity: '', fields: {} };
        if (!msg || typeof msg !== 'string') return parsed;

        var kvPairs = msg.match(/(\w+(?:_[a-zA-Z0-9])*)=(?:[^\s"]+|"[^"]*")/g) || [];
        kvPairs.forEach(function(pair) {
            var eqIdx = pair.indexOf('=');
            if (eqIdx === -1) return;
            var key = pair.substring(0, eqIdx);
            var rawVal = pair.substring(eqIdx + 1);
            var val = rawVal.replace(/^"|"$/g, '');
            parsed.fields[key] = val;
            if (key === 'type') parsed.type = val;
            else if (key === 'subtype') parsed.subtype = val;
            else if (key === 'severity') parsed.severity = val;
        });
        return parsed;
    }

    function getSeverityLabel(sev) {
        var s = (sev || '').toLowerCase();
        if (s === 'critical' || s === 'high' || s === 'alert' || s === 'emergency') return 'critical';
        if (s === 'error' || s === 'major') return 'error';
        if (s === 'warning' || s === 'medium') return 'warning';
        if (s === 'notice') return 'notice';
        return 'info';
    }

    function formatFortiGateLogHtml(msg) {
        var p = parseFortiGateLog(msg);
        var type = p.type || 'UNKNOWN';
        var subtype = p.subtype || '';
        var severity = p.severity || '';
        var sevLabel = getSeverityLabel(severity);
        var f = p.fields;

        var html = '<div style="margin-bottom:16px;">';
        html += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">';
        html += '<span class="badge ' + sevLabel + '" style="font-size:0.9rem;padding:4px 12px;">' + escapeHtml(severity.toUpperCase()) + '</span>';
        html += '<span style="color:#58a6ff;font-weight:600;font-size:1rem;">' + escapeHtml(type) + '</span>';
        if (subtype) html += '<span style="color:#8b949e;">/ ' + escapeHtml(subtype) + '</span>';
        html += '</div>';

        var fields = [];
        var importantFields = ['srcip', 'srcport', 'dstip', 'dstport', 'proto', 'action', 'sentbyte', 'rcvdbyte', 'duration', 'iface', 'policyid', 'vd', 'sessionid', 'srcintf', 'dstintf', 'hostname', 'logid', 'app', 'appid', 'apprisk', 'virus', 'file', 'sig_name', 'signature', ' quarantined', 'url', 'method', 'user', 'srcuser', 'dstuser', 'ha_role', 'cluster_state', 'change_reason', 'service', 'transport', 'srcname', 'dstname'];
        var fieldLabels = {
            'srcip': 'Source IP', 'srcport': 'Src Port', 'dstip': 'Dest IP', 'dstport': 'Dst Port',
            'proto': 'Protocol', 'action': 'Action', 'sentbyte': 'Sent Bytes', 'rcvdbyte': 'Rcvd Bytes',
            'duration': 'Duration (s)', 'iface': 'Interface', 'policyid': 'Policy ID', 'vd': 'VDOM',
            'sessionid': 'Session ID', 'srcintf': 'Src Interface', 'dstintf': 'Dst Interface',
            'hostname': 'Hostname', 'logid': 'Log ID', 'app': 'Application', 'appid': 'App ID',
            'apprisk': 'App Risk', 'virus': 'Virus', 'file': 'File', 'sig_name': 'Signature',
            'signature': 'Signature ID', 'service': 'Service', 'transport': 'Transport',
            'srcname': 'Src Name', 'dstname': 'Dst Name', 'ha_role': 'HA Role',
            'cluster_state': 'Cluster State', 'change_reason': 'Change Reason',
            'user': 'User', 'srcuser': 'Src User', 'dstuser': 'Dst User', 'method': 'Method', 'url': 'URL'
        };

        var hasSrcName = f.srcname !== undefined && f.srcname !== '';
        var hasDstName = f.dstname !== undefined && f.dstname !== '';

        importantFields.forEach(function(key) {
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
                fields.push('<div style="display:flex;gap:8px;min-height:24px;"><span style="color:#8b949e;min-width:120px;">' + escapeHtml(label) + ':</span><span>' + valHtml + '</span></div>');
            }
        });

        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:4px 16px;">' + fields.join('') + '</div>';
        html += '</div>';

        var msgStart = msg.indexOf('msg=');
        var rawMsg = '';
        if (msgStart !== -1) {
            rawMsg = msg.substring(msgStart);
            var spaceIdx = rawMsg.indexOf(' ');
            if (spaceIdx !== -1) rawMsg = rawMsg.substring(0, spaceIdx);
            rawMsg = rawMsg.replace(/^msg=/, '');
        }

        html += '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin-top:8px;">';
        html += '<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;margin-bottom:6px;">Raw Message</div>';
        html += '<div style="font-family:monospace;font-size:0.85rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(msg) + '</div>';
        html += '</div>';

        return html;
    }

    // Eagerly load timezone from server on page load
    function loadTimezoneFromServer() {
        fetch(API_BASE + '/display-settings', { credentials: 'same-origin' })
            .then(function(res) { if (res.ok) return res.json(); })
            .then(function(data) {
                if (data && data.data && data.data['display_timezone']) {
                    setTimezone(data.data['display_timezone']);
                }
            }).catch(function() {});
    }
    loadTimezoneFromServer();

    // Set globals for diagram-panels.js and other interop
    window.API_BASE = API_BASE;
    window.escapeHtml = escapeHtml;
    window.formatBytes = formatBytes;
    window.formatNum = formatNum;
    window.connStyle = connStyle;
    window.matchMethodBadge = matchMethodBadge;
    window.typeBadgeHtml = typeBadgeHtml;
    window.showToast = showToast;
    window.showError = showError;
    window.showSuccess = showSuccess;
    window.clearToasts = clearToasts;
    window.parseFortiGateLog = parseFortiGateLog;
    window.formatFortiGateLogHtml = formatFortiGateLogHtml;

    // AUDIT-129: client-side error reporting. An uncaught JS error or unhandled
    // promise rejection otherwise only flashes the 5-second toast (if that) and
    // then vanishes, leaving the operator blind to client failures in prod.
    // Forward them to the server log via a best-effort beacon — capped per page
    // load so a render loop can't flood the log, and wrapped so the reporter can
    // never itself throw.
    (function installClientErrorReporter() {
        if (typeof window === 'undefined') return;
        var sent = 0;
        var MAX = 5; // per page load
        function report(message, source, line, col, stack) {
            if (sent >= MAX || !message) return;
            sent++;
            var payload = JSON.stringify({
                message: String(message).slice(0, 1000),
                source: String(source || '').slice(0, 500),
                line: line || 0,
                col: col || 0,
                stack: String(stack || '').slice(0, 4000),
                url: (window.location && window.location.href) || '',
            });
            try {
                if (navigator && navigator.sendBeacon) {
                    navigator.sendBeacon('/api/client-error', new Blob([payload], { type: 'application/json' }));
                } else {
                    fetch('/api/client-error', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: payload,
                        keepalive: true,
                    }).catch(function() {});
                }
            } catch (e) { /* never let the reporter throw */ }
        }
        window.addEventListener('error', function(e) {
            report(e.message, e.filename, e.lineno, e.colno, e.error && e.error.stack);
        });
        window.addEventListener('unhandledrejection', function(e) {
            var r = e.reason;
            report((r && r.message) || String(r), '', 0, 0, r && r.stack);
        });
    })();

    // Read a Console design token off :root (resolves the active theme).
    function cssVar(name, fallback) {
        try {
            var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (e) { return fallback; }
    }

    // "#4c8dff" / "#fff" -> "76, 141, 255" for building rgba() gradient stops.
    function hexToRgb(hex) {
        var h = String(hex).trim().replace('#', '');
        if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
        var n = parseInt(h, 16);
        if (h.length !== 6 || isNaN(n)) return '76, 141, 255'; // accent fallback
        return ((n >> 16) & 255) + ', ' + ((n >> 8) & 255) + ', ' + (n & 255);
    }

    // Vertical area-fill gradient for a line chart, derived from the line's own
    // color. Punchier in the dark theme (flat surfaces swallow a faint fill);
    // tasteful in light. Shared by createChart() (initial render) and the theme
    // recolor pass so a Day/Night flip rebuilds the fill, not just the axes.
    function fillGradient(ctx2d, borderColor, height) {
        var isLight = document.documentElement.getAttribute('data-theme') === 'light';
        var topA = isLight ? 0.22 : 0.46;
        var midA = isLight ? 0.06 : 0.16;
        var rgb = hexToRgb(borderColor || '#4c8dff');
        var g = ctx2d.createLinearGradient(0, 0, 0, height || 250);
        g.addColorStop(0, 'rgba(' + rgb + ',' + topA + ')');
        g.addColorStop(0.55, 'rgba(' + rgb + ',' + midA + ')');
        g.addColorStop(1, 'rgba(' + rgb + ',0)');
        return g;
    }

    function setupChartDefaults() {
        if (!window.Chart) return;
        var faint = cssVar('--fwmon-text-faint', '#8b949e');
        var dim = cssVar('--fwmon-text-dim', '#c9d1d9');

        // General text color and font
        Chart.defaults.color = faint;
        Chart.defaults.font.family = '"Inter", ui-sans-serif, system-ui, -apple-system, sans-serif';
        Chart.defaults.font.size = 10;
        Chart.defaults.responsive = true;
        Chart.defaults.maintainAspectRatio = false;

        // Grid lines styling
        if (Chart.defaults.scale && Chart.defaults.scale.grid) {
            Chart.defaults.scale.grid.color = cssVar('--fwmon-grid-stroke', 'rgba(48, 54, 61, 0.2)');
            Chart.defaults.scale.grid.borderColor = 'transparent';
            Chart.defaults.scale.grid.drawBorder = false;
        }
        if (Chart.defaults.scale && Chart.defaults.scale.ticks) {
            Chart.defaults.scale.ticks.color = faint;
            Chart.defaults.scale.ticks.font = {
                family: '"JetBrains Mono", monospace',
                size: 9
            };
        }

        // Custom Tooltip defaults
        if (Chart.defaults.plugins && Chart.defaults.plugins.tooltip) {
            Chart.defaults.plugins.tooltip.backgroundColor = cssVar('--fwmon-card-bg', '#161b22');
            Chart.defaults.plugins.tooltip.titleColor = cssVar('--fwmon-text', '#e6edf3');
            Chart.defaults.plugins.tooltip.titleFont = { size: 12, weight: '600' };
            Chart.defaults.plugins.tooltip.bodyColor = dim;
            Chart.defaults.plugins.tooltip.borderColor = cssVar('--fwmon-border', 'rgba(255, 255, 255, 0.08)');
            Chart.defaults.plugins.tooltip.borderWidth = 1;
            Chart.defaults.plugins.tooltip.padding = 10;
            Chart.defaults.plugins.tooltip.cornerRadius = 6;
            Chart.defaults.plugins.tooltip.displayColors = true;
            Chart.defaults.plugins.tooltip.boxWidth = 8;
            Chart.defaults.plugins.tooltip.boxHeight = 8;
            Chart.defaults.plugins.tooltip.usePointStyle = true;
        }

        // Legend defaults
        if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
            Chart.defaults.plugins.legend.labels.color = dim;
            Chart.defaults.plugins.legend.labels.boxWidth = 8;
            Chart.defaults.plugins.legend.labels.boxHeight = 8;
            Chart.defaults.plugins.legend.labels.usePointStyle = true;
            Chart.defaults.plugins.legend.labels.padding = 12;
            Chart.defaults.plugins.legend.labels.font = {
                size: 11,
                weight: '500'
            };
        }
    }

    // Recolor every live Chart.js instance to the active theme. Updating
    // Chart.defaults only affects charts built afterward, so we also walk
    // each instance's resolved options (some charts set per-chart colors)
    // and repaint with update('none') — no animation, no data refetch.
    // uPlot charts are canvas-drawn from JS opts and can't be restyled in
    // place; those pages listen for fwmon:themechange and rebuild themselves.
    function recolorChartsForTheme() {
        if (!window.Chart || typeof Chart.getChart !== 'function') return;
        setupChartDefaults();
        var grid = cssVar('--fwmon-grid-stroke', 'rgba(48, 54, 61, 0.2)');
        var faint = cssVar('--fwmon-text-faint', '#8b949e');
        var dim = cssVar('--fwmon-text-dim', '#c9d1d9');
        var cardBg = cssVar('--fwmon-card-bg', '#161b22');
        var text = cssVar('--fwmon-text', '#e6edf3');
        var border = cssVar('--fwmon-border', 'rgba(255,255,255,0.08)');
        var canvases = document.querySelectorAll('canvas');
        for (var i = 0; i < canvases.length; i++) {
            var ch = Chart.getChart(canvases[i]);
            if (!ch || !ch.options) continue;
            var sc = ch.options.scales || {};
            Object.keys(sc).forEach(function(k) {
                if (!sc[k]) return;
                if (sc[k].grid) sc[k].grid.color = grid;
                if (sc[k].ticks) sc[k].ticks.color = faint;
            });
            var pl = ch.options.plugins || {};
            if (pl.legend && pl.legend.labels) pl.legend.labels.color = dim;
            if (pl.tooltip) {
                pl.tooltip.backgroundColor = cardBg;
                pl.tooltip.titleColor = text;
                pl.tooltip.bodyColor = dim;
                pl.tooltip.borderColor = border;
            }
            // Rebuild area-fill gradients + point borders for line datasets so a
            // theme flip changes the fill intensity, not just the axes. The
            // gradient is a canvas object baked at creation; recoloring needs a
            // fresh one keyed off the new theme.
            try {
                var ctx2d = ch.ctx;
                var areaH = (ch.chartArea && ch.chartArea.bottom) || 250;
                (ch.data && ch.data.datasets ? ch.data.datasets : []).forEach(function(ds) {
                    var isLine = (ds.type || ch.config.type) === 'line';
                    if (isLine && ds.fill && ds.backgroundColor && ds.borderColor && ctx2d) {
                        ds.backgroundColor = fillGradient(ctx2d, ds.borderColor, areaH);
                        if (ds.pointBorderColor) ds.pointBorderColor = cardBg;
                    }
                });
            } catch (e) { /* dataset shape varies; skip fill rebuild */ }
            try { ch.update('none'); } catch (e) { /* chart mid-teardown */ }
        }
    }
    window.addEventListener('fwmon:themechange', recolorChartsForTheme);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupChartDefaults);
    } else {
        setupChartDefaults();
    }
})();
