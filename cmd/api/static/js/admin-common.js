// admin-common.js — Shared utilities for admin pages
(function() {
    'use strict';

    var API_BASE = '/admin/api';
    var csrfTokenCache = '';

    function fetchCsrfToken() {
        return fetch(API_BASE + '/csrf-token', { credentials: 'same-origin' })
            .then(function(res) { return res.json(); })
            .then(function(data) {
                csrfTokenCache = data.csrf_token || '';
                return csrfTokenCache;
            })['catch'](function(err) {
                console.error('Failed to fetch CSRF token:', err);
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

    function formatDate(dateStr) {
        if (!dateStr) return '-';
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        var tz = getTimezone();
        return d.toLocaleString('en-US', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    }

    function formatDateShort(dateStr) {
        if (!dateStr) return '-';
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return '-';
        var tz = getTimezone();
        return d.toLocaleString('en-US', { timeZone: tz, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function formatBytes(bytes) {
        if (bytes == null || bytes === 0) return '0 B';
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

    function apiFetch(url, options) {
        options = options || {};
        var headers = Object.assign({
            'X-CSRF-Token': getCsrfToken(),
            'Content-Type': 'application/json'
        }, options.headers || {});
        return fetch(url, {
            method: options.method || 'GET',
            headers: headers,
            body: options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : undefined,
            credentials: 'same-origin'
        }).then(function(res) {
            if (res.status === 401 || res.status === 302) {
                window.location.href = '/admin/login';
                return Promise.reject(new Error('Not authenticated'));
            }
            if (res.status === 403) {
                return res.json().then(function(err) {
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
        })['catch'](function() {
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
            ['catch'](function(err) {
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
            try { fn(); } catch (e) { console.error('pollWhenVisible callback threw:', e); }
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
            console.log('%cFirewall-Mon v' + v.version, 'color:#58a6ff;font-weight:bold');
        }
    })['catch'](function() { /* version endpoint not exposed — old build */ });

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

    // Export to window for use by other scripts and diagram modules
    window.AdminCommon = {
        API_BASE: API_BASE,
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
        renderSidebar: renderSidebar
    };

    function renderSidebar(currentPage) {
        if (!currentPage) {
            var path = window.location.pathname.replace(/\/$/, '');
            var segments = path.split('/');
            var lastSegment = segments[segments.length - 1];
            var pageMap = { 'dashboard':'', 'devices':'devices', 'interfaces':'interfaces', 'connections':'connections',
                'settings':'settings', 'syslog':'syslog', 'flows':'flows', 'alerts':'alerts', 'traps':'traps',
                'alert-policies':'alert-policies', 'maintenance':'maintenance', 'probes':'probes', 'sites':'sites',
                'probe-pending':'probe-pending', 'irc':'irc' };
            currentPage = pageMap[lastSegment] || 'dashboard';
        }

        var pageIcons = {
            'dashboard': '&#9632;', 'devices': '&#9881;', 'connections': '&#8644;', 'interfaces': '&#8646;',
            'syslog': '&#9993;', 'flows': '&#8674;', 'alerts': '&#9888;', 'traps': '&#9889;',
            'alert-policies': '&#9881;', 'maintenance': '&#128295;', 'settings': '&#9881;',
            'probes': '&#9678;', 'sites': '&#9962;', 'probe-pending': '&#9200;', 'irc': '&#128172;'
        };
        var navHtml = '<div class="nav-section"><div class="nav-section-title">Monitoring</div>' +
            '<a class="nav-item' + (currentPage === 'dashboard' ? ' active' : '') + '" href="/admin"><span class="nav-icon">' + pageIcons['dashboard'] + '</span> Dashboard</a>' +
            '<a class="nav-item' + (currentPage === 'devices' ? ' active' : '') + '" href="/admin/devices"><span class="nav-icon">' + pageIcons['devices'] + '</span> Devices</a>' +
            '<a class="nav-item' + (currentPage === 'connections' ? ' active' : '') + '" href="/admin/connections"><span class="nav-icon">' + pageIcons['connections'] + '</span> Connections</a>' +
            '<a class="nav-item' + (currentPage === 'interfaces' ? ' active' : '') + '" href="/admin/interfaces"><span class="nav-icon">' + pageIcons['interfaces'] + '</span> Interfaces</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">Data</div>' +
            '<a class="nav-item' + (currentPage === 'syslog' ? ' active' : '') + '" href="/admin/syslog"><span class="nav-icon">' + pageIcons['syslog'] + '</span> Syslog</a>' +
            '<a class="nav-item' + (currentPage === 'flows' ? ' active' : '') + '" href="/admin/flows"><span class="nav-icon">' + pageIcons['flows'] + '</span> Flows</a>' +
            '<a class="nav-item' + (currentPage === 'alerts' ? ' active' : '') + '" href="/admin/alerts"><span class="nav-icon">' + pageIcons['alerts'] + '</span> Alerts</a>' +
            '<a class="nav-item' + (currentPage === 'traps' ? ' active' : '') + '" href="/admin/traps"><span class="nav-icon">' + pageIcons['traps'] + '</span> Traps</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">Infrastructure</div>' +
            '<a class="nav-item' + (currentPage === 'probes' ? ' active' : '') + '" href="/admin/probes"><span class="nav-icon">' + pageIcons['probes'] + '</span> Probes</a>' +
            '<a class="nav-item' + (currentPage === 'sites' ? ' active' : '') + '" href="/admin/sites"><span class="nav-icon">' + pageIcons['sites'] + '</span> Sites</a>' +
            '<a class="nav-item' + (currentPage === 'probe-pending' ? ' active' : '') + '" href="/admin/probe-pending"><span class="nav-icon">' + pageIcons['probe-pending'] + '</span> Pending</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">Configuration</div>' +
            '<a class="nav-item' + (currentPage === 'alert-policies' ? ' active' : '') + '" href="/admin/alert-policies"><span class="nav-icon">' + pageIcons['alert-policies'] + '</span> Alert Policies</a>' +
            '<a class="nav-item' + (currentPage === 'maintenance' ? ' active' : '') + '" href="/admin/maintenance"><span class="nav-icon">' + pageIcons['maintenance'] + '</span> Maintenance</a>' +
            '</div><div class="nav-section"><div class="nav-section-title">System</div>' +
            '<a class="nav-item' + (currentPage === 'settings' ? ' active' : '') + '" href="/admin/settings"><span class="nav-icon">' + pageIcons['settings'] + '</span> Settings</a>' +
            '<a class="nav-item' + (currentPage === 'irc' ? ' active' : '') + '" href="/admin/irc"><span class="nav-icon">' + pageIcons['irc'] + '</span> IRC</a>' +
            '</div>';

        var sidebarNav = document.querySelector('.sidebar-nav');
        if (sidebarNav) {
            sidebarNav.innerHTML = navHtml;
        }
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
            })['catch'](function() {});
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
})();
