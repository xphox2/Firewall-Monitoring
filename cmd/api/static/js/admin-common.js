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

    function showError(msg) {
        var el = document.getElementById('error-msg');
        if (!el) return;
        el.textContent = msg;
        el.style.display = 'block';
        setTimeout(function() { el.style.display = 'none'; }, 5000);
    }

    function showSuccess(msg) {
        var el = document.getElementById('success-msg');
        if (!el) return;
        el.textContent = msg;
        el.style.display = 'block';
        setTimeout(function() { el.style.display = 'none'; }, 5000);
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

    function doLogout() {
        apiFetch(API_BASE + '/logout', { method: 'POST' }).then(function() {
            window.location.href = '/admin/login';
        })['catch'](function() {
            window.location.href = '/admin/login';
        });
    }

    function delegateEvent(eventType, actionMap) {
        document.addEventListener(eventType, function(e) {
            var el = e.target.closest('[data-action]');
            if (!el) return;
            var handler = actionMap[el.dataset.action];
            if (handler) handler(el, e);
        });
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
        apiFetch: apiFetch,
        doLogout: doLogout,
        delegateEvent: delegateEvent,
        getTimezone: getTimezone,
        setTimezone: setTimezone,
        formatDate: formatDate,
        formatDateShort: formatDateShort
    };

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
})();
