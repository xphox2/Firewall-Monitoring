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
        showToast: showToast,
        clearToasts: clearToasts,
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
})();
