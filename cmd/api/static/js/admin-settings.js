/* Settings page UI chrome (v0.11.14): vertical section nav, #hash deep links,
 * dirty tracking, and the sticky save bar. Data plumbing (loadSettings /
 * saveSettings) stays in admin-main.js — this module only tracks the fields
 * those functions read, so the password / 2FA / users / tokens cards (which
 * have their own buttons and endpoints) never trigger the save bar.
 *
 * Exposed as window.FwmonSettingsUI, invoked from loadPageData('settings').
 * If this file fails to load the page degrades gracefully: the Account
 * section is hard-coded active in the HTML and the save button still works
 * through the existing data-action delegation. */
(function () {
    'use strict';

    // Exactly the containers saveSettings() collects from. Anything outside
    // this scope is not "global settings" and must not count as dirty.
    var TRACKED_CONTAINERS = [
        '#settings-alerts', '#settings-notifications', '#settings-smtp',
        '#settings-reports', '#settings-spike', '#settings-detection',
        '#display-settings'
    ];
    var TRACKED_SELECTOR = TRACKED_CONTAINERS.join(',');

    var baseline = null;      // Map<fieldKey, value> from the last load/save
    var reloadFn = null;      // loadSettings, injected by admin-main.js
    var bound = false;        // one-time listener guard

    function fieldKey(el) {
        return (el.closest(TRACKED_SELECTOR) ? el.closest(TRACKED_SELECTOR).id : el.id) +
            '::' + (el.name || el.id);
    }

    function fieldValue(el) {
        return el.type === 'checkbox' ? String(el.checked) : String(el.value);
    }

    function trackedFields() {
        var page = document.getElementById('page-settings');
        if (!page) return [];
        var sel = TRACKED_CONTAINERS.map(function (c) {
            return c + ' input, ' + c + ' select';
        }).join(',');
        var fields = Array.prototype.slice.call(page.querySelectorAll(sel));
        var tz = document.getElementById('display-timezone');
        if (tz) fields.push(tz);
        return fields;
    }

    function serialize() {
        var map = new Map();
        trackedFields().forEach(function (el) {
            map.set(fieldKey(el), fieldValue(el));
        });
        return map;
    }

    function snapshotBaseline() {
        baseline = serialize();
        updateSaveBar();
    }

    function dirtyCount() {
        if (!baseline) return 0;
        var n = 0;
        serialize().forEach(function (val, key) {
            // Fields absent from the baseline (grid re-rendered mid-edit,
            // failed fetch) count as clean — safer than a phantom-dirty bar.
            if (baseline.has(key) && baseline.get(key) !== val) n++;
        });
        return n;
    }

    function isDirty() { return dirtyCount() > 0; }

    function updateSaveBar() {
        var bar = document.getElementById('settings-savebar');
        if (!bar) return;
        // CSS data-min-role hiding is the belt; this is the suspenders.
        var role = document.documentElement.dataset.role;
        var n = (role && role !== 'admin') ? 0 : dirtyCount();
        var msg = document.getElementById('settings-dirty-msg');
        if (msg) msg.textContent = n + ' unsaved change' + (n === 1 ? '' : 's');
        bar.hidden = n === 0;
    }

    function navItems() {
        return Array.prototype.slice.call(
            document.querySelectorAll('#settings-nav .settings-nav-item'));
    }

    function firstVisibleSection() {
        var item = navItems().find(function (a) {
            return getComputedStyle(a).display !== 'none';
        });
        return item ? item.dataset.settingsSection : 'account';
    }

    function sectionExists(name) {
        return !!document.querySelector('.settings-section[data-section="' + name + '"]');
    }

    function sectionVisibleForRole(name) {
        var item = document.querySelector(
            '#settings-nav .settings-nav-item[data-settings-section="' + name + '"]');
        return !!item && getComputedStyle(item).display !== 'none';
    }

    function showSection(name, opts) {
        opts = opts || {};
        if (!sectionExists(name) || !sectionVisibleForRole(name)) {
            name = firstVisibleSection();
        }
        navItems().forEach(function (a) {
            a.classList.toggle('active', a.dataset.settingsSection === name);
        });
        Array.prototype.forEach.call(
            document.querySelectorAll('#page-settings .settings-section'),
            function (s) { s.classList.toggle('active', s.dataset.section === name); });
        if (!opts.noHash) {
            // replaceState, NOT pushState: the SPA's popstate handler re-runs
            // loadSettings(), which re-renders every grid — section switches
            // must not create history entries or Back would eat unsaved edits.
            history.replaceState(null, '', '/admin/settings#' + name);
        }
    }

    function sectionFromHash() {
        var h = (location.hash || '').replace(/^#/, '');
        return h && sectionExists(h) ? h : firstVisibleSection();
    }

    function discard() {
        if (typeof reloadFn === 'function') {
            reloadFn(); // re-renders grids from the server; admin-main.js
                        // re-snapshots the baseline when the load completes
        }
    }

    function bindOnce() {
        if (bound) return;
        bound = true;

        var nav = document.getElementById('settings-nav');
        if (nav) {
            nav.addEventListener('click', function (e) {
                var item = e.target.closest('.settings-nav-item');
                if (!item) return;
                e.preventDefault();
                showSection(item.dataset.settingsSection);
            });
        }

        // Manual URL edits / in-page anchor links.
        window.addEventListener('hashchange', function () {
            var page = document.getElementById('page-settings');
            if (page && page.classList.contains('active')) {
                showSection(sectionFromHash(), { noHash: true });
            }
        });

        // Dirty tracking via delegation: loadSettings() rebuilds the grids
        // with innerHTML on every visit, so direct listeners would be lost.
        var page = document.getElementById('page-settings');
        if (page) {
            ['input', 'change'].forEach(function (evt) {
                page.addEventListener(evt, function (e) {
                    var el = e.target;
                    if (!el || !(el.matches && el.matches('input, select'))) return;
                    if (el.closest(TRACKED_SELECTOR) || el.id === 'display-timezone') {
                        updateSaveBar();
                    }
                });
            });
        }

        // Role resolution (admin-users.js): if the active section's nav item
        // just got hidden (viewer deep-linked #access), fall back.
        document.addEventListener('fwmon:role-resolved', function () {
            var active = document.querySelector('#settings-nav .settings-nav-item.active');
            if (active && getComputedStyle(active).display === 'none') {
                showSection(firstVisibleSection());
            }
            updateSaveBar();
        });
    }

    function init(opts) {
        opts = opts || {};
        if (opts.reload) reloadFn = opts.reload;
        bindOnce();
        showSection(sectionFromHash(), { noHash: !location.hash });
    }

    window.FwmonSettingsUI = {
        init: init,
        snapshotBaseline: snapshotBaseline,
        isDirty: isDirty,
        discard: discard
    };
})();
