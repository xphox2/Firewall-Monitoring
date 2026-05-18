/* admin-controls.js — reusable UI control primitives.
 *
 * Exports window.FwmonControls. Built for v0.10.212 bundle-A2 to give every
 * analytics page (syslog, alerts, traps, traps stats, etc.) the same range
 * pill bar + auto-apply filter + URL-state machinery the flows page got in
 * v0.10.211, without duplicating the wiring inline in admin-main.js for
 * each page.
 *
 * Patterns:
 *   - State is a plain object owned by the caller; helpers operate on it
 *     via getter/setter functions you pass in.
 *   - URL sync is `history.replaceState` (no back-stack pollution).
 *   - Auto-apply debounces text inputs (default 400ms) and fires immediately
 *     on selects, pills, and Enter/blur in inputs.
 *   - Chip rendering takes an array of {key, label, value, stateKey} and
 *     fires a callback on the × click.
 *
 * Every helper is idempotent + safe to call when the target elements are
 * absent (e.g. before a page first renders). No-op rather than throwing.
 */
(function() {
    'use strict';

    function bindRangePills(containerId, opts) {
        var bar = document.getElementById(containerId);
        if (!bar || bar.__fwmonRangeBound) return;
        bar.__fwmonRangeBound = true;

        var attr = (opts && opts.attr) || 'data-range';
        var onChange = opts && opts.onChange;
        if (!onChange) return;

        bar.addEventListener('click', function(ev) {
            var btn = ev.target && ev.target.closest && ev.target.closest('.chart-range-pill');
            if (!btn || btn.disabled) return;
            var v = btn.getAttribute(attr);
            if (v == null) return;
            onChange(v, btn);
        });
    }

    function activatePill(containerId, value, opts) {
        var bar = document.getElementById(containerId);
        if (!bar) return;
        var attr = (opts && opts.attr) || 'data-range';
        var pills = bar.querySelectorAll('.chart-range-pill');
        for (var i = 0; i < pills.length; i++) {
            pills[i].classList.toggle('active', pills[i].getAttribute(attr) === String(value));
        }
    }

    // bindAutoApply — debounced text inputs + immediate selects.
    //
    // spec: {
    //   inputs:   [{id, stateKey, debounceMs?}, ...],
    //   selects:  [{id, stateKey}, ...],
    //   onChange: function() — called after each commit, debounced or not
    // }
    function bindAutoApply(spec) {
        if (!spec || !spec.onChange) return;
        (spec.inputs || []).forEach(function(input) {
            var el = document.getElementById(input.id);
            if (!el || el.__fwmonAutoBound) return;
            el.__fwmonAutoBound = true;
            var debounceMs = input.debounceMs != null ? input.debounceMs : 400;
            var pending = null;
            var commit = function() {
                spec.state[input.stateKey] = el.value.trim();
                spec.onChange();
            };
            el.addEventListener('input', function() {
                if (pending) clearTimeout(pending);
                pending = setTimeout(commit, debounceMs);
            });
            el.addEventListener('blur', function() {
                if (pending) { clearTimeout(pending); pending = null; }
                if (spec.state[input.stateKey] !== el.value.trim()) commit();
            });
            el.addEventListener('keydown', function(ev) {
                if (ev.key === 'Enter') {
                    if (pending) { clearTimeout(pending); pending = null; }
                    commit();
                    el.blur();
                }
            });
        });
        (spec.selects || []).forEach(function(sel) {
            var el = document.getElementById(sel.id);
            if (!el || el.__fwmonAutoBound) return;
            el.__fwmonAutoBound = true;
            el.addEventListener('change', function() {
                spec.state[sel.stateKey] = el.value || '';
                spec.onChange();
            });
        });
    }

    // setInputValues — apply state → DOM after URL parsing.
    function setInputValues(spec) {
        (spec.inputs || []).forEach(function(input) {
            var el = document.getElementById(input.id);
            if (!el) return;
            var v = spec.state[input.stateKey] || '';
            if (el.value !== v) el.value = v;
        });
        (spec.selects || []).forEach(function(sel) {
            var el = document.getElementById(sel.id);
            if (!el) return;
            var v = spec.state[sel.stateKey] || '';
            if (el.value !== v) el.value = v;
        });
    }

    // stateFromURL — read query params into state, respecting defaults.
    // defaults: {key: defaultValue, ...}
    // keys:     array of state-key names to look up in the URL.
    function stateFromURL(defaults, keys) {
        var state = Object.assign({}, defaults);
        try {
            var url = new URL(window.location.href);
            keys.forEach(function(k) {
                var raw = url.searchParams.get(k);
                if (raw == null || raw === '') return;
                // Number coercion if the default is numeric.
                if (typeof defaults[k] === 'number') {
                    var n = Number(raw);
                    if (isFinite(n)) state[k] = n;
                } else {
                    state[k] = raw;
                }
            });
        } catch (e) { /* swallow, fall back to defaults */ }
        return state;
    }

    // syncURL — write state → URL via replaceState. Omits keys whose value
    // matches the default so the URL stays clean.
    function syncURL(state, defaults, keys) {
        try {
            var url = new URL(window.location.href);
            keys.forEach(function(k) {
                var v = state[k];
                var dv = defaults[k];
                if (v === '' || v == null || String(v) === String(dv)) {
                    url.searchParams['delete'](k);
                } else {
                    url.searchParams.set(k, String(v));
                }
            });
            window.history.replaceState(null, '', url.toString());
        } catch (e) { /* swallow */ }
    }

    // renderChips — pretty-print active filters.
    //
    // chips: [{ stateKey, key, label, formatValue?(v) }] — `label` is the
    //   short text shown for the value; if omitted, the raw value is used.
    //   `key` is the small left-side tag label.
    // onClear: function(stateKey) — called when × is clicked.
    function renderChips(containerId, state, chipDefs, onClear) {
        var host = document.getElementById(containerId);
        if (!host) return;
        var html = '';
        for (var i = 0; i < chipDefs.length; i++) {
            var def = chipDefs[i];
            var v = state[def.stateKey];
            if (v === '' || v == null) continue;
            var label = def.formatValue ? def.formatValue(v) : String(v);
            html += '<span class="fwmon-chip" data-statekey="' + esc(def.stateKey) + '">' +
                '<span class="fwmon-chip-key">' + esc(def.key) + '</span>' +
                '<span class="fwmon-chip-val">' + esc(label) + '</span>' +
                '<button type="button" class="fwmon-chip-clear" aria-label="Clear filter">×</button>' +
            '</span>';
        }
        host.innerHTML = html;
        if (!html) return;
        host.querySelectorAll('.fwmon-chip-clear').forEach(function(btn) {
            btn.addEventListener('click', function(ev) {
                var chip = ev.target.closest('.fwmon-chip');
                if (!chip) return;
                var k = chip.getAttribute('data-statekey');
                if (k && onClear) onClear(k);
            });
        });
    }

    // renderRangePills — render the pill HTML for a range bar.
    // pills: [{value, label, title?}]
    function renderRangePills(containerId, pills, currentValue) {
        var bar = document.getElementById(containerId);
        if (!bar) return;
        var html = '';
        for (var i = 0; i < pills.length; i++) {
            var p = pills[i];
            var active = String(p.value) === String(currentValue) ? ' active' : '';
            html += '<button type="button" class="chart-range-pill' + active +
                '" data-range="' + esc(p.value) + '"' +
                (p.title ? ' title="' + esc(p.title) + '"' : '') +
                '>' + esc(p.label) + '</button>';
        }
        bar.innerHTML = html;
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /* -------------------------------------------------------------------- *
     * attachAnalyticsPage — opinionated wrapper for syslog/alerts/traps.
     *
     * Each of those tabs follows the same shape: a hours-selecting pill bar
     * in the header, a set of dropdown + text-input filters, an active-
     * filter chip strip, and a load() callback that consumes the current
     * state. This helper wires all four into a single page descriptor.
     *
     * descriptor: {
     *   page:           'syslog' | 'alerts' | 'traps'   // url-state namespace
     *   rangePillsId:   element id of the .chart-range-pills container
     *   chipsId:        element id of the .fwmon-chips container
     *   inputs:         [{ id, stateKey, debounceMs?, chipKey?, chipLabel? }, ...]
     *   selects:        [{ id, stateKey, chipKey?, chipLabel?(v)? }, ...]
     *   defaults:       { hours: 24, ... }     // baseline state
     *   onChange:       function(state)        // called after every state mutation
     * }
     *
     * Returns an object exposing getState() / refresh() for the caller.
     * Idempotent — calling twice with the same descriptor is a no-op
     * because each helper checks its own one-shot binding flag.
     * -------------------------------------------------------------------- */
    function attachAnalyticsPage(d) {
        if (!d || !d.page || !d.onChange) return null;
        var allKeys = ['hours'].concat(
            (d.inputs || []).map(function(i) { return i.stateKey; })
        ).concat(
            (d.selects || []).map(function(s) { return s.stateKey; })
        );
        var state = stateFromURL(d.defaults, allKeys);
        d._state = state;

        function commit() {
            setInputValues({ state: state, inputs: d.inputs, selects: d.selects });
            activatePill(d.rangePillsId, state.hours);
            renderChips(d.chipsId, state, chipDefsFrom(d), function(stateKey) {
                state[stateKey] = (typeof d.defaults[stateKey] === 'number')
                    ? d.defaults[stateKey] : '';
                commit();
            });
            syncURL(state, d.defaults, allKeys);
            d.onChange(state);
        }

        bindRangePills(d.rangePillsId, {
            onChange: function(v) {
                var n = Number(v);
                state.hours = isFinite(n) ? n : v;
                commit();
            }
        });

        bindAutoApply({
            state:    state,
            inputs:   d.inputs || [],
            selects:  d.selects || [],
            onChange: commit
        });

        // First paint — apply URL state to DOM and run the loader.
        commit();

        return {
            getState: function() { return Object.assign({}, state); },
            refresh:  function() { d.onChange(state); }
        };
    }

    function chipDefsFrom(d) {
        var defs = [];
        (d.inputs || []).forEach(function(i) {
            if (!i.chipKey) return;
            defs.push({ stateKey: i.stateKey, key: i.chipKey,
                        formatValue: i.chipLabel || null });
        });
        (d.selects || []).forEach(function(s) {
            if (!s.chipKey) return;
            defs.push({ stateKey: s.stateKey, key: s.chipKey,
                        formatValue: s.chipLabel || null });
        });
        return defs;
    }

    window.FwmonControls = {
        bindRangePills:      bindRangePills,
        activatePill:        activatePill,
        bindAutoApply:       bindAutoApply,
        setInputValues:      setInputValues,
        stateFromURL:        stateFromURL,
        syncURL:             syncURL,
        renderChips:         renderChips,
        renderRangePills:    renderRangePills,
        attachAnalyticsPage: attachAnalyticsPage
    };
})();
