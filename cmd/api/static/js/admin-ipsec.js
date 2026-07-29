// admin-ipsec.js — IPSec tunnel wizard (v0.11.89, PR-B).
// Authoring + preview only: design a cross-vendor tunnel, validate it, and see
// the exact config each firewall would receive. NO device writes (that's PR-C).
(function () {
    'use strict';

    var AC = window.AdminCommon;
    var API = AC.API_BASE;
    var wired = false;
    var caps = null;       // { a, b, allowed, profiles } for the selected pair
    var devices = [];      // eligible (fortigate/opnsense) devices
    var lastPreviewOK = false;
    var hintGen = { a: 0, b: 0 };         // per-endpoint request token — drop stale hint responses
    var capsGen = 0;                      // per-pair token — drop stale capability responses
    var lastHintSubnets = { a: '', b: '' }; // last auto-filled subnets, so a re-pick can refresh them
    var endpointHints = { a: null, b: null }; // cached hints per endpoint (peer-IP options + egress→peer sync)
    var loadedDevice = { a: '', b: '' };      // device id whose hints are loaded per endpoint (re-load only on change)

    function $(id) { return document.getElementById(id); }

    // Any change to the intent invalidates a prior clean preview — Save must not
    // persist an intent that was never previewed (the block-findings gate would lie).
    // Any edit after a clean preview un-gates Save. It is also the one hook every
    // field already funnels through (form-level input/change bubbling), so the
    // schematic redraws from here rather than needing listeners of its own.
    function invalidate() {
        lastPreviewOK = false;
        $('ipsec-save-btn').disabled = true;
        refreshDerived();
    }

    // Guarded: this runs on every keystroke, including before a device pair or
    // capabilities exist.
    function refreshDerived() {
        if (!$('ipsec-schematic')) return;
        cryptoSummary();
        renderFacts('a');
        renderFacts('b');
        renderSchematic();
        if (phase === 'verify') renderMatrix();
        updateFootNote();
    }
    function esc(s) { return AC.escapeHtml(String(s == null ? '' : s)); }
    function vendorOf(d) { return (d.vendor || 'fortigate'); }

    // ---- list -----------------------------------------------------------
    function init() {
        if (!wired) { wire(); wired = true; }
        loadTunnels();
    }

    function loadTunnels() {
        AC.apiFetch(API + '/ipsec/tunnels').then(function (r) {
            renderTunnels((r && r.data) || []);
        }).catch(function (e) {
            var role = (AC && AC.sessionRole) || '';
            if (/role|forbidden|allow this action/i.test(e.message) || (role && role !== 'admin')) {
                $('ipsec-tunnels-wrap').innerHTML = '<div class="card" style="padding:16px;color:var(--fwmon-text-mute);">IPSec provisioning is admin-only.</div>';
                return;
            }
            fwmonLog.error('[IPSec] load tunnels failed:', e);
            AC.showError('Failed to load tunnels: ' + e.message);
        });
    }

    function statusBadge(s) {
        var cls = {
            up: 'success', degraded: 'success', down: 'danger', error: 'danger',
            rollback_failed: 'danger', draft: 'info', rolled_back: 'info',
            deploying: 'warning', rolling_back: 'warning'
        }[s] || 'info';
        return '<span class="badge ' + cls + '">' + esc(s || 'draft') + '</span>';
    }

    // Row-action gating — mirrors the server's ipsecEditable/ipsecDeletable + the
    // deploy/rollback source-status sets, so the UI doesn't offer dead-end clicks
    // (the server still enforces every rule with a 409). 'down' (C2b-2b) carries
    // a deploy record just like degraded/up: rollback yes, edit/delete no.
    function canEdit(s) { return ['deploying', 'degraded', 'up', 'down', 'rolling_back', 'rollback_failed'].indexOf(s) === -1; }
    function canDelete(s) { return ['draft', 'rolled_back', 'error'].indexOf(s) !== -1; }
    function canDeploy(s) { return ['draft', 'rolled_back'].indexOf(s) !== -1; }
    function canRollback(s) { return ['degraded', 'up', 'down', 'error', 'rollback_failed'].indexOf(s) !== -1; }
    // Recheck re-runs SA-liveness (read-only on devices) — the recovery for a
    // tunnel that came up after the one-shot post-deploy check and reads 'down'.
    function canRecheck(s) { return ['up', 'down', 'degraded'].indexOf(s) !== -1; }
    function canReset(s) { return s === 'error' || s === 'rollback_failed'; }
    function inProgress(s) { return s === 'deploying' || s === 'rolling_back'; }

    function renderTunnels(list) {
        var wrap = $('ipsec-tunnels-wrap');
        if (!list.length) {
            wrap.innerHTML = '<div class="card" style="padding:20px;color:var(--fwmon-text-mute);">No tunnels yet. Click “+ New Tunnel” to design one.</div>';
            return;
        }
        var rows = list.map(function (t) {
            var s = t.status || 'draft';
            var btns = '<button class="btn sm secondary" data-action="ipsec-preflight" data-min-role="admin" data-id="' + t.id + '" title="Read-only REST check — no device writes">Preflight</button> ';
            if (inProgress(s)) {
                btns += '<button class="btn sm secondary" data-action="ipsec-progress" data-min-role="admin" data-id="' + t.id + '" data-op="' + (s === 'rolling_back' ? 'rollback' : 'deploy') + '">View progress</button> ';
            }
            if (canDeploy(s)) {
                btns += '<button class="btn sm primary" data-action="ipsec-deploy" data-min-role="admin" data-id="' + t.id + '" title="Writes config to the FortiGate device">Deploy</button> ';
            }
            if (canRecheck(s)) {
                btns += '<button class="btn sm secondary" data-action="ipsec-recheck" data-min-role="admin" data-id="' + t.id + '" title="Re-verify SA liveness from the live device state — no device writes">Recheck</button> ';
            }
            if (canRollback(s)) {
                btns += '<button class="btn sm warning" data-action="ipsec-rollback" data-min-role="admin" data-id="' + t.id + '" title="Removes the deployed config from the device">Rollback</button> ';
            }
            if (canReset(s)) {
                btns += '<button class="btn sm secondary" data-action="ipsec-reset" data-min-role="admin" data-id="' + t.id + '" title="Clear Firewall-Mon\'s deploy record (device may still hold objects — verify manually)">Reset…</button> ';
            }
            btns += '<button class="btn sm secondary" data-action="ipsec-edit" data-min-role="admin" data-id="' + t.id + '"' + (canEdit(s) ? '' : ' disabled title="Roll back before editing"') + '>Edit</button> ' +
                '<button class="btn sm danger" data-action="ipsec-delete" data-min-role="admin" data-id="' + t.id + '"' + (canDelete(s) ? '' : ' disabled title="Roll back before deleting"') + '>Delete</button>';
            return '<tr>' +
                '<td>' + esc(t.name || ('fwm-t' + t.id)) + '</td>' +
                '<td>' + esc(t.a_vendor || '?') + ' ↔ ' + esc(t.b_vendor || '?') + '</td>' +
                '<td>' + statusBadge(s) + '</td>' +
                '<td style="text-align:right;">' + btns + '</td></tr>';
        }).join('');
        wrap.innerHTML = '<div style="overflow-x:auto;"><table class="fwmon-table">' +
            '<thead><tr><th>Name</th><th>Endpoints</th><th>Status</th><th></th></tr></thead>' +
            '<tbody>' + rows + '</tbody></table></div>';
    }

    // ---- wizard ---------------------------------------------------------
    function openWizard(id) {
        $('ipsec-wizard-title').textContent = id ? 'Edit IPSec Tunnel' : 'New IPSec Tunnel';
        $('ipsec-edit-id').value = id || '';
        caps = null; lastPreviewOK = false;
        lastHintSubnets.a = ''; lastHintSubnets.b = '';
        endpointHints.a = null; endpointHints.b = null;
        loadedDevice.a = ''; loadedDevice.b = '';
        hintGen.a++; hintGen.b++; // invalidate any in-flight hint responses from a prior open
        $('ipsec-crypto-section').style.display = 'none';
        $('ipsec-endpoints-section').style.display = 'none';
        $('ipsec-preview-section').style.display = 'none';
        $('ipsec-save-btn').disabled = true;
        $('ipsec-findings').innerHTML = '';
        $('ipsec-preview-panes').innerHTML = '';
        ['a-subnets', 'a-id', 'b-subnets', 'b-id', 'a-gateway', 'b-gateway', 'psk',
            'a-egress-custom', 'a-lan-custom', 'b-egress-custom', 'b-lan-custom',
            'a-peer-custom', 'b-peer-custom'].forEach(function (f) { $('ipsec-' + f).value = ''; });
        lanUnticked = { a: {}, b: {} };
        disabledPaths = {};
        // The LAN pickers are checkbox lists, not selects — reset them separately.
        ['a-egress', 'b-egress', 'a-peer', 'b-peer'].forEach(function (f) {
            $('ipsec-' + f).innerHTML = '<option value="__custom__">Custom…</option>';
            $('ipsec-' + f).value = '__custom__';
            $('ipsec-' + f + '-custom').style.display = '';
        });
        ['a', 'b'].forEach(function (pfx) { populateLanList(pfx, []); });
        $('ipsec-a-dyn').checked = false; $('ipsec-b-dyn').checked = false;
        idDirty.a = false; idDirty.b = false;
        ['a', 'b'].forEach(function (pfx) { var h = $('ipsec-' + pfx + '-id-hint'); if (h) { h.textContent = ''; h.style.display = 'none'; } });
        // Stale anchors from a previous open would otherwise decorate fields that
        // have just been reset.
        clearAnchors();
        $('ipsec-schematic').innerHTML = '';
        // The summary is visible IMMEDIATELY on open, so unlike the paths list it
        // cannot wait to be re-rendered: Edit → Cancel → New Tunnel would
        // otherwise show the previous tunnel's endpoints and path count.
        if ($('ipsec-summary')) { $('ipsec-summary').innerHTML = ''; }
        // The paths list would self-heal on phase entry, but leaving the previous
        // tunnel's rows sitting in the DOM is the same class of staleness and
        // costs one line to remove.
        if ($('ipsec-paths')) { $('ipsec-paths').innerHTML = ''; }
        $('ipsec-matrix').innerHTML = '';
        $('ipsec-existing').hidden = true;
        $('ipsec-crypto-detail').hidden = true;
        var cryptoTgl = document.querySelector('[data-action="ipsec-crypto-toggle"]');
        if (cryptoTgl) { cryptoTgl.setAttribute('aria-expanded', 'false'); cryptoTgl.textContent = 'change'; }
        $('ipsec-tab-design').classList.remove('has-block', 'has-warn');
        setPhase('design');

        AC.apiFetch(API + '/devices').then(function (r) {
            devices = ((r && r.data) || []).filter(function (d) {
                var v = vendorOf(d);
                return v === 'fortigate' || v === 'opnsense';
            });
            var opts = '<option value="">— select —</option>' + devices.map(function (d) {
                return '<option value="' + d.id + '">' + esc(d.name) + ' (' + esc(vendorOf(d)) + ')</option>';
            }).join('');
            $('ipsec-dev-a').innerHTML = opts;
            $('ipsec-dev-b').innerHTML = opts;
            AC.openModal('ipsec-wizard-modal');
            if (id) loadTunnelIntoWizard(id);
        }).catch(function (e) { AC.showError('Failed to load devices: ' + e.message); });
    }

    function deviceById(id) { return devices.find(function (d) { return String(d.id) === String(id); }); }

    function onDevicesChosen() {
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        // Findings belong to the pair that was validated. Changing either device
        // makes every one of them stale, and the hint reload repopulates the very
        // fields they decorate — so a warning about the OLD FortiGate's ports would
        // otherwise sit under the NEW one's freshly-loaded checklist.
        clearAnchors();
        $('ipsec-findings').innerHTML = '';
        // Capabilities are fetched per pair and every consumer keys off `caps`
        // (the Verify gate, the profile radios, the crypto summary). Without a
        // token, two quick device changes can let the OLDER response land last and
        // rebuild the crypto controls for a pair that is no longer selected.
        //
        // The bump happens BEFORE the incomplete-pair return, not after it: those
        // responses are just as stale, and leaving them unguarded meant clearing a
        // device hid the duplicate-tunnel note only for an in-flight reply to put
        // the OLD pair's note straight back — the fix undoing itself.
        var gen = ++capsGen;
        // Dropped for the same reason: a failed fetch for the NEW pair would
        // otherwise leave the previous pair's descriptor in place, so the Verify
        // gate would pass and the crypto radios would still be the old pair's.
        caps = null;
        if (!a || !b) {
            // Drop in-flight hints for whichever side was cleared, and forget that
            // its device was loaded. Bumping the token WITHOUT clearing
            // loadedDevice would strand that endpoint: re-picking the same device
            // is a no-op for the loadedDevice guard, so the response we just
            // discarded would never be re-requested and its fields would stay
            // empty. The side still selected keeps its token and any hand-picked
            // interface, which is exactly what loadedDevice exists to protect.
            if (!a) { hintGen.a++; loadedDevice.a = ''; }
            if (!b) { hintGen.b++; loadedDevice.b = ''; }
            $('ipsec-existing').hidden = true;
            refreshDerived();
            return Promise.resolve();
        }
        // Peer/public IP + interfaces + subnets are all populated from each device's
        // real polled data by loadHints (below).
        var capsP = AC.apiFetch(API + '/ipsec/capabilities?a=' + encodeURIComponent(vendorOf(a)) + '&b=' + encodeURIComponent(vendorOf(b))).then(function (r) {
            if (gen !== capsGen) return; // a newer pair was picked while this was in flight
            caps = (r && r.data) || null;
            if (!caps) return;
            $('ipsec-caps-note').textContent = 'Both ends support: ' + (caps.allowed.encryption || []).join(', ') + '.';
            applyLanPickerVisibility();
            renderProfiles();
            populateCustom();
            populateIDTypes();
            $('ipsec-crypto-section').style.display = '';
            $('ipsec-endpoints-section').style.display = '';
            $('ipsec-a-title').textContent = a.name;
            $('ipsec-b-title').textContent = b.name;
            cryptoSummary();
        }).catch(function (e) { AC.showError('No shared crypto for this pair: ' + e.message); });
        checkExisting();
        // Populate interfaces/peer-IP/subnets from each device's real polled data —
        // but only (re)load the endpoint whose device actually changed, so editing
        // one end never clobbers a hand-picked peer/interface on the other. Non-fatal.
        var pending = [];
        if (String(a.id) !== loadedDevice.a) { loadedDevice.a = String(a.id); pending.push(loadHints('a', a.id)); }
        if (String(b.id) !== loadedDevice.b) { loadedDevice.b = String(b.id); pending.push(loadHints('b', b.id)); }
        return Promise.all([capsP, Promise.all(pending)]).then(function () {
            prefillIdentity('a'); prefillIdentity('b');
            refreshDerived();
        });
    }

    // ---- data-driven endpoint hints -------------------------------------
    // Fill the egress/LAN <select>s with the device's actual interfaces and
    // pre-fill protected subnets from its LAN addressing. A "Custom…" option is
    // always kept so an operator can still type an interface not yet polled.
    function ifaceLabel(i) {
        return i.name + ' — ' + (i.type_name || '?') + (i.status ? ' (' + i.status + ')' : '');
    }

    function populateIfaceSelect(pfx, kind, ifaces, suggested) {
        var sel = $('ipsec-' + pfx + '-' + kind);
        var opts = ifaces.length ? '<option value="">— select —</option>' : '';
        opts += ifaces.map(function (i) {
            return '<option value="' + esc(i.name) + '">' + esc(ifaceLabel(i)) + '</option>';
        }).join('');
        opts += '<option value="__custom__">Custom…</option>';
        sel.innerHTML = opts;
        if (suggested) { sel.value = suggested; }
        else if (!ifaces.length) { sel.value = '__custom__'; }
        toggleCustom(pfx, kind);
    }

    // ---- LAN interfaces: a checkbox list, not a select --------------------
    // Several inside ports can carry the protected subnets, and the two are
    // independent — N subnets behind one port, or one subnet per port, both
    // render the same. The ports whose addressing MATCHES the protected subnets
    // tick themselves (see autoTickLANFromSubnets); the list stays editable,
    // because a port can carry traffic for a subnet routed downstream of it,
    // which no address table can show.

    // Only vendors whose rules NAME an interface get the picker. OPNsense's pass
    // rules are floating and subnet-scoped, so asking there would request a value
    // nothing reads — and would imply semantics the rules don't have.
    function applyLanPickerVisibility() {
        ['a', 'b'].forEach(function (pfx) {
            var group = $('ipsec-' + pfx + '-lan-group');
            if (!group) { return; }
            var end = caps && caps[pfx];
            // Default to showing it: if capabilities haven't loaded we must not
            // silently hide a field the operator has to fill in.
            var uses = !end || end.uses_lan_iface !== false;
            group.style.display = uses ? '' : 'none';
            // Clear it when hiding, or leftover text keeps riding the payload and
            // can raise a blocking unsafe_value finding against a field the
            // operator can no longer see.
            if (!uses) { setLanValues(pfx, []); }
        });
    }

    function lanList(pfx) { return $('ipsec-' + pfx + '-lan-list'); }
    function lanCustom(pfx) { return $('ipsec-' + pfx + '-lan-custom'); }

    // Split the custom box on commas so several unpolled interfaces round-trip;
    // one text input otherwise caps you at a single name.
    function lanCustomNames(pfx) {
        var el = lanCustom(pfx);
        if (!el) { return []; }
        return (el.value || '').split(',').map(function (n) { return n.trim(); }).filter(Boolean);
    }

    // Render the checkbox list, preserving anything already ticked (hints can
    // land after an edit has restored the stored selection).
    function populateLanList(pfx, ifaces) {
        var box = lanList(pfx);
        if (!box) { return; }
        var keep = lanChecked(pfx);
        var lans = (ifaces || []).filter(function (i) { return i.is_lan; });
        if (!lans.length) {
            box.innerHTML = '<div style="color:var(--fwmon-text-faint);font-size:0.8rem;">No LAN interfaces detected — name them below.</div>';
            return;
        }
        box.innerHTML = lans.map(function (i) {
            // Show each interface's networks: that is what makes the choice
            // checkable against the protected subnets without guessing.
            var nets = (i.addresses || []).map(function (a) { return a.cidr; }).filter(Boolean);
            var hint = nets.length ? ' <span style="color:var(--fwmon-text-faint);">— ' + esc(nets.join(', ')) + '</span>' : '';
            var on = keep.indexOf(i.name) !== -1 ? ' checked' : '';
            return '<label class="iface-check"><input type="checkbox" value="' + esc(i.name) + '"' + on + '>' +
                '<span>' + esc(ifaceLabel(i)) + hint + '</span></label>';
        }).join('');
    }


    // ---- inside ports, derived from the subnets ---------------------------
    // FortiOS policies are interface-scoped by construction: a policy body with
    // "srcintf": [] is rejected outright, so the port genuinely has to be named
    // in the config. The OPERATOR is a different question. The wizard already
    // knows every interface's networks (it prints them next to each checkbox)
    // and it already knows the protected subnets, so making a human match the
    // two by eye is asking them to redo arithmetic the page has already done —
    // and getting it wrong is silent: the tunnel comes up and the traffic for
    // the unnamed port is dropped.
    //
    // So the ports carrying the protected subnets tick themselves.
    //
    // Three rules keep this honest:
    //   * ADD only, never untick — a port may legitimately carry traffic for a
    //     subnet the address table cannot show (anything routed downstream).
    //   * An explicit untick is remembered, so the box does not fight the
    //     operator by re-ticking on the next keystroke.
    //   * It runs on an ACTIVE subnet edit only, never on restore. Reopening a
    //     saved tunnel must not quietly change which ports its rules name.
    var lanUnticked = { a: {}, b: {} };

    function ipv4ToInt(ip) {
        var p = String(ip).split('.');
        if (p.length !== 4) { return null; }
        var n = 0;
        for (var i = 0; i < 4; i++) {
            var o = Number(p[i]);
            if (!isFinite(o) || o < 0 || o > 255 || p[i] === '') { return null; }
            n = (n * 256) + o;
        }
        return n;
    }

    // IPv4 only — an IPv6 CIDR returns null and simply does not auto-tick,
    // which leaves the operator exactly the manual control they have today
    // rather than guessing from a half-parsed address.
    function parseCidr4(s) {
        var m = /^\s*(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})\s*$/.exec(String(s || ''));
        if (!m) { return null; }
        var base = ipv4ToInt(m[1]), bits = Number(m[2]);
        if (base === null || bits < 0 || bits > 32) { return null; }
        var mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
        return { net: (base & mask) >>> 0, mask: mask, bits: bits };
    }

    // Overlap in EITHER direction, mirroring the server's containment test: the
    // port may hold the wider network or the narrower one.
    function cidrOverlaps(x, y) {
        if (!x || !y) { return false; }
        var m = x.bits < y.bits ? x.mask : y.mask;
        return ((x.net & m) >>> 0) === ((y.net & m) >>> 0);
    }

    function autoTickLANFromSubnets(pfx) {
        var box = lanList(pfx);
        if (!box) { return; }
        var end = caps && caps[pfx];
        if (end && end.uses_lan_iface === false) { return; } // vendor names no interface
        var ifaces = ((endpointHints[pfx] || {}).interfaces) || [];
        if (!ifaces.length) { return; }

        var wanted = subnetsOf(pfx).map(parseCidr4).filter(Boolean);
        if (!wanted.length) { return; }

        var carriers = {};
        ifaces.forEach(function (i) {
            if (!i.is_lan) { return; }
            (i.addresses || []).forEach(function (a) {
                var net = parseCidr4(a.cidr);
                if (!net) { return; }
                for (var k = 0; k < wanted.length; k++) {
                    if (cidrOverlaps(net, wanted[k])) { carriers[i.name] = true; return; }
                }
            });
        });

        var changed = false;
        Array.prototype.slice.call(box.querySelectorAll('input[type=checkbox]')).forEach(function (cb) {
            if (cb.checked || !carriers[cb.value] || lanUnticked[pfx][cb.value]) { return; }
            cb.checked = true;
            changed = true;
        });
        if (changed) { invalidate(); refreshDerived(); }
    }

    function lanChecked(pfx) {
        var box = lanList(pfx);
        if (!box) { return []; }
        return Array.prototype.slice.call(box.querySelectorAll('input[type=checkbox]'))
            .filter(function (cb) { return cb.checked; })
            .map(function (cb) { return cb.value; });
    }

    // The effective list: ticked boxes plus any custom names, deduped.
    function lanVals(pfx) {
        var out = [], seen = {};
        lanChecked(pfx).concat(lanCustomNames(pfx)).forEach(function (n) {
            if (n && !seen[n]) { seen[n] = true; out.push(n); }
        });
        return out;
    }

    // Restore a stored list on edit. Names the device still reports get ticked;
    // anything it no longer reports drops into the custom box rather than being
    // silently lost.
    function setLanValues(pfx, names) {
        var box = lanList(pfx);
        names = (names || []).filter(Boolean);
        var leftover = [];
        var boxes = box ? Array.prototype.slice.call(box.querySelectorAll('input[type=checkbox]')) : [];
        boxes.forEach(function (cb) { cb.checked = false; });
        names.forEach(function (n) {
            var hit = null;
            for (var i = 0; i < boxes.length; i++) { if (boxes[i].value === n) { hit = boxes[i]; break; } }
            if (hit) { hit.checked = true; } else { leftover.push(n); }
        });
        if (lanCustom(pfx)) { lanCustom(pfx).value = leftover.join(', '); }
    }

    function toggleCustom(pfx, kind) {
        var sel = $('ipsec-' + pfx + '-' + kind);
        var custom = $('ipsec-' + pfx + '-' + kind + '-custom');
        if (custom) { custom.style.display = (sel.value === '__custom__') ? '' : 'none'; }
    }

    // The effective interface name: the custom text when "Custom…" is selected,
    // otherwise the chosen option's value.
    function ifaceVal(pfx, kind) {
        var sel = $('ipsec-' + pfx + '-' + kind);
        if (sel.value === '__custom__') { return ($('ipsec-' + pfx + '-' + kind + '-custom').value || '').trim(); }
        return (sel.value || '').trim();
    }

    // Select a stored interface name when editing: pick the option if the device
    // still reports it, else fall back to Custom… with the name preserved.
    function setIfaceValue(pfx, kind, name) {
        var sel = $('ipsec-' + pfx + '-' + kind);
        name = name || '';
        var has = Array.prototype.some.call(sel.options, function (o) { return o.value === name; });
        if (name && has) { sel.value = name; }
        else if (name) { sel.value = '__custom__'; $('ipsec-' + pfx + '-' + kind + '-custom').value = name; }
        else { sel.value = ''; }
        toggleCustom(pfx, kind);
    }

    // Build the peer/public-IP dropdown options from the device's detected
    // interface addresses (each labelled WAN=public / LAN=private), plus the polled
    // management IP if no interface reports it.
    function addrOptions(h) {
        var opts = [], seen = {};
        (h.interfaces || []).forEach(function (i) {
            (i.addresses || []).forEach(function (a) {
                if (!a.ip || seen[a.ip]) { return; }
                seen[a.ip] = true;
                opts.push({ ip: a.ip, label: a.ip + ' — ' + i.name + ' (' + (a.public ? 'WAN' : 'LAN') + ')' });
            });
        });
        if (h.wan_ip && !seen[h.wan_ip]) {
            opts.push({ ip: h.wan_ip, label: h.wan_ip + ' — management IP' });
        }
        return opts;
    }

    function populatePeerSelect(pfx, h) {
        var sel = $('ipsec-' + pfx + '-peer');
        var opts = addrOptions(h);
        var html = opts.length ? '<option value="">— select —</option>' : '';
        html += opts.map(function (o) { return '<option value="' + esc(o.ip) + '">' + esc(o.label) + '</option>'; }).join('');
        html += '<option value="__custom__">Custom…</option>';
        sel.innerHTML = html;
        // Default to the detected public endpoint; if it isn't a listed address
        // (e.g. a NAT public IP), preload it into the Custom… field. With no
        // addresses at all, fall straight to Custom… so the field is usable.
        var suggested = h.suggested_peer_ip || '';
        if (!suggested && !opts.length) {
            sel.value = '__custom__';
            toggleCustom(pfx, 'peer');
        } else {
            setIfaceValue(pfx, 'peer', suggested);
        }
        // Behind-NAT default: a device monitored over an RFC1918 address dials out
        // from behind NAT, so its endpoint should be DYNAMIC — a private mgmt IP is
        // NOT a reachable static peer (that config black-holes the tunnel; the server
        // also blocks it as peer_unroutable). Set SYMMETRICALLY on each fresh device
        // pick (a public mgmt IP re-clears it — never leave a stale dynamic on when
        // the operator switches to a public device). loadTunnelIntoWizard applies a
        // stored tunnel's dynamic value AFTER this, so editing is unaffected.
        $('ipsec-' + pfx + '-dyn').checked = isPrivateIPv4(suggested);
    }

    // isPrivateIPv4 reports RFC1918 / CGNAT / loopback / link-local (mirrors the
    // server's isPrivate) so the wizard can spot a behind-NAT management address.
    function isPrivateIPv4(s) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((s || '').trim());
        if (!m) return false;
        var a = +m[1], b = +m[2];
        if (a > 255 || b > 255 || +m[3] > 255 || +m[4] > 255) return false;
        return a === 10 ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64/10
            a === 127 ||
            (a === 169 && b === 254);
    }

    // When the egress (WAN) interface changes, re-default the peer/public IP to that
    // interface's address (preferring a public one) — unless the operator has typed
    // a manual Custom… value, which we never clobber.
    function syncPeerToEgress(pfx) {
        var h = endpointHints[pfx];
        if (!h) { return; }
        if ($('ipsec-' + pfx + '-peer').value === '__custom__') { return; }
        var egress = ifaceVal(pfx, 'egress');
        var iface = (h.interfaces || []).find(function (i) { return i.name === egress; });
        if (!iface || !(iface.addresses || []).length) { return; }
        var pub = iface.addresses.find(function (a) { return a.public; });
        setIfaceValue(pfx, 'peer', (pub || iface.addresses[0]).ip);
    }

    function loadHints(pfx, deviceId) {
        var gen = ++hintGen[pfx]; // stamp this request; a newer device pick bumps it
        return AC.apiFetch(API + '/devices/' + deviceId + '/ipsec-hints').then(function (r) {
            if (gen !== hintGen[pfx]) { return; } // superseded by a later pick — ignore
            var h = (r && r.data) || {};
            endpointHints[pfx] = h;
            var ifaces = h.interfaces || [];
            populateIfaceSelect(pfx, 'egress', ifaces, h.suggested_egress);
            populateLanList(pfx, ifaces);
            populatePeerSelect(pfx, h);
            // Fill subnets when the box is empty OR still holds the prior auto-fill
            // (so re-picking a device refreshes them) — but never clobber an operator
            // edit.
            var box = $('ipsec-' + pfx + '-subnets');
            var suggested = (h.lan_subnets || []).join('\n');
            if (!box.value.trim() || box.value === lastHintSubnets[pfx]) {
                box.value = suggested;
            }
            lastHintSubnets[pfx] = suggested;
            // The checklist only just gained its interfaces; if subnets are
            // already present (auto-filled or restored-then-edited) the ports
            // they imply can be derived now.
            autoTickLANFromSubnets(pfx);
            // Hints mutate fields programmatically (no change event fires), so a hint
            // landing after a clean preview must re-gate Save.
            invalidate();
        }).catch(function (e) {
            if (gen !== hintGen[pfx]) { return; }
            fwmonLog.warn('[IPSec] interface hints failed for device ' + deviceId + ':', e);
            // Degrade: keep the management IP as a peer option so the operator isn't
            // forced to hand-type it, and leave interfaces editable via Custom….
            var d = deviceById(deviceId);
            var fh = { interfaces: [], wan_ip: (d && d.ip_address) || '', suggested_peer_ip: (d && d.ip_address) || '' };
            endpointHints[pfx] = fh;
            populateIfaceSelect(pfx, 'egress', [], '');
            // No polled interfaces: the checklist renders its "name them below"
            // note and the custom box carries the operator's entry.
            populateLanList(pfx, []);
            populatePeerSelect(pfx, fh);
            invalidate();
        });
    }

    function renderProfiles() {
        var host = $('ipsec-profiles');
        var items = (caps.profiles || []).map(function (p) {
            return '<label class="toggle-label" style="cursor:pointer;"><input type="radio" name="ipsec-profile" value="' + esc(p.name) + '"> <span>' + esc(p.label) + '</span></label>';
        }).join('');
        items += '<label class="toggle-label" style="cursor:pointer;"><input type="radio" name="ipsec-profile" value="custom"> <span>Custom</span></label>';
        host.innerHTML = items;
        var first = host.querySelector('input[type=radio]');
        if (first) { first.checked = true; }
        Array.prototype.forEach.call(host.querySelectorAll('input[type=radio]'), function (el) {
            el.addEventListener('change', function () {
                $('ipsec-custom-crypto').style.display = (el.value === 'custom' && el.checked) ? '' : 'none';
            });
        });
    }

    function fillSel(id, arr, fmt) {
        $(id).innerHTML = (arr || []).map(function (v) { return '<option value="' + esc(v) + '">' + esc(fmt ? fmt(v) : v) + '</option>'; }).join('');
    }

    function modeLabel(v) {
        return v === 'policy-based' ? 'Policy-based (specific selectors — no VTI)' : 'Route-based (VTI + routes)';
    }

    function populateCustom() {
        var a = caps.allowed;
        // Tunnel mode is negotiated: only modes BOTH ends support are offered. When
        // just one is available (e.g. FortiGate↔OPNsense → policy-based), lock it.
        fillSel('ipsec-mode', a.modes, modeLabel);
        $('ipsec-mode').disabled = (a.modes || []).length <= 1;
        $('ipsec-mode-note').textContent = (a.modes || []).length <= 1
            ? 'This vendor pair supports ' + modeLabel(a.modes[0]).toLowerCase() + ' only.'
            : '';
        fillSel('ipsec-ikever', a.ike_versions);
        fillSel('ipsec-enc', a.encryption);
        fillSel('ipsec-integ', [''].concat(a.integrity || []), function (v) { return v || '(none — required off for GCM)'; });
        fillSel('ipsec-prf', a.prf);
        fillSel('ipsec-dh', a.dh_groups, function (v) { return 'DH ' + v; });
        $('ipsec-pfs').disabled = !a.pfs;
    }

    function idTypeLabel(v) {
        return v === 'fqdn' ? 'FQDN' : v === 'ip' ? 'IP address' : v === 'keyid' ? 'Key ID' : v;
    }

    // populateIDTypes fills each end's IKE identity-type <select> from the
    // negotiated id_types (intersection of both ends' capabilities). Because
    // OPNsense no longer advertises keyid, a FortiGate↔OPNsense pair only offers
    // ip/fqdn. Defaults to FQDN (the cross-vendor string-identity default) and
    // preserves a still-valid prior choice across device changes.
    function populateIDTypes() {
        var types = (caps.allowed.id_types || []);
        if (!types.length) { types = ['fqdn']; }
        ['a', 'b'].forEach(function (pfx) {
            var id = 'ipsec-' + pfx + '-idtype', prev = $(id).value;
            fillSel(id, types, idTypeLabel);
            $(id).value = (types.indexOf(prev) >= 0) ? prev : (types.indexOf('fqdn') >= 0 ? 'fqdn' : types[0]);
        });
    }

    function idTypeVal(pfx) { return $('ipsec-' + pfx + '-idtype').value || 'fqdn'; }

    // setIdType selects a stored identity type IF it's an offered option; an
    // unsupported legacy value (e.g. keyid on a pair including OPNsense) is left at
    // the populateIDTypes default so the wizard can't re-submit an invalid type.
    function setIdType(pfx, type) {
        if (!type) return;
        var sel = $('ipsec-' + pfx + '-idtype');
        if (Array.prototype.some.call(sel.options, function (o) { return o.value === type; })) { sel.value = type; }
    }

    // ---- IKE identity: data-driven prefill + instant client-side pre-check -----
    // The SERVER (validation.go validateIdentity) is authoritative and gates Save
    // via the findings panel; the JS below just (a) auto-fills a guaranteed-valid
    // identity from real device data so the operator rarely types it, and (b)
    // mirrors the server rules for an inline error BEFORE Preview. idDirty tracks a
    // manual edit / a loaded stored value so the prefill never clobbers an override.
    var idDirty = { a: false, b: false };

    // isIPv4 / isIPv4Range mirror net.ParseIP / the server's isIPRange (first '-').
    function isIPv4(s) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
        if (!m) return false;
        for (var i = 1; i <= 4; i++) {
            // Match Go's net.ParseIP (client must never be STRICTER than the server):
            // it rejects >255 AND leading-zero octets like "01.2.3.4".
            if (parseInt(m[i], 10) > 255) return false;
            if (m[i].length > 1 && m[i].charAt(0) === '0') return false;
        }
        return true;
    }
    function looksIPv6(s) { return s.indexOf(':') >= 0 && /^[0-9a-fA-F:.]+$/.test(s) && (s.match(/:/g) || []).length >= 2; }
    function isIPv4Range(s) {
        var i = s.indexOf('-');
        if (i <= 0 || i >= s.length - 1) return false;
        return isIPv4(s.slice(0, i)) && isIPv4(s.slice(i + 1));
    }

    // sanitizeFqdnId turns a device name into a valid FQDN identity (mirrors the
    // server fqdn charset [A-Za-z0-9._-]): lower-case, collapse invalid runs to '-',
    // trim leading/trailing separators, cap at 63. A device name is never an IP.
    function sanitizeFqdnId(name) {
        var s = String(name || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
        return s.replace(/^[.\-_]+/, '').replace(/[.\-_]+$/, '').slice(0, 63);
    }

    // defaultIdentity: sanitized device name for fqdn, the end's WAN/peer IP for ip.
    function defaultIdentity(pfx, dev) {
        if (idTypeVal(pfx) === 'ip') { return ifaceVal(pfx, 'peer') || (dev && dev.ip_address) || ''; }
        var s = sanitizeFqdnId(dev && dev.name);
        // A device NAMED like an IP (e.g. "192.168.5.107") sanitizes to an IP-shaped
        // string, which the fqdn rules would then block — so the prefill must not
        // produce one. Fall back to a guaranteed-valid non-IP default.
        if (!s || isIPv4(s) || isIPv4Range(s)) { s = 'site-' + pfx; }
        return s;
    }

    // prefillIdentity fills the id input from device data unless the operator has
    // edited it (idDirty). Re-run on device change and on id-type change.
    function prefillIdentity(pfx) {
        if (idDirty[pfx]) { validateId(pfx); return; }
        var dev = deviceById($('ipsec-dev-' + pfx).value);
        if (!dev) return;
        var v = defaultIdentity(pfx, dev);
        if (v) { $('ipsec-' + pfx + '-id').value = v; }
        validateId(pfx);
    }

    // idError returns '' if the identity is valid, else a message — kept byte-for-
    // byte in step with the server rules (validation.go validateIdentity).
    function idError(pfx) {
        var val = $('ipsec-' + pfx + '-id').value.trim();
        if (val === '') return 'An IKE identity is required.';
        if (val.length > 63) return 'Maximum 63 characters (FortiGate limit).';
        if (idTypeVal(pfx) === 'ip') {
            return (isIPv4(val) || looksIPv6(val)) ? '' : 'Not a valid IP address.';
        }
        // fqdn
        if (isIPv4(val) || looksIPv6(val)) return 'An FQDN identity can’t be an IP address — switch the identity type to IP.';
        if (isIPv4Range(val)) return 'An IP address range isn’t a valid IKE identity.';
        if (!/^[A-Za-z0-9._-]+$/.test(val)) return 'Only letters, digits, dots, hyphens and underscores are allowed (no “:”, “@” or spaces).';
        return '';
    }
    function validateId(pfx) {
        var hint = $('ipsec-' + pfx + '-id-hint'), err = idError(pfx);
        hint.textContent = err;
        hint.style.display = err ? '' : 'none';
        return err === '';
    }

    function chosenProfile() {
        var r = document.querySelector('input[name=ipsec-profile]:checked');
        return r ? r.value : 'custom';
    }

    // Build the TunnelIntent the wizard POSTs. name/vti/inner/reqid are omitted —
    // the server hydrates them deterministically from the assigned tunnel ID.
    function collectIntent() {
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        var prof = chosenProfile();
        var ike, esp, ikever, ikeLife, childLife;
        if (prof === 'custom') {
            var enc = $('ipsec-enc').value;
            var isGCM = /gcm/.test(enc);
            ikever = $('ipsec-ikever').value;
            ike = { enc: enc, integ: isGCM ? '' : $('ipsec-integ').value, prf: $('ipsec-prf').value, dh: $('ipsec-dh').value };
            esp = { enc: enc, integ: isGCM ? '' : $('ipsec-integ').value, pfs: $('ipsec-pfs').checked ? $('ipsec-dh').value : '' };
            ikeLife = 86400; childLife = 3600;
        } else {
            var p = (caps.profiles || []).find(function (x) { return x.name === prof; });
            ike = p.ike; esp = p.esp; ikever = p.ike_version;
            ikeLife = p.ike_lifetime_secs; childLife = p.child_lifetime_secs;
        }
        function subnets(id) { return $(id).value.split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean); }
        function end(dev, pfx, life) {
            return {
                device_id: dev.id, vendor: vendorOf(dev),
                peer_ip: ifaceVal(pfx, 'peer'),
                dynamic: $('ipsec-' + pfx + '-dyn').checked,
                egress_iface: ifaceVal(pfx, 'egress'),
                lan_ifaces: lanVals(pfx),
            // Mirror the head into the legacy scalar so anything still reading it
            // (older builds, stored-intent diffs) sees a consistent value.
            lan_iface: lanVals(pfx)[0] || '',
                local_id: { type: idTypeVal(pfx), value: $('ipsec-' + pfx + '-id').value.trim() },
                protected_subnets: subnets('ipsec-' + pfx + '-subnets'),
                gateway: $('ipsec-' + pfx + '-gateway').value.trim(),
                child_lifetime_secs: life, mss_clamp: 1350
            };
        }
        // Offset the two child-SA lifetimes so the ends never rekey simultaneously
        // (duplicate-SA avoidance). The dynamic/behind-NAT end must initiate, so it
        // owns rekey with the shorter lifetime; the peer gets the longer one.
        var aDyn = $('ipsec-a-dyn').checked, bDyn = $('ipsec-b-dyn').checked;
        var lifeA = childLife, lifeB = childLife;
        if (bDyn && !aDyn) { lifeA = childLife * 2; }
        else { lifeB = childLife * 2; } // A initiates, both static, or both dynamic → B longer
        return {
            id: parseInt($('ipsec-edit-id').value, 10) || 0,
            enabled: true, ike_version: ikever, mode: ($('ipsec-mode') && $('ipsec-mode').value) || 'route-based',
            ike: ike, esp: esp, ike_lifetime_secs: ikeLife,
            dpd: { delay_secs: 30, timeout_secs: 0 },
            psk: $('ipsec-psk').value, // blank = auto-generate on save
            disabled_paths: Object.keys(disabledPaths),
            ends: [end(a, 'a', lifeA), end(b, 'b', lifeB)]
        };
    }


    // ---- selectively disabled paths --------------------------------------
    // The selectors are otherwise the full cross product of the two ends'
    // subnets, which hands every network on one side a path to every network on
    // the other — a user VLAN reaching the far side's management net purely
    // because both were listed.
    //
    // Keys mirror the server exactly: canonical "aCIDR|bCIDR" in tunnel A|B
    // orientation. Canonical so that reformatting a subnet keeps a path
    // disabled rather than silently re-enabling it (fail closed), and so the
    // two sides agree about which pair a key names.
    var disabledPaths = {};

    function ipToInt(ip) {
        var p = String(ip).split('.');
        if (p.length !== 4) { return null; }
        var n = 0;
        for (var i = 0; i < 4; i++) {
            var o = Number(p[i]);
            if (!isFinite(o) || o < 0 || o > 255 || p[i] === '') { return null; }
            n = (n * 256) + o;
        }
        return n;
    }

    // Canonical network form, matching Go's net.IPNet.String(). "" when it does
    // not parse — which never matches a key, so the path stays ENABLED, bounded
    // by the server's subnet_invalid block.
    function canonNet(cidr) {
        var m = /^\s*(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})\s*$/.exec(String(cidr || ''));
        if (!m) { return ''; }
        var base = ipToInt(m[1]), bits = Number(m[2]);
        if (base === null || bits < 0 || bits > 32) { return ''; }
        var mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
        var net = (base & mask) >>> 0;
        return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + bits;
    }

    function pathKey(aNet, bNet) {
        var ca = canonNet(aNet), cb = canonNet(bNet);
        return (ca && cb) ? ca + '|' + cb : '';
    }

    function pathEnabled(aNet, bNet) {
        var k = pathKey(aNet, bNet);
        return !k || !disabledPaths[k];
    }

    function togglePath(aNet, bNet) {
        var k = pathKey(aNet, bNet);
        if (!k) { return; }
        if (disabledPaths[k]) { delete disabledPaths[k]; } else { disabledPaths[k] = true; }
        pruneDisabledPaths();
        invalidate();
        refreshDerived();
    }

    // Drop keys naming subnets that are no longer listed. An operator who edits
    // a subnet has not asked to keep a rule about a network they removed, and a
    // stale key would be invisible — nothing on screen would explain it.
    function pruneDisabledPaths() {
        var live = {};
        subnetsOf('a').forEach(function (an) {
            subnetsOf('b').forEach(function (bn) {
                var k = pathKey(an, bn);
                if (k) { live[k] = true; }
            });
        });
        Object.keys(disabledPaths).forEach(function (k) {
            if (!live[k]) { delete disabledPaths[k]; }
        });
    }



    // ---- the link schematic ---------------------------------------------
    // The wizard's spine: what is being built, drawn as it is typed. Every
    // failure this feature shipped was a mismatch the form never showed.

    function subnetsOf(pfx) {
        return $('ipsec-' + pfx + '-subnets').value.split(/[\n,]+/)
            .map(function (s) { return s.trim(); }).filter(Boolean);
    }

    function modeVal() { return ($('ipsec-mode') && $('ipsec-mode').value) || 'route-based'; }

    // trafficMatrix is PURE — the schematic and the Verify matrix both read it, so
    // the two can never disagree.
    //
    // It must be mode-aware or it lies. fgPhase2Pairs fans out one phase2 per
    // (local x remote) pair ONLY in policy-based mode; route-based renders a SINGLE
    // 0.0.0.0/0 <-> 0.0.0.0/0 child and steers with per-subnet static routes.
    // Drawing 4 lanes against a device holding 1 child would recreate the exact
    // UI-says-N/device-holds-1 confusion this whole saga was about.
    function trafficMatrix(aNets, bNets, mode) {
        if (mode === 'route-based') {
            return {
                routed: true,
                lanes: [{ a: '0.0.0.0/0', b: '0.0.0.0/0' }],
                childCount: (aNets.length && bNets.length) ? 1 : 0,
                aRoutes: bNets, // A installs routes TO B's networks
                bRoutes: aNets
            };
        }
        var lanes = [], on = 0;
        aNets.forEach(function (an) {
            bNets.forEach(function (bn) {
                var en = pathEnabled(an, bn);
                if (en) { on++; }
                lanes.push({ a: an, b: bn, enabled: en });
            });
        });
        // childCount counts ENABLED lanes only: it is what the device will
        // actually hold, and overstating it is the UI-lies-about-the-device
        // failure this whole area exists to avoid.
        return { routed: false, lanes: lanes, childCount: on, total: lanes.length, aRoutes: [], bRoutes: [] };
    }

    // Findings paint the schematic. Keyed by "end:subject" so two mismatches on one
    // end stay distinguishable — which is exactly why Subject is on the wire.
    var laneFlags = {};

    function laneFlagFor(end, net) {
        return laneFlags[end + ':' + net] || null;
    }

    function nodeHtml(pfx, dev) {
        var dyn = $('ipsec-' + pfx + '-dyn').checked;
        var addr = ifaceVal(pfx, 'peer');
        var egress = ifaceVal(pfx, 'egress');
        var meta = [];
        if (egress) meta.push('out via ' + esc(egress));
        if (dyn) meta.push('behind NAT · dials out');
        return '<div class="ipsec-node">' +
            '<div class="ipsec-node-vendor">' + esc(vendorOf(dev)) + '</div>' +
            '<div class="ipsec-node-name">' + esc(dev.name) + '</div>' +
            '<div class="ipsec-node-addr">' +
                esc(addr || (dyn ? 'no fixed address' : '—')) + '</div>' +
            (meta.length ? '<div class="ipsec-node-meta">' + meta.join(' · ') + '</div>' : '') +
            '</div>';
    }

    function renderSchematic() {
        var host = $('ipsec-schematic');
        if (!host) return;
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        if (!a || !b || !caps) { host.innerHTML = ''; renderSummary(); return; }

        var mode = modeVal();
        var spanLabel = ($('ipsec-ikever') ? $('ipsec-ikever').value : 'ikev2') + ' · ' +
            (mode === 'route-based' ? 'route-based' : 'policy-based');

        // The link only. The pairs are their own view now — see renderPaths.
        host.innerHTML = '<div class="ipsec-link">' +
            nodeHtml('a', a) +
            '<div class="ipsec-span">' +
                '<div class="ipsec-span-label">' + esc(spanLabel) + '</div>' +
                '<div class="ipsec-span-rule"></div>' +
            '</div>' +
            nodeHtml('b', b) +
            '</div>';
        renderSummary();
        renderPaths();
    }

    // The header spine: ONE bounded line. It never lists pairs, which is what
    // stops the header growing with the configuration — the failure that made
    // the wizard feel unscrollable before the diagram got its own view. The
    // TOTAL lives here rather than in the scrolling list, so the number that
    // says whether the tunnel is what you intended is always on screen.
    function renderSummary() {
        var host = $('ipsec-summary');
        if (!host) return;
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        if (!a || !b || !caps) { host.innerHTML = ''; return; }

        var m = trafficMatrix(subnetsOf('a'), subnetsOf('b'), modeVal());
        var count;
        if (m.routed) {
            count = 'one 0.0.0.0/0 selector, steered by route';
        } else if (!m.lanes.length) {
            count = 'no networks yet';
        } else {
            var tot = m.total != null ? m.total : m.lanes.length;
            // Both vocabularies: the plain phrase, plus the term the devices
            // themselves print, so it is checkable against `diagnose vpn tunnel
            // list` / `swanctl`. Never "tunnels" — conflating children with
            // tunnels is the confusion that cost days.
            count = (m.childCount === tot ? tot + ' path' + (tot === 1 ? '' : 's')
                                          : m.childCount + ' of ' + tot + ' paths') +
                ' · ' + m.childCount + ' child SA' + (m.childCount === 1 ? '' : 's') + ' (phase2)';
        }
        host.innerHTML = '<strong>' + esc(a.name) + '</strong> ↔ <strong>' + esc(b.name) + '</strong>' +
            ' <span class="ipsec-summary-count">· ' + esc(count) + '</span>';
    }

    // The paths view. Grouped by the site-A network because a flat list is the
    // PRODUCT of both ends' subnet counts — five a side is twenty-five rows —
    // and grouping makes "everything from this network is off" visible without
    // counting.
    // renderPaths replaces the list wholesale, which destroys the very button
    // the operator just activated: focus falls to <body>, and openModal's focus
    // trap then sends the next Tab back to the TOP of the dialog. Toggling five
    // of twenty-five rows would mean re-traversing the wizard five times — which
    // would make "keyboard reachable" true in principle and hostile in practice.
    // Remember what was focused by its DATA, since the node itself does not
    // survive, and restore it afterwards.
    function focusedPathRef() {
        var el = document.activeElement;
        if (!el || !el.closest || !el.closest('#ipsec-paths')) { return null; }
        var btn = el.closest('[data-action]');
        if (!btn) { return null; }
        return { action: btn.dataset.action, a: btn.dataset.a, b: btn.dataset.b };
    }

    function restorePathFocus(ref) {
        if (!ref) { return; }
        var sel = '#ipsec-paths [data-action="' + ref.action + '"]' +
            '[data-a="' + (window.CSS && CSS.escape ? CSS.escape(ref.a) : ref.a) + '"]';
        if (ref.b) { sel += '[data-b="' + (window.CSS && CSS.escape ? CSS.escape(ref.b) : ref.b) + '"]'; }
        var el;
        try { el = document.querySelector(sel); } catch (e) { el = null; }
        if (el && el.focus) { el.focus(); }
    }

    function renderPaths() {
        var host = $('ipsec-paths');
        if (!host) return;
        var keepFocus = focusedPathRef();
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        if (!a || !b || !caps) {
            host.innerHTML = '<div class="ipsec-paths-empty">Pick both firewalls to see what this tunnel will carry.</div>';
            return;
        }

        var m = trafficMatrix(subnetsOf('a'), subnetsOf('b'), modeVal());
        if (!m.lanes.length || !subnetsOf('a').length || !subnetsOf('b').length) {
            host.innerHTML = '<div class="ipsec-paths-empty">Add the networks each site shares to see what this tunnel will carry.</div>';
            return;
        }
        if (m.routed) {
            // Route-based negotiates ONE 0.0.0.0/0 child and steers by route, so
            // there is no per-path selector to switch off. Offering a control the
            // device cannot honour is the UI-lies-about-the-device failure this
            // area is scarred by.
            host.innerHTML = '<div class="ipsec-paths-empty">Route-based: the devices negotiate a single ' +
                '0.0.0.0/0 selector and steer with static routes, so individual paths cannot be ' +
                'switched off here. ' + esc(a.name) + ' installs ' + m.aRoutes.length + ' route' +
                (m.aRoutes.length === 1 ? '' : 's') + '; ' + esc(b.name) + ' installs ' + m.bRoutes.length + '.</div>';
            return;
        }

        // Preserve enumeration order; group on the site-A network.
        var order = [], byA = {};
        m.lanes.forEach(function (l) {
            if (!byA[l.a]) { byA[l.a] = []; order.push(l.a); }
            byA[l.a].push(l);
        });

        var html = order.map(function (an) {
            var group = byA[an];
            var on = group.filter(function (l) { return l.enabled !== false; }).length;
            // aria-pressed on the group is genuinely tri-state: "mixed" is the
            // honest answer for a partly-enabled group.
            var gp = on === group.length ? 'true' : (on === 0 ? 'false' : 'mixed');
            var rows = group.map(function (l) {
                var flag = laneFlagFor(0, l.a) || laneFlagFor(1, l.b);
                var off = l.enabled === false;
                return '<button type="button" class="ipsec-path' + (flag ? ' is-warn' : '') + '"' +
                    ' aria-pressed="' + (off ? 'false' : 'true') + '"' +
                    ' data-action="ipsec-path-toggle" data-a="' + esc(l.a) + '" data-b="' + esc(l.b) + '"' +
                    ' title="' + (off ? 'Not carried — click to carry it' : 'Carried — click to stop carrying it') + '">' +
                    '<span class="ipsec-path-net">' + esc(l.a) + '</span>' +
                    '<span class="ipsec-path-link">↔</span>' +
                    '<span class="ipsec-path-net r">' + esc(l.b) + '</span>' +
                    '<span class="ipsec-path-state">' + (off ? 'off' : 'on') + '</span>' +
                    (flag ? '<span class="ipsec-path-flag">' + esc(flag) + '</span>' : '') +
                    '</button>';
            }).join('');
            return '<div class="ipsec-paths-group">' +
                '<button type="button" class="ipsec-paths-head" aria-pressed="' + gp + '"' +
                    ' data-action="ipsec-group-toggle" data-a="' + esc(an) + '"' +
                    ' title="Switch every path from this network on or off">' +
                    '<span>' + esc(an) + '</span>' +
                    '<span class="ipsec-paths-head-count">' + on + ' of ' + group.length + '</span>' +
                '</button>' + rows + '</div>';
        }).join('');
        host.innerHTML = html;
        restorePathFocus(keepFocus);
    }

    // Whole-group toggle: one click instead of twenty-five when a network should
    // stop being carried. All-on turns the group off; anything else turns it on,
    // so a partly-disabled group resolves toward carrying rather than dropping.
    function toggleGroup(aNet) {
        var bNets = subnetsOf('b');
        if (!bNets.length) return;
        var allOn = bNets.every(function (bn) { return pathEnabled(aNet, bn); });
        bNets.forEach(function (bn) {
            var k = pathKey(aNet, bn);
            if (!k) return;
            if (allOn) { disabledPaths[k] = true; } else { delete disabledPaths[k]; }
        });
        pruneDisabledPaths();
        invalidate();
        refreshDerived();
    }


    // The Verify matrix is the same data as a table — one source, so the two views
    // can never disagree about how many children the device will hold.
    function renderMatrix() {
        var host = $('ipsec-matrix');
        if (!host) return;
        var a = deviceById($('ipsec-dev-a').value), b = deviceById($('ipsec-dev-b').value);
        if (!a || !b) { host.innerHTML = ''; return; }
        var aNets = subnetsOf('a'), bNets = subnetsOf('b');
        var m = trafficMatrix(aNets, bNets, modeVal());
        // Route-based ALWAYS yields one 0.0.0.0/0 lane, so `!m.lanes.length` alone
        // would render "one child SA carries everything" for a tunnel with an empty
        // side that will carry nothing — and contradict the schematic, which shows
        // its empty state. Both views must agree; that is the point of sharing
        // trafficMatrix.
        if (!m.lanes.length || !aNets.length || !bNets.length) {
            host.innerHTML = '<p class="ipsec-matrix-cap">Both sites need at least one network before this tunnel carries anything.</p>';
            return;
        }

        // The status cell stays TERSE. The full sentence already appears twice —
        // on the lane in the schematic and on the field that caused it — and a
        // paragraph inside a table cell wrecks the row rhythm that makes the
        // matrix scannable in the first place.
        var rows = m.lanes.map(function (l) {
            var flag = laneFlagFor(0, l.a) || laneFlagFor(1, l.b);
            // A switched-off path must read as NOT carried here too. This is the
            // last screen before deploy, and the schematic and this table share
            // trafficMatrix precisely so they cannot disagree — saying "carried"
            // on a pair the device will hold no selector for is the
            // UI-lies-about-the-device failure in its most consequential place.
            var off = l.enabled === false;
            var status = off ? 'not carried' : (flag ? '⚠ see Paths' : 'carried');
            var cls = off ? ' class="is-off"' : (flag ? ' class="is-warn"' : '');
            return '<tr' + cls + '><td>' + esc(l.a) + '</td><td>' + esc(l.b) + '</td>' +
                '<td>' + status + '</td></tr>';
        }).join('');
        var cap = m.routed
            ? 'Route-based: one 0.0.0.0/0 child SA carries everything; the networks below are steered by static routes.'
            : m.childCount + ' child SA' + (m.childCount === 1 ? '' : 's') + ' (phase2) will exist on each device.';
        host.innerHTML = '<div style="overflow-x:auto;"><table>' +
            '<thead><tr><th>' + esc(a.name) + '</th><th>' + esc(b.name) + '</th><th>Status</th></tr></thead>' +
            '<tbody>' + rows + '</tbody></table></div>' +
            '<p class="ipsec-matrix-cap">' + cap + '</p>' +
            (m.routed ? '<p class="ipsec-matrix-cap">' + esc(a.name) + ' routes: ' +
                esc(m.aRoutes.join(', ') || '—') + ' · ' + esc(b.name) + ' routes: ' +
                esc(m.bRoutes.join(', ') || '—') + '</p>' : '');
    }

    // ---- findings anchored to the field that caused them ------------------
    // The server sends a stable `code` on every finding; this maps it to the
    // control the operator has to edit. Anything unmapped still renders in the
    // summary — findings are never lost.
    // Codes are taken verbatim from internal/ipsec/validation.go — an entry that
    // does not match a real emitted code is dead weight, and a real code that is
    // missing here silently falls back to the summary.
    var ANCHOR = {
        lan_missing: 'lan', lan_subnet_mismatch: 'lan',
        egress_missing: 'egress',
        peer_ip_invalid: 'peer', peer_unroutable: 'peer', peer_private: 'peer',
        id_missing: 'id', id_too_long: 'id', id_fqdn_is_ip: 'id',
        id_fqdn_is_range: 'id', id_fqdn_charset: 'id', id_ip_invalid: 'id',
        subnet_invalid: 'subnets', too_many_subnets: 'subnets', selectors_missing: 'subnets',
        default_route_over_vti: 'subnets', self_lockout: 'subnets',
        gateway_invalid: 'gateway',
        psk_invalid: 'psk'
    };

    // reserved_token is raised for BOTH the PSK (tunnel-wide) and an IKE identity
    // (per-end) — the same code, two different fields. A flat code→slot map would
    // drop an identity error onto the PSK box, so it is resolved by whether the
    // finding carries an end.
    function slotFor(code, hasEnd) {
        if (code === 'reserved_token') { return hasEnd ? 'id' : 'psk'; }
        return ANCHOR[code];
    }

    function clearAnchors() {
        laneFlags = {};
        var nodes = document.querySelectorAll('#ipsec-wizard-form .ipsec-anchor');
        Array.prototype.forEach.call(nodes, function (n) { n.innerHTML = ''; });
        ['ipsec-tab-design', 'ipsec-tab-diagram'].forEach(function (id) {
            var t = $(id);
            if (t) t.classList.remove('has-block', 'has-warn');
        });
    }

    // An anchored finding is worse than a summarised one if the operator cannot
    // SEE it. Most anchors sit inside "Connection details" (<details>, closed) or
    // the crypto disclosure (hidden), and inserting into a collapsed subtree while
    // the summary says "each is marked on the field it affects" sends the operator
    // to Design to look for a message that is not on screen — exactly the silent
    // failure this redesign exists to remove. So reveal every container on the way
    // up before the finding lands in it.
    function revealAnchor(host) {
        var el = host;
        while (el && el.id !== 'ipsec-wizard-form') {
            if (el.tagName === 'DETAILS') { el.open = true; }
            if (el.id === 'ipsec-crypto-detail' && el.hidden) {
                el.hidden = false;
                var tgl = document.querySelector('[data-action="ipsec-crypto-toggle"]');
                if (tgl) { tgl.setAttribute('aria-expanded', 'true'); tgl.textContent = 'done'; }
            }
            el = el.parentElement;
        }
    }

    function renderFindings(findings) {
        clearAnchors();
        var list = findings || [];
        var block = list.filter(function (f) { return f.severity === 'block'; });
        var warn = list.filter(function (f) { return f.severity === 'warn'; });
        var summary = [];

        list.forEach(function (f) {
            if (f.severity !== 'block' && f.severity !== 'warn') return;
            // End A is 0, which is FALSY — `if (f.end)` would drop every end-A
            // anchor, i.e. half the findings, on the end that is usually the
            // FortiGate. The type check is load-bearing.
            var hasEnd = typeof f.end === 'number';
            var slot = slotFor(f.code, hasEnd);
            if (f.subject && hasEnd) { laneFlags[f.end + ':' + f.subject] = f.message; }
            if (!slot || (slot !== 'psk' && !hasEnd)) { summary.push(f); return; }

            var id = slot === 'psk' ? 'psk' : (f.end === 0 ? 'a-' : 'b-') + slot;
            var host = document.querySelector('#ipsec-wizard-form .ipsec-anchor[data-anchor="' + id + '"]');
            if (!host) { summary.push(f); return; }
            var cls = 'ipsec-anchor-item' + (f.severity === 'warn' ? ' is-warn' : '');
            host.insertAdjacentHTML('beforeend', '<div class="' + cls + '">' + esc(f.message) + '</div>');
            revealAnchor(host);
        });

        var html = summary.map(function (f) {
            return '<div class="ipsec-finding ' + (f.severity === 'block' ? 'is-block' : 'is-warn') + '">' +
                (f.severity === 'block' ? '✕ ' : '⚠ ') + esc(f.message) + '</div>';
        }).join('');
        if (!block.length && !warn.length) {
            html = '<div class="ipsec-finding is-ok">✓ No issues — ready to save.</div>';
        } else if (!html) {
            // Everything was anchored; say so rather than leaving the panel blank.
            html = '<div class="ipsec-finding' + (block.length ? ' is-block' : ' is-warn') + '">' +
                block.length + ' blocking, ' + warn.length + ' warning — each is marked on the field it affects.</div>';
        }
        $('ipsec-findings').innerHTML = html;

        // A phase holding a problem says so on its own tab, so a finding anchored
        // on the Design panel is discoverable from Verify.
        var tab = $('ipsec-tab-design');
        if (tab) {
            tab.classList.toggle('has-block', block.length > 0);
            tab.classList.toggle('has-warn', block.length === 0 && warn.length > 0);
        }
        // Same for Paths — but only when that view actually SHOWS the flagged
        // rows. Route-based renders one explanatory paragraph and no rows, so a
        // badge there would send the operator to a screen with nothing on it.
        var ptab = $('ipsec-tab-diagram');
        if (ptab) {
            var showsRows = modeVal() !== 'route-based' && Object.keys(laneFlags).length > 0;
            // Severity matters: default_route_over_vti is a BLOCK, and badging it
            // amber would understate what the Design tab shows in red.
            var laneBlock = showsRows && block.some(function (f) {
                return f.subject && laneFlags[f.end + ':' + f.subject];
            });
            ptab.classList.toggle('has-block', laneBlock);
            ptab.classList.toggle('has-warn', showsRows && !laneBlock);
        }
        renderSchematic();
        renderMatrix();
        return block.length === 0;
    }

    function renderPreviewPanes(ends, provisional) {
        // The server now answers 200 with findings and NO ends when the intent
        // cannot be rendered yet (it used to 400 and the findings were lost). Say
        // so, rather than leaving a blank panel that reads like a failed request.
        if (!ends || !ends.length) {
            $('ipsec-preview-panes').innerHTML =
                '<p class="ipsec-matrix-cap">No configuration to show yet — resolve the items above and validate again.</p>';
            return;
        }
        var note = provisional ? '<div style="color:var(--fwmon-text-mute);font-size:0.72rem;margin-bottom:4px;">Provisional — tunnel name, VTI addressing, and reqid are assigned on Save.</div>' : '';
        $('ipsec-preview-panes').innerHTML = (ends || []).map(function (e) {
            return '<div style="min-width:0;">' + note +
                '<div style="font-size:0.78rem;font-weight:600;color:var(--fwmon-text-dim);margin-bottom:4px;">End ' + (e.end === 0 ? 'A' : 'B') + ' — ' + esc(e.vendor) + ' (' + e.steps + ' steps)</div>' +
                '<pre style="overflow-x:auto;background:var(--fwmon-bg);border:1px solid var(--fwmon-border);border-radius:6px;padding:10px;font-size:0.72rem;max-height:320px;">' + esc(e.preview) + '</pre></div>';
        }).join('');
    }

    function preview() {
        var intent;
        try { intent = collectIntent(); } catch (e) { AC.showError('Complete the endpoints first'); return; }
        AC.apiFetch(API + '/ipsec/preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: intent }).then(function (r) {
            var d = (r && r.data) || {};
            $('ipsec-preview-section').style.display = '';
            var ok = renderFindings(d.validation);
            renderPreviewPanes(d.ends, d.provisional);
            lastPreviewOK = ok;
            $('ipsec-save-btn').disabled = !ok;
            updateFootNote();
        }).catch(function (e) { AC.showError('Preview failed: ' + e.message); });
    }

    function save() {
        if (!lastPreviewOK) { AC.showError('Run Validate and resolve any blockers first'); return; }
        var intent = collectIntent();
        var id = parseInt($('ipsec-edit-id').value, 10) || 0;
        var url = id ? (API + '/ipsec/tunnels/' + id) : (API + '/ipsec/tunnels');
        AC.apiFetch(url, { method: id ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: intent }).then(function (r) {
            var newId = (r && r.data && r.data.intent && r.data.intent.id) || id;
            AC.showSuccess(id ? 'Tunnel updated' : 'Tunnel draft saved');
            // Re-fetch the AUTHORITATIVE preview (real name/VTI/reqid) and show it.
            if (newId) {
                AC.apiFetch(API + '/ipsec/tunnels/' + newId + '/preview').then(function (pr) {
                    var d = (pr && pr.data) || {};
                    renderFindings(d.validation);
                    renderPreviewPanes(d.ends, false);
                }).catch(function () {});
                $('ipsec-edit-id').value = newId;
                $('ipsec-wizard-title').textContent = 'Edit IPSec Tunnel';
            }
            loadTunnels();
        }).catch(function (e) { AC.showError('Save failed: ' + e.message); });
    }

    function loadTunnelIntoWizard(id) {
        AC.apiFetch(API + '/ipsec/tunnels/' + id).then(function (r) {
            var t = r && r.data && r.data.intent;
            if (!t) return;
            $('ipsec-dev-a').value = t.ends[0].device_id;
            $('ipsec-dev-b').value = t.ends[1].device_id;
            // Populate crypto + endpoint fields only AFTER capabilities load, so the
            // stored proposals are restored (not silently reset) and peer prefill
            // doesn't clobber the saved values.
            onDevicesChosen().then(function () {
                restoreCrypto(t);
                setIfaceValue('a', 'peer', t.ends[0].peer_ip); setIfaceValue('b', 'peer', t.ends[1].peer_ip);
                $('ipsec-a-dyn').checked = !!t.ends[0].dynamic; $('ipsec-b-dyn').checked = !!t.ends[1].dynamic;
                setIfaceValue('a', 'egress', t.ends[0].egress_iface); setIfaceValue('b', 'egress', t.ends[1].egress_iface);
                setLanValues('a', t.ends[0].lan_ifaces || (t.ends[0].lan_iface ? [t.ends[0].lan_iface] : [])); setLanValues('b', t.ends[1].lan_ifaces || (t.ends[1].lan_iface ? [t.ends[1].lan_iface] : []));
                // Restore the stored selection BEFORE the subnets, so the first
                // schematic render already reflects it.
                disabledPaths = {};
                (t.disabled_paths || []).forEach(function (k) { if (k) { disabledPaths[k] = true; } });
                $('ipsec-a-subnets').value = (t.ends[0].protected_subnets || []).join('\n');
                $('ipsec-b-subnets').value = (t.ends[1].protected_subnets || []).join('\n');
                $('ipsec-a-id').value = (t.ends[0].local_id || {}).value || ''; $('ipsec-b-id').value = (t.ends[1].local_id || {}).value || '';
                // Restore the stored identity type into the select (options populated by
                // onDevicesChosen above); an unsupported stored type (legacy keyid) falls
                // back to the populateIDTypes default (fqdn).
                setIdType('a', (t.ends[0].local_id || {}).type); setIdType('b', (t.ends[1].local_id || {}).type);
                // Stored identities are user data — mark dirty so a later type change
                // doesn't overwrite them with the device-name default; still validate.
                idDirty.a = true; idDirty.b = true; validateId('a'); validateId('b');
                $('ipsec-a-gateway').value = t.ends[0].gateway || ''; $('ipsec-b-gateway').value = t.ends[1].gateway || '';
                // PSK stays masked (unchanged on save); Save stays gated until preview.
                lastPreviewOK = false; $('ipsec-save-btn').disabled = true;
                // Editing a custom-crypto tunnel must SHOW the crypto controls —
                // restoreCrypto force-shows #ipsec-custom-crypto, so the enclosing
                // disclosure has to open with it or the operator sees nothing.
                if ($('ipsec-custom-crypto').style.display !== 'none') {
                    $('ipsec-crypto-detail').hidden = false;
                    var tgl = document.querySelector('[data-action="ipsec-crypto-toggle"]');
                    if (tgl) { tgl.setAttribute('aria-expanded', 'true'); tgl.textContent = 'done'; }
                }
                refreshDerived();
            });
        }).catch(function (e) { AC.showError('Failed to load tunnel: ' + e.message); });
    }

    function del(id) {
        AC.confirm('Delete this tunnel draft?', { title: 'Delete tunnel?', confirmLabel: 'Delete', danger: true }).then(function (ok) {
            if (!ok) return;
            AC.apiFetch(API + '/ipsec/tunnels/' + id, { method: 'DELETE' }).then(function () {
                AC.showSuccess('Tunnel deleted'); loadTunnels();
            }).catch(function (e) { AC.showError('Delete failed: ' + e.message); });
        });
    }

    // ---- phases ----------------------------------------------------------
    // BOTH panels stay mounted; one is hidden. Nothing is ever re-rendered per
    // phase: collectIntent reads ~25 controls straight from the DOM, wire() binds
    // direct listeners once, and loadHints lands async into targets that must
    // still exist. An innerHTML-swapping step machine breaks all three.
    var phase = 'design';

    function setPhase(next) {
        // Gate: both devices picked AND capabilities loaded. Without caps,
        // renderProfiles never ran and Verify would render with zero profile
        // radios — chosenProfile() would then silently report 'custom'.
        if (next === 'verify' && !caps) {
            AC.showError('Pick both firewalls first.');
            return;
        }
        phase = next;
        // Ordered, so Next/Back are derived rather than hardcoded — a third
        // phase would otherwise need every one of these rewritten again.
        var ORDER = ['design', 'diagram', 'verify'];
        var at = ORDER.indexOf(next);
        if (at < 0) { at = 0; next = phase = 'design'; }

        ORDER.forEach(function (p) {
            var panel = $('ipsec-panel-' + p), tab = $('ipsec-tab-' + p);
            if (panel) { panel.style.display = p === next ? '' : 'none'; }
            if (tab) { tab.setAttribute('aria-current', p === next ? 'step' : 'false'); }
        });

        // The Paths view fills the dialog, which needs a DEFINITE height —
        // max-height alone leaves it content-sized and every flex child below
        // collapses to auto. Toggled, not just added, so the other two phases
        // keep sizing to their content.
        var wiz = document.querySelector('.ipsec-wiz');
        if (wiz) { wiz.classList.toggle('phase-diagram', next === 'diagram'); }

        var last = at === ORDER.length - 1;
        $('ipsec-next-btn').style.display = last ? 'none' : '';
        $('ipsec-back-btn').style.display = at === 0 ? 'none' : '';
        $('ipsec-preview-btn').style.display = last ? '' : 'none';
        $('ipsec-save-btn').style.display = last ? '' : 'none';
        if (!last) {
            $('ipsec-next-btn').dataset.phase = ORDER[at + 1];
            $('ipsec-next-btn').textContent = next === 'design' ? 'Review the paths' : 'Check it over';
        }
        if (at > 0) { $('ipsec-back-btn').dataset.phase = ORDER[at - 1]; }

        if (next === 'diagram') { renderPaths(); }
        if (last) {
            // A mid-flow device change silently rebuilds the crypto radios, so the
            // matrix is recomputed on every entry rather than cached.
            renderMatrix();
        }
        updateFootNote();
        var panel = $('ipsec-panel-' + next);
        if (panel && panel.focus) panel.focus();
    }

    // Say WHY Save is disabled. invalidate() kills it on every keystroke, and
    // today it does so with no on-screen reason at all.
    function updateFootNote() {
        var note = $('ipsec-foot-note');
        if (!note) return;
        // Only Verify shows Validate/Save, so only Verify may talk about them —
        // naming a button that is not on screen is worse than saying nothing.
        if (phase !== 'verify') { note.textContent = ''; note.classList.remove('is-warn'); return; }
        if (lastPreviewOK) {
            note.textContent = 'Checked — saving also runs preflight.';
            note.classList.remove('is-warn');
        } else {
            note.textContent = 'Changed since it was last checked — run Validate to save.';
            note.classList.add('is-warn');
        }
    }

    // Crypto reads as one settled sentence; the six controls live behind "change".
    function cryptoSummary() {
        var el = $('ipsec-crypto-summary');
        if (!el || !caps) return;
        var prof = chosenProfile();
        var parts = [];
        if (prof !== 'custom') {
            var p = (caps.profiles || []).find(function (x) { return x.name === prof; });
            if (p) {
                parts = [p.name, (p.ike.enc || '').toUpperCase(), (p.ike.dh ? 'DH' + p.ike.dh : ''), p.ike_version];
            }
        } else {
            parts = ['Custom', ($('ipsec-enc').value || '').toUpperCase(),
                ($('ipsec-dh').value ? 'DH' + $('ipsec-dh').value : ''), $('ipsec-ikever').value];
        }
        el.textContent = parts.filter(Boolean).join(' · ');
    }

    // Derived answers presented as confirmed facts rather than re-asked questions.
    function renderFacts(pfx) {
        var host = $('ipsec-' + pfx + '-facts');
        if (!host) return;
        var egress = ifaceVal(pfx, 'egress'), addr = ifaceVal(pfx, 'peer');
        var dyn = $('ipsec-' + pfx + '-dyn').checked;
        var bits = [];
        if (addr) bits.push('<span>Address <span class="ipsec-fact-val">' + esc(addr) + '</span></span>');
        if (egress) bits.push('<span>Out via <span class="ipsec-fact-val">' + esc(egress) + '</span></span>');
        if (dyn) bits.push('<span>Behind NAT · dials out</span>');
        host.innerHTML = bits.join('');
    }

    // Catch a duplicate at authoring rather than at preflight.
    function checkExisting() {
        var host = $('ipsec-existing');
        if (!host) return;
        var a = $('ipsec-dev-a').value, b = $('ipsec-dev-b').value;
        var editing = parseInt($('ipsec-edit-id').value, 10) || 0;
        if (!a || !b) { host.hidden = true; return; }
        var gen = capsGen; // same token: a device change invalidates this answer too
        AC.apiFetch(API + '/ipsec/tunnels').then(function (r) {
            if (gen !== capsGen) return;
            var hit = ((r && r.data) || []).filter(function (t) {
                if (t.id === editing) return false;
                // Promoted endpoint columns on models.IPSecTunnel — a_device_id /
                // b_device_id. Sorted, because A/B is an authoring choice: the same
                // pair picked the other way round is the same pair.
                var ids = [String(t.a_device_id), String(t.b_device_id)].sort();
                return ids.join('|') === [String(a), String(b)].sort().join('|');
            });
            if (!hit.length) { host.hidden = true; return; }
            host.hidden = false;
            host.innerHTML = 'These two already have ' + hit.length + ' tunnel' + (hit.length === 1 ? '' : 's') +
                ': ' + hit.map(function (t) { return esc(t.name || ('#' + t.id)); }).join(', ') +
                '. A second one is allowed, but check this is not a duplicate.';
        }).catch(function () { host.hidden = true; });
    }

    function wire() {
        AC.delegateEvent('click', {
            'ipsec-phase': function (el) { setPhase(el.dataset.phase); },
            'ipsec-path-toggle': function (el) { togglePath(el.dataset.a, el.dataset.b); },
            'ipsec-group-toggle': function (el) { toggleGroup(el.dataset.a); },
            'ipsec-crypto-toggle': function (el) {
                // The disclosure IS #ipsec-custom-crypto's container restyled — a
                // second visibility mechanism ANDed on top would leave an operator
                // editing a custom-crypto tunnel staring at nothing.
                var box = $('ipsec-crypto-detail');
                var open = !box.hidden;
                box.hidden = open;
                el.setAttribute('aria-expanded', String(!open));
                el.textContent = open ? 'change' : 'done';
            },
            'ipsec-new': function () { openWizard(0); },
            'ipsec-edit': function (el) { openWizard(parseInt(el.dataset.id, 10)); },
            'ipsec-delete': function (el) { del(parseInt(el.dataset.id, 10)); },
            'ipsec-wizard-close': function () { AC.closeModal('ipsec-wizard-modal'); },
            'ipsec-preview': function () { preview(); },
            'ipsec-save': function () { save(); },
            'ipsec-preflight': function (el) { preflight(parseInt(el.dataset.id, 10)); },
            'ipsec-preflight-close': function () { stopPreflightPoll(); AC.closeModal('ipsec-preflight-modal'); },
            'ipsec-deploy': function (el) { startDeploy(parseInt(el.dataset.id, 10)); },
            'ipsec-rollback': function (el) { startRollback(parseInt(el.dataset.id, 10)); },
            'ipsec-recheck': function (el) { startRecheck(parseInt(el.dataset.id, 10)); },
            'ipsec-reset': function (el) { resetDeploy(parseInt(el.dataset.id, 10)); },
            'ipsec-progress': function (el) { openDeployModal(parseInt(el.dataset.id, 10), el.dataset.op || 'deploy'); },
            'ipsec-deploy-close': function () { stopDeployPoll(); AC.closeModal('ipsec-deploy-modal'); loadTunnels(); },
            // Explicit acknowledge on a FAILED deploy — the error stays on screen
            // until the operator clicks this (it never auto-dismisses).
            'ipsec-deploy-ack': function () { stopDeployPoll(); AC.closeModal('ipsec-deploy-modal'); loadTunnels(); },
            'ipsec-deploy-copyerr': function () {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(lastDeployErrorText || '').then(function () {
                        if (AC.showSuccess) AC.showSuccess('Error copied to clipboard.');
                    }).catch(function () {});
                }
            }
        });
        $('ipsec-dev-a').addEventListener('change', onDevicesChosen);
        $('ipsec-dev-b').addEventListener('change', onDevicesChosen);
        // Reveal the free-text field only when "Custom…" is chosen (egress/LAN/peer).
        ['a-egress', 'b-egress', 'a-peer', 'b-peer'].forEach(function (f) {
            $('ipsec-' + f).addEventListener('change', function () { toggleCustom(f.charAt(0), f.slice(2)); });
        });
        // Ticking a LAN interface changes the intent, so it must re-gate Save the
        // same way any other field does. Delegated, since the boxes are rebuilt
        // whenever hints land.
        ['a', 'b'].forEach(function (pfx) {
            var box = lanList(pfx);
            if (box) {
                box.addEventListener('change', function (ev) {
                    var cb = ev.target;
                    if (cb && cb.type === 'checkbox') {
                        // Remember a deliberate untick so the next keystroke in the
                        // subnets box does not put it straight back.
                        if (cb.checked) { delete lanUnticked[pfx][cb.value]; }
                        else { lanUnticked[pfx][cb.value] = true; }
                    }
                    invalidate();
                });
            }
            var cust = lanCustom(pfx);
            if (cust) { cust.addEventListener('input', invalidate); }
        });
        // Changing the egress (WAN) interface re-defaults the peer/public IP to that
        // interface's address.
        ['a-egress', 'b-egress'].forEach(function (f) {
            $('ipsec-' + f).addEventListener('change', function () { syncPeerToEgress(f.charAt(0)); });
        });
        // IKE identity: track manual edits (so prefill doesn't clobber) + show the
        // instant client-side error; re-derive the default when the id-type flips.
        ['a', 'b'].forEach(function (pfx) {
            $('ipsec-' + pfx + '-id').addEventListener('input', function () { idDirty[pfx] = true; validateId(pfx); });
            $('ipsec-' + pfx + '-idtype').addEventListener('change', function () { prefillIdentity(pfx); });
        });
        // Any edit after a clean preview invalidates it (see invalidate()).
        // Typing subnets derives the inside ports. Bound to the textarea itself,
        // NOT to the form, so a restore (which sets .value programmatically and
        // fires no input event) can never rewrite a saved port selection.
        ['a', 'b'].forEach(function (pfx) {
            var sb = $('ipsec-' + pfx + '-subnets');
            if (sb) {
                sb.addEventListener('input', function () {
                    autoTickLANFromSubnets(pfx);
                    pruneDisabledPaths();
                });
            }
        });
        $('ipsec-wizard-form').addEventListener('input', invalidate);
        $('ipsec-wizard-form').addEventListener('change', invalidate);
    }

    // restoreCrypto re-selects the stored crypto when editing, so opening a tunnel
    // to fix (say) a subnet doesn't silently reset its proposals to the first preset.
    function restoreCrypto(t) {
        if (!caps) return;
        var match = (caps.profiles || []).find(function (p) {
            return p.ike_version === t.ike_version && p.ike.enc === t.ike.enc && p.ike.dh === t.ike.dh &&
                p.esp.enc === t.esp.enc && p.esp.pfs === t.esp.pfs;
        });
        var radios = document.querySelectorAll('input[name=ipsec-profile]');
        function pick(val) {
            Array.prototype.forEach.call(radios, function (r) {
                r.checked = (r.value === val);
                if (r.checked) r.dispatchEvent(new Event('change'));
            });
        }
        if ($('ipsec-mode') && t.mode) $('ipsec-mode').value = t.mode; // mode is orthogonal to the crypto profile
        if (match) {
            pick(match.name);
        } else {
            pick('custom');
            $('ipsec-ikever').value = t.ike_version; $('ipsec-enc').value = t.ike.enc;
            $('ipsec-integ').value = t.ike.integ || ''; $('ipsec-prf').value = t.ike.prf; $('ipsec-dh').value = t.ike.dh;
            $('ipsec-pfs').checked = !!t.esp.pfs;
            $('ipsec-custom-crypto').style.display = '';
        }
    }

    // ---- deploy preflight (READ-ONLY) -----------------------------------
    // Enqueue a per-end REST preflight, then poll the result and render it.
    // No device writes happen — this only reads to check auth + collisions.
    var preflightTimer = null;
    // Generation token: bumped on every start/close so a stale in-flight fetch
    // or pending timer from a previous open (or another row) is dropped instead
    // of rendering into / re-polling the now-closed-or-reused modal.
    var preflightGen = 0;

    function stopPreflightPoll() {
        preflightGen++;
        if (preflightTimer) { clearTimeout(preflightTimer); preflightTimer = null; }
    }

    function preflightLive(gen) {
        var m = $('ipsec-preflight-modal');
        return gen === preflightGen && !!(m && m.classList.contains('active'));
    }

    // The collector runs commands on its heartbeat (default 60s), so a preflight
    // result routinely takes ~a minute to arrive. Poll well past that before
    // declaring a timeout (a short window made a succeeded check look failed).
    var PREFLIGHT_WINDOW_MS = 150000; // ~2.5 min
    var PREFLIGHT_POLL_MS = 3000;

    function mmss(ms) {
        var s = Math.max(0, Math.round(ms / 1000));
        return Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2);
    }

    // Advisories are NON-BLOCKING findings about pre-existing device state that
    // will degrade the tunnel (e.g. a static route that outranks the tunnel's).
    // They are rendered as warnings and deliberately gate nothing: the operator
    // decides, and Deploy stays available whether or not any are present.
    function advisoriesHtml(list) {
        if (!list || !list.length) return '';
        var items = list.map(function (a) {
            return '<li style="margin-bottom:8px;">' +
                '<div style="font-weight:600;">' + esc(a.title || 'Advisory') + '</div>' +
                (a.detail ? '<div style="font-size:0.82rem;margin-top:2px;">' + esc(a.detail) + '</div>' : '') +
                (a.remedy ? '<div style="font-size:0.82rem;margin-top:3px;color:var(--fwmon-text-mute);">' + esc(a.remedy) + '</div>' : '') +
                '</li>';
        }).join('');
        return '<div class="card" style="padding:10px;margin-top:8px;border-left:3px solid var(--fwmon-sig-warn);">' +
            '<div style="font-weight:600;color:var(--fwmon-sig-warn);margin-bottom:6px;">' +
            'Advisory · ' + list.length + ' item' + (list.length === 1 ? '' : 's') +
            ' — this does not block the deploy</div>' +
            '<ul style="margin:0;padding-left:16px;">' + items + '</ul></div>';
    }

    function endReportHtml(e, state) {
        state = state || {};
        var r = e.report;
        var head = '<div style="font-weight:600;margin-bottom:4px;">End ' + (e.end === 0 ? 'A' : 'B') +
            ' <span style="color:var(--fwmon-text-mute);font-weight:normal;">(device #' + esc(e.device_id) + ')</span> ' +
            statusBadge(e.status) + '</div>';
        if (!r) {
            // A terminal end (succeeded/failed/expired) with no parseable report
            // must NEVER show the spinner — surface the raw collector output (or a
            // plain note) so it can't spin forever hiding the real message.
            var endTerminal = (e.status === 'succeeded' || e.status === 'failed' || e.status === 'expired');
            var body;
            if (endTerminal) {
                var termColor = (e.status === 'succeeded') ? 'var(--fwmon-text-mute)' : 'var(--fwmon-sig-crit)';
                body = '<div style="color:' + termColor + ';font-size:0.85rem;">' + (e.raw_result ? esc(e.raw_result) : 'Completed but returned no report.') + '</div>';
            } else if (state.exhausted) {
                body = '<div style="color:var(--fwmon-sig-warn);font-size:0.85rem;">Still waiting — the collector hasn\'t run this yet. Confirm the device has a collector assigned and is online, then check again.</div>';
            } else {
                // Still polling: a spinner so it never looks frozen (the top status
                // line carries the elapsed-time counter).
                body = '<div style="color:var(--fwmon-text-mute);font-size:0.85rem;display:flex;align-items:center;gap:8px;">' +
                    '<span class="fwmon-spinner"></span>' +
                    '<span>Waiting for the collector to run this check…</span></div>';
            }
            return '<div class="card" style="padding:12px;">' + head + body + '</div>';
        }
        function b(ok, warn, label) {
            var cls = ok ? 'success' : (warn ? 'warning' : 'danger');
            return '<span class="badge ' + cls + '" style="margin-right:6px;">' + esc(label) + '</span>';
        }
        // The collision verdict is only trustworthy once we actually reached the
        // API and authenticated — otherwise the check never ran, so never show a
        // reassuring green "no collision" on an unreachable/auth-failed end (the
        // report's conflict/indeterminate are Go zero-values in that case).
        var collisionBadge;
        if (r.conflict) {
            collisionBadge = b(false, false, 'name collision');
        } else if (!r.reachable || !r.auth_ok) {
            collisionBadge = b(false, true, 'collision check not run');
        } else if (r.indeterminate) {
            collisionBadge = b(false, true, 'collision check inconclusive');
        } else {
            collisionBadge = b(true, false, 'no collision');
        }
        var advisories = e.advisories || [];
        var badges =
            b(r.reachable, false, r.reachable ? 'reachable' : 'unreachable') +
            b(r.auth_ok, false, r.auth_ok ? 'auth ok' : 'auth failed') +
            collisionBadge +
            (advisories.length ? b(false, true, advisories.length + ' advisory') : '');
        var ver = r.os_version ? '<div style="font-size:0.82rem;color:var(--fwmon-text-mute);margin-top:4px;">version: ' + esc(r.os_version) + '</div>' : '';
        var checks = (r.checks || []).map(function (c) {
            var mark = c.collision ? '⚠ collision' : (c.indeterminate ? '? inconclusive' : (c.ok ? '✓' : '✗'));
            return '<li style="font-family:monospace;font-size:0.78rem;color:var(--fwmon-text-mute);">' +
                esc(mark) + ' ' + esc(c.check) + ' (HTTP ' + esc(c.status_code || 0) + ')' +
                (c.note ? ' — ' + esc(c.note) : '') + '</li>';
        }).join('');
        return '<div class="card" style="padding:12px;">' + head +
            '<div style="margin:6px 0;">' + badges + '</div>' + ver +
            (checks ? '<ul style="margin:8px 0 0 0;padding-left:16px;">' + checks + '</ul>' : '') +
            advisoriesHtml(advisories) + '</div>';
    }

    // A top status line so activity is visible even before per-end data changes:
    // a spinner while polling, a warn + "Check again" once waiting times out.
    function preflightStatusLine(id, state) {
        if (state.polling) {
            return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;color:var(--fwmon-text-mute);font-size:0.85rem;">' +
                '<span class="fwmon-spinner"></span><span>Checking for results… ' + esc(mmss(state.elapsedMs)) +
                ' <span style="color:var(--fwmon-text-faint);">— the collector runs this on its next check-in (up to ~1 min)</span></span></div>';
        }
        if (state.exhausted) {
            return '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px;">' +
                '<span style="color:var(--fwmon-sig-warn);font-size:0.85rem;">No result after ' + esc(mmss(state.elapsedMs)) + ' — the collector may be offline or the command is still queued.</span>' +
                '<button class="btn sm secondary" data-action="ipsec-preflight" data-min-role="admin" data-id="' + id + '">Check again</button></div>';
        }
        return '';
    }

    function renderPreflightBody(id, data, state) {
        var ends = (data && data.ends) || [];
        $('ipsec-preflight-body').innerHTML =
            preflightStatusLine(id, state) +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
            ends.map(function (e) { return endReportHtml(e, state); }).join('') + '</div>';
    }

    function pollPreflight(id, gen, startMs) {
        if (!preflightLive(gen)) return; // modal closed or superseded — stop
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/preflight').then(function (r) {
            if (!preflightLive(gen)) return;
            var data = (r && r.data) || {};
            var ends = data.ends || [];
            var terminal = ends.length > 0 && ends.every(function (e) {
                return e.status === 'succeeded' || e.status === 'failed' || e.status === 'expired';
            });
            var elapsed = Date.now() - startMs;
            var more = !terminal && elapsed < PREFLIGHT_WINDOW_MS;
            renderPreflightBody(id, data, { elapsedMs: elapsed, polling: more, exhausted: !terminal && !more });
            if (more) {
                preflightTimer = setTimeout(function () { pollPreflight(id, gen, startMs); }, PREFLIGHT_POLL_MS);
            }
        }).catch(function (e) {
            if (!preflightLive(gen)) return;
            $('ipsec-preflight-body').innerHTML = '<div class="card" style="padding:12px;color:var(--fwmon-sig-crit);">Failed to read preflight result: ' + esc(e.message) + '</div>';
        });
    }

    function preflight(id) {
        stopPreflightPoll();          // cancel any prior poll + invalidate its generation
        var gen = preflightGen;       // this run's token (captured after the bump)
        var startMs = Date.now();
        $('ipsec-preflight-body').innerHTML =
            '<div style="display:flex;align-items:center;gap:8px;color:var(--fwmon-text-mute);font-size:0.9rem;">' +
            '<span class="fwmon-spinner"></span><span>Starting preflight…</span></div>';
        AC.openModal('ipsec-preflight-modal');
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/preflight', { method: 'POST' }).then(function () {
            if (gen !== preflightGen) return; // superseded/closed before the POST returned
            pollPreflight(id, gen, startMs);
        }).catch(function (e) {
            if (!preflightLive(gen)) return;
            $('ipsec-preflight-body').innerHTML = '<div class="card" style="padding:12px;color:var(--fwmon-sig-crit);">Could not start preflight: ' + esc(e.message) + '</div>';
        });
    }

    // ---- deploy / rollback (WRITES config) ------------------------------
    // Deploy renders + enqueues per-end apply commands; the collector writes then
    // verifies. Rollback removes from the stored snapshot. Both are poll-driven,
    // mirroring the preflight machinery (generation token guards stale timers).
    var deployTimer = null;
    var deployGen = 0;
    var DEPLOY_WINDOW_MS = 300000; // ~5 min total safety cap — writes + verify GETs on a busy box
    var DEPLOY_POLL_MS = 3000;
    // A deploy is several collector round-trips (parallel apply → SA-liveness verify),
    // each up to one heartbeat (~1 min). Track the CURRENT phase separately so the
    // "up to ~1 min" reassurance resets per round-trip instead of a single cumulative
    // timer sailing past the ~1 min it claims. phaseKey = the observable per-round-trip state.
    var deployPhaseKey = '';
    var deployPhaseStartMs = 0;

    function stopDeployPoll() {
        deployGen++;
        if (deployTimer) { clearTimeout(deployTimer); deployTimer = null; }
    }
    function deployLive(gen) {
        var m = $('ipsec-deploy-modal');
        return gen === deployGen && !!(m && m.classList.contains('active'));
    }

    function startDeploy(id) {
        // Surface blocking validation BEFORE writing — the server also 409s, but we
        // want the operator to see exactly why and never fire a doomed deploy.
        AC.apiFetch(API + '/ipsec/tunnels/' + id).then(function (r) {
            var d = (r && r.data) || {};
            var blocks = (d.validation || []).filter(function (f) { return f.severity === 'block'; });
            if (blocks.length) {
                AC.showError('Cannot deploy — resolve blocking findings first: ' +
                    blocks.map(function (f) { return f.message; }).join('; '));
                return;
            }
            AC.confirm('This WRITES IPSec configuration to the FortiGate device over its REST API. You can roll it back afterwards. Continue?',
                { title: 'Deploy tunnel?', confirmLabel: 'Deploy', danger: false }).then(function (ok) {
                if (!ok) return;
                openDeployModal(id, 'deploy');
                AC.apiFetch(API + '/ipsec/tunnels/' + id + '/deploy', { method: 'POST' }).then(function () {
                    if (!deployLive(deployGen)) return;
                    pollDeploy(id, deployGen, Date.now(), 'deploy');
                }).catch(function (e) {
                    if (!deployLive(deployGen)) return;
                    $('ipsec-deploy-body').innerHTML = deployErrorCard('Could not start deploy: ' + esc(e.message));
                });
            });
        }).catch(function (e) { AC.showError('Failed to load tunnel: ' + e.message); });
    }

    function startRollback(id) {
        AC.confirm('This REMOVES the deployed IPSec configuration from the device (phase1/phase2, tunnel interface, routes and policies for this tunnel). Continue?',
            { title: 'Roll back tunnel?', confirmLabel: 'Roll back', danger: true }).then(function (ok) {
            if (!ok) return;
            openDeployModal(id, 'rollback');
            AC.apiFetch(API + '/ipsec/tunnels/' + id + '/rollback', { method: 'POST' }).then(function () {
                if (!deployLive(deployGen)) return;
                pollDeploy(id, deployGen, Date.now(), 'rollback');
            }).catch(function (e) {
                if (!deployLive(deployGen)) return;
                $('ipsec-deploy-body').innerHTML = deployErrorCard('Could not start rollback: ' + esc(e.message));
            });
        });
    }

    // startRecheck re-runs SA-liveness verification (read-only on the devices):
    // it re-enqueues the ipsec_status probes and reopens the progress modal, which
    // polls the same deploy GET until the tunnel resolves to up/down from the fresh
    // device state. No confirm — it writes nothing to the firewalls.
    function startRecheck(id) {
        openDeployModal(id, 'recheck');
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/recheck', { method: 'POST' }).then(function () {
            if (!deployLive(deployGen)) return;
            pollDeploy(id, deployGen, Date.now(), 'recheck');
        }).catch(function (e) {
            if (!deployLive(deployGen)) return;
            $('ipsec-deploy-body').innerHTML = deployErrorCard('Could not start recheck: ' + esc(e.message));
        });
    }

    // resetDeploy force-clears a wedged deploy record (error/rollback_failed). It
    // touches NO device — the operator acknowledges the device may still hold
    // objects and must verify manually.
    function resetDeploy(id) {
        AC.confirm('Clear Firewall-Mon\'s deploy record for this tunnel? The device MAY still hold objects for it — this does NOT remove them; verify and remove them manually. Use this only when a rollback cannot complete (e.g. the collector was offline).',
            { title: 'Reset deploy record?', confirmLabel: 'Clear record', danger: true }).then(function (ok) {
            if (!ok) return;
            AC.apiFetch(API + '/ipsec/tunnels/' + id + '/deploy/reset', { method: 'POST' }).then(function (r) {
                AC.showSuccess((r && r.data && r.data.warning) || 'Deploy record cleared.');
                stopDeployPoll(); AC.closeModal('ipsec-deploy-modal'); loadTunnels();
            }).catch(function (e) { AC.showError('Reset failed: ' + e.message); });
        });
    }

    function openDeployModal(id, op) {
        stopDeployPoll();
        deployReasonSnapshot = ''; // fresh per-deploy so a prior failure can't leak in
        deployPhaseKey = '';       // fresh phase tracking (first poll seeds it)
        deployPhaseStartMs = Date.now();
        $('ipsec-deploy-title').textContent = (op === 'rollback') ? 'Roll Back Tunnel'
            : (op === 'recheck') ? 'Recheck Tunnel' : 'Deploy Tunnel';
        $('ipsec-deploy-sub').textContent = (op === 'rollback')
            ? 'Removes the deployed configuration from the device (only objects tagged for this tunnel).'
            : (op === 'recheck')
                ? 'Re-reads the live SA state from both firewalls (read-only) and updates the tunnel status.'
                : 'Writes configuration to the firewall over its REST API, then verifies the objects exist.';
        $('ipsec-deploy-body').innerHTML =
            '<div style="display:flex;align-items:center;gap:8px;color:var(--fwmon-text-mute);font-size:0.9rem;">' +
            '<span class="fwmon-spinner"></span><span>Starting ' + esc(op) + '…</span></div>';
        AC.openModal('ipsec-deploy-modal');
        // A "View progress" open (op known, no POST) starts polling immediately.
        pollDeploy(id, deployGen, Date.now(), op);
    }

    function deployErrorCard(html) {
        return '<div class="card" style="padding:12px;color:var(--fwmon-sig-crit);">' + html + '</div>';
    }

    function deployTerminal(status, data) {
        // C2b-2b: degraded with SA-liveness probes still in flight is NOT
        // terminal — keep polling until they resolve to up/down/inconclusive.
        if (status === 'degraded' && data && data.sa_pending) return false;
        return ['degraded', 'up', 'down', 'error', 'rolled_back', 'rollback_failed'].indexOf(status) !== -1;
    }

    function collisionGuidance(data) {
        if (!data || !data.conflict) return '';
        var paths = (data.collisions || []).map(function (p) { return esc(p); }).join(', ');
        return '<div class="card" style="padding:12px;border-left:3px solid var(--fwmon-sig-warn);margin-bottom:10px;">' +
            '<div style="font-weight:600;color:var(--fwmon-sig-warn);margin-bottom:4px;">Object collision — nothing was written</div>' +
            '<div style="font-size:0.85rem;color:var(--fwmon-text-mute);">One or more objects already exist at this tunnel\'s keys' +
            (paths ? ' (<span style="font-family:monospace;">' + paths + '</span>)' : '') + '.' +
            '<ul style="margin:8px 0 0 0;padding-left:16px;">' +
            '<li><b>If they are ours</b> (a previous partial deploy): click <b>Rollback</b> first, then Deploy again.</li>' +
            '<li><b>If they are not ours</b> (a pre-existing config the collector reported as foreign): do NOT roll back — resolve the conflicting object on the device, then retry.</li>' +
            '</ul></div></div>';
    }

    function deployEndCard(e) {
        // C2b-2b: when the SA-liveness probe resolved for this end, show it.
        var saHtml = '';
        if (e.sa) {
            var saUp = (e.sa.ike === 'up' && e.sa.child === 'up');
            var saDown = (e.sa.ike === 'down' || e.sa.child === 'down');
            saHtml = ' <span class="badge ' + (saUp ? 'success' : (saDown ? 'danger' : 'warning')) + '">' +
                'SA ' + (saUp ? 'up' : (saDown ? 'down' : 'unknown')) + '</span>';
        }
        var head = '<div style="font-weight:600;margin-bottom:4px;">End ' + (e.end === 0 ? 'A' : 'B') +
            ' <span style="color:var(--fwmon-text-mute);font-weight:normal;">(device #' + esc(e.device_id) + ')</span> ' +
            statusBadge(e.status) + saHtml + '</div>';
        var r = e.report;
        var body;
        if (r && typeof r === 'object') {
            function badge(ok, warn, label) {
                var cls = ok ? 'success' : (warn ? 'warning' : 'danger');
                return '<span class="badge ' + cls + '" style="margin-right:6px;">' + esc(label) + '</span>';
            }
            var parts = [];
            if (r.op === 'remove') {
                parts.push(badge(r.applied, false, r.applied ? 'removed' : 'remove incomplete'));
            } else {
                parts.push(badge(r.applied, false, r.applied ? 'applied' : (r.aborted ? 'aborted' : 'apply failed')));
                parts.push(badge(r.verified, !r.verified && r.applied, r.verified ? 'verified' : 'unverified'));
                if (r.conflict) parts.push(badge(false, true, 'collision'));
            }
            // Join with whitespace so adjacent pills are clearly separated (and copy
            // as "applied verified", not "appliedverified").
            var badges = parts.join(' ');
            var counts = (typeof r.steps_ok === 'number' && typeof r.steps_total === 'number')
                ? '<span style="font-size:0.8rem;color:var(--fwmon-text-mute);margin-left:4px;">' + esc(r.steps_ok) + '/' + esc(r.steps_total) + ' steps ok</span>'
                : '';
            var steps = (r.steps || []).map(function (s) {
                var mark = s.ok ? '✓' : '✗';
                return '<li style="font-family:monospace;font-size:0.76rem;color:var(--fwmon-text-mute);">' +
                    esc(mark) + ' ' + esc(s.op) + ' ' + esc(s.path) + ' (HTTP ' + esc(s.status || 0) + ')' +
                    (s.note ? ' — ' + esc(s.note) : '') + '</li>';
            }).join('');
            var err = r.error ? '<div style="font-size:0.82rem;color:var(--fwmon-sig-crit);margin-top:4px;">' + esc(r.error) + '</div>' : '';
            body = '<div style="margin:6px 0;">' + badges + counts + '</div>' + err +
                (steps ? '<ul style="margin:8px 0 0 0;padding-left:16px;">' + steps + '</ul>' : '');
        } else if (e.status === 'pending' || e.status === 'dispatched' || e.status === 'none') {
            body = '<div style="color:var(--fwmon-text-mute);font-size:0.85rem;display:flex;align-items:center;gap:8px;">' +
                '<span class="fwmon-spinner"></span><span>Waiting for the collector to run this…</span></div>';
        } else {
            body = '<div style="color:var(--fwmon-text-mute);font-size:0.85rem;">' + (e.raw_result ? esc(e.raw_result) : 'No report.') + '</div>';
        }
        return '<div class="card" style="padding:12px;">' + head + body + '</div>';
    }

    // lastDeployErrorText holds the aggregated failure reason for the Copy button.
    var lastDeployErrorText = '';

    // deployReasonSnapshot captures the apply-failure detail from the live
    // (rolling_back) frame — where the failed-apply report + failing step (e.g.
    // addGateway) are present — so the reason survives into the terminal
    // rolled_back frame, which no longer carries it. Reset per-deploy in
    // openDeployModal. Module-scope so it isn't wiped by each poll's re-render.
    var deployReasonSnapshot = '';

    // deployApplyFailure extracts the reason from any end whose report is a FAILED
    // apply (not a remove): the report error plus each failing step's endpoint.
    // Returns '' when no end shows an apply failure (so a clean/remove frame won't
    // overwrite a captured reason).
    function deployApplyFailure(data) {
        var reasons = [];
        (data && data.ends || []).forEach(function (e) {
            var r = e.report;
            if (!r || typeof r !== 'object') return;
            if (r.op === 'remove') return;      // removes succeeding is not the failure
            if (r.applied === true) return;     // this end applied fine
            var lbl = 'End ' + (e.end === 0 ? 'A' : 'B');
            if (r.error) reasons.push(lbl + ': ' + r.error);
            (r.steps || []).forEach(function (s) {
                if (!s.ok) reasons.push(lbl + ' · ' + s.op + ' ' + s.path + ' (HTTP ' + (s.status || 0) + ')' + (s.note ? ' — ' + s.note : ''));
            });
        });
        return reasons.join('\n');
    }

    // deployFailureReason gathers every scrap of "why" from a terminal failure:
    // the top-level note plus each end's report error and failing-step notes (the
    // collector's ApplyReport, incl. OPNsense validation detail).
    function deployFailureReason(data) {
        var reasons = [];
        if (data && data.note) reasons.push(data.note);
        (data && data.ends || []).forEach(function (e) {
            var lbl = 'End ' + (e.end === 0 ? 'A' : 'B');
            var r = e.report;
            if (r && typeof r === 'object') {
                if (r.error) reasons.push(lbl + ': ' + r.error);
                (r.steps || []).forEach(function (s) {
                    if (!s.ok && s.note) reasons.push(lbl + ' · ' + s.op + ' ' + s.path + ': ' + s.note);
                });
            } else if (e.raw_result) {
                reasons.push(lbl + ': ' + e.raw_result);
            }
        });
        return reasons.join('\n');
    }

    // deployFailureBanner is a persistent, copyable stop-and-read panel shown on a
    // failed terminal (error / rolled_back / rollback_failed). It NEVER auto-
    // dismisses — the operator clears it with the explicit Acknowledge button.
    function deployFailureBanner(data) {
        var status = (data && data.status) || '';
        var title = status === 'rolled_back' ? 'Deploy failed — automatically rolled back'
            : status === 'rollback_failed' ? 'Rollback did not complete — the device may still hold objects'
                : 'Deploy failed';
        // Prefer the live apply-failure detail (this frame), then the snapshot
        // captured during rolling_back, then the backend-supplied note/reason, then
        // the fallback. This is what makes the addGateway error survive the rollback.
        lastDeployErrorText = deployApplyFailure(data) || deployReasonSnapshot ||
            deployFailureReason(data) || 'No further detail was reported by the collector.';
        return '<div class="card" style="padding:14px;border-left:4px solid var(--fwmon-sig-crit);margin-bottom:12px;">' +
            '<div style="font-weight:700;color:var(--fwmon-sig-crit);margin-bottom:6px;">✕ ' + esc(title) + '</div>' +
            '<div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--fwmon-text-faint);margin-bottom:4px;">Reason — stays here until you acknowledge</div>' +
            '<pre style="white-space:pre-wrap;word-break:break-word;user-select:text;font-family:monospace;font-size:0.8rem;max-height:38vh;overflow:auto;margin:0 0 10px 0;background:var(--fwmon-surface-2,rgba(127,127,127,0.12));padding:10px;border-radius:6px;">' + esc(lastDeployErrorText) + '</pre>' +
            '<button class="btn sm secondary" data-action="ipsec-deploy-copyerr" type="button">Copy</button> ' +
            '<button class="btn sm primary" data-action="ipsec-deploy-ack" type="button">Acknowledge &amp; Close</button>' +
            '</div>';
    }

    function renderDeployBody(id, data, state, op) {
        var status = (data && data.status) || '';
        // Capture the apply-failure reason on EVERY poll (it rides the rolling_back
        // frame, not a terminal one), richest-wins, so the terminal banner can show
        // it after the rollback clears the per-end apply reports.
        var applyFail = deployApplyFailure(data);
        if (applyFail && applyFail.length > deployReasonSnapshot.length) deployReasonSnapshot = applyFail;
        var line;
        if (state.polling) {
            // Label by phase so the modal doesn't say "Deploying…" once the apply
            // commands have succeeded and the server is now waiting on the SA-
            // liveness probes (C2b-2b): the work is different ("verifying"), and
            // the "up to ~1 min" reassurance is misleading once the elapsed timer
            // clearly exceeds the claimed heartbeat window. After ~90s drop the
            // reassurance entirely — the elapsed timer itself signals the wait.
            var isSA = (status === 'degraded' && data && data.sa_pending);
            var phaseLabel = isSA ? 'Verifying SA liveness' : 'Deploying';
            // Reassurance + primary counter are PER-PHASE: each collector round-trip
            // legitimately takes up to ~1 min, so keying on the phase timer (not
            // cumulative elapsed) keeps "up to ~1 min" truthful each step.
            var phaseMs = (typeof state.phaseMs === 'number') ? state.phaseMs : state.elapsedMs;
            var phaseSec = Math.floor(phaseMs / 1000);
            var reassurance = (phaseSec <= 90)
                ? ' <span style="color:var(--fwmon-text-faint);">— the collector picks up this step on its next check-in (up to ~1 min)</span>'
                : ' <span style="color:var(--fwmon-text-faint);">— still waiting</span>';
            // Total elapsed stays visible (mandatory — keeps a genuinely stuck deploy
            // from hiding behind a per-phase reset) once it diverges from the phase timer.
            var totalNote = (state.elapsedMs > phaseMs + 1500)
                ? ' <span style="color:var(--fwmon-text-faint);">(' + esc(mmss(state.elapsedMs)) + ' total)</span>'
                : '';
            line = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;color:var(--fwmon-text-mute);font-size:0.85rem;">' +
                '<span class="fwmon-spinner"></span><span>' + esc(phaseLabel) + '… ' + esc(mmss(phaseMs)) +
                reassurance + totalNote + '</span></div>';
        } else if (state.exhausted) {
            line = '<div style="color:var(--fwmon-sig-warn);font-size:0.85rem;margin-bottom:10px;">No terminal result after ' + esc(mmss(state.elapsedMs)) + ' — the collector may be offline or still queued. This modal will pick it up if you reopen “View progress”.</div>';
        } else {
            // Contextual recovery actions. From error/rollback_failed a re-deploy is
            // refused server-side (a deploy record exists) — the exits are Rollback
            // (retry the reversal) and Reset (force-clear, device-may-hold-objects).
            var actions = '';
            if (status === 'error' || status === 'rollback_failed') {
                actions = ' <button class="btn sm warning" data-action="ipsec-rollback" data-min-role="admin" data-id="' + id + '">Rollback</button>' +
                    ' <button class="btn sm secondary" data-action="ipsec-reset" data-min-role="admin" data-id="' + id + '">Reset…</button>';
            }
            var autoLbl = (data && data.auto) ? ' <span class="badge info">automatic rollback</span>' : '';
            line = '<div style="margin-bottom:10px;font-size:0.9rem;">Status: ' + statusBadge(status) + autoLbl +
                (data && data.note ? ' <span style="color:var(--fwmon-text-mute);">— ' + esc(data.note) + '</span>' : '') +
                actions + '</div>';
        }
        var ends = (data && data.ends) || [];
        var endsHtml = ends.length
            ? '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' + ends.map(deployEndCard).join('') + '</div>'
            : '';
        // On a FAILED terminal, pin a persistent, copyable, must-acknowledge banner
        // at the top so the reason can't scroll/flash by.
        var failed = !state.polling && !state.exhausted &&
            (status === 'error' || status === 'rolled_back' || status === 'rollback_failed');
        var banner = failed ? deployFailureBanner(data) : '';
        $('ipsec-deploy-body').innerHTML = banner + collisionGuidance(data) + line + endsHtml;
    }

    function pollDeploy(id, gen, startMs, op) {
        if (!deployLive(gen)) return;
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/deploy').then(function (r) {
            if (!deployLive(gen)) return;
            var data = (r && r.data) || {};
            var elapsed = Date.now() - startMs;
            // Reset the per-phase timer whenever the deploy ADVANCES. The observable
            // per-round-trip state is status + each end's command status + sa_pending;
            // every change is a genuine phase step (statuses are monotonic, no thrash).
            // rolling_back frames carry no ends[] — both removes run as one round-trip,
            // so rollback stays a single phase (one reset when ends vanish).
            var phaseKey = (data.status || '') + '|' +
                ((data.ends || []).map(function (e) { return e.status; }).join(',')) + '|' +
                (data.sa_pending ? 'sa' : '');
            if (phaseKey !== deployPhaseKey) {
                deployPhaseKey = phaseKey;
                deployPhaseStartMs = Date.now();
            }
            var phaseMs = Date.now() - deployPhaseStartMs;
            var terminal = deployTerminal(data.status, data);
            var more = !terminal && elapsed < DEPLOY_WINDOW_MS;
            renderDeployBody(id, data, { elapsedMs: elapsed, phaseMs: phaseMs, polling: more, exhausted: !terminal && !more }, op);
            if (more) {
                deployTimer = setTimeout(function () { pollDeploy(id, gen, startMs, op); }, DEPLOY_POLL_MS);
            }
        }).catch(function (e) {
            if (!deployLive(gen)) return;
            $('ipsec-deploy-body').innerHTML = deployErrorCard('Failed to read status: ' + esc(e.message));
        });
    }

    window.FwmonIPSec = { init: init };
})();
