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
    var lastHintSubnets = { a: '', b: '' }; // last auto-filled subnets, so a re-pick can refresh them
    var endpointHints = { a: null, b: null }; // cached hints per endpoint (peer-IP options + egress→peer sync)
    var loadedDevice = { a: '', b: '' };      // device id whose hints are loaded per endpoint (re-load only on change)

    function $(id) { return document.getElementById(id); }

    // Any change to the intent invalidates a prior clean preview — Save must not
    // persist an intent that was never previewed (the block-findings gate would lie).
    function invalidate() { lastPreviewOK = false; $('ipsec-save-btn').disabled = true; }
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
    // (the server still enforces every rule with a 409).
    function canEdit(s) { return ['deploying', 'degraded', 'up', 'rolling_back', 'rollback_failed'].indexOf(s) === -1; }
    function canDelete(s) { return ['draft', 'rolled_back', 'error'].indexOf(s) !== -1; }
    function canDeploy(s) { return ['draft', 'rolled_back'].indexOf(s) !== -1; }
    function canRollback(s) { return ['degraded', 'up', 'error', 'rollback_failed'].indexOf(s) !== -1; }
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
        ['a-egress', 'a-lan', 'b-egress', 'b-lan', 'a-peer', 'b-peer'].forEach(function (f) {
            $('ipsec-' + f).innerHTML = '<option value="__custom__">Custom…</option>';
            $('ipsec-' + f).value = '__custom__';
            $('ipsec-' + f + '-custom').style.display = '';
        });
        $('ipsec-a-dyn').checked = false; $('ipsec-b-dyn').checked = false;

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
        if (!a || !b) { return Promise.resolve(); }
        // Peer/public IP + interfaces + subnets are all populated from each device's
        // real polled data by loadHints (below).
        var capsP = AC.apiFetch(API + '/ipsec/capabilities?a=' + encodeURIComponent(vendorOf(a)) + '&b=' + encodeURIComponent(vendorOf(b))).then(function (r) {
            caps = (r && r.data) || null;
            if (!caps) return;
            $('ipsec-caps-note').textContent = 'Both ends support: ' + (caps.allowed.encryption || []).join(', ') + '.';
            renderProfiles();
            populateCustom();
            $('ipsec-crypto-section').style.display = '';
            $('ipsec-endpoints-section').style.display = '';
            $('ipsec-a-title').textContent = 'Endpoint A — ' + a.name + ' (' + vendorOf(a) + ')';
            $('ipsec-b-title').textContent = 'Endpoint B — ' + b.name + ' (' + vendorOf(b) + ')';
        }).catch(function (e) { AC.showError('No shared crypto for this pair: ' + e.message); });
        // Populate interfaces/peer-IP/subnets from each device's real polled data —
        // but only (re)load the endpoint whose device actually changed, so editing
        // one end never clobbers a hand-picked peer/interface on the other. Non-fatal.
        var pending = [];
        if (String(a.id) !== loadedDevice.a) { loadedDevice.a = String(a.id); pending.push(loadHints('a', a.id)); }
        if (String(b.id) !== loadedDevice.b) { loadedDevice.b = String(b.id); pending.push(loadHints('b', b.id)); }
        return Promise.all([capsP, Promise.all(pending)]).then(function () { });
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
            populateIfaceSelect(pfx, 'lan', ifaces, h.suggested_lan);
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
            populateIfaceSelect(pfx, 'lan', [], '');
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

    function populateCustom() {
        var a = caps.allowed;
        fillSel('ipsec-ikever', a.ike_versions);
        fillSel('ipsec-enc', a.encryption);
        fillSel('ipsec-integ', [''].concat(a.integrity || []), function (v) { return v || '(none — required off for GCM)'; });
        fillSel('ipsec-prf', a.prf);
        fillSel('ipsec-dh', a.dh_groups, function (v) { return 'DH ' + v; });
        $('ipsec-pfs').disabled = !a.pfs;
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
                lan_iface: ifaceVal(pfx, 'lan'),
                local_id: { type: 'keyid', value: $('ipsec-' + pfx + '-id').value.trim() },
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
            enabled: true, ike_version: ikever, mode: 'route-based',
            ike: ike, esp: esp, ike_lifetime_secs: ikeLife,
            dpd: { delay_secs: 30, timeout_secs: 0 },
            psk: $('ipsec-psk').value, // blank = auto-generate on save
            ends: [end(a, 'a', lifeA), end(b, 'b', lifeB)]
        };
    }

    function renderFindings(findings) {
        var block = (findings || []).filter(function (f) { return f.severity === 'block'; });
        var warn = (findings || []).filter(function (f) { return f.severity === 'warn'; });
        var html = '';
        block.forEach(function (f) { html += '<div style="color:var(--fwmon-danger,#f85149);font-size:0.82rem;">✕ ' + esc(f.message) + '</div>'; });
        warn.forEach(function (f) { html += '<div style="color:var(--fwmon-warning,#d29922);font-size:0.82rem;">⚠ ' + esc(f.message) + '</div>'; });
        if (!html) html = '<div style="color:var(--fwmon-success,#3fb950);font-size:0.82rem;">✓ No issues — ready to save.</div>';
        $('ipsec-findings').innerHTML = html;
        return block.length === 0;
    }

    function renderPreviewPanes(ends, provisional) {
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
        }).catch(function (e) { AC.showError('Preview failed: ' + e.message); });
    }

    function save() {
        if (!lastPreviewOK) { AC.showError('Run Validate & Preview and resolve any blockers first'); return; }
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
                setIfaceValue('a', 'lan', t.ends[0].lan_iface); setIfaceValue('b', 'lan', t.ends[1].lan_iface);
                $('ipsec-a-subnets').value = (t.ends[0].protected_subnets || []).join('\n');
                $('ipsec-b-subnets').value = (t.ends[1].protected_subnets || []).join('\n');
                $('ipsec-a-id').value = (t.ends[0].local_id || {}).value || ''; $('ipsec-b-id').value = (t.ends[1].local_id || {}).value || '';
                $('ipsec-a-gateway').value = t.ends[0].gateway || ''; $('ipsec-b-gateway').value = t.ends[1].gateway || '';
                // PSK stays masked (unchanged on save); Save stays gated until preview.
                lastPreviewOK = false; $('ipsec-save-btn').disabled = true;
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

    function wire() {
        AC.delegateEvent('click', {
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
            'ipsec-reset': function (el) { resetDeploy(parseInt(el.dataset.id, 10)); },
            'ipsec-progress': function (el) { openDeployModal(parseInt(el.dataset.id, 10), el.dataset.op || 'deploy'); },
            'ipsec-deploy-close': function () { stopDeployPoll(); AC.closeModal('ipsec-deploy-modal'); loadTunnels(); }
        });
        $('ipsec-dev-a').addEventListener('change', onDevicesChosen);
        $('ipsec-dev-b').addEventListener('change', onDevicesChosen);
        // Reveal the free-text field only when "Custom…" is chosen (egress/LAN/peer).
        ['a-egress', 'a-lan', 'b-egress', 'b-lan', 'a-peer', 'b-peer'].forEach(function (f) {
            $('ipsec-' + f).addEventListener('change', function () { toggleCustom(f.charAt(0), f.slice(2)); });
        });
        // Changing the egress (WAN) interface re-defaults the peer/public IP to that
        // interface's address.
        ['a-egress', 'b-egress'].forEach(function (f) {
            $('ipsec-' + f).addEventListener('change', function () { syncPeerToEgress(f.charAt(0)); });
        });
        // Any edit after a clean preview invalidates it (see invalidate()).
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
        var badges =
            b(r.reachable, false, r.reachable ? 'reachable' : 'unreachable') +
            b(r.auth_ok, false, r.auth_ok ? 'auth ok' : 'auth failed') +
            collisionBadge;
        var ver = r.os_version ? '<div style="font-size:0.82rem;color:var(--fwmon-text-mute);margin-top:4px;">version: ' + esc(r.os_version) + '</div>' : '';
        var checks = (r.checks || []).map(function (c) {
            var mark = c.collision ? '⚠ collision' : (c.indeterminate ? '? inconclusive' : (c.ok ? '✓' : '✗'));
            return '<li style="font-family:monospace;font-size:0.78rem;color:var(--fwmon-text-mute);">' +
                esc(mark) + ' ' + esc(c.check) + ' (HTTP ' + esc(c.status_code || 0) + ')' +
                (c.note ? ' — ' + esc(c.note) : '') + '</li>';
        }).join('');
        return '<div class="card" style="padding:12px;">' + head +
            '<div style="margin:6px 0;">' + badges + '</div>' + ver +
            (checks ? '<ul style="margin:8px 0 0 0;padding-left:16px;">' + checks + '</ul>' : '') + '</div>';
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
    var DEPLOY_WINDOW_MS = 300000; // ~5 min — writes + verify GETs on a busy box
    var DEPLOY_POLL_MS = 3000;

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
        $('ipsec-deploy-title').textContent = (op === 'rollback') ? 'Roll Back Tunnel' : 'Deploy Tunnel';
        $('ipsec-deploy-sub').textContent = (op === 'rollback')
            ? 'Removes the deployed configuration from the device (only objects tagged for this tunnel).'
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

    function deployTerminal(status) {
        return ['degraded', 'up', 'error', 'rolled_back', 'rollback_failed'].indexOf(status) !== -1;
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
        var head = '<div style="font-weight:600;margin-bottom:4px;">End ' + (e.end === 0 ? 'A' : 'B') +
            ' <span style="color:var(--fwmon-text-mute);font-weight:normal;">(device #' + esc(e.device_id) + ')</span> ' +
            statusBadge(e.status) + '</div>';
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

    function renderDeployBody(id, data, state, op) {
        var status = (data && data.status) || '';
        var line;
        if (state.polling) {
            line = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;color:var(--fwmon-text-mute);font-size:0.85rem;">' +
                '<span class="fwmon-spinner"></span><span>' + (op === 'rollback' ? 'Rolling back' : 'Deploying') + '… ' + esc(mmss(state.elapsedMs)) +
                ' <span style="color:var(--fwmon-text-faint);">— the collector applies this on its next check-in (up to ~1 min)</span></span></div>';
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
        $('ipsec-deploy-body').innerHTML = collisionGuidance(data) + line + endsHtml;
    }

    function pollDeploy(id, gen, startMs, op) {
        if (!deployLive(gen)) return;
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/deploy').then(function (r) {
            if (!deployLive(gen)) return;
            var data = (r && r.data) || {};
            var elapsed = Date.now() - startMs;
            var terminal = deployTerminal(data.status);
            var more = !terminal && elapsed < DEPLOY_WINDOW_MS;
            renderDeployBody(id, data, { elapsedMs: elapsed, polling: more, exhausted: !terminal && !more }, op);
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
