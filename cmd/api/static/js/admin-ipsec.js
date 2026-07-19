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
        var cls = { up: 'success', down: 'danger', error: 'danger', draft: 'info', deploying: 'warning' }[s] || 'info';
        return '<span class="badge ' + cls + '">' + esc(s || 'draft') + '</span>';
    }

    function renderTunnels(list) {
        var wrap = $('ipsec-tunnels-wrap');
        if (!list.length) {
            wrap.innerHTML = '<div class="card" style="padding:20px;color:var(--fwmon-text-mute);">No tunnels yet. Click “+ New Tunnel” to design one.</div>';
            return;
        }
        var rows = list.map(function (t) {
            return '<tr>' +
                '<td>' + esc(t.name || ('fwm-t' + t.id)) + '</td>' +
                '<td>' + esc(t.a_vendor || '?') + ' ↔ ' + esc(t.b_vendor || '?') + '</td>' +
                '<td>' + statusBadge(t.status) + '</td>' +
                '<td style="text-align:right;">' +
                    '<button class="btn sm secondary" data-action="ipsec-preflight" data-min-role="admin" data-id="' + t.id + '" title="Read-only REST check — no device writes">Preflight</button> ' +
                    '<button class="btn sm secondary" data-action="ipsec-edit" data-min-role="admin" data-id="' + t.id + '">Edit</button> ' +
                    '<button class="btn sm danger" data-action="ipsec-delete" data-min-role="admin" data-id="' + t.id + '">Delete</button>' +
                '</td></tr>';
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
        ['a-subnets', 'a-id', 'b-subnets', 'b-id', 'psk',
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
            'ipsec-preflight-close': function () { stopPreflightPoll(); AC.closeModal('ipsec-preflight-modal'); }
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

    function stopPreflightPoll() {
        if (preflightTimer) { clearTimeout(preflightTimer); preflightTimer = null; }
    }

    function yn(v) { return v ? 'yes' : 'no'; }

    function endReportHtml(e) {
        var r = e.report;
        var head = '<div style="font-weight:600;margin-bottom:4px;">End ' + (e.end === 0 ? 'A' : 'B') +
            ' <span style="color:var(--fwmon-text-mute);font-weight:normal;">(device #' + esc(e.device_id) + ')</span> ' +
            statusBadge(e.status) + '</div>';
        if (!r) {
            var note = e.status === 'none' ? 'not run yet' :
                (e.status === 'pending' || e.status === 'dispatched') ? 'waiting for the collector…' :
                (e.raw_result ? esc(e.raw_result) : 'no report');
            return '<div class="card" style="padding:12px;">' + head + '<div style="color:var(--fwmon-text-mute);font-size:0.85rem;">' + note + '</div></div>';
        }
        function b(ok, warn, label) {
            var cls = ok ? 'success' : (warn ? 'warning' : 'danger');
            return '<span class="badge ' + cls + '" style="margin-right:6px;">' + esc(label) + '</span>';
        }
        var badges =
            b(r.reachable, false, r.reachable ? 'reachable' : 'unreachable') +
            b(r.auth_ok, false, r.auth_ok ? 'auth ok' : 'auth failed') +
            (r.conflict ? b(false, false, 'name collision') :
                (r.indeterminate ? b(false, true, 'collision check inconclusive') : b(true, false, 'no collision')));
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

    function renderPreflightBody(data) {
        var ends = (data && data.ends) || [];
        $('ipsec-preflight-body').innerHTML =
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
            ends.map(endReportHtml).join('') + '</div>';
    }

    function pollPreflight(id, triesLeft) {
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/preflight').then(function (r) {
            var data = (r && r.data) || {};
            renderPreflightBody(data);
            var ends = data.ends || [];
            var terminal = ends.length > 0 && ends.every(function (e) {
                return e.status === 'succeeded' || e.status === 'failed' || e.status === 'expired';
            });
            if (!terminal && triesLeft > 0) {
                preflightTimer = setTimeout(function () { pollPreflight(id, triesLeft - 1); }, 2000);
            }
        }).catch(function (e) {
            $('ipsec-preflight-body').innerHTML = '<div class="card" style="padding:12px;color:var(--fwmon-sig-crit);">Failed to read preflight result: ' + esc(e.message) + '</div>';
        });
    }

    function preflight(id) {
        stopPreflightPoll();
        $('ipsec-preflight-body').innerHTML = '<div class="card" style="padding:12px;color:var(--fwmon-text-mute);">Starting preflight…</div>';
        AC.openModal('ipsec-preflight-modal');
        AC.apiFetch(API + '/ipsec/tunnels/' + id + '/preflight', { method: 'POST' }).then(function () {
            pollPreflight(id, 12); // ~24s of polling
        }).catch(function (e) {
            $('ipsec-preflight-body').innerHTML = '<div class="card" style="padding:12px;color:var(--fwmon-sig-crit);">Could not start preflight: ' + esc(e.message) + '</div>';
        });
    }

    window.FwmonIPSec = { init: init };
})();
