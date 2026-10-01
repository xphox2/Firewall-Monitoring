/* Passkey (WebAuthn) browser helpers — window.FwmonPasskey.
 *
 * Shared by the login page (admin-login.js, which does NOT load
 * admin-common.js) and the admin pages (profile passkey management, the
 * change-password forms). No DOM, no storage: only feature detection, the
 * server's public passkey config, and the base64url <-> ArrayBuffer
 * conversion the WebAuthn API needs.
 *
 * Rules every caller relies on:
 *  - usable(cfg) is the ONE gate for showing passkey UI. It is true only when
 *    the server says passkeys are enabled (GET /api/auth/passkey/config), the
 *    browser has WebAuthn, the page is a secure context, and this page's
 *    origin is one of the configured origins. Any fetch/parse error means
 *    "disabled" — with passkeys off there is no UI and no error.
 *  - Credential ids, challenges and user handles are opaque bytes: they are
 *    only ever converted and passed back to the server, never shown, parsed
 *    or stored (nothing here touches browser storage of any kind).
 */
(function () {
    'use strict';

    var CONFIG_URL = '/api/auth/passkey/config';
    var configPromise = null;

    function bufToB64url(buf) {
        var bytes = new Uint8Array(buf);
        var s = '';
        for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function b64urlToBuf(str) {
        var s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) { s += '='; }
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out.buffer;
    }

    function browserSupported() {
        return typeof window !== 'undefined' &&
            !!window.PublicKeyCredential &&
            window.isSecureContext === true &&
            !!(navigator.credentials && navigator.credentials.get && navigator.credentials.create);
    }

    // getConfig → Promise<{enabled, origins, rp_id}>; never rejects. Cached
    // per page load.
    function getConfig() {
        if (!configPromise) {
            configPromise = fetch(CONFIG_URL, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
                .then(function (res) { return res.ok ? res.json() : null; })
                .then(function (body) {
                    var d = body && body.success && body.data;
                    if (!d || d.enabled !== true) { return { enabled: false, origins: [] }; }
                    return { enabled: true, origins: Array.isArray(d.origins) ? d.origins : [], rp_id: d.rp_id || '' };
                })
                .catch(function () { return { enabled: false, origins: [] }; });
        }
        return configPromise;
    }

    function originAllowed(cfg) {
        return !!(cfg && Array.isArray(cfg.origins) && cfg.origins.indexOf(window.location.origin) !== -1);
    }

    // usable: the server has passkeys on AND this browser/page can use them.
    function usable(cfg) {
        return !!(cfg && cfg.enabled === true) && browserSupported() && originAllowed(cfg);
    }

    function convertDescriptors(list) {
        if (!Array.isArray(list)) { return list; }
        return list.map(function (d) {
            var c = {};
            Object.keys(d).forEach(function (k) { c[k] = d[k]; });
            c.id = b64urlToBuf(d.id);
            return c;
        });
    }

    function shallowCopy(o) {
        var c = {};
        Object.keys(o || {}).forEach(function (k) { c[k] = o[k]; });
        return c;
    }

    // requestOptions: server CredentialAssertion.publicKey → get() options.
    function requestOptions(pk) {
        var o = shallowCopy(pk);
        o.challenge = b64urlToBuf(pk.challenge);
        if (pk.allowCredentials) { o.allowCredentials = convertDescriptors(pk.allowCredentials); }
        return o;
    }

    // creationOptions: server CredentialCreation.publicKey → create() options.
    function creationOptions(pk) {
        var o = shallowCopy(pk);
        o.challenge = b64urlToBuf(pk.challenge);
        o.user = shallowCopy(pk.user);
        o.user.id = b64urlToBuf(pk.user.id);
        if (pk.excludeCredentials) { o.excludeCredentials = convertDescriptors(pk.excludeCredentials); }
        return o;
    }

    function clientExtensions(cred) {
        try { return cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}; } catch (e) { return {}; }
    }

    // assertionJSON: a get() result → the body /login/finish parses.
    function assertionJSON(cred) {
        var r = cred.response;
        var out = {
            id: cred.id,
            rawId: bufToB64url(cred.rawId),
            type: cred.type,
            clientExtensionResults: clientExtensions(cred),
            response: {
                clientDataJSON: bufToB64url(r.clientDataJSON),
                authenticatorData: bufToB64url(r.authenticatorData),
                signature: bufToB64url(r.signature)
            }
        };
        if (r.userHandle) { out.response.userHandle = bufToB64url(r.userHandle); }
        if (cred.authenticatorAttachment) { out.authenticatorAttachment = cred.authenticatorAttachment; }
        return out;
    }

    // attestationJSON: a create() result → the body /register/finish parses.
    function attestationJSON(cred) {
        var r = cred.response;
        var out = {
            id: cred.id,
            rawId: bufToB64url(cred.rawId),
            type: cred.type,
            clientExtensionResults: clientExtensions(cred),
            response: {
                clientDataJSON: bufToB64url(r.clientDataJSON),
                attestationObject: bufToB64url(r.attestationObject)
            }
        };
        if (typeof r.getTransports === 'function') {
            try { out.response.transports = r.getTransports(); } catch (e) { /* optional */ }
        }
        if (cred.authenticatorAttachment) { out.authenticatorAttachment = cred.authenticatorAttachment; }
        return out;
    }

    // isCancel: the user dismissed the browser prompt (or it timed out) —
    // callers stay silent instead of showing an error.
    function isCancel(err) {
        return !!err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
    }

    window.FwmonPasskey = {
        getConfig: getConfig,
        usable: usable,
        browserSupported: browserSupported,
        originAllowed: originAllowed,
        requestOptions: requestOptions,
        creationOptions: creationOptions,
        assertionJSON: assertionJSON,
        attestationJSON: attestationJSON,
        isCancel: isCancel,
        bufToB64url: bufToB64url,
        b64urlToBuf: b64urlToBuf
    };
})();
