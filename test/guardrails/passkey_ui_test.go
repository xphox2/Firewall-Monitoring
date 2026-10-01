package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Source-scanning guards for the passkey (WebAuthn) UI. They pin the
// properties a refactor could silently lose: the login button is never shown
// without the server-config gate, no inline handlers / scripts (strict CSP),
// passkey names never reach innerHTML, admin calls carry the CSRF header,
// re-issued sessions keep working, and nothing lands in browser storage.

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

// section returns body[from marker .. to marker), failing when either is
// missing so a renamed marker cannot turn a guard into a no-op.
func section(t *testing.T, name, body, from, to string) string {
	t.Helper()
	a := strings.Index(body, from)
	if a < 0 {
		t.Fatalf("%s: start marker %q not found", name, from)
	}
	b := strings.Index(body[a:], to)
	if b < 0 {
		t.Fatalf("%s: end marker %q not found after start", name, to)
	}
	return body[a : a+b]
}

// TestPasskeyLogin_ButtonGatedByServerConfig: the passkey section ships
// hidden, and the ONLY code that reveals it runs after FwmonPasskey.usable()
// accepted the config fetched from /api/auth/passkey/config.
func TestPasskeyLogin_ButtonGatedByServerConfig(t *testing.T) {
	html := readRepoFile(t, "web/admin/login.html")
	if !regexp.MustCompile(`id="passkey-section"\s+class="hidden[ "]`).MatchString(html) {
		t.Error(`login.html: #passkey-section must carry class "hidden" in the markup (shown only by admin-login.js after the config check)`)
	}
	helper := strings.Index(html, `src="/static/js/fwmon-passkey.js"`)
	login := strings.Index(html, `src="/static/js/admin-login.js"`)
	if helper < 0 || login < 0 || helper > login {
		t.Error("login.html must load fwmon-passkey.js before admin-login.js")
	}

	js := readRepoFile(t, "cmd/api/static/js/admin-login.js")
	reveal := "section.classList.remove('hidden')"
	if n := strings.Count(js, reveal); n != 1 {
		t.Fatalf("admin-login.js: expected exactly one reveal of the passkey section, found %d", n)
	}
	gate := section(t, "admin-login.js", js, "PK.getConfig().then(function(cfg) {", reveal)
	if !strings.Contains(gate, "if (!PK.usable(cfg)) { return; }") {
		t.Error("admin-login.js: the passkey section must be revealed only after `if (!PK.usable(cfg)) { return; }` inside getConfig().then")
	}
	if strings.Contains(js, "passkey-section').classList.remove") {
		t.Error("admin-login.js: the passkey section is revealed outside the config gate")
	}

	helperJS := readRepoFile(t, "cmd/api/static/js/fwmon-passkey.js")
	for _, sig := range []string{
		"var CONFIG_URL = '/api/auth/passkey/config';",
		"cfg.enabled === true) && browserSupported() && originAllowed(cfg)",
		"!!window.PublicKeyCredential",
		"window.isSecureContext === true",
		"cfg.origins.indexOf(window.location.origin) !== -1",
		// Any fetch / parse failure means "disabled" — no UI, no error.
		".catch(function () { return { enabled: false, origins: [] }; })",
	} {
		if !strings.Contains(helperJS, sig) {
			t.Errorf("fwmon-passkey.js missing gate signal %q", sig)
		}
	}
}

// TestPasskeyLogin_SilentCancelGenericError: one generic failure message, a
// cancelled prompt stays silent, and success shares the password path.
func TestPasskeyLogin_SilentCancelGenericError(t *testing.T) {
	js := readRepoFile(t, "cmd/api/static/js/admin-login.js")
	for _, sig := range []string{
		"if (PK.isCancel(err)) {",
		"showError(PASSKEY_FAILED);",
		"completeLogin(fin.data);",
		"API_BASE + '/auth/passkey/login/begin'",
		"API_BASE + '/auth/passkey/login/finish'",
	} {
		if !strings.Contains(js, sig) {
			t.Errorf("admin-login.js missing %q", sig)
		}
	}
	// No server error text is surfaced for a passkey failure.
	if strings.Contains(js, "fin.error") || strings.Contains(js, "begin.error") {
		t.Error("admin-login.js must not surface server error text for passkey sign-in (one generic message)")
	}
	helperJS := readRepoFile(t, "cmd/api/static/js/fwmon-passkey.js")
	if !strings.Contains(helperJS, "err.name === 'NotAllowedError' || err.name === 'AbortError'") {
		t.Error("fwmon-passkey.js isCancel must treat NotAllowedError / AbortError as a user cancel")
	}
}

var inlineHandlerRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*["']`)

// TestPasskeyUI_NoInlineHandlersOrScripts: strict CSP (script-src nonce, no
// unsafe-inline) — inline handlers would silently not run.
func TestPasskeyUI_NoInlineHandlersOrScripts(t *testing.T) {
	for _, f := range []string{
		"web/admin/login.html",
		"cmd/api/static/js/fwmon-passkey.js",
		"cmd/api/static/js/admin-login.js",
		"cmd/api/static/js/admin-profile.js",
		"cmd/api/static/js/admin-users.js",
	} {
		body := readRepoFile(t, f)
		if m := inlineHandlerRe.FindString(body); m != "" {
			t.Errorf("%s contains an inline event handler %q — use addEventListener / data-action", f, strings.TrimSpace(m))
		}
	}
	html := readRepoFile(t, "web/admin/login.html")
	for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(html, -1) {
		if !strings.Contains(tag, " src=") && !strings.Contains(tag, "{{ .Nonce }}") {
			t.Errorf("login.html has an inline <script> without the CSP nonce: %s", tag)
		}
	}
	admin := readRepoFile(t, "web/admin/admin.html")
	card := section(t, "admin.html", admin, `id="card-passkeys"`, "</div>\n        </div>")
	if m := inlineHandlerRe.FindString(card); m != "" {
		t.Errorf("admin.html passkeys card contains an inline handler %q", m)
	}
	if !regexp.MustCompile(`id="card-passkeys"\s+hidden`).MatchString(admin) {
		t.Error(`admin.html: #card-passkeys must ship with the hidden attribute (revealed only when passkeys are enabled)`)
	}
}

// TestPasskeyUI_NamesNeverInnerHTML: passkey names are user-controlled.
func TestPasskeyUI_NamesNeverInnerHTML(t *testing.T) {
	profile := readRepoFile(t, "cmd/api/static/js/admin-profile.js")
	pk := section(t, "admin-profile.js", profile, "/* ---------------- Passkeys (WebAuthn)", "function saveProfile(")
	if strings.Contains(pk, "innerHTML") || strings.Contains(pk, "insertAdjacentHTML") || strings.Contains(pk, "outerHTML") {
		t.Error("admin-profile.js passkey section must build the DOM with textContent / createElement, never HTML strings")
	}
	if !strings.Contains(pk, "n.textContent = text;") {
		t.Error("admin-profile.js passkey section: the element helper must set textContent")
	}
	login := readRepoFile(t, "cmd/api/static/js/admin-login.js")
	if strings.Contains(login, "innerHTML") {
		t.Error("admin-login.js must not use innerHTML (passkey notice names are user-controlled)")
	}
	if !strings.Contains(login, "li.textContent =") {
		t.Error("admin-login.js: passkey notice names must be written with textContent")
	}
	users := readRepoFile(t, "cmd/api/static/js/admin-users.js")
	btn := section(t, "admin-users.js", users, "function passkeyButton(u) {", "\n        }\n")
	if !strings.Contains(btn, `data-name="' + esc(u.username) + '"`) || !strings.Contains(btn, `data-id="' + esc(u.id) + '"`) {
		t.Error("admin-users.js passkeyButton must escape the username and id it puts in attributes")
	}
}

// TestPasskeyUI_CSRFAndSessionReissue: every admin passkey call rides
// AC.apiFetch (which sets X-CSRF-Token); responses that re-issue the session
// hand their new CSRF token to AC.setCsrfToken.
func TestPasskeyUI_CSRFAndSessionReissue(t *testing.T) {
	common := readRepoFile(t, "cmd/api/static/js/admin-common.js")
	for _, sig := range []string{
		"'X-CSRF-Token': getCsrfToken(),",
		"function setCsrfToken(t) {",
		"setCsrfToken: setCsrfToken,",
		"promptFields: promptFieldsModal,",
	} {
		if !strings.Contains(common, sig) {
			t.Errorf("admin-common.js missing %q", sig)
		}
	}

	profile := readRepoFile(t, "cmd/api/static/js/admin-profile.js")
	pk := section(t, "admin-profile.js", profile, "/* ---------------- Passkeys (WebAuthn)", "function saveProfile(")
	if regexp.MustCompile(`[^.]fetch\(`).MatchString(pk) {
		t.Error("admin-profile.js passkey section must use AC.apiFetch (CSRF header), not bare fetch")
	}
	for _, sig := range []string{
		"AC.apiFetch(API_BASE + '/passkeys')",
		"AC.apiFetch(API_BASE + '/passkeys/register/begin'",
		"AC.apiFetch(API_BASE + '/passkeys/register/finish'",
		"AC.apiFetch(API_BASE + '/passkeys/notices/ack'",
		"method: 'PUT', body: { name: n }",
		"method: 'DELETE', body: { password: creds.password, totp_code: creds.totp_code }",
		"AC.setCsrfToken(d.csrf_token)",
		"adoptSession(res);",
	} {
		if !strings.Contains(pk, sig) {
			t.Errorf("admin-profile.js passkey section missing %q", sig)
		}
	}

	users := readRepoFile(t, "cmd/api/static/js/admin-users.js")
	rm := section(t, "admin-users.js", users, "'user-remove-passkeys': function (el) {", "'user-delete': function (el) {")
	for _, sig := range []string{
		"AC.confirm(",
		"AC.apiFetch(API_BASE + '/users/' + encodeURIComponent(el.dataset.id) + '/passkeys', { method: 'DELETE' })",
		"AC.setCsrfToken(d.csrf_token)",
	} {
		if !strings.Contains(rm, sig) {
			t.Errorf("admin-users.js remove-passkeys action missing %q", sig)
		}
	}

	// The endpoints the UI calls exist in main.go.
	main := readRepoFile(t, "cmd/api/main.go")
	for _, r := range []string{
		`api.GET("/auth/passkey/config"`,
		`api.POST("/auth/passkey/login/begin"`,
		`api.POST("/auth/passkey/login/finish"`,
		`admin.GET("/api/passkeys"`,
		`admin.POST("/api/passkeys/register/begin"`,
		`admin.POST("/api/passkeys/register/finish"`,
		`admin.POST("/api/passkeys/notices/ack"`,
		`admin.PUT("/api/passkeys/:id"`,
		`admin.DELETE("/api/passkeys/:id"`,
		`admin.DELETE("/api/users/:id/passkeys"`,
	} {
		if !strings.Contains(main, r) {
			t.Errorf("main.go no longer registers %s, which the passkey UI calls", r)
		}
	}
}

// TestPasskeyUI_ChangePasswordSendsRemovePasskeys: both change-password forms
// send remove_passkeys from a checkbox that is ticked by default.
func TestPasskeyUI_ChangePasswordSendsRemovePasskeys(t *testing.T) {
	main := readRepoFile(t, "cmd/api/static/js/admin-main.js")
	if !strings.Contains(main, "remove_passkeys: removePasskeys") {
		t.Error("admin-main.js changePassword must send remove_passkeys")
	}
	admin := readRepoFile(t, "web/admin/admin.html")
	if !regexp.MustCompile(`id="change-password-remove-passkeys"\s+checked`).MatchString(admin) {
		t.Error("admin.html: the profile 'Also remove all my passkeys' box must be checked by default")
	}
	common := readRepoFile(t, "cmd/api/static/js/admin-common.js")
	for _, sig := range []string{"pkBox.checked = true;", "remove_passkeys: pkBox.checked"} {
		if !strings.Contains(common, sig) {
			t.Errorf("admin-common.js forced password change missing %q", sig)
		}
	}
}

// TestPasskeyUI_NoBrowserStorage: no passkey state (or anything else) in
// localStorage / sessionStorage from the passkey code.
func TestPasskeyUI_NoBrowserStorage(t *testing.T) {
	helper := readRepoFile(t, "cmd/api/static/js/fwmon-passkey.js")
	profile := readRepoFile(t, "cmd/api/static/js/admin-profile.js")
	pk := section(t, "admin-profile.js", profile, "/* ---------------- Passkeys (WebAuthn)", "function saveProfile(")
	login := readRepoFile(t, "cmd/api/static/js/admin-login.js")
	pkLogin := section(t, "admin-login.js", login, "var PASSKEY_FAILED", "setupPasskeyLogin();")
	for name, body := range map[string]string{
		"fwmon-passkey.js":             helper,
		"admin-profile.js passkeys":    pk,
		"admin-login.js passkey login": pkLogin,
	} {
		if strings.Contains(body, "localStorage") || strings.Contains(body, "sessionStorage") || strings.Contains(body, "document.cookie") {
			t.Errorf("%s must not touch browser storage or cookies", name)
		}
	}
}

// TestPasskeyUI_ReissueHoldsAuthRedirect: a request that bumps the caller's
// own token version runs under the 401-redirect hold, so a background poll
// landing before the re-issued cookie cannot yank the tab to /admin/login.
func TestPasskeyUI_ReissueHoldsAuthRedirect(t *testing.T) {
	common := readRepoFile(t, "cmd/api/static/js/admin-common.js")
	hold := section(t, "admin-common.js", common, "function withAuthRedirectHold(fn) {", "\n    }\n")
	for _, sig := range []string{
		"window.__fwmonAuthRedirectHold = true;",
		".finally(function() { window.__fwmonAuthRedirectHold = prev; })",
	} {
		if !strings.Contains(hold, sig) {
			t.Errorf("withAuthRedirectHold missing %q", sig)
		}
	}
	if !strings.Contains(common, "if (window.__fwmonAuthRedirectHold) {") {
		t.Error("apiFetch no longer honours __fwmonAuthRedirectHold on 401")
	}

	profile := readRepoFile(t, "cmd/api/static/js/admin-profile.js")
	del := section(t, "admin-profile.js", profile, "function deletePasskey(btn) {", "function ackPasskeyNotices()")
	held := section(t, "admin-profile.js deletePasskey", del, "AC.withAuthRedirectHold(function () {", "}).then(function (res) {\n                AC.showSuccess")
	for _, sig := range []string{"method: 'DELETE'", "adoptSession(res);"} {
		if !strings.Contains(held, sig) {
			t.Errorf("deletePasskey: %q must run inside AC.withAuthRedirectHold", sig)
		}
	}

	users := readRepoFile(t, "cmd/api/static/js/admin-users.js")
	rm := section(t, "admin-users.js", users, "'user-remove-passkeys': function (el) {", "'user-delete': function (el) {")
	if !strings.Contains(rm, "(self ? AC.withAuthRedirectHold(call) : call())") {
		t.Error("admin-users.js: removing your own passkeys must run under AC.withAuthRedirectHold")
	}
	call := section(t, "admin-users.js call", rm, "var call = function () {", "\n                    };")
	if !strings.Contains(call, "AC.setCsrfToken(d.csrf_token)") {
		t.Error("admin-users.js: the CSRF token must be adopted inside the held call")
	}
}

// TestPasskeyUI_ConfigFetchTimesOut: getConfig settles (as disabled) even when
// the request hangs, so nothing that waits on it can block rendering.
func TestPasskeyUI_ConfigFetchTimesOut(t *testing.T) {
	js := readRepoFile(t, "cmd/api/static/js/fwmon-passkey.js")
	cfg := section(t, "fwmon-passkey.js", js, "function getConfig() {", "return configPromise;")
	for _, sig := range []string{
		"new AbortController()",
		"ctrl.abort();",
		"signal: ctrl ? ctrl.signal : undefined",
		"Promise.race([request, timeout])",
		".catch(function () { return { enabled: false, origins: [] }; })",
	} {
		if !strings.Contains(cfg, sig) {
			t.Errorf("getConfig missing timeout signal %q", sig)
		}
	}
	if !regexp.MustCompile(`var CONFIG_TIMEOUT_MS = [1-9][0-9]{3};`).MatchString(js) {
		t.Error("fwmon-passkey.js: CONFIG_TIMEOUT_MS must be a few seconds")
	}
}

// TestPasskeyUI_WebAuthnCalledInsideUserGesture: Safari/WebKit refuse
// credentials.get/create outside a user gesture. Login prefetches the begin
// options so the click calls get() directly; profile add calls create() from
// a dialog button's synchronous run(); a refusal after a non-gesture fallback
// is reported, not swallowed.
func TestPasskeyUI_WebAuthnCalledInsideUserGesture(t *testing.T) {
	login := readRepoFile(t, "cmd/api/static/js/admin-login.js")
	click := section(t, "admin-login.js", login, "btn.addEventListener('click', function() {", "btn.disabled = true;")
	for _, sig := range []string{
		"var fresh = takeFresh();",
		"attempt = finish(callGet(fresh.publicKey), true);",
	} {
		if !strings.Contains(click, sig) {
			t.Errorf("admin-login.js click handler missing %q (get() must run inside the click)", sig)
		}
	}
	gesturePath := section(t, "admin-login.js gesture path", click, "if (fresh) {", "} else {")
	if strings.Contains(gesturePath, ".then(") || strings.Contains(gesturePath, "fetch") {
		t.Error("admin-login.js: nothing may be awaited before get() on the prefetched (gesture) path")
	}
	for _, sig := range []string{
		"fetchOptions();\n            btn.addEventListener", // prefetch when the button appears
		"if (!viaGesture) { showError(PASSKEY_BLOCKED); }",
		"Date.now() - p.at < PREFETCH_MAX_AGE_MS",
	} {
		if !strings.Contains(login, sig) {
			t.Errorf("admin-login.js missing %q", sig)
		}
	}

	common := readRepoFile(t, "cmd/api/static/js/admin-common.js")
	if !strings.Contains(common, "btn.addEventListener('click', function() { cleanup(b.run ? b.run() : b.value); });") {
		t.Error("dialogModal: a button's run() must be called synchronously in its click handler")
	}
	profile := readRepoFile(t, "cmd/api/static/js/admin-profile.js")
	add := section(t, "admin-profile.js", profile, "function addPasskey() {", "function renamePasskey(btn) {")
	run := section(t, "admin-profile.js addPasskey", add, "run: function () {", "}\n                });")
	if !strings.Contains(run, "navigator.credentials.create({ publicKey: PK.creationOptions(pk) })") {
		t.Error("admin-profile.js: credentials.create() must be called from AC.gestureModal's run()")
	}
	if strings.Count(add, "navigator.credentials.create(") != 1 {
		t.Error("admin-profile.js: credentials.create() must be called only from the gesture dialog")
	}
}
