# Admin frontend JavaScript — conventions

This directory holds the first-party admin-panel JavaScript (the public
wallboard lives under `web/public/`). These files are embedded into the API
binary via `//go:embed` and served directly — there is **no build/transpile
step today** (the esbuild migration is AUDIT-139).

## Language standard: ES2020 (AUDIT-131)

**Target ES2020 (ES11).** This is settled by the project's documented browser
baseline — **Chrome/Edge 105+, Safari 15.4+, Firefox 121+** (see the README
"Browser Support" section, AUDIT-168) — all of which fully support ES2020
(`let`/`const`, arrow functions, template literals, `async`/`await`, spread/
rest, optional chaining, nullish coalescing, `Promise.allSettled`, etc.).

- ✅ Use modern syntax freely. `admin-irc.js` is already written this way and is
  **correct** — the older "pick ES5" framing in the audit is superseded by the
  evergreen baseline.
- ❌ Do **not** add new ES5-compatibility workarounds. In particular the
  bracket-notation `promise['catch'](…)` form (a relic of IE11 reserved-word
  handling) is **legacy** — write `promise.catch(…)`. The remaining `['catch']`
  call sites are tracked for a cleanup sweep under **AUDIT-132**; don't add more.
- No `<script type="module">` / bundler is wired yet, so keep each file a
  self-contained IIFE that attaches to the shared `AdminCommon` / `AC`
  namespace rather than using ES module `import`/`export` (until AUDIT-139).

## Other conventions

- **Escape before `innerHTML`.** Use `AC.escapeHtml()` for any value that
  reaches the DOM as HTML (the `escapeHtml` nullish-guard from AUDIT-059 means
  numeric `0` renders correctly).
- **No inline `onclick="…"`.** Use `addEventListener` / `data-action`
  delegation (AUDIT-053) — the CSP `script-src` is strict (nonce-locked, no
  `unsafe-inline`), so inline handlers won't run.
- **Logging** goes through `fwmonLog.*` (AUDIT-151), not bare `console.*`.
- **API calls** go through `apiFetch` (handles CSRF, the iframe-safe 401
  redirect from AUDIT-058, and the transient-5xx retry from AUDIT-130).
