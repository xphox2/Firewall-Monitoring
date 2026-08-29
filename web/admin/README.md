# Admin UI pages (`web/admin/`)

These HTML documents are the admin interface, embedded into the server binary
via `//go:embed` and served by `cmd/api`. `admin.html` is the single-page app
shell and now hosts the large majority of pages (dashboard, devices, sites,
probes, IRC, alerts, event-rules, settings, …) as in-page `page-<name>` divs
switched client-side by `admin-main.js`. The remaining separate full-page
documents are `device-detail.html`, `connection-detail.html`, and
`login.html`.

## Sidebar/header duplication is being retired by folding pages into the SPA

AUDIT-161 originally flagged that the sidebar nav, header, and `<script>` list
were duplicated across the standalone pages, and the prior decision was to
**accept** the duplication rather than templatize. That trade-off stopped paying
off: the duplicated `<head>`/sidebar drifted (stylesheet order, nav CSS,
branding), which caused a run of nav-font bugs. The response is to remove the
duplication at the source by **folding the standalone pages into the `admin.html`
SPA** — one `<head>`, one sidebar, one nav definition.

- **Probes, Sites, IRC** were folded in (their markup moved into `page-probes` /
  `page-sites` / `page-irc` divs; their logic in `admin-{name}.js` now exposes an
  `init()` the SPA calls on page show). Their routes render `admin.html`.
- **device-detail** and **connection-detail** are the remaining detail pages;
  they take an entity id in the URL and load charts, so they are folded in a
  separate follow-up that adds id-from-path routing and lazy chart-asset loading.
- **login** stays standalone by design (pre-auth, its own self-contained layout).

The shared sidebar/nav CSS is single-sourced in `admin-tw-bridge.css` (linked
last on every page) so any page still using the shell renders identically.
