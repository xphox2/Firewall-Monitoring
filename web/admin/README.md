# Admin UI pages (`web/admin/`)

These standalone HTML documents are the admin interface, embedded into the
server binary via `//go:embed` and served by `cmd/api`. `admin.html` is the
single-page app shell (most tabs live inside it); the others
(`device-detail.html`, `connection-detail.html`, `probes.html`, `sites.html`,
`probe-pending.html`, `irc.html`, `login.html`) are separate full-page documents
with their own `<script>`/`<link>` lists.

## Duplicated sidebar/header markup is intentional (AUDIT-160/161)

AUDIT-161 flagged that the sidebar nav, header, and `<script>` tag list are
duplicated across these pages, and suggested either a Go `template.ParseGlob`
layout or an htmx-style include. **We accept the duplication and do not
templatize**, by decision:

- This is a **single-tenant, internal operator tool** with a small, stable set
  of pages — not a content site where layout churns. The nav changes rarely.
- The pages are plain `//go:embed` static documents with no server-side render
  step; introducing Go HTML templating (or htmx) for the shell would add a
  build/render layer and real regression risk to a **working** UI for a purely
  cosmetic DRY gain.
- The trade-off — when the nav *does* change, it must be edited in each page —
  is a known, bounded maintenance cost that's cheaper than the rework + risk.

If the page count or nav complexity grows materially, revisit this with a
`template.ParseGlob` shared layout. Until then, keep the markup in sync by hand
and treat this note as the record of the decision.
