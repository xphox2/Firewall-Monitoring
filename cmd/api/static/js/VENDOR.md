# Vendored browser libraries (AUDIT-160)

The admin/public UI ships a handful of third-party JavaScript/CSS libraries as
**committed, pre-minified artifacts** rather than pulling them from a CDN or an
`npm install` at build time. This is deliberate: the server embeds `web/` and
`cmd/api/static/` via `//go:embed`, so the UI must work fully offline/air-gapped
with no external fetch and no Node build step at deploy time.

The trade-off AUDIT-160 flagged is provenance: a committed minified blob has no
record of *which* upstream version it is or where to get the matching source.
This file is that record. When refreshing a library, update its row here, keep
the version in sync with `package.json`'s `vendoredBrowserLibraries`, and prefer
the upstream's official minified release so the banner/version stays embedded.

All vendored libraries below are **MIT-licensed**, matching this project's MIT
license — no copyleft obligations. Each minified file retains its upstream
copyright/license banner.

| File | Library | Version | Upstream | License |
|---|---|---|---|---|
| `js/chart.umd.min.js` | Chart.js | 4.4.7 | https://github.com/chartjs/Chart.js | MIT |
| `js/chartjs-plugin-zoom.min.js` | chartjs-plugin-zoom | 2.0.1 | https://github.com/chartjs/chartjs-plugin-zoom | MIT |
| `js/cytoscape.min.js` | Cytoscape.js | 3.30.4 | https://github.com/cytoscape/cytoscape.js | MIT |
| `js/cytoscape-fcose.js` | cytoscape-fcose | see note¹ | https://github.com/iVis-at-Bilkent/cytoscape.js-fcose | MIT |
| `js/cose-base.js` | cose-base | see note¹ | https://github.com/iVis-at-Bilkent/cose-base | MIT |
| `js/layout-base.js` | layout-base | see note¹ | https://github.com/iVis-at-Bilkent/layout-base | MIT |
| `js/gridstack-all.min.js` | GridStack.js | 10.3.1 | https://github.com/gridstack/gridstack.js | MIT |
| `js/uPlot.iife.min.js` | µPlot | 1.6.31 | https://github.com/leeoniya/uPlot | MIT |
| `css/gridstack.min.css` | GridStack.js | 10.3.1 | https://github.com/gridstack/gridstack.js | MIT |
| `css/uPlot.min.css` | µPlot | 1.6.31 | https://github.com/leeoniya/uPlot | MIT |

¹ **Version not embedded in the artifact.** The three cytoscape-fcose layout-stack
files are webpack UMD bundles with no version banner, so the exact patch can't be
read back from the committed blob. They are the fcose layout dependency chain
(`cytoscape-fcose` → `cose-base` → `layout-base`) for the connection-map diagram.
Confirm and pin their versions against the upstream release tags on the next
vendor refresh (fetch the tagged `dist/` artifact so the banner is retained).

> **App-owned (NOT vendored), for clarity:** `js/admin-*.js`,
> `js/diagram-cytoscape.js`, `js/diagram-panels.js`, `js/public-dashboard.js`,
> and `css/admin-*.css` / `css/styles.css` / `css/tailwind.css` are this
> project's own source, not third-party libraries.
