# Third-Party Notices

Firewall-Mon includes the following third-party software. Each component is listed with its license terms; full license texts follow the inventory.

---

## Browser-side assets (vendored under `cmd/api/static/`)

### Chart.js — MIT

- **Version**: 4.4.7
- **Copyright**: (c) 2024 Chart.js Contributors
- **Source**: https://github.com/chartjs/Chart.js
- **File**: `cmd/api/static/js/chart.umd.min.js`

### @kurkle/color — MIT

Bundled inside Chart.js UMD; included by reference.

- **Version**: 0.3.2
- **Copyright**: (c) 2023 Jukka Kurkela
- **Source**: https://github.com/kurkle/color

### chartjs-plugin-zoom — MIT

- **Version**: 2.0.1
- **Copyright**: (c) 2016-2023 chartjs-plugin-zoom Contributors
- **Source**: https://github.com/chartjs/chartjs-plugin-zoom
- **File**: `cmd/api/static/js/chartjs-plugin-zoom.min.js`

### uPlot — MIT

- **Version**: 1.6.31
- **Copyright**: (c) Leon Sorokin
- **Source**: https://github.com/leeoniya/uPlot
- **Files**: `cmd/api/static/js/uPlot.iife.min.js`, `cmd/api/static/css/uPlot.min.css`

### Cytoscape.js — MIT

- **Version**: 3.30.4
- **Copyright**: (c) 2016-2024 The Cytoscape Consortium
- **Source**: https://github.com/cytoscape/cytoscape.js
- **File**: `cmd/api/static/js/cytoscape.min.js`

### cytoscape-fcose — MIT

- **Version**: 2.2.0
- **Copyright**: i-Vis Research Group, Bilkent University
- **Source**: https://github.com/iVis-at-Bilkent/cytoscape.js-fcose
- **File**: `cmd/api/static/js/cytoscape-fcose.js`

### cose-base — MIT

- **Version**: 2.2.0 (paired with cytoscape-fcose 2.2.0)
- **Copyright**: i-Vis Research Group, Bilkent University
- **Source**: https://github.com/iVis-at-Bilkent/cose-base
- **File**: `cmd/api/static/js/cose-base.js`

### layout-base — Apache-2.0

- **Version**: 3.1.0 (paired with cose-base 2.2.0)
- **Copyright**: i-Vis Research Group, Bilkent University, 2007-present
- **Source**: https://github.com/iVis-at-Bilkent/layout-base
- **File**: `cmd/api/static/js/layout-base.js`
- **Note**: embeds the JAMA SVD routine (also Apache-2.0).

### Gridstack.js — MIT

- **Version**: 10.3.1
- **Copyright**: (c) Gridstack contributors
- **Source**: https://github.com/gridstack/gridstack.js
- **Files**: `cmd/api/static/js/gridstack-all.min.js`, `cmd/api/static/css/gridstack.min.css`

### Tailwind CSS — MIT

Compiled output included as `cmd/api/static/css/tailwind.css`. Build-time only.

- **Version**: 3.4.x (see `package.json`)
- **Copyright**: (c) Tailwind Labs, Inc.
- **Source**: https://github.com/tailwindlabs/tailwindcss

### Inter (font) — SIL Open Font License 1.1

- **Copyright**: Copyright (c) The Inter Project Authors (Rasmus Andersson)
- **Source**: https://github.com/rsms/inter
- **File**: `cmd/api/static/fonts/inter-latin.woff2`

### JetBrains Mono (font) — SIL Open Font License 1.1

- **Copyright**: Copyright (c) JetBrains s.r.o. and contributors
- **Source**: https://github.com/JetBrains/JetBrainsMono
- **File**: `cmd/api/static/fonts/jetbrains-mono-latin.woff2`

---

## Server-side Go dependencies (`go.mod`)

### Direct dependencies

| Package | Version | License |
|---|---|---|
| [github.com/gin-gonic/gin](https://github.com/gin-gonic/gin) | v1.10.1 | MIT |
| [github.com/glebarez/sqlite](https://github.com/glebarez/sqlite) | v1.11.0 | MIT |
| [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) | v5.2.2 | MIT |
| [github.com/gosnmp/gosnmp](https://github.com/gosnmp/gosnmp) | v1.43.2 | BSD-2-Clause |
| [github.com/jackc/pgx/v5](https://github.com/jackc/pgx) | v5.6.0 | MIT |
| [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang) | v1.23.2 | Apache-2.0 |
| [github.com/thoj/go-ircevent](https://github.com/thoj/go-ircevent) | v0.0.0-20210723 | BSD-3-Clause |
| [github.com/wcharczuk/go-chart/v2](https://github.com/wcharczuk/go-chart) | v2.1.2 | MIT |
| [go.opentelemetry.io/otel](https://github.com/open-telemetry/opentelemetry-go) | v1.44.0 | Apache-2.0 |
| [go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp](https://github.com/open-telemetry/opentelemetry-go) | v1.44.0 | Apache-2.0 |
| [go.opentelemetry.io/otel/sdk](https://github.com/open-telemetry/opentelemetry-go) | v1.44.0 | Apache-2.0 |
| [go.opentelemetry.io/otel/trace](https://github.com/open-telemetry/opentelemetry-go) | v1.44.0 | Apache-2.0 |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.51.0 | BSD-3-Clause |
| [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) | v0.55.0 | BSD-3-Clause |
| [golang.org/x/time](https://pkg.go.dev/golang.org/x/time) | v0.5.0 | BSD-3-Clause |
| [gorm.io/driver/postgres](https://gorm.io/) | v1.6.0 | MIT |
| [gorm.io/gorm](https://gorm.io/) | v1.31.1 | MIT |

### Indirect dependencies

The above pull in ~60 indirect dependencies; the full list and their versions are in `go.mod`. License terms for each are available at `https://pkg.go.dev/<module-path>?tab=licenses`. Notable transitive dependencies include `bytedance/sonic` (Apache-2.0), `modernc.org/sqlite` (BSD-3-Clause), `google/uuid` (BSD-3-Clause), `prometheus/client_model` / `prometheus/common` (Apache-2.0), and `klauspost/cpuid` (MIT).

---

## License texts

### MIT License

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

Applies to: Chart.js, @kurkle/color, chartjs-plugin-zoom, uPlot, Cytoscape.js, cytoscape-fcose, cose-base, Gridstack.js, Tailwind CSS, gin, glebarez/sqlite, golang-jwt, jackc/pgx/v5, wcharczuk/go-chart, gorm.

### BSD-2-Clause

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

Applies to: gosnmp.

### BSD-3-Clause

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

Applies to: thoj/go-ircevent, golang.org/x/crypto, golang.org/x/net, golang.org/x/time.

### Apache License 2.0

Full text: https://www.apache.org/licenses/LICENSE-2.0.txt

Applies to: layout-base (including the embedded JAMA SVD routine), prometheus/client_golang, and the `go.opentelemetry.io/otel*` modules (otel, otel/sdk, otel/trace, and the OTLP HTTP trace exporter).

### SIL Open Font License 1.1

Full text: https://openfontlicense.org/

Applies to: Inter, JetBrains Mono.

---

## Adding new third-party code

If you vendor a new browser-side asset or add a new direct Go dependency, append it to the corresponding section above with: name, version, license, copyright, source URL, and (for vendored files) the file path. Group new entries by license under the existing headings so the license texts remain comprehensive for everything in the inventory.
