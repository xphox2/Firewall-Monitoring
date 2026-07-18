package report

// ReportTheme is the single source of visual truth for every report render —
// fleet report and critical alert, web preview and email, light and dark. One
// template consumes these tokens inline; there is no CSS-override theming
// (the old `.admin-preview !important` block is gone).
//
// EMAIL-SAFETY INVARIANTS (enforced by tests):
//   - No pure #ffffff / #000000 anywhere. Gmail iOS and classic Outlook
//     force-invert emails with zero developer hooks; off-white surfaces and
//     charcoal inks survive both directions of forced inversion, pure
//     white/black do not.
//   - Accents are midtones so Outlook's partial inversion (which may keep the
//     accent while flipping the surface behind it) stays legible.
//
// The values align with the admin SPA's --fwmon-* tokens (admin-design-
// system.css) so the web preview feels native to the site, with pure-white
// substitutes swapped for off-white.
type ReportTheme struct {
	// Name is "light" or "dark" (the ThemeByName key and settings value).
	Name string
	// ColorScheme feeds the color-scheme/supported-color-schemes metas and
	// the :root CSS property. Single-scheme on purpose: a fixed-theme email
	// declares ONLY its own scheme — declaring "light dark" invites Apple
	// Mail's automatic transforms with no dark stylesheet to back them.
	ColorScheme string

	Canvas  string // page background behind the sheet
	Surface string // the sheet + device cards
	Panel   string // KPI / mini / spike-group fills

	Ink     string // primary text
	InkDim  string // secondary text
	InkMute string // tertiary text / axis labels

	Hairline     string // structural 1px borders
	HairlineSoft string // row rules inside tables

	Accent string
	Ok     string
	Warn   string
	Crit   string

	OkTint   string // verdict band fills
	WarnTint string
	CritTint string

	ChartBG   string // ALWAYS opaque — a transparent chart is the classic
	ChartGrid string // dark-mode disaster (recolored surface, fixed pixels)
	ChartAxis string

	SeriesCPU    string
	SeriesMem    string
	SeriesAccent string
}

var themeLight = ReportTheme{
	Name:        "light",
	ColorScheme: "light",
	Canvas:      "#eef1f5",
	Surface:     "#fafbfc",
	Panel:       "#eef2f7",

	Ink:     "#16242c",
	InkDim:  "#4a5c66",
	InkMute: "#5f6e79",

	Hairline:     "#d3dae3",
	HairlineSoft: "#e4e9f0",

	Accent: "#2563eb",
	Ok:     "#138a5e",
	Warn:   "#9a6b0e",
	Crit:   "#c8323a",

	OkTint:   "#e6f2ec",
	WarnTint: "#f6efdc",
	// CritTint is a shade lighter than the natural pick so Crit text on it
	// clears WCAG AA 4.5:1 (#c8323a on #f9edee = 4.6:1; #f8e9ea was 4.49).
	CritTint: "#f9edee",

	ChartBG:   "#fafbfc",
	ChartGrid: "#dde3ea",
	ChartAxis: "#5f6e79",

	SeriesCPU:    "#c8323a",
	SeriesMem:    "#6d28d9",
	SeriesAccent: "#2563eb",
}

var themeDark = ReportTheme{
	Name:        "dark",
	ColorScheme: "dark",
	Canvas:      "#0d1117",
	Surface:     "#161b22",
	Panel:       "#1f2630",

	Ink:     "#e6edf3",
	InkDim:  "#8b949e",
	InkMute: "#828d99",

	Hairline:     "#2a313b",
	HairlineSoft: "#232a34",

	Accent: "#4c8dff",
	Ok:     "#36c98a",
	Warn:   "#e7b53c",
	Crit:   "#f2555a",

	OkTint:   "#15251e",
	WarnTint: "#262115",
	CritTint: "#2a181b",

	ChartBG:   "#161b22",
	ChartGrid: "#2a313b",
	ChartAxis: "#8b949e",

	SeriesCPU:    "#f2555a",
	SeriesMem:    "#c4b5fd",
	SeriesAccent: "#4c8dff",
}

// ThemeByName maps a settings/query value to a theme. Anything other than
// "dark" (including blank — RefreshSettings skips blank values, and email
// defaults to light) resolves to light.
func ThemeByName(name string) ReportTheme {
	if name == "dark" {
		return themeDark
	}
	return themeLight
}
