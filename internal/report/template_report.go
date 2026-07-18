package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// RenderReportHTML renders a ReportModel into a single self-contained HTML
// document using only email-safe HTML/CSS: a hybrid single-column 600px table
// layout (MSO ghost tables for classic Outlook's Word engine), all critical
// styles inline, and every color drawn from m.Theme — one template serves the
// web preview and the email in both light and dark.
func RenderReportHTML(m ReportModel) (string, error) {
	if m.Theme.Name == "" {
		// A zero-value theme would render every color empty — default to
		// light rather than emit a colorless document.
		m.Theme = ThemeByName("")
	}
	var buf bytes.Buffer
	if err := reportTemplate.ExecuteTemplate(&buf, "report", m); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}
	return buf.String(), nil
}

// msoOpen/msoClose are the Outlook "ghost table" conditional comments that
// lock the layout to 600px in the Word rendering engine (classic Windows
// Outlook ignores max-width on divs). They MUST be injected as template.HTML:
// html/template discards HTML comments during rendering ("comments behave
// like white space"), so writing <!--[if mso]> literally in the template
// would silently strip the ghost tables from every email — verified against
// the Go source, and pinned by TestReportHTMLWellFormed's MSO assertion.
func msoOpen() template.HTML {
	return template.HTML(`<!--[if mso | IE]><table role="presentation" width="600" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`)
}

func msoClose() template.HTML {
	return template.HTML(`<!--[if mso | IE]></td></tr></table><![endif]-->`)
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":                 strings.ToUpper,
	"dict":                  templateDict,
	"gtColor":               gtColor,
	"renderAlertChart":      RenderAlertTimelineSVG,
	"fmtMinutes":            FormatMinutes,
	"renderThroughputChart": RenderThroughputChart,
	"renderCPUMemChart":     RenderCPUMemSVGChart,
	"msoOpen":               msoOpen,
	"msoClose":              msoClose,
	// Font stacks as template funcs (template.CSS passes the quoted names
	// through the style-attribute context unmangled).
	"fontStack": func() template.CSS { return template.CSS(fontStack) },
	"monoStack": func() template.CSS { return template.CSS(monoStack) },
}).Parse(reportTemplateSrc))

// gtColor returns pos when n > 0, otherwise zero — lets a KPI value (e.g.
// Offline/Critical counts) render muted at zero and in its alert color above it.
func gtColor(n int, pos, zero string) string {
	if n > 0 {
		return pos
	}
	return zero
}

// templateDict builds a map from alternating key/value args so sub-templates
// can be invoked with named fields (e.g. {{template "kpi" dict "Label" x ...}}).
func templateDict(pairs ...interface{}) (map[string]interface{}, error) {
	if len(pairs)%2 != 0 {
		return nil, fmt.Errorf("dict: odd number of args")
	}
	m := make(map[string]interface{}, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %d is not a string", i)
		}
		m[key] = pairs[i+1]
	}
	return m, nil
}

// fontStack / monoStack are the report's only typefaces. Segoe UI FIRST is
// deliberate: classic Outlook's Word engine resolves the first font it knows
// or falls back to Times New Roman — it does not walk the stack like a
// browser. No web fonts: Gmail and Outlook never load them, and an
// unrecognized @font-face is exactly what triggers the Times fallback.
const fontStack = `'Segoe UI',-apple-system,Roboto,Helvetica,Arial,sans-serif`
const monoStack = `Consolas,'SFMono-Regular',Menlo,'Courier New',monospace`

// Design language: "flat instrument panel". One visual device per element —
// a fill OR a hairline, never fill+ring+shadow stacks. No box-shadows, no
// gradients, no SVG filters, no accent side-bars. All colors come from
// ReportTheme (theme.go): off-white/charcoal surfaces, midtone accents,
// never pure #ffffff/#000000 (survives Gmail/Outlook forced dark-mode
// inversion). Layout: hybrid 600px single column, padding on <td> only,
// tables with border-collapse:separate and hairlines on cells (the Word
// engine mis-renders table-level collapse). border-radius is enhancement
// only — classic Outlook renders square corners, and that is fine.
const reportTemplateSrc = `
{{define "report"}}{{$t := .Theme}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="color-scheme" content="{{$t.ColorScheme}}">
<meta name="supported-color-schemes" content="{{$t.ColorScheme}}">
<title>Firewall Monitor — {{.Period}} Operations Report</title>
<style>
  :root { color-scheme: {{$t.ColorScheme}}; }
  body { -webkit-text-size-adjust: 100%; margin: 0; padding: 0; }
  @media only screen and (max-width: 620px) {
    .sheet { width: 100% !important; border-left: none !important; border-right: none !important; border-radius: 0 !important; }
    .content-cell { padding-left: 16px !important; padding-right: 16px !important; }
    .kpi-cell { display: inline-block !important; width: 31% !important; margin: 1% 0.5% !important; box-sizing: border-box; }
    .kpi-spacer { display: none !important; }
    .bw-card { display: block !important; width: 100% !important; margin-bottom: 10px !important; }
    .bw-spacer { display: none !important; }
    .mini-cell { display: inline-block !important; width: 48% !important; margin: 1% 0.5% !important; box-sizing: border-box; }
    .mini-spacer { display: none !important; }
  }
  /* Outlook.com / Outlook-app partial-invert repair (best effort; ignored
     elsewhere). Re-pins the load-bearing surfaces and inks. */
  [data-ogsc] .ink { color: {{$t.Ink}} !important; }
  [data-ogsc] .inkdim { color: {{$t.InkDim}} !important; }
  [data-ogsb] .sheet { background-color: {{$t.Surface}} !important; }
  [data-ogsb] .panel-fill { background-color: {{$t.Panel}} !important; }
{{if .Collapsible}}
  details > summary { cursor: pointer; list-style: none; outline: none; }
  details > summary::-webkit-details-marker { display: none; }
  details .details-arrow { display: inline-block !important; transition: transform 0.18s ease; transform: rotate(-90deg); color: {{$t.InkMute}}; }
  details[open] .details-arrow { transform: rotate(0deg); }
  .device-block summary { transition: background-color 0.15s ease; }
  .device-block summary:hover { background-color: {{$t.Panel}} !important; }
  @media print {
    body { background: #fdfdfb !important; }
    .no-print { display: none !important; }
    details { display: block !important; }
    details > summary { display: none !important; }
    .device-block { break-inside: avoid; page-break-inside: avoid; }
  }
{{end}}
</style>
</head>
<body style="margin:0;padding:0;background:{{$t.Canvas}};color:{{$t.Ink}};font-family:{{fontStack}};">
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:{{$t.Canvas}};">{{.StatusHeadline}} — {{.StatusDetail}}&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{{$t.Canvas}};">
<tr><td align="center" style="padding:24px 8px;">
{{msoOpen}}
<div style="max-width:600px;margin:0 auto;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="sheet" style="width:100%;max-width:600px;background:{{$t.Surface}};border:1px solid {{$t.Hairline}};border-radius:8px;overflow:hidden;">

  <tr><td bgcolor="{{$t.Accent}}" style="background-color:{{$t.Accent}};height:3px;line-height:3px;font-size:1px;">&nbsp;</td></tr>

  <tr><td class="content-cell" style="padding:26px 24px 18px;border-bottom:1px solid {{$t.Hairline}};">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="vertical-align:top;">
        <div style="font-family:{{fontStack}};font-size:11px;font-weight:700;color:{{$t.Accent}};text-transform:uppercase;letter-spacing:1.6px;">Firewall Monitor</div>
        <div class="ink" style="font-family:{{fontStack}};font-size:22px;font-weight:700;color:{{$t.Ink}};letter-spacing:-0.3px;margin-top:5px;line-height:1.2;">{{.Period}} Operations Report</div>
        <div class="inkdim" style="font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};margin-top:5px;">{{.Date}} &middot; {{.Timezone}}</div>
      </td>
      <td align="right" style="vertical-align:top;white-space:nowrap;">
        <span class="panel-fill" style="display:inline-block;background:{{$t.Panel}};color:{{$t.Accent}};border-radius:6px;padding:6px 11px;font-size:11px;font-weight:700;font-family:{{monoStack}};letter-spacing:0.3px;">LAST {{.Hours}}H</span>
      </td>
    </tr></table>
  </td></tr>

  {{if eq .StatusLevel "crit"}}
  <tr><td class="content-cell verdict-crit" bgcolor="{{$t.CritTint}}" style="background:{{$t.CritTint}};padding:16px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "verdict" dict "T" $t "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" $t.Crit "Text" $t.Crit}}
  </td></tr>
  {{else if eq .StatusLevel "warn"}}
  <tr><td class="content-cell verdict-warn" bgcolor="{{$t.WarnTint}}" style="background:{{$t.WarnTint}};padding:16px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "verdict" dict "T" $t "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" $t.Warn "Text" $t.Warn}}
  </td></tr>
  {{else}}
  <tr><td class="content-cell verdict-ok" bgcolor="{{$t.OkTint}}" style="background:{{$t.OkTint}};padding:16px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "verdict" dict "T" $t "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" $t.Ok "Text" $t.Ok}}
  </td></tr>
  {{end}}

  <tr><td class="content-cell" style="padding:18px 24px;border-bottom:1px solid {{$t.Hairline}};">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      {{template "kpi" dict "T" $t "Label" "Devices" "Value" (printf "%d" .TotalDevices) "Color" $t.Ink}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "T" $t "Label" "Online" "Value" (printf "%d" .OnlineDevices) "Color" $t.Ok}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "T" $t "Label" "Offline" "Value" (printf "%d" .OfflineDevices) "Color" (gtColor .OfflineDevices $t.Crit $t.InkMute)}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "T" $t "Label" (printf "Alerts %dh" .Hours) "Value" (printf "%d" .TotalAlerts) "Color" $t.Ink}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "T" $t "Label" "Critical" "Value" (printf "%d" .CriticalAlerts) "Color" (gtColor .CriticalAlerts $t.Crit $t.InkMute)}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "T" $t "Label" "Uptime" "Value" (printf "%.2f%%" .FleetUptimePct) "Color" $t.Accent}}
    </tr></table>
  </td></tr>

  <tr><td class="content-cell" style="padding:22px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "secthead" dict "T" $t "Text" "Bandwidth & Traffic"}}
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:10px;"><tr>
      <td width="49%" class="bw-card" style="vertical-align:top;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="panel-fill" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:14px 18px;">
          <div class="inkdim" style="font-family:{{fontStack}};font-size:10px;color:{{$t.InkDim}};text-transform:uppercase;letter-spacing:1px;font-weight:600;">Peak Throughput</div>
          <div class="ink" style="font-family:{{monoStack}};font-size:20px;font-weight:700;color:{{$t.Ink}};margin-top:5px;">{{.PeakThroughput}}</div>
        </td></tr></table>
      </td>
      <td width="2%" class="bw-spacer"></td>
      <td width="49%" class="bw-card" style="vertical-align:top;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="panel-fill" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:14px 18px;">
          <div class="inkdim" style="font-family:{{fontStack}};font-size:10px;color:{{$t.InkDim}};text-transform:uppercase;letter-spacing:1px;font-weight:600;">Total Transferred</div>
          <div class="ink" style="font-family:{{monoStack}};font-size:20px;font-weight:700;color:{{$t.Ink}};margin-top:5px;">{{.TotalTransfer}}</div>
        </td></tr></table>
      </td>
    </tr></table>

    {{if .TopTalkers}}
    {{template "eyebrow" dict "T" $t "Text" "Top Talkers"}}
    {{range .TopTalkers}}{{template "talker" dict "T" $t "D" .}}{{end}}
    {{else}}
    <div class="inkdim" style="font-family:{{fontStack}};font-size:12px;color:{{$t.InkDim}};margin-top:12px;font-style:italic;">No interface traffic recorded in this window.</div>
    {{end}}

    {{if .SpikeGroups}}
    {{template "eyebrow" dict "T" $t "Text" "Traffic Spikes"}}
    <div class="inkdim" style="font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};margin-bottom:10px;line-height:1.4;">
      Detected <strong class="ink" style="color:{{$t.Ink}};">{{.SpikeTotal}}</strong> throughput spike{{if ne .SpikeTotal 1}}s{{end}} on <strong class="ink" style="color:{{$t.Ink}};">{{.SpikeIfaceCount}}</strong> interface{{if ne .SpikeIfaceCount 1}}s{{end}}
      {{if .SpikeCritical}}<span style="color:{{$t.Crit}};font-weight:600;"> &middot; {{.SpikeCritical}} critical</span>{{end}}
      {{if .SpikeWarning}}<span style="color:{{$t.Warn}};font-weight:600;"> &middot; {{.SpikeWarning}} warning</span>{{end}}
    </div>
    {{range .SpikeGroups}}{{template "spikegroup" dict "T" $t "D" .}}{{end}}
    {{if .SpikeMore}}<div class="inkdim" style="font-family:{{fontStack}};font-size:11px;color:{{$t.InkDim}};margin-top:4px;font-style:italic;">+ {{.SpikeMore}} more interface{{if ne .SpikeMore 1}}s{{end}} with spikes</div>{{end}}
    {{end}}
  </td></tr>

  {{if .HasAlerts}}
  <tr><td class="content-cell" style="padding:22px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "secthead" dict "T" $t "Text" "Alert Activity"}}
    {{if .IsEmail}}
    <div class="inkdim" style="font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};line-height:1.5;">
      A total of <strong class="ink" style="color:{{$t.Ink}};">{{.TotalAlerts}}</strong> alerts were recorded during this report window, including <span style="color:{{$t.Crit}};font-weight:600;">{{.CriticalAlerts}} critical</span> events.
    </div>
    <div class="inkdim" style="font-family:{{fontStack}};font-size:11.5px;color:{{$t.InkMute}};margin-top:8px;font-style:italic;">
      Note: The interactive alert timeline graph is viewable in the Web Admin Console.
    </div>
    {{else}}
    <div style="width:100%;overflow-x:auto;">
      {{renderAlertChart .AlertBuckets $t}}
    </div>
    {{end}}
  </td></tr>
  {{end}}

  {{if .Ops}}
  <tr><td class="content-cell" style="padding:22px 24px;border-bottom:1px solid {{$t.Hairline}};">
    {{template "secthead" dict "T" $t "Text" "Operations (30 days)"}}
    <div class="inkdim" style="font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};line-height:1.7;">
      Mean time to acknowledge: <strong class="ink" style="color:{{$t.Ink}};">{{fmtMinutes .Ops.MTTAMinutes}}</strong>
      <span style="color:{{$t.InkMute}};">({{.Ops.AckedCount}} operator-acknowledged)</span>
      &nbsp;&middot;&nbsp; Mean time to resolve: <strong class="ink" style="color:{{$t.Ink}};">{{fmtMinutes .Ops.MTTRMinutes}}</strong>
      <span style="color:{{$t.InkMute}};">({{.Ops.ResolvedCount}} resolved)</span>
    </div>
    {{if .Ops.Noise}}
    <div class="ink" style="font-family:{{fontStack}};font-size:12px;color:{{$t.Ink}};font-weight:600;margin-top:14px;margin-bottom:6px;">Noisiest alerts</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:{{fontStack}};font-size:12px;color:{{$t.InkDim}};border-collapse:separate;border-spacing:0;">
      <tr style="text-align:left;">
        <th class="inkdim" style="padding:4px 8px 6px 0;font-weight:600;color:{{$t.InkMute}};border-bottom:1px solid {{$t.Hairline}};">Alert</th>
        <th class="inkdim" style="padding:4px 8px 6px;font-weight:600;color:{{$t.InkMute}};border-bottom:1px solid {{$t.Hairline}};">Device</th>
        <th class="inkdim" align="right" style="padding:4px 8px 6px;font-weight:600;text-align:right;color:{{$t.InkMute}};border-bottom:1px solid {{$t.Hairline}};">Fires</th>
        <th class="inkdim" align="right" style="padding:4px 0 6px 8px;font-weight:600;text-align:right;color:{{$t.InkMute}};border-bottom:1px solid {{$t.Hairline}};">Suppressed</th>
      </tr>
      {{range .Ops.Noise}}
      <tr>
        <td style="padding:6px 8px 6px 0;font-family:{{monoStack}};border-bottom:1px solid {{$t.HairlineSoft}};">{{.AlertType}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid {{$t.HairlineSoft}};">{{.DeviceName}}</td>
        <td align="right" class="ink" style="padding:6px 8px;text-align:right;font-weight:600;color:{{$t.Ink}};border-bottom:1px solid {{$t.HairlineSoft}};">{{.Count}}</td>
        <td align="right" style="padding:6px 0 6px 8px;text-align:right;color:{{$t.InkMute}};border-bottom:1px solid {{$t.HairlineSoft}};">{{.Suppressed}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}
  </td></tr>
  {{end}}

  <tr><td class="content-cell" style="padding:22px 24px 10px;">
    {{template "secthead" dict "T" $t "Text" "Device Detail"}}
    {{range .Devices}}
      {{if $.Collapsible}}
      <details open class="device-block" style="display:block;background:{{$t.Surface}};border:1px solid {{$t.Hairline}};border-radius:8px;padding:0;margin-bottom:14px;">
        <summary style="padding:14px 18px;border-bottom:1px solid {{$t.HairlineSoft}};">{{template "devhead" dict "T" $t "D" .}}</summary>
        <div style="padding:14px 18px 18px;">{{template "devbody" dict "T" $t "D" .}}</div>
      </details>
      {{else}}
      <div class="device-block" style="background:{{$t.Surface}};border:1px solid {{$t.Hairline}};border-radius:8px;margin-bottom:14px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr><td style="padding:14px 18px;border-bottom:1px solid {{$t.HairlineSoft}};">{{template "devhead" dict "T" $t "D" .}}</td></tr>
          <tr><td style="padding:14px 18px 18px;">{{template "devbody" dict "T" $t "D" .}}</td></tr>
        </table>
      </div>
      {{end}}
    {{end}}
  </td></tr>

  <tr><td class="content-cell" style="padding:22px 24px 28px;border-top:1px solid {{$t.Hairline}};text-align:center;">
    {{if .IsEmail}}
    <div class="inkdim" style="font-family:{{fontStack}};margin-bottom:14px;font-size:12px;color:{{$t.InkDim}};line-height:1.5;">
      To explore high-resolution interactive charts and drill down into sFlow traffic details, view this report in the <span style="color:{{$t.Accent}};font-weight:600;">Firewall Monitor Web Console</span>.
    </div>
    {{end}}
    <div class="inkdim" style="font-family:{{fontStack}};font-size:11px;color:{{$t.InkMute}};">Generated {{.GeneratedAt}} by Firewall Monitor{{if .Version}} &middot; v{{.Version}}{{end}}</div>
  </td></tr>

</table>
</div>
{{msoClose}}
</td></tr>
</table>
</body>
</html>{{end}}

{{define "verdict"}}{{$t := .T}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
  <td style="vertical-align:middle;width:22px;">
    <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{{.Dot}};font-size:1px;line-height:10px;">&nbsp;</span>
  </td>
  <td style="vertical-align:middle;">
    <div style="font-family:{{fontStack}};font-size:16px;font-weight:700;line-height:1.25;color:{{.Text}};">{{.Headline}}</div>
    <div class="verdict-detail inkdim" style="font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};margin-top:3px;">{{.Detail}}</div>
  </td>
</tr></table>{{end}}

{{define "secthead"}}{{$t := .T}}<div class="secthead ink" style="font-family:{{fontStack}};font-size:12px;font-weight:700;color:{{$t.Ink}};text-transform:uppercase;letter-spacing:1.4px;margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid {{$t.Hairline}};line-height:1.25;">{{.Text}}</div>{{end}}

{{define "eyebrow"}}{{$t := .T}}<div class="inkdim" style="font-family:{{fontStack}};font-size:10px;color:{{$t.InkDim}};text-transform:uppercase;letter-spacing:1px;font-weight:700;margin:20px 0 10px;">{{.Text}}</div>{{end}}

{{define "kpi"}}{{$t := .T}}<td class="kpi-cell panel-fill" width="15%" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:12px 4px;text-align:center;vertical-align:top;">
  <div class="kpi-value" style="font-family:{{monoStack}};font-size:18px;font-weight:700;color:{{.Color}};line-height:1.1;">{{.Value}}</div>
  <div class="kpi-label inkdim" style="font-family:{{fontStack}};font-size:9px;color:{{$t.InkDim}};text-transform:uppercase;letter-spacing:0.7px;margin-top:6px;font-weight:600;">{{.Label}}</div>
</td>{{end}}

{{define "talker"}}{{$t := .T}}{{$d := .D}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:8px;"><tr>
  <td width="35%" style="font-family:{{fontStack}};font-size:12px;color:{{$t.InkDim}};padding-right:10px;vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
    <strong class="talker-text ink" style="color:{{$t.Ink}};">{{$d.IfaceName}}</strong>{{if $d.DeviceName}} <span class="talker-device inkdim" style="color:{{$t.InkDim}};font-size:11px;">({{$d.DeviceName}})</span>{{end}}
  </td>
  <td width="45%" style="vertical-align:middle;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      {{if $d.BarPct}}<td width="{{$d.BarPct}}%" bgcolor="{{$t.Accent}}" style="background:{{$t.Accent}};height:8px;line-height:8px;font-size:1px;border-radius:4px;">&nbsp;</td>{{end}}
      {{if lt $d.BarPct 100}}<td bgcolor="{{$t.HairlineSoft}}" class="talker-bar-bg" style="background:{{$t.HairlineSoft}};height:8px;line-height:8px;font-size:1px;{{if not $d.BarPct}}border-radius:4px;{{else}}border-radius:0 4px 4px 0;{{end}}">&nbsp;</td>{{end}}
    </tr></table>
  </td>
  <td width="20%" align="right" class="ink" style="font-size:12px;color:{{$t.Ink}};padding-left:10px;vertical-align:middle;white-space:nowrap;font-family:{{monoStack}};font-weight:600;">
    {{$d.TotalHuman}}<span class="inkdim" style="color:{{$t.InkDim}};font-size:10px;font-weight:400;"> &middot; {{$d.PeakHuman}} pk</span>
  </td>
</tr></table>{{end}}

{{define "spikegroup"}}{{$t := .T}}{{$d := .D}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="spikegroup" style="margin-bottom:8px;"><tr>
  <td class="panel-fill" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:0;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="padding:9px 14px;vertical-align:middle;">
        <span style="display:inline-block;background:{{if $d.IsCritical}}{{$t.CritTint}}{{else}}{{$t.WarnTint}}{{end}};color:{{if $d.IsCritical}}{{$t.Crit}}{{else}}{{$t.Warn}}{{end}};border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700;font-family:{{monoStack}};">{{$d.Count}}&times;</span>
        <span class="spike-text ink" style="font-family:{{fontStack}};color:{{$t.Ink}};font-size:12.5px;font-weight:600;">&nbsp;{{$d.Interface}}</span>{{if $d.DeviceName}} <span class="spike-meta inkdim" style="font-family:{{fontStack}};color:{{$t.InkDim}};font-size:12px;">{{$d.DeviceName}}</span>{{end}}
        {{if and $d.Critical (ne $d.Critical $d.Count)}}<span style="color:{{$t.Crit}};font-size:11px;font-weight:600;"> ({{$d.Critical}} critical)</span>{{end}}
      </td>
      <td align="right" class="spike-meta inkdim" style="padding:9px 14px;vertical-align:middle;font-family:{{fontStack}};font-size:11px;color:{{$t.InkDim}};white-space:nowrap;">
        peak <span class="ink" style="color:{{$t.Ink}};font-family:{{monoStack}};font-weight:600;">{{$d.PeakHuman}}</span>{{if $d.Window}} &middot; {{$d.Window}}{{end}}
      </td>
    </tr></table>
  </td>
</tr></table>{{end}}

{{define "devhead"}}{{$t := .T}}{{$d := .D}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
  <td style="vertical-align:middle;">
    <span class="device-name ink" style="font-family:{{fontStack}};font-size:14px;font-weight:700;color:{{$t.Ink}};">{{$d.Name}}</span>
    {{if $d.Online}}
    <span class="status-online" style="display:inline-block;background:{{$t.OkTint}};color:{{$t.Ok}};border-radius:12px;padding:2px 10px;font-family:{{fontStack}};font-size:10px;font-weight:700;letter-spacing:0.5px;margin-left:8px;">ONLINE</span>
    {{else}}
    <span class="status-offline" style="display:inline-block;background:{{$t.CritTint}};color:{{$t.Crit}};border-radius:12px;padding:2px 10px;font-family:{{fontStack}};font-size:10px;font-weight:700;letter-spacing:0.5px;margin-left:8px;">OFFLINE</span>
    {{end}}
  </td>
  <td align="right" class="device-ip inkdim" style="vertical-align:middle;font-size:12px;color:{{$t.InkDim}};font-family:{{monoStack}};">
    {{$d.IPAddress}}
    <span class="details-arrow" style="display:none;margin-left:8px;font-size:10px;vertical-align:middle;">&#9660;</span>
  </td>
</tr></table>{{end}}

{{define "devbody"}}{{$t := .T}}{{$d := .D}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:2px;"><tr>
  {{template "mini" dict "T" $t "Label" "CPU avg/max" "Value" (printf "%.0f / %.0f%%" $d.CPUAvg $d.CPUMax)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "T" $t "Label" "Mem avg/max" "Value" (printf "%.0f / %.0f%%" $d.MemAvg $d.MemMax)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "T" $t "Label" "Disk" "Value" (printf "%.0f%%" $d.DiskUsage)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "T" $t "Label" "Sessions" "Value" (printf "%d" $d.SessionCount)}}
</tr></table>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:14px;"><tr>
  <td class="inkdim" style="vertical-align:middle;font-family:{{fontStack}};font-size:11px;color:{{$t.InkDim}};width:60px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;">Uptime</td>
  <td style="vertical-align:middle;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      {{if $d.UptimeBarPct}}<td width="{{$d.UptimeBarPct}}%" bgcolor="{{$t.Ok}}" style="background:{{$t.Ok}};height:8px;line-height:8px;font-size:1px;border-radius:4px;">&nbsp;</td>{{end}}
      {{if lt $d.UptimeBarPct 100}}<td bgcolor="{{$t.HairlineSoft}}" class="uptime-bar-bg" style="background:{{$t.HairlineSoft}};height:8px;line-height:8px;font-size:1px;{{if not $d.UptimeBarPct}}border-radius:4px;{{else}}border-radius:0 4px 4px 0;{{end}}">&nbsp;</td>{{end}}
    </tr></table>
  </td>
  <td align="right" class="uptime-value ink" style="vertical-align:middle;font-size:12px;color:{{$t.Ink}};padding-left:12px;width:64px;font-family:{{monoStack}};font-weight:600;">{{printf "%.2f%%" $d.UptimePct}}</td>
</tr></table>

{{if $d.IsEmail}}
  {{template "eyebrow" dict "T" $t "Text" "Resource Trends"}}
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:8px;"><tr><td class="panel-fill" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:12px 16px;font-family:{{fontStack}};font-size:12.5px;color:{{$t.InkDim}};line-height:1.6;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:2px 0;">
          <strong class="ink" style="color:{{$t.Ink}};">CPU Usage:</strong> average <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesCPU}};">{{printf "%.1f%%" $d.CPUAvg}}</span>, peak <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesCPU}};">{{printf "%.1f%%" $d.CPUMax}}</span>
        </td>
      </tr>
      <tr>
        <td style="padding:2px 0;border-top:1px solid {{$t.HairlineSoft}};">
          <strong class="ink" style="color:{{$t.Ink}};">Memory:</strong> average <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesMem}};">{{printf "%.1f%%" $d.MemAvg}}</span>, peak <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesMem}};">{{printf "%.1f%%" $d.MemMax}}</span>
        </td>
      </tr>
      {{if $d.Talkers}}
        {{with (index $d.Talkers 0)}}
        <tr>
          <td style="padding:2px 0;border-top:1px solid {{$t.HairlineSoft}};">
            <strong class="ink" style="color:{{$t.Ink}};">Busiest Link ({{.IfaceName}}):</strong> <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesAccent}};">{{.TotalHuman}}</span> total, peak <span style="font-family:{{monoStack}};font-weight:600;color:{{$t.SeriesAccent}};">{{.PeakHuman}}</span>
          </td>
        </tr>
        {{end}}
      {{end}}
    </table>
  </td></tr></table>
{{else}}
  {{template "eyebrow" dict "T" $t "Text" "CPU & Memory History"}}
  <div style="width:100%;overflow-x:auto;margin-bottom:8px;">
    {{renderCPUMemChart $d $d.Timezone $t}}
  </div>

  {{if $d.HasSparkline}}
  {{template "eyebrow" dict "T" $t "Text" "Throughput · Busiest Interface"}}
  <div style="width:100%;overflow-x:auto;margin-bottom:8px;">
    {{renderThroughputChart $d $d.Timezone $t}}
  </div>
  {{end}}
{{end}}

{{if $d.Talkers}}
{{template "eyebrow" dict "T" $t "Text" "Interfaces"}}
{{range $d.Talkers}}{{template "talker" dict "T" $t "D" .}}{{end}}
{{end}}

{{if $d.Spikes}}
{{template "eyebrow" dict "T" $t "Text" "Traffic Spikes"}}
{{range $d.Spikes}}{{template "spikegroup" dict "T" $t "D" .}}{{end}}
{{end}}

{{if $d.SpikeFlows}}
{{template "eyebrow" dict "T" $t "Text" "Top Flows During Spikes (sampled)"}}
{{range $d.SpikeFlows}}{{template "spikeflow" dict "T" $t "D" .}}{{end}}
{{end}}
{{end}}

{{define "spikeflow"}}{{$t := .T}}{{$d := .D}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:6px;"><tr>
  <td class="spike-flow-src ink" style="font-family:{{monoStack}};font-size:11.5px;color:{{$t.Ink}};vertical-align:middle;">
    {{$d.Src}} <span style="color:{{$t.InkMute}};">&rarr;</span> {{$d.Dst}}
  </td>
  <td align="right" style="font-family:{{fontStack}};font-size:11px;color:{{$t.InkDim}};white-space:nowrap;vertical-align:middle;padding-left:10px;">
    <span class="spike-flow-proto panel-fill" style="background:{{$t.Panel}};color:{{$t.InkDim}};border-radius:4px;padding:1px 5px;font-weight:600;font-size:9.5px;text-transform:uppercase;margin-right:6px;">{{$d.Protocol}}</span> <span class="spike-flow-bytes ink" style="color:{{$t.Ink}};font-family:{{monoStack}};font-weight:600;">{{$d.BytesHuman}}</span>
  </td>
</tr></table>{{end}}

{{define "mini"}}{{$t := .T}}<td class="mini-cell" width="23.5%" style="text-align:center;vertical-align:top;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="panel-fill" bgcolor="{{$t.Panel}}" style="background:{{$t.Panel}};border-radius:8px;padding:11px 4px;">
    <div class="mini-value ink" style="font-family:{{monoStack}};font-size:12px;font-weight:700;color:{{$t.Ink}};">{{.Value}}</div>
    <div class="mini-label inkdim" style="font-family:{{fontStack}};font-size:9px;color:{{$t.InkDim}};text-transform:uppercase;letter-spacing:0.4px;margin-top:4px;font-weight:600;">{{.Label}}</div>
  </td></tr></table>
</td>{{end}}
`
