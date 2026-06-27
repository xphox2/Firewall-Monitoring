package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// RenderReportHTML renders a ReportModel into a single self-contained HTML
// document using only email-safe HTML/CSS (tables + inline-styled divs, no
// external assets and no image attachments). The output renders identically in
// an email body, the admin panel iframe, and a browser print-to-PDF.
func RenderReportHTML(m ReportModel) (string, error) {
	var buf bytes.Buffer
	if err := reportTemplate.ExecuteTemplate(&buf, "report", m); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}
	return buf.String(), nil
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":                 strings.ToUpper,
	"dict":                  templateDict,
	"gtColor":               gtColor,
	"renderAlertChart":      RenderAlertTimelineSVG,
	"renderThroughputChart": RenderThroughputChart,
	"renderCPUMemChart":     RenderCPUMemSVGChart,
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

// Design tokens (light "operations brief"): paper #ffffff on #eef1f5, navy
// letterhead #15233b, ink #0f172a/#475569/#94a3b8, hairline #e6eaf1, data
// accent #1e3a5f, status green/amber/red. Display = Georgia serif (title +
// section heads), body = system sans, metrics = monospace. Email-safe: tables
// + inline styles, no external assets, prints cleanly (dark ink on white).
const reportTemplateSrc = `
{{define "report"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall Monitor — {{.Period}} Operations Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  body { 
    -webkit-text-size-adjust: 100%; 
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  }
  details > summary { cursor:pointer; list-style:none; outline:none; }
  details > summary::-webkit-details-marker { display:none; }
  
  /* Disclosure arrow transition */
  details .details-arrow {
    display: inline-block !important;
    transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    transform: rotate(-90deg);
    color: #64748b;
  }
  details[open] .details-arrow {
    transform: rotate(0deg);
  }
  .admin-preview .details-arrow {
    color: #8b949e !important;
  }
  
  /* Premium animations and hover effects in admin preview mode */
  .admin-preview .kpi-cell,
  .admin-preview .bw-card > div,
  .admin-preview .device-block,
  .admin-preview .mini-cell > div,
  .admin-preview .spikegroup {
    transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.22s cubic-bezier(0.16, 1, 0.3, 1), background-color 0.22s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .admin-preview .kpi-cell:hover,
  .admin-preview .bw-card > div:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.25);
  }
  .admin-preview .device-block:hover {
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.18);
  }
  .admin-preview .mini-cell > div:hover {
    transform: translateY(-1px);
    background-color: #2b303b !important;
  }
  .admin-preview .device-block summary {
    transition: background-color 0.2s ease;
  }
  .admin-preview .device-block summary:hover {
    background-color: #21262d !important;
  }

  /* Admin Panel dark theme native overrides */
  body.admin-preview { 
    background: #0d1117 !important; 
    color: #c9d1d9 !important; 
  }
  .admin-preview .sheet { 
    background: #161b22 !important; 
    border-color: #30363d !important; 
  }
  .admin-preview .content-cell { 
    border-color: #30363d !important; 
  }
  
  /* Verdicts dark colors */
  .admin-preview .verdict-crit { background: #2d1919 !important; border-left-color: #f85149 !important; border-bottom-color: #30363d !important; }
  .admin-preview .verdict-crit div { color: #f87171 !important; }
  .admin-preview .verdict-crit .verdict-detail { color: #fca5a5 !important; }
  
  .admin-preview .verdict-warn { background: #2d2419 !important; border-left-color: #d29922 !important; border-bottom-color: #30363d !important; }
  .admin-preview .verdict-warn div { color: #fbbf24 !important; }
  .admin-preview .verdict-warn .verdict-detail { color: #fcd34d !important; }
  
  .admin-preview .verdict-ok { background: #192d1f !important; border-left-color: #3fb950 !important; border-bottom-color: #30363d !important; }
  .admin-preview .verdict-ok div { color: #34d399 !important; }
  .admin-preview .verdict-ok .verdict-detail { color: #6ee7b7 !important; }

  /* KPIs dark colors */
  .admin-preview .kpi-cell { 
    background: #21262d !important; 
    border-color: #30363d !important; 
  }
  .admin-preview .kpi-cell .kpi-value { 
    color: #f0f6fc !important; 
  }
  .admin-preview .kpi-cell .kpi-label { 
    color: #8b949e !important; 
  }
  
  /* Bandwidth & Traffic dark colors */
  .admin-preview .bw-card > div { 
    background: #21262d !important; 
    border-color: #30363d !important; 
  }
  .admin-preview .bw-card div { 
    color: #f0f6fc !important; 
  }
  .admin-preview .talker-text {
    color: #c9d1d9 !important;
  }
  .admin-preview .talker-device {
    color: #8b949e !important;
  }
  .admin-preview .talker-bar-bg {
    background: #30363d !important;
  }
  .admin-preview .spikegroup {
    background: #21262d !important;
    border-color: #30363d !important;
  }
  .admin-preview .spikegroup .spike-text {
    color: #c9d1d9 !important;
  }
  .admin-preview .spikegroup .spike-meta {
    color: #8b949e !important;
  }
  
  /* SVG Charts overrides */
  .admin-preview .grid-line { stroke: #30363d !important; }
  .admin-preview .axis-line { stroke: #30363d !important; }
  .admin-preview .axis-label { fill: #8b949e !important; }
  .admin-preview .trend-line { stroke: #58a6ff !important; }
  .admin-preview .cpu-line { stroke: #f85149 !important; }
  .admin-preview .mem-line { stroke: #58a6ff !important; }
  .admin-preview .hover-slice:hover { fill: rgba(88, 166, 255, 0.08) !important; }

  /* Device Cards dark colors */
  .admin-preview .device-block {
    background: #161b22 !important;
    border-color: #30363d !important;
  }
  .admin-preview .device-block summary {
    border-bottom-color: #30363d !important;
    background: #161b22 !important;
  }
  .admin-preview .device-name {
    color: #f0f6fc !important;
  }
  .admin-preview .device-ip {
    color: #8b949e !important;
  }
  .admin-preview .status-online {
    background: rgba(16, 185, 129, 0.15) !important;
    color: #34d399 !important;
    border-color: rgba(16, 185, 129, 0.25) !important;
  }
  .admin-preview .status-offline {
    background: rgba(239, 68, 68, 0.15) !important;
    color: #f87171 !important;
    border-color: rgba(239, 68, 68, 0.25) !important;
  }
  .admin-preview .mini-cell > div {
    background: #21262d !important;
    border-color: #30363d !important;
  }
  .admin-preview .mini-value {
    color: #f0f6fc !important;
  }
  .admin-preview .mini-label {
    color: #8b949e !important;
  }
  .admin-preview .uptime-bar-bg {
    background: #30363d !important;
  }
  .admin-preview .uptime-value {
    color: #f0f6fc !important;
  }
  .admin-preview .spike-flow-src {
    color: #c9d1d9 !important;
  }
  .admin-preview .spike-flow-proto {
    background: #30363d !important;
    color: #8b949e !important;
  }
  .admin-preview .spike-flow-bytes {
    color: #f0f6fc !important;
  }
  .admin-preview .secthead {
    border-left-color: #58a6ff !important;
  }

  /* Responsive and Print Media Rules */
  @media only screen and (max-width: 600px) {
    .sheet { width: 100% !important; border: none !important; border-radius: 0 !important; }
    .content-cell { padding-left: 16px !important; padding-right: 16px !important; }
    .kpi-cell { display: inline-block !important; width: 48% !important; margin: 1% !important; padding: 12px 4px !important; box-sizing: border-box; }
    .kpi-spacer { display: none !important; }
    .bw-card { display: block !important; width: 100% !important; margin-bottom: 12px !important; }
    .bw-spacer { display: none !important; }
    .mini-cell { display: inline-block !important; width: 48% !important; margin: 1% !important; box-sizing: border-box; }
    .mini-spacer { display: none !important; }
  }
  
  @media print {
    body { background:#ffffff !important; color: #000000 !important; }
    body.admin-preview { background:#ffffff !important; color: #000000 !important; }
    .sheet { border:none !important; border-radius:0 !important; background: #ffffff !important; }
    .admin-preview .sheet { background: #ffffff !important; border: none !important; }
    .no-print { display:none !important; }
    details { display:block !important; }
    details > summary { display:none !important; }
    .device-block { break-inside:avoid; page-break-inside:avoid; border: none !important; }
    .admin-preview .device-block { border: none !important; background: #ffffff !important; border-radius: 0 !important; box-shadow: none !important; margin-bottom: 24px !important; }
    .kpi-cell { background: #ffffff !important; border: 1px solid #cbd5e1 !important; }
    .admin-preview .kpi-cell { background: #ffffff !important; border: 1px solid #cbd5e1 !important; }
    .admin-preview .kpi-cell .kpi-value { color: #0f172a !important; }
    .admin-preview .kpi-cell .kpi-label { color: #475569 !important; }
    .admin-preview .bw-card > div { background: #ffffff !important; border: 1px solid #cbd5e1 !important; }
    .admin-preview .bw-card div { color: #0f172a !important; }
    .admin-preview .mini-cell > div { background: #ffffff !important; border: 1px solid #cbd5e1 !important; }
    .admin-preview .mini-value { color: #0f172a !important; }
    .admin-preview .mini-label { color: #475569 !important; }
    .grid-line { stroke: #cbd5e1 !important; stroke-dasharray: 2,2 !important; }
    .axis-line { stroke: #94a3b8 !important; }
    .axis-label { fill: #475569 !important; }
    .trend-line { stroke: #1e3a5f !important; }
  }
</style>
</head>
<body class="{{if .Collapsible}}admin-preview{{end}}" style="margin:0;padding:0;background:#f1f5f9;color:#0f172a;">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:inherit;padding:28px 0;">
<tr><td align="center">
<table class="sheet" width="680" cellpadding="0" cellspacing="0" role="presentation" style="width:680px;max-width:680px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">

  <!-- Gradient Brand Accent Line -->
  <tr><td style="background: linear-gradient(90deg, #4f46e5, #3b82f6, #10b981); height: 6px; line-height: 6px; font-size: 1px;">&nbsp;</td></tr>

  <!-- Letterhead -->
  <tr><td class="content-cell" style="padding:32px 36px 20px;border-bottom:1px solid #f1f5f9;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
      <td style="vertical-align:top;">
        <div style="font-size:11px;font-weight:700;color:#4f46e5;text-transform:uppercase;letter-spacing:1.8px;font-family:'Plus Jakarta Sans', sans-serif;">Firewall Monitor</div>
        <div style="font-family:'Plus Jakarta Sans', sans-serif;font-size:26px;font-weight:800;color:#0f172a;letter-spacing:-0.5px;margin-top:6px;line-height:1.15;">{{.Period}} Operations Report</div>
        <div style="font-size:13px;color:#64748b;margin-top:6px;font-weight:500;">{{.Date}} &middot; {{.Timezone}}</div>
      </td>
      <td align="right" style="vertical-align:top;white-space:nowrap;">
        <span style="display:inline-block;background:#e0e7ff;color:#4338ca;border:1px solid #c7d2fe;border-radius:6px;padding:6px 12px;font-size:11px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;letter-spacing:0.3px;">LAST {{.Hours}}H</span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Status verdict band -->
  {{if eq .StatusLevel "crit"}}
  <tr><td class="content-cell verdict-crit" style="background:#fef2f2;border-left:5px solid #ef4444;border-bottom:1px solid #fee2e2;padding:18px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#ef4444" "Text" "#991b1b"}}
  </td></tr>
  {{else if eq .StatusLevel "warn"}}
  <tr><td class="content-cell verdict-warn" style="background:#fffbeb;border-left:5px solid #f59e0b;border-bottom:1px solid #fef3c7;padding:18px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#f59e0b" "Text" "#9a3412"}}
  </td></tr>
  {{else}}
  <tr><td class="content-cell verdict-ok" style="background:#f0fdf4;border-left:5px solid #10b981;border-bottom:1px solid #dcfce7;padding:18px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#10b981" "Text" "#065f46"}}
  </td></tr>
  {{end}}

  <!-- Fleet KPI strip -->
  <tr><td class="content-cell" style="padding:20px 36px;border-bottom:1px solid #f1f5f9;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
      {{template "kpi" dict "Label" "Devices" "Value" (printf "%d" .TotalDevices) "Color" "#0f172a"}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "Label" "Online" "Value" (printf "%d" .OnlineDevices) "Color" "#10b981"}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "Label" "Offline" "Value" (printf "%d" .OfflineDevices) "Color" (gtColor .OfflineDevices "#ef4444" "#94a3b8")}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "Label" (printf "Alerts %dh" .Hours) "Value" (printf "%d" .TotalAlerts) "Color" "#0f172a"}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "Label" "Critical" "Value" (printf "%d" .CriticalAlerts) "Color" (gtColor .CriticalAlerts "#ef4444" "#94a3b8")}}
      <td class="kpi-spacer" width="2%"></td>
      {{template "kpi" dict "Label" "Uptime" "Value" (printf "%.2f%%" .FleetUptimePct) "Color" "#4f46e5"}}
    </tr></table>
  </td></tr>

  <!-- Bandwidth & Traffic -->
  <tr><td class="content-cell" style="padding:24px 36px;border-bottom:1px solid #f1f5f9;">
    {{template "secthead" "Bandwidth & Traffic"}}
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:12px;"><tr>
      <td width="49%" class="bw-card" style="vertical-align:top;">
        <div style="border:1px solid #e2e8f0;background:#f8fafc;border-radius:10px;padding:16px 20px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Peak Throughput</div>
          <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:22px;font-weight:800;color:#1e3a5f;margin-top:6px;">{{.PeakThroughput}}</div>
        </div>
      </td>
      <td width="2%" class="bw-spacer"></td>
      <td width="49%" class="bw-card" style="vertical-align:top;">
        <div style="border:1px solid #e2e8f0;background:#f8fafc;border-radius:10px;padding:16px 20px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Total Transferred</div>
          <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:22px;font-weight:800;color:#0f172a;margin-top:6px;">{{.TotalTransfer}}</div>
        </div>
      </td>
    </tr></table>

    {{if .TopTalkers}}
    {{template "eyebrow" "Top Talkers"}}
    {{range .TopTalkers}}{{template "talker" .}}{{end}}
    {{else}}
    <div style="font-size:12px;color:#64748b;margin-top:14px;font-style:italic;">No interface traffic recorded in this window.</div>
    {{end}}

    {{if .SpikeGroups}}
    {{template "eyebrow" "Traffic Spikes"}}
    <div style="font-size:12.5px;color:#475569;margin-bottom:12px;line-height:1.4;">
      Detected <strong style="color:#0f172a;">{{.SpikeTotal}}</strong> throughput spike{{if ne .SpikeTotal 1}}s{{end}} on <strong style="color:#0f172a;">{{.SpikeIfaceCount}}</strong> interface{{if ne .SpikeIfaceCount 1}}s{{end}}
      {{if .SpikeCritical}}<span style="color:#ef4444;font-weight:600;"> &middot; {{.SpikeCritical}} critical</span>{{end}}
      {{if .SpikeWarning}}<span style="color:#d97706;font-weight:600;"> &middot; {{.SpikeWarning}} warning</span>{{end}}
    </div>
    {{range .SpikeGroups}}{{template "spikegroup" .}}{{end}}
    {{if .SpikeMore}}<div style="font-size:11px;color:#64748b;margin-top:4px;font-style:italic;">+ {{.SpikeMore}} more interface{{if ne .SpikeMore 1}}s{{end}} with spikes</div>{{end}}
    {{end}}
  </td></tr>

  <!-- Alert Activity Section -->
  {{if .HasAlerts}}
  <tr><td class="content-cell" style="padding:24px 36px;border-bottom:1px solid #f1f5f9;">
    {{template "secthead" "Alert Activity"}}
    {{if .IsEmail}}
    <div style="font-size:12.5px;color:#475569;line-height:1.5;">
      A total of <strong style="color:#0f172a;">{{.TotalAlerts}}</strong> alerts were recorded during this report window, including <span style="color:#ef4444;font-weight:600;">{{.CriticalAlerts}} critical</span> events.
    </div>
    <div style="font-size:11.5px;color:#64748b;margin-top:8px;font-style:italic;">
      Note: The interactive alert timeline graph is viewable in the Web Admin Console.
    </div>
    {{else}}
    <div style="width:100%;overflow-x:auto;">
      {{renderAlertChart .AlertBuckets}}
    </div>
    {{end}}
  </td></tr>
  {{end}}

  <!-- Per-device detail -->
  <tr><td class="content-cell" style="padding:24px 36px 12px;">
    {{template "secthead" "Device Detail"}}
    {{range .Devices}}
      {{if $.Collapsible}}
      <details open class="device-block" style="display:block;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:0;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.02);">
        <summary style="padding:16px 20px;border-bottom:1px solid #f1f5f9;">{{template "devhead" .}}</summary>
        <div style="padding:16px 20px 20px;">{{template "devbody" .}}</div>
      </details>
      {{else}}
      <div class="device-block" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.02);">
        <div style="padding:16px 20px;border-bottom:1px solid #f1f5f9;">{{template "devhead" .}}</div>
        <div style="padding:16px 20px 20px;">{{template "devbody" .}}</div>
      </div>
      {{end}}
    {{end}}
  </td></tr>

  <!-- Footer -->
  <tr><td class="content-cell" style="padding:24px 36px 32px;border-top:1px solid #f1f5f9;text-align:center;">
    {{if .IsEmail}}
    <div style="margin-bottom:16px;font-size:12px;color:#64748b;line-height:1.5;">
      To explore high-resolution interactive charts and drill down into sFlow traffic details, view this report in the <span style="color:#4f46e5;font-weight:600;">Firewall Monitor Web Console</span>.
    </div>
    {{end}}
    <div style="font-size:11px;color:#94a3b8;font-weight:500;">Generated {{.GeneratedAt}} by Firewall Monitor{{if .Version}} &middot; v{{.Version}}{{end}}</div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>{{end}}

{{define "verdict"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
  <td style="vertical-align:middle;width:24px;">
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:{{.Dot}};box-shadow:0 0 0 4px {{.Dot}}22;"></span>
  </td>
  <td style="vertical-align:middle;">
    <div style="font-family:'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;font-size:16px;font-weight:700;line-height:1.2;">{{.Headline}}</div>
    <div style="font-size:12.5px;color:#475569;margin-top:3px;font-weight:500;" class="verdict-detail">{{.Detail}}</div>
  </td>
</tr></table>{{end}}

{{define "secthead"}}<div class="secthead" style="font-family:'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;font-size:14px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:1px;margin:0 0 16px;border-left:3px solid #4f46e5;padding-left:10px;line-height:1.25;">{{.}}</div>{{end}}

{{define "eyebrow"}}<div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin:22px 0 10px;">{{.}}</div>{{end}}

{{define "kpi"}}<td class="kpi-cell" width="15%" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 6px;text-align:center;vertical-align:top;">
  <div class="kpi-value" style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:20px;font-weight:800;color:{{.Color}};line-height:1.1;">{{.Value}}</div>
  <div class="kpi-label" style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:0.8px;margin-top:6px;font-weight:600;">{{.Label}}</div>
</td>{{end}}

{{define "talker"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:8px;"><tr>
  <td width="35%" style="font-size:12px;color:#334155;padding-right:10px;vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
    <strong class="talker-text" style="color:#1e293b;">{{.IfaceName}}</strong>{{if .DeviceName}} <span class="talker-device" style="color:#64748b;font-size:11px;">({{.DeviceName}})</span>{{end}}
  </td>
  <td width="45%" style="vertical-align:middle;">
    <div class="talker-bar-bg" style="background:#f1f5f9;border-radius:6px;height:10px;width:100%;overflow:hidden;">
      <div style="background-color:#3b82f6;background-image:linear-gradient(90deg, #4f46e5, #3b82f6);height:10px;border-radius:6px;width:{{.BarPct}}%;"></div>
    </div>
  </td>
  <td width="20%" align="right" style="font-size:12px;color:#0f172a;padding-left:10px;vertical-align:middle;white-space:nowrap;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-weight:600;">
    {{.TotalHuman}}<span style="color:#64748b;font-size:10px;font-weight:400;"> &middot; {{.PeakHuman}} pk</span>
  </td>
</tr></table>{{end}}

{{define "spikegroup"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" class="spikegroup" style="margin-bottom:8px;border:1px solid #e2e8f0;border-left:4px solid {{if .IsCritical}}#ef4444{{else}}#f59e0b{{end}};background:#f8fafc;border-radius:8px;"><tr>
  <td style="padding:10px 14px;vertical-align:middle;">
    <span style="display:inline-block;background:{{if .IsCritical}}#fee2e2{{else}}#fef3c7{{end}};color:{{if .IsCritical}}#991b1b{{else}}#9a3412{{end}};border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{.Count}}&times;</span>
    <span class="spike-text" style="color:#1e293b;font-size:12.5px;font-weight:600;">&nbsp;{{.Interface}}</span>{{if .DeviceName}} <span class="spike-meta" style="color:#64748b;font-size:12px;">{{.DeviceName}}</span>{{end}}
    {{if and .Critical (ne .Critical .Count)}}<span style="color:#ef4444;font-size:11px;font-weight:600;"> ({{.Critical}} critical)</span>{{end}}
  </td>
  <td align="right" class="spike-meta" style="padding:10px 14px;vertical-align:middle;font-size:11px;color:#64748b;white-space:nowrap;">
    peak <span style="color:#0f172a;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-weight:600;">{{.PeakHuman}}</span>{{if .Window}} &middot; {{.Window}}{{end}}
  </td>
</tr></table>{{end}}

{{define "devhead"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
  <td style="vertical-align:middle;">
    <span class="device-name" style="font-family:'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;font-size:15px;font-weight:700;color:#0f172a;">{{.Name}}</span>
    {{if .Online}}
    <span class="status-online" style="display:inline-block;background:#ecfdf5;color:#047857;border:1px solid #a7f3d0;border-radius:20px;padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:0.5px;margin-left:8px;">ONLINE</span>
    {{else}}
    <span class="status-offline" style="display:inline-block;background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:20px;padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:0.5px;margin-left:8px;">OFFLINE</span>
    {{end}}
  </td>
  <td align="right" class="device-ip" style="vertical-align:middle;font-size:12px;color:#64748b;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-weight:500;">
    {{.IPAddress}}
    <span class="details-arrow" style="display:none;margin-left:8px;font-size:10px;vertical-align:middle;">&#9660;</span>
  </td>
</tr></table>{{end}}

{{define "devbody"}}
<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:4px;"><tr>
  {{template "mini" dict "Label" "CPU avg/max" "Value" (printf "%.0f / %.0f%%" .CPUAvg .CPUMax)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "Label" "Mem avg/max" "Value" (printf "%.0f / %.0f%%" .MemAvg .MemMax)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "Label" "Disk" "Value" (printf "%.0f%%" .DiskUsage)}}
  <td class="mini-spacer" width="2%"></td>
  {{template "mini" dict "Label" "Sessions" "Value" (printf "%d" .SessionCount)}}
</tr></table>

<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:16px;"><tr>
  <td style="vertical-align:middle;font-size:11px;color:#64748b;width:60px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;">Uptime</td>
  <td style="vertical-align:middle;">
    <div class="uptime-bar-bg" style="background:#e2e8f0;border-radius:6px;height:10px;width:100%;overflow:hidden;">
      <div style="background-color:#10b981;background-image:linear-gradient(90deg, #10b981, #059669);height:10px;border-radius:6px;width:{{.UptimeBarPct}}%;"></div>
    </div>
  </td>
  <td align="right" class="uptime-value" style="vertical-align:middle;font-size:12px;color:#0f172a;padding-left:12px;width:64px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-weight:600;">{{printf "%.2f%%" .UptimePct}}</td>
</tr></table>

{{if .IsEmail}}
  {{template "eyebrow" "Resource Trends"}}
  <div style="font-size:12.5px;color:#475569;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin-bottom:8px;line-height:1.6;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      <tr>
        <td style="padding:2px 0;">
          <strong style="color:#0f172a;">CPU Usage:</strong> average <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#ef4444;">{{printf "%.1f%%" .CPUAvg}}</span>, peak <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#ef4444;">{{printf "%.1f%%" .CPUMax}}</span>
        </td>
      </tr>
      <tr>
        <td style="padding:2px 0;border-top:1px solid #f1f5f9;">
          <strong style="color:#0f172a;">Memory:</strong> average <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#2563eb;">{{printf "%.1f%%" .MemAvg}}</span>, peak <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#2563eb;">{{printf "%.1f%%" .MemMax}}</span>
        </td>
      </tr>
      {{if .Talkers}}
        {{with (index .Talkers 0)}}
        <tr>
          <td style="padding:2px 0;border-top:1px solid #f1f5f9;">
            <strong style="color:#0f172a;">Busiest Link ({{.IfaceName}}):</strong> <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#1e3a5f;">{{.TotalHuman}}</span> total, peak <span style="font-family:'SFMono-Regular',Consolas,monospace;font-weight:600;color:#1e3a5f;">{{.PeakHuman}}</span>
          </td>
        </tr>
        {{end}}
      {{end}}
    </table>
  </div>
{{else}}
  {{template "eyebrow" "CPU & Memory History"}}
  <div style="width:100%;overflow-x:auto;margin-bottom:8px;">
    {{renderCPUMemChart . .Timezone}}
  </div>

  {{if .HasSparkline}}
  {{template "eyebrow" "Throughput · Busiest Interface"}}
  <div style="width:100%;overflow-x:auto;margin-bottom:8px;">
    {{renderThroughputChart . .Timezone}}
  </div>
  {{end}}
{{end}}

{{if .Talkers}}
{{template "eyebrow" "Interfaces"}}
{{range .Talkers}}{{template "talker" .}}{{end}}
{{end}}

{{if .Spikes}}
{{template "eyebrow" "Traffic Spikes"}}
{{range .Spikes}}{{template "spikegroup" .}}{{end}}
{{end}}

{{if .SpikeFlows}}
{{template "eyebrow" "Top Flows During Spikes (sampled)"}}
{{range .SpikeFlows}}{{template "spikeflow" .}}{{end}}
{{end}}
{{end}}

{{define "spikeflow"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:6px;"><tr>
  <td class="spike-flow-src" style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:11.5px;color:#0f172a;vertical-align:middle;">
    {{.Src}} <span style="color:#94a3b8;">&rarr;</span> {{.Dst}}
  </td>
  <td align="right" style="font-size:11px;color:#64748b;white-space:nowrap;vertical-align:middle;padding-left:10px;">
    <span class="spike-flow-proto" style="background:#f1f5f9;color:#475569;border-radius:4px;padding:1px 5px;font-weight:600;font-size:9.5px;text-transform:uppercase;margin-right:6px;">{{.Protocol}}</span> <span class="spike-flow-bytes" style="color:#0f172a;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-weight:600;">{{.BytesHuman}}</span>
  </td>
</tr></table>{{end}}

{{define "mini"}}<td class="mini-cell" width="23.5%" style="text-align:center;vertical-align:top;">
  <div style="border:1px solid #e2e8f0;background:#ffffff;border-radius:8px;padding:12px 6px;">
    <div class="mini-value" style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:12px;font-weight:700;color:#0f172a;">{{.Value}}</div>
    <div class="mini-label" style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:0.4px;margin-top:4px;font-weight:600;">{{.Label}}</div>
  </div>
</td>{{end}}
`
