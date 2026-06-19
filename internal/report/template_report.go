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
<style>
  body { -webkit-text-size-adjust:100%; }
  details > summary { cursor:pointer; list-style:none; outline:none; }
  details > summary::-webkit-details-marker { display:none; }
  @media print {
    body { background:#ffffff !important; }
    .sheet { border:none !important; border-radius:0 !important; }
    .no-print { display:none !important; }
    details { display:block !important; }
    details > summary { display:none !important; }
    .device-block { break-inside:avoid; page-break-inside:avoid; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#eef1f5;color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#eef1f5;padding:28px 0;">
<tr><td align="center">
<table class="sheet" width="680" cellpadding="0" cellspacing="0" role="presentation" style="width:680px;max-width:680px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">

  <!-- Letterhead -->
  <tr><td style="padding:30px 36px 18px;border-bottom:2px solid #15233b;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
      <td style="vertical-align:top;">
        <div style="font-size:11px;font-weight:700;color:#1e3a5f;text-transform:uppercase;letter-spacing:1.6px;">Firewall Monitor</div>
        <div style="font-family:Georgia,'Times New Roman',serif;font-size:27px;font-weight:700;color:#0f172a;letter-spacing:-0.3px;margin-top:6px;line-height:1.15;">{{.Period}} Operations Report</div>
        <div style="font-size:13px;color:#475569;margin-top:7px;">{{.Date}} &middot; {{.Timezone}}</div>
      </td>
      <td align="right" style="vertical-align:top;white-space:nowrap;">
        <span style="display:inline-block;background:#f1f5fb;color:#1e3a5f;border:1px solid #d3deeb;border-radius:6px;padding:6px 12px;font-size:11px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;letter-spacing:0.3px;">LAST {{.Hours}}H</span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Status verdict band (signature) -->
  {{if eq .StatusLevel "crit"}}
  <tr><td style="background:#fef2f2;border-left:4px solid #dc2626;border-bottom:1px solid #e6eaf1;padding:16px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#dc2626" "Text" "#b91c1c"}}
  </td></tr>
  {{else if eq .StatusLevel "warn"}}
  <tr><td style="background:#fffbeb;border-left:4px solid #d97706;border-bottom:1px solid #e6eaf1;padding:16px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#d97706" "Text" "#b45309"}}
  </td></tr>
  {{else}}
  <tr><td style="background:#f0fdf4;border-left:4px solid #16a34a;border-bottom:1px solid #e6eaf1;padding:16px 36px;">
    {{template "verdict" dict "Headline" .StatusHeadline "Detail" .StatusDetail "Dot" "#16a34a" "Text" "#15803d"}}
  </td></tr>
  {{end}}

  <!-- Fleet KPI strip -->
  <tr><td style="padding:4px 28px;border-bottom:1px solid #e6eaf1;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
      {{template "kpi" dict "Label" "Devices" "Value" (printf "%d" .TotalDevices) "Color" "#0f172a" "First" true}}
      {{template "kpi" dict "Label" "Online" "Value" (printf "%d" .OnlineDevices) "Color" "#15803d"}}
      {{template "kpi" dict "Label" "Offline" "Value" (printf "%d" .OfflineDevices) "Color" (gtColor .OfflineDevices "#b91c1c" "#94a3b8")}}
      {{template "kpi" dict "Label" (printf "Alerts %dh" .Hours) "Value" (printf "%d" .TotalAlerts) "Color" "#0f172a"}}
      {{template "kpi" dict "Label" "Critical" "Value" (printf "%d" .CriticalAlerts) "Color" (gtColor .CriticalAlerts "#b91c1c" "#94a3b8")}}
      {{template "kpi" dict "Label" "Fleet Uptime" "Value" (printf "%.2f%%" .FleetUptimePct) "Color" "#1e3a5f"}}
    </tr></table>
  </td></tr>

  <!-- Bandwidth & Traffic -->
  <tr><td style="padding:22px 36px;border-bottom:1px solid #e6eaf1;">
    {{template "secthead" "Bandwidth & Traffic"}}
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:6px;"><tr>
      <td width="50%" style="padding-right:8px;vertical-align:top;">
        <div style="border:1px solid #e6eaf1;background:#f8fafc;border-radius:8px;padding:13px 15px;">
          <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.7px;">Peak Throughput</div>
          <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:21px;font-weight:700;color:#1e3a5f;margin-top:5px;">{{.PeakThroughput}}</div>
        </div>
      </td>
      <td width="50%" style="padding-left:8px;vertical-align:top;">
        <div style="border:1px solid #e6eaf1;background:#f8fafc;border-radius:8px;padding:13px 15px;">
          <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.7px;">Total Transferred</div>
          <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:21px;font-weight:700;color:#0f172a;margin-top:5px;">{{.TotalTransfer}}</div>
        </div>
      </td>
    </tr></table>

    {{if .TopTalkers}}
    {{template "eyebrow" "Top Talkers"}}
    {{range .TopTalkers}}{{template "talker" .}}{{end}}
    {{else}}
    <div style="font-size:12px;color:#64748b;margin-top:14px;">No interface traffic recorded in this window.</div>
    {{end}}

    {{if .SpikeGroups}}
    {{template "eyebrow" "Traffic Spikes"}}
    <div style="font-size:12px;color:#475569;margin-bottom:9px;">
      <strong style="color:#0f172a;">{{.SpikeTotal}}</strong> spike{{if ne .SpikeTotal 1}}s{{end}} on {{.SpikeIfaceCount}} interface{{if ne .SpikeIfaceCount 1}}s{{end}}
      {{if .SpikeCritical}}<span style="color:#b91c1c;"> &middot; {{.SpikeCritical}} critical</span>{{end}}
      {{if .SpikeWarning}}<span style="color:#b45309;"> &middot; {{.SpikeWarning}} warning</span>{{end}}
    </div>
    {{range .SpikeGroups}}{{template "spikegroup" .}}{{end}}
    {{if .SpikeMore}}<div style="font-size:11px;color:#94a3b8;margin-top:3px;">+ {{.SpikeMore}} more interface{{if ne .SpikeMore 1}}s{{end}} with spikes</div>{{end}}
    {{end}}
  </td></tr>

  {{if .HasAlerts}}
  <tr><td style="padding:22px 36px;border-bottom:1px solid #e6eaf1;">
    {{template "secthead" "Alert Activity"}}
    <div style="width:100%;overflow-x:auto;">
      {{renderAlertChart .AlertBuckets}}
    </div>
  </td></tr>
  {{end}}

  <!-- Per-device detail -->
  <tr><td style="padding:22px 36px 8px;">
    {{template "secthead" "Device Detail"}}
    {{range .Devices}}
      {{if $.Collapsible}}
      <details open class="device-block" style="display:block;background:#f9fafb;border:1px solid #e6eaf1;border-radius:9px;padding:0;margin-bottom:12px;">
        <summary style="padding:14px 18px;">{{template "devhead" .}}</summary>
        <div style="padding:0 18px 16px;">{{template "devbody" .}}</div>
      </details>
      {{else}}
      <div class="device-block" style="background:#f9fafb;border:1px solid #e6eaf1;border-radius:9px;margin-bottom:12px;">
        <div style="padding:14px 18px;border-bottom:1px solid #e6eaf1;">{{template "devhead" .}}</div>
        <div style="padding:14px 18px 16px;">{{template "devbody" .}}</div>
      </div>
      {{end}}
    {{end}}
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:16px 36px 22px;border-top:1px solid #e6eaf1;text-align:center;">
    <div style="font-size:11px;color:#94a3b8;">Generated {{.GeneratedAt}} by Firewall Monitor{{if .Version}} &middot; v{{.Version}}{{end}}</div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>{{end}}

{{define "verdict"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
  <td style="vertical-align:top;width:18px;padding-top:5px;">
    <span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{{.Dot}};"></span>
  </td>
  <td style="vertical-align:top;">
    <div style="font-size:16px;font-weight:700;color:{{.Text}};line-height:1.2;">{{.Headline}}</div>
    <div style="font-size:12.5px;color:#475569;margin-top:3px;">{{.Detail}}</div>
  </td>
</tr></table>{{end}}

{{define "secthead"}}<div style="font-family:Georgia,'Times New Roman',serif;font-size:17px;font-weight:700;color:#0f172a;margin:0 0 14px;">{{.}}</div>{{end}}

{{define "eyebrow"}}<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.9px;font-weight:600;margin:18px 0 9px;">{{.}}</div>{{end}}

{{define "kpi"}}<td width="16%" style="padding:14px 6px;text-align:center;{{if not .First}}border-left:1px solid #eef1f5;{{end}}">
  <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:21px;font-weight:700;color:{{.Color}};line-height:1.1;">{{.Value}}</div>
  <div style="font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.6px;margin-top:6px;">{{.Label}}</div>
</td>{{end}}

{{define "talker"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:7px;"><tr>
  <td width="34%" style="font-size:12px;color:#0f172a;padding-right:10px;vertical-align:middle;white-space:nowrap;overflow:hidden;">
    <strong>{{.IfaceName}}</strong>{{if .DeviceName}} <span style="color:#94a3b8;">{{.DeviceName}}</span>{{end}}
  </td>
  <td width="46%" style="vertical-align:middle;">
    <div style="background:#eef1f5;border-radius:4px;height:12px;width:100%;">
      <div style="background:#1e3a5f;height:12px;border-radius:4px;width:{{.BarPct}}%;"></div>
    </div>
  </td>
  <td width="20%" align="right" style="font-size:12px;color:#0f172a;padding-left:10px;vertical-align:middle;white-space:nowrap;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">
    {{.TotalHuman}}<span style="color:#94a3b8;font-size:10px;"> &middot; {{.PeakHuman}} pk</span>
  </td>
</tr></table>{{end}}

{{define "spikegroup"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:6px;border:1px solid #e6eaf1;border-left:3px solid {{if .IsCritical}}#dc2626{{else}}#d97706{{end}};background:#f8fafc;border-radius:6px;"><tr>
  <td style="padding:8px 12px;vertical-align:middle;">
    <span style="display:inline-block;background:{{if .IsCritical}}#fee2e2{{else}}#fef3c7{{end}};color:{{if .IsCritical}}#b91c1c{{else}}#b45309{{end}};border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{.Count}}&times;</span>
    <span style="color:#0f172a;font-size:12px;font-weight:600;">&nbsp;{{.Interface}}</span>{{if .DeviceName}} <span style="color:#94a3b8;font-size:12px;">{{.DeviceName}}</span>{{end}}
    {{if and .Critical (ne .Critical .Count)}}<span style="color:#94a3b8;font-size:11px;"> ({{.Critical}} critical)</span>{{end}}
  </td>
  <td align="right" style="padding:8px 12px;vertical-align:middle;font-size:11px;color:#64748b;white-space:nowrap;">
    peak <span style="color:#0f172a;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{.PeakHuman}}</span>{{if .Window}} &middot; {{.Window}}{{end}}
  </td>
</tr></table>{{end}}

{{define "devhead"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
  <td style="vertical-align:middle;">
    <span style="font-size:14px;font-weight:700;color:#0f172a;">{{.Name}}</span>
    {{if .Online}}<span style="display:inline-block;background:#dcfce7;color:#15803d;border:1px solid #bbf7d0;border-radius:20px;padding:2px 9px;font-size:10px;font-weight:700;letter-spacing:0.4px;margin-left:8px;">ONLINE</span>
    {{else}}<span style="display:inline-block;background:#fee2e2;color:#b91c1c;border:1px solid #fecaca;border-radius:20px;padding:2px 9px;font-size:10px;font-weight:700;letter-spacing:0.4px;margin-left:8px;">OFFLINE</span>{{end}}
  </td>
  <td align="right" style="vertical-align:middle;font-size:12px;color:#64748b;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{.IPAddress}}</td>
</tr></table>{{end}}

{{define "devbody"}}
<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:10px;"><tr>
  {{template "mini" dict "Label" "CPU avg/max" "Value" (printf "%.0f / %.0f%%" .CPUAvg .CPUMax) "First" true}}
  {{template "mini" dict "Label" "Mem avg/max" "Value" (printf "%.0f / %.0f%%" .MemAvg .MemMax)}}
  {{template "mini" dict "Label" "Disk" "Value" (printf "%.0f%%" .DiskUsage)}}
  {{template "mini" dict "Label" "Sessions" "Value" (printf "%d" .SessionCount)}}
</tr></table>

<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:12px;"><tr>
  <td style="vertical-align:middle;font-size:11px;color:#94a3b8;width:60px;text-transform:uppercase;letter-spacing:0.5px;">Uptime</td>
  <td style="vertical-align:middle;">
    <div style="background:#eef1f5;border-radius:4px;height:10px;width:100%;">
      <div style="background:#16a34a;height:10px;border-radius:4px;width:{{.UptimeBarPct}}%;"></div>
    </div>
  </td>
  <td align="right" style="vertical-align:middle;font-size:12px;color:#0f172a;padding-left:10px;width:64px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{printf "%.2f%%" .UptimePct}}</td>
</tr></table>

{{template "eyebrow" "CPU & Memory History"}}
<div style="width:100%;overflow-x:auto;margin-bottom:6px;">
  {{renderCPUMemChart . .Timezone}}
</div>

{{if .HasSparkline}}
{{template "eyebrow" "Throughput · Busiest Interface"}}
<div style="width:100%;overflow-x:auto;margin-bottom:6px;">
  {{renderThroughputChart . .Timezone}}
</div>
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

{{define "spikeflow"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:5px;"><tr>
  <td style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:11.5px;color:#0f172a;vertical-align:middle;">
    {{.Src}} <span style="color:#94a3b8;">&rarr;</span> {{.Dst}}
  </td>
  <td align="right" style="font-size:11px;color:#64748b;white-space:nowrap;vertical-align:middle;padding-left:10px;">
    {{.Protocol}} &middot; <span style="color:#0f172a;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;">{{.BytesHuman}}</span>
  </td>
</tr></table>{{end}}

{{define "mini"}}<td width="25%" style="text-align:center;{{if .First}}padding:0 4px 0 0;{{else}}padding:0 4px;{{end}}">
  <div style="border:1px solid #e6eaf1;background:#ffffff;border-radius:6px;padding:9px 6px;">
    <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:13px;font-weight:700;color:#0f172a;">{{.Value}}</div>
    <div style="font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.4px;margin-top:4px;">{{.Label}}</div>
  </div>
</td>{{end}}
`
