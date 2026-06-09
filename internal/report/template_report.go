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
	"renderAlertChart":      RenderAlertTimelineSVG,
	"renderThroughputChart": RenderThroughputChart,
	"renderCPUMemChart":     RenderCPUMemSVGChart,
}).Parse(reportTemplateSrc))

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

const reportTemplateSrc = `
{{define "report"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall Monitor — {{.Period}} Report</title>
<style>
  body { -webkit-text-size-adjust:100%; }
  details > summary { cursor:pointer; list-style:none; outline:none; }
  details > summary::-webkit-details-marker { display:none; }
  @media print {
    body { background:#ffffff !important; }
    .no-print { display:none !important; }
    details { display:block !important; }
    details > summary { display:none !important; }
    .device-block { break-inside:avoid; page-break-inside:avoid; }
    .surface { box-shadow:none !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#08090c;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#08090c;padding:24px 0;">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" role="presentation" style="width:680px;max-width:680px;">

  <!-- Header -->
  <tr><td class="surface" style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:10px;padding:22px 26px;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
      <td style="vertical-align:middle;">
        <div style="font-size:20px;font-weight:700;color:#e6edf3;letter-spacing:-0.2px;">Firewall Monitor</div>
        <div style="font-size:13px;color:#8b949e;margin-top:3px;">{{.Period}} Report &middot; {{.Date}} ({{.Timezone}})</div>
      </td>
      <td align="right" style="vertical-align:middle;">
        <span style="display:inline-block;background:rgba(125,211,252,0.12);color:#7dd3fc;border:1px solid rgba(125,211,252,0.4);border-radius:20px;padding:6px 14px;font-size:12px;font-weight:600;">Last {{.Hours}}h</span>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="height:16px;line-height:16px;font-size:0;">&nbsp;</td></tr>

  <!-- Fleet KPI cards -->
  <tr><td>
    <table width="100%" cellpadding="0" cellspacing="8" role="presentation">
      <tr>
        {{template "kpi" dict "Label" "Devices" "Value" (printf "%d" .TotalDevices) "Color" "#e6edf3"}}
        {{template "kpi" dict "Label" "Online" "Value" (printf "%d" .OnlineDevices) "Color" "#86efac"}}
        {{template "kpi" dict "Label" "Offline" "Value" (printf "%d" .OfflineDevices) "Color" "#fca5a5"}}
      </tr>
      <tr>
        {{template "kpi" dict "Label" (printf "Alerts (%dh)" .Hours) "Value" (printf "%d" .TotalAlerts) "Color" "#e6edf3"}}
        {{template "kpi" dict "Label" "Critical" "Value" (printf "%d" .CriticalAlerts) "Color" "#fca5a5"}}
        {{template "kpi" dict "Label" "Fleet Uptime" "Value" (printf "%.2f%%" .FleetUptimePct) "Color" "#7dd3fc"}}
      </tr>
    </table>
  </td></tr>

  <tr><td style="height:18px;line-height:18px;font-size:0;">&nbsp;</td></tr>

  <!-- Bandwidth & Traffic -->
  <tr><td class="surface" style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:10px;padding:20px 24px;">
    <div style="font-size:15px;font-weight:700;color:#e6edf3;margin-bottom:14px;">Bandwidth &amp; Traffic</div>

    <table width="100%" cellpadding="0" cellspacing="10" role="presentation"><tr>
      <td width="50%" style="background:rgba(255, 255, 255, 0.03);border:1px solid rgba(255, 255, 255, 0.05);border-radius:8px;padding:12px 14px;">
        <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">Peak Throughput</div>
        <div style="font-size:20px;font-weight:700;color:#7dd3fc;margin-top:4px;">{{.PeakThroughput}}</div>
      </td>
      <td width="50%" style="background:rgba(255, 255, 255, 0.03);border:1px solid rgba(255, 255, 255, 0.05);border-radius:8px;padding:12px 14px;">
        <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">Total Transferred</div>
        <div style="font-size:20px;font-weight:700;color:#e6edf3;margin-top:4px;">{{.TotalTransfer}}</div>
      </td>
    </tr></table>

    {{if .TopTalkers}}
    <div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin:18px 0 8px;">Top Talkers</div>
    {{range .TopTalkers}}{{template "talker" .}}{{end}}
    {{else}}
    <div style="font-size:12px;color:#8b949e;margin-top:14px;">No interface traffic recorded in this window.</div>
    {{end}}

    {{if .SpikeGroups}}
    <div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin:18px 0 6px;">Traffic Spikes</div>
    <div style="font-size:12px;color:#c9d1d9;margin-bottom:8px;">
      <strong style="color:#e6edf3;">{{.SpikeTotal}}</strong> spike{{if ne .SpikeTotal 1}}s{{end}} on {{.SpikeIfaceCount}} interface{{if ne .SpikeIfaceCount 1}}s{{end}}
      {{if .SpikeCritical}}<span style="color:#fca5a5;"> &middot; {{.SpikeCritical}} critical</span>{{end}}
      {{if .SpikeWarning}}<span style="color:#fcd34d;"> &middot; {{.SpikeWarning}} warning</span>{{end}}
    </div>
    {{range .SpikeGroups}}{{template "spikegroup" .}}{{end}}
    {{if .SpikeMore}}<div style="font-size:11px;color:#6e7681;margin-top:2px;">+ {{.SpikeMore}} more interface{{if ne .SpikeMore 1}}s{{end}} with spikes</div>{{end}}
    {{end}}
  </td></tr>

  {{if .HasAlerts}}
  <tr><td style="height:18px;line-height:18px;font-size:0;">&nbsp;</td></tr>
  <tr><td class="surface" style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:10px;padding:20px 24px;">
    <div style="font-size:15px;font-weight:700;color:#e6edf3;margin-bottom:14px;">Alert Timeline</div>
    <div style="width:100%;overflow-x:auto;">
      {{renderAlertChart .AlertBuckets}}
    </div>
  </td></tr>
  {{end}}

  <tr><td style="height:18px;line-height:18px;font-size:0;">&nbsp;</td></tr>

  <!-- Per-device detail -->
  <tr><td>
    <div style="font-size:15px;font-weight:700;color:#e6edf3;margin:0 2px 10px;">Devices</div>
    {{range .Devices}}
      {{if $.Collapsible}}
      <details open class="device-block surface" style="display:block;background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:10px;padding:0;margin-bottom:12px;">
        <summary style="padding:14px 18px;">{{template "devhead" .}}</summary>
        <div style="padding:0 18px 16px;">{{template "devbody" .}}</div>
      </details>
      {{else}}
      <div class="device-block surface" style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:10px;margin-bottom:12px;">
        <div style="padding:14px 18px;border-bottom:1px solid rgba(255, 255, 255, 0.08);">{{template "devhead" .}}</div>
        <div style="padding:14px 18px 16px;">{{template "devbody" .}}</div>
      </div>
      {{end}}
    {{end}}
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:18px 4px;text-align:center;">
    <div style="font-size:11px;color:#6e7681;">Generated {{.GeneratedAt}} by Firewall Monitor{{if .Version}} v{{.Version}}{{end}}</div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>{{end}}

{{define "kpi"}}<td width="33%" style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(255, 255, 255, 0.08);border-radius:8px;padding:14px 10px;text-align:center;">
  <div style="font-size:22px;font-weight:700;color:{{.Color}};line-height:1.1;">{{.Value}}</div>
  <div style="font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:0.6px;margin-top:5px;">{{.Label}}</div>
</td>{{end}}

{{define "talker"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:7px;"><tr>
  <td width="34%" style="font-size:12px;color:#e6edf3;padding-right:10px;vertical-align:middle;white-space:nowrap;overflow:hidden;">
    <strong>{{.IfaceName}}</strong>{{if .DeviceName}} <span style="color:#8b949e;">{{.DeviceName}}</span>{{end}}
  </td>
  <td width="46%" style="vertical-align:middle;">
    <div style="background:rgba(255,255,255,0.06);border-radius:4px;height:12px;width:100%;">
      <div style="background:#7dd3fc;height:12px;border-radius:4px;width:{{.BarPct}}%;"></div>
    </div>
  </td>
  <td width="20%" align="right" style="font-size:12px;color:#e6edf3;padding-left:10px;vertical-align:middle;white-space:nowrap;">
    {{.TotalHuman}}<span style="color:#8b949e;font-size:10px;"> &middot; {{.PeakHuman}} pk</span>
  </td>
</tr></table>{{end}}

{{define "spikegroup"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:6px;border:1px solid rgba(255, 255, 255, 0.08);border-left:3px solid {{if .IsCritical}}#fca5a5{{else}}#fcd34d{{end}};background:rgba(255, 255, 255, 0.03);border-radius:6px;"><tr>
  <td style="padding:8px 12px;vertical-align:middle;">
    <span style="display:inline-block;background:{{if .IsCritical}}rgba(252,165,165,0.15){{else}}rgba(252,211,77,0.15){{end}};color:{{if .IsCritical}}#fca5a5{{else}}#fcd34d{{end}};border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;">{{.Count}}&times;</span>
    <span style="color:#e6edf3;font-size:12px;font-weight:600;">&nbsp;{{.Interface}}</span>{{if .DeviceName}} <span style="color:#8b949e;font-size:12px;">{{.DeviceName}}</span>{{end}}
    {{if and .Critical (ne .Critical .Count)}}<span style="color:#8b949e;font-size:11px;"> ({{.Critical}} critical)</span>{{end}}
  </td>
  <td align="right" style="padding:8px 12px;vertical-align:middle;font-size:11px;color:#8b949e;white-space:nowrap;">
    peak <span style="color:#e6edf3;">{{.PeakHuman}}</span>{{if .Window}} &middot; {{.Window}}{{end}}
  </td>
</tr></table>{{end}}

{{define "devhead"}}<table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>
  <td style="vertical-align:middle;">
    <span style="font-size:14px;font-weight:700;color:#e6edf3;">{{.Name}}</span>
    {{if .Online}}<span style="display:inline-block;background:rgba(134,239,172,0.15);color:#86efac;border:1px solid rgba(134,239,172,0.4);border-radius:20px;padding:2px 9px;font-size:10px;font-weight:600;margin-left:8px;">ONLINE</span>
    {{else}}<span style="display:inline-block;background:rgba(252,165,165,0.15);color:#fca5a5;border:1px solid rgba(252,165,165,0.4);border-radius:20px;padding:2px 9px;font-size:10px;font-weight:600;margin-left:8px;">OFFLINE</span>{{end}}
  </td>
  <td align="right" style="vertical-align:middle;font-size:12px;color:#8b949e;">{{.IPAddress}}</td>
</tr></table>{{end}}

{{define "devbody"}}
<table width="100%" cellpadding="0" cellspacing="6" role="presentation" style="margin-top:10px;"><tr>
  {{template "mini" dict "Label" "CPU avg/max" "Value" (printf "%.0f / %.0f%%" .CPUAvg .CPUMax)}}
  {{template "mini" dict "Label" "Mem avg/max" "Value" (printf "%.0f / %.0f%%" .MemAvg .MemMax)}}
  {{template "mini" dict "Label" "Disk" "Value" (printf "%.0f%%" .DiskUsage)}}
  {{template "mini" dict "Label" "Sessions" "Value" (printf "%d" .SessionCount)}}
</tr></table>

<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:10px;"><tr>
  <td style="vertical-align:middle;font-size:11px;color:#8b949e;width:70px;">Uptime</td>
  <td style="vertical-align:middle;">
    <div style="background:rgba(255,255,255,0.06);border-radius:4px;height:10px;width:100%;">
      <div style="background:#86efac;height:10px;border-radius:4px;width:{{.UptimeBarPct}}%;"></div>
    </div>
  </td>
  <td align="right" style="vertical-align:middle;font-size:11px;color:#e6edf3;padding-left:10px;width:64px;">{{printf "%.2f%%" .UptimePct}}</td>
</tr></table>

<div style="font-size:11px;color:#8b949e;margin:14px 0 6px;">CPU &amp; Memory History</div>
<div style="width:100%;overflow-x:auto;margin-bottom:14px;">
  {{renderCPUMemChart . .Timezone}}
</div>

{{if .HasSparkline}}
<div style="font-size:11px;color:#8b949e;margin:14px 0 6px;">Throughput (Busiest Interface)</div>
<div style="width:100%;overflow-x:auto;margin-bottom:14px;">
  {{renderThroughputChart . .Timezone}}
</div>
{{end}}

{{if .Talkers}}
<div style="font-size:11px;color:#8b949e;margin:12px 0 6px;">Interfaces</div>
{{range .Talkers}}{{template "talker" .}}{{end}}
{{end}}

{{if .Spikes}}
<div style="font-size:11px;color:#8b949e;margin:12px 0 6px;">Traffic Spikes</div>
{{range .Spikes}}{{template "spikegroup" .}}{{end}}
{{end}}
{{end}}

{{define "mini"}}<td style="background:rgba(255, 255, 255, 0.03);border:1px solid rgba(255, 255, 255, 0.05);border-radius:6px;padding:8px 6px;text-align:center;">
  <div style="font-size:13px;font-weight:600;color:#e6edf3;">{{.Value}}</div>
  <div style="font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:0.4px;margin-top:3px;">{{.Label}}</div>
</td>{{end}}
`
