package report

import (
	"bytes"
	"fmt"
	"mime/quotedprintable"
	"sort"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// BuildDailyReport builds a self-contained HTML daily report (no attachments).
func BuildDailyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, error) {
	return buildReport(devices, deviceData, tz, 24, "Daily", "")
}

// BuildWeeklyReport builds a self-contained HTML weekly report (no attachments).
func BuildWeeklyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, error) {
	return buildReport(devices, deviceData, tz, 168, "Weekly", "")
}

// BuildReport renders a report HTML body + subject for the given window. The
// collapsible flag wraps per-device detail in <details> (admin preview); email
// sends always-open blocks. Returns (subject, html, error). Renders in the
// light theme — theme-aware callers use BuildReportWithOps.
func BuildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string, collapsible bool) (string, string, error) {
	subject, html, _, _, err := BuildReportWithOps(devices, deviceData, tz, hours, period, version, collapsible, nil, ThemeByName(""))
	return subject, html, err
}

// emailDeviceChartSlots bounds the per-device CPU/Mem PNGs riding in one
// email; emailDeviceCap bounds FULL device sections (overflow renders as
// compact rows); emailQPBudget is the Gmail clip guard — Gmail clips at
// ~102KB of TRANSFER-ENCODED HTML, so the fit loop measures the
// quoted-printable bytes exactly as SendHTMLEmail encodes them. A rich
// device card is ~11.5KB QP, so the cap alone can't guarantee the budget —
// BuildReportWithOps shrinks the full-section count until it fits.
const (
	emailDeviceChartSlots = 6
	emailDeviceCap        = 12
	emailQPBudget         = 92 * 1024
)

// BuildReportWithOps is BuildReport plus the F05/F06 Operations section
// (nil ops = section omitted) and an explicit theme (v0.11.116 — the web
// preview follows the SPA Day/Night choice; email follows the
// report_email_theme setting). Returns (subject, html, text, attachments,
// error); text is the model-generated text/plain alternative (v0.11.117);
// attachments are the themed chart PNGs, produced ONLY for the email render
// (v0.11.118) — the web preview keeps inline SVGs.
func BuildReportWithOps(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string, collapsible bool, ops *OpsStats, theme ReportTheme) (string, string, string, []notifier.Attachment, error) {
	m := BuildReportModel(devices, deviceData, tz, hours, period)
	m.Ops = ops
	m.Version = version
	m.Collapsible = collapsible
	m.IsEmail = !collapsible
	m.Theme = theme
	if m.Theme.Name == "" {
		m.Theme = ThemeByName("") // zero-value guard: never render unthemed
	}
	for i := range m.Devices {
		m.Devices[i].IsEmail = m.IsEmail
	}

	// Plaintext always covers the FULL fleet — rendered before any email
	// device-section capping.
	text := RenderReportText(m)

	var html string
	var attachments []notifier.Attachment
	var err error
	if m.IsEmail {
		html, attachments, err = renderEmailWithCharts(m)
	} else {
		html, err = RenderReportHTML(m)
	}
	if err != nil {
		return "", "", "", nil, err
	}
	loc, e := time.LoadLocation(tz)
	if e != nil {
		loc = time.UTC
	}
	subject := fmt.Sprintf("Firewall Monitor — %s Report — %s", period, time.Now().In(loc).Format("2006-01-02"))
	return subject, html, text, attachments, nil
}

// renderEmailWithCharts produces the email HTML + its themed PNG attachments:
//
//  1. Device sections are reordered by attention priority (offline → most
//     alerts → highest CPU) so the devices an operator must see never fall
//     below the fold or the cap.
//  2. The top emailDeviceChartSlots drawable devices get CPU/Mem chart PNGs;
//     the fleet alert timeline rides along when there were alerts.
//  3. The full-section count starts at emailDeviceCap and SHRINKS until the
//     quoted-printable HTML fits emailQPBudget (Gmail clips at ~102KB of
//     encoded HTML with zero warning). Devices below the cap render as
//     compact summary rows; attachments whose section fell below the cap are
//     dropped so no orphan image chips appear.
//
// Chart failures degrade silently to the HTML tables, which always carry
// every number.
func renderEmailWithCharts(m ReportModel) (string, []notifier.Attachment, error) {
	ordered := append([]DeviceCard(nil), m.Devices...)
	sort.SliceStable(ordered, func(a, b int) bool {
		if ordered[a].Online != ordered[b].Online {
			return !ordered[a].Online // offline first
		}
		if ordered[a].AlertCount != ordered[b].AlertCount {
			return ordered[a].AlertCount > ordered[b].AlertCount
		}
		return ordered[a].CPUMax > ordered[b].CPUMax
	})

	var alertAtt *notifier.Attachment
	if m.HasAlerts {
		if png, err := RenderAlertTimelinePNG(m.AlertBuckets, m.Theme); err == nil && png != nil {
			alertAtt = &notifier.Attachment{ContentID: "report_alerts", Data: png, MIMEType: "image/png"}
		}
	}

	// Pre-render chart candidates once; the fit loop below only decides how
	// many survive.
	type devChart struct {
		pos int // position in ordered
		png []byte
	}
	var charts []devChart
	for i := range ordered {
		if len(charts) == emailDeviceChartSlots {
			break
		}
		if png, err := RenderCPUMemPNG(ordered[i], m.Theme); err == nil && png != nil {
			charts = append(charts, devChart{pos: i, png: png})
		}
	}

	capN := len(ordered)
	if capN > emailDeviceCap {
		capN = emailDeviceCap
	}
	for {
		full := append([]DeviceCard(nil), ordered[:capN]...)
		var atts []notifier.Attachment
		if alertAtt != nil {
			m.AlertChartCID = alertAtt.ContentID
			atts = append(atts, *alertAtt)
		}
		for _, c := range charts {
			if c.pos >= capN {
				continue // compact row — no img anchor, so no attachment
			}
			cid := fmt.Sprintf("report_cpumem_%d", c.pos)
			full[c.pos].ChartCID = cid
			atts = append(atts, notifier.Attachment{ContentID: cid, Data: c.png, MIMEType: "image/png"})
		}
		m.Devices = full
		m.MoreDevices = ordered[capN:]

		html, err := RenderReportHTML(m)
		if err != nil {
			return "", nil, err
		}
		if qpEncodedLen(html) <= emailQPBudget || capN <= 1 {
			return html, atts, nil
		}
		capN--
	}
}

// qpEncodedLen measures the quoted-printable size of s — the bytes Gmail
// actually counts against its clip threshold.
func qpEncodedLen(s string) int {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.Len()
}

func buildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string) (string, string, error) {
	return BuildReport(devices, deviceData, tz, hours, period, version, false)
}

// CriticalAlertData holds data for the critical alert template.
type CriticalAlertData struct {
	Timestamp      string
	AlertType      string
	DeviceName     string
	DeviceIP       string
	Message        string
	MetricName     string
	CurrentValue   float64
	Threshold      float64
	DeviceStatus   string
	CPUMemChartCID string
	Theme          ReportTheme
}

// BuildCriticalAlertEmail builds an HTML email for a critical alert, themed
// with the same flat instrument-panel system as the fleet report. Callers
// resolve the theme (the poller reads report_email_theme from the DB at send
// time — its env-frozen config copy must NOT be the source). Returns
// (subject, html, text, attachments, error); text is the text/plain
// alternative (v0.11.117).
func BuildCriticalAlertEmail(alert *models.Alert, device *models.Device, recentHistory []models.SystemStatus, theme ReportTheme) (string, string, string, []notifier.Attachment, error) {
	if theme.Name == "" {
		theme = ThemeByName("")
	}
	data := CriticalAlertData{
		Timestamp:    alert.Timestamp.Format(time.RFC3339),
		AlertType:    string(alert.AlertType),
		DeviceName:   device.Name,
		DeviceIP:     device.IPAddress,
		Message:      alert.Message,
		MetricName:   alert.MetricName,
		CurrentValue: alert.CurrentValue,
		Threshold:    alert.Threshold,
		DeviceStatus: device.Status,
		Theme:        theme,
	}

	var attachments []notifier.Attachment

	// Themed CPU/Mem chart (v0.11.118 — both themes; the old light-only
	// legacy renderer and its dark-theme suppression are gone).
	if chartPNG, err := RenderCPUMemHistoryPNG(recentHistory, theme); err == nil && chartPNG != nil {
		cid := "cpumem_critical"
		data.CPUMemChartCID = cid
		attachments = append(attachments, notifier.Attachment{
			ContentID: cid,
			Data:      chartPNG,
			MIMEType:  "image/png",
		})
	}

	var buf bytes.Buffer
	if err := criticalAlertTemplate.Execute(&buf, data); err != nil {
		return "", "", "", nil, fmt.Errorf("render critical template: %w", err)
	}

	subject := fmt.Sprintf("[CRITICAL] %s — %s (%s)",
		notifier.SanitizeHeader(string(alert.AlertType)),
		notifier.SanitizeHeader(device.Name),
		notifier.SanitizeHeader(device.IPAddress))
	return subject, buf.String(), RenderCriticalAlertText(data), attachments, nil
}
