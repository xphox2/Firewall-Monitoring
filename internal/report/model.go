package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// ReportModel is the pure-data view of a fleet report. It carries no rendered
// images — every visual in the report is drawn from these fields with
// email-safe HTML/CSS (see template_report.go), so the same model renders
// identically in the email body, the admin panel, and a printed PDF.
type ReportModel struct {
	Period      string // "Daily" / "Weekly"
	Date        string
	Timezone    string
	GeneratedAt string
	Version     string
	Hours       int
	Collapsible bool // admin preview wraps device detail in <details>

	// Fleet KPIs
	TotalDevices   int
	OnlineDevices  int
	OfflineDevices int
	TotalAlerts    int
	CriticalAlerts int
	FleetUptimePct float64

	// Status verdict — the plain-language headline the report leads with.
	// Level is "ok" / "warn" / "crit"; the template colors the band from it.
	StatusLevel    string
	StatusHeadline string
	StatusDetail   string

	// Bandwidth & Traffic
	PeakThroughput string // human-readable, e.g. "842.0 Mbps"
	TotalTransfer  string // human-readable, e.g. "1.2 TB"
	TopTalkers     []TopTalker

	// Traffic spikes — summarized by interface, not listed per event.
	SpikeGroups     []SpikeGroup
	SpikeTotal      int // total spike events across the fleet
	SpikeCritical   int
	SpikeWarning    int
	SpikeIfaceCount int // number of distinct device+interface groups
	SpikeMore       int // groups beyond the displayed cap

	// Alert timeline
	AlertBuckets []AlertBucket
	HasAlerts    bool

	Devices []DeviceCard
}

// TopTalker is one bar in a Top-Talkers chart (fleet- or device-level).
type TopTalker struct {
	DeviceName string
	IfaceName  string
	TotalHuman string // bytes transferred, human-readable
	PeakHuman  string // peak throughput, human-readable
	BarPct     int    // 0..100, relative to the busiest talker in the set
}

// SpikeGroup summarizes all throughput anomalies for one device+interface over
// the window — count, peak rate, worst severity, and the time span — instead of
// listing every individual event (a busy link can spike 30+ times).
type SpikeGroup struct {
	DeviceName string // blank when rendered inside a device card (redundant there)
	Interface  string
	Count      int
	Critical   int    // how many of Count were critical
	PeakHuman  string // peak throughput across the group, human-readable
	WorstSev   string // "critical" / "warning"
	IsCritical bool
	Window     string // "May 30 02:14 – 14:31"
}

// AlertBucket is one column in the alert-frequency timeline.
type AlertBucket struct {
	Label   string
	Count   int
	BarPct  int // 0..100, relative to the busiest bucket
	Crit    bool
	Tooltip string // Detailed text for hover tooltips
}

// SparkBar is one column in a device throughput sparkline.
type SparkBar struct {
	HeightPct int // 0..100
}

// DeviceCard is the per-device detail block.
type DeviceCard struct {
	Name           string
	IPAddress      string
	Status         string
	Online         bool
	CPUAvg         float64
	CPUMax         float64
	MemAvg         float64
	MemMax         float64
	DiskUsage      float64
	UptimePct      float64
	UptimeBarPct   int
	SessionCount   int
	AlertCount     int
	Sparkline      []SparkBar
	SparklineRaw   []float64
	SparklineTimes []time.Time
	CPUHistory     []float64
	MemHistory     []float64
	SysTimes       []time.Time
	HasSparkline   bool
	Talkers        []TopTalker
	Spikes         []SpikeGroup
	SpikeFlows     []SpikeFlow // top sFlow conversations seen during this device's spikes
	Timezone       string
}

// SpikeFlow is one sampled flow conversation observed on an interface during a
// traffic spike. Surfaced in the report so an operator can tell at a glance what
// the spiking traffic was (and whether it warrants logging into the firewall).
type SpikeFlow struct {
	Src        string // source address
	Dst        string // destination address:port
	Protocol   string
	BytesHuman string
}

// BuildReportModel assembles a ReportModel from gathered per-device data.
func BuildReportModel(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period string) ReportModel {
	now := time.Now()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}

	m := ReportModel{
		Period:       period,
		Date:         now.In(loc).Format("Monday, January 2, 2006"),
		Timezone:     tz,
		GeneratedAt:  now.In(loc).Format("2006-01-02 15:04 MST"),
		Hours:        hours,
		TotalDevices: len(devices),
	}

	type fleetTalker struct {
		device string
		t      IfaceTraffic
	}
	var fleetTalkers []fleetTalker
	var fleetSpikes []spikeItem
	var allAlerts []models.Alert
	var uptimeSum float64
	var uptimeCount int
	var peakBps, totalBytes float64

	for i, device := range devices {
		online := device.Status == "online"
		if online {
			m.OnlineDevices++
		} else {
			m.OfflineDevices++
		}

		if i >= len(deviceData) || deviceData[i] == nil {
			m.Devices = append(m.Devices, DeviceCard{
				Name:      device.Name,
				IPAddress: device.IPAddress,
				Status:    device.Status,
				Online:    online,
			})
			continue
		}
		dd := deviceData[i]

		m.TotalAlerts += dd.AlertCount
		for _, a := range dd.Alerts {
			if isCriticalAlert(a) {
				m.CriticalAlerts++
			}
		}
		allAlerts = append(allAlerts, dd.Alerts...)

		if dd.UptimeDaysTracked > 0 {
			uptimeSum += dd.UptimePct
			uptimeCount++
		}

		for _, t := range dd.Talkers {
			fleetTalkers = append(fleetTalkers, fleetTalker{device: device.Name, t: t})
			totalBytes += t.TotalBytes
			if t.PeakBps > peakBps {
				peakBps = t.PeakBps
			}
		}

		// Per-device spike summary (device name omitted — it's in the header).
		var devItems []spikeItem
		for _, s := range dd.Spikes {
			item := spikeItem{device: device.Name, s: s}
			devItems = append(devItems, item)
			fleetSpikes = append(fleetSpikes, item)
		}
		devGroups, _, _, _, _ := groupSpikes(devItems, loc, false, 6)

		card := DeviceCard{
			Name:           device.Name,
			IPAddress:      device.IPAddress,
			Status:         device.Status,
			Online:         online,
			CPUAvg:         dd.CPUAvg,
			CPUMax:         dd.CPUMax,
			MemAvg:         dd.MemAvg,
			MemMax:         dd.MemMax,
			DiskUsage:      dd.DiskUsage,
			UptimePct:      dd.UptimePct,
			UptimeBarPct:   clampPct(dd.UptimePct),
			SessionCount:   dd.SessionCount,
			AlertCount:     dd.AlertCount,
			Talkers:        barsFromTalkers(device.Name, dd.Talkers, false),
			Sparkline:      sparkline(dd.Sparkline),
			SparklineRaw:   dd.Sparkline,
			SparklineTimes: dd.SparklineTimes,
			CPUHistory:     dd.CPUHistory,
			MemHistory:     dd.MemHistory,
			SysTimes:       dd.SysTimes,
			Spikes:         devGroups,
			SpikeFlows:     dd.SpikeFlows,
			Timezone:       tz,
		}
		card.HasSparkline = len(card.Sparkline) > 0
		m.Devices = append(m.Devices, card)
	}

	// Fleet spike summary — grouped by device+interface, headline counts, top 8.
	m.SpikeGroups, m.SpikeMore, m.SpikeTotal, m.SpikeCritical, m.SpikeWarning = groupSpikes(fleetSpikes, loc, true, 8)
	m.SpikeIfaceCount = len(m.SpikeGroups) + m.SpikeMore

	// Fleet Top Talkers — sort by bytes transferred, keep the busiest 8.
	sort.Slice(fleetTalkers, func(a, b int) bool {
		return fleetTalkers[a].t.TotalBytes > fleetTalkers[b].t.TotalBytes
	})
	if len(fleetTalkers) > 8 {
		fleetTalkers = fleetTalkers[:8]
	}
	var maxTalker float64
	for _, ft := range fleetTalkers {
		if ft.t.TotalBytes > maxTalker {
			maxTalker = ft.t.TotalBytes
		}
	}
	for _, ft := range fleetTalkers {
		m.TopTalkers = append(m.TopTalkers, TopTalker{
			DeviceName: ft.device,
			IfaceName:  ft.t.Name,
			TotalHuman: formatBytes(ft.t.TotalBytes),
			PeakHuman:  formatThroughput(ft.t.PeakBps),
			BarPct:     pctOf(ft.t.TotalBytes, maxTalker),
		})
	}

	m.PeakThroughput = formatThroughput(peakBps)
	m.TotalTransfer = formatBytes(totalBytes)

	m.AlertBuckets = bucketAlerts(allAlerts, hours)
	m.HasAlerts = len(allAlerts) > 0

	if uptimeCount > 0 {
		m.FleetUptimePct = uptimeSum / float64(uptimeCount)
	}

	m.computeStatusVerdict()

	return m
}

// computeStatusVerdict derives the report's headline health verdict from the
// fleet KPIs. Priority: offline devices or critical alerts → critical; any
// other alert/spike activity → minor; otherwise nominal.
func (m *ReportModel) computeStatusVerdict() {
	switch {
	case m.OfflineDevices > 0 || m.CriticalAlerts > 0:
		m.StatusLevel = "crit"
		m.StatusHeadline = "Attention required"
	case m.TotalAlerts > 0 || m.SpikeTotal > 0:
		m.StatusLevel = "warn"
		m.StatusHeadline = "Operational — minor activity"
	default:
		m.StatusLevel = "ok"
		m.StatusHeadline = "All systems nominal"
	}

	parts := make([]string, 0, 4)
	if m.OfflineDevices == 0 {
		parts = append(parts, fmt.Sprintf("%d/%d devices online", m.OnlineDevices, m.TotalDevices))
	} else {
		parts = append(parts, fmt.Sprintf("%d of %d online, %d offline", m.OnlineDevices, m.TotalDevices, m.OfflineDevices))
	}
	if m.CriticalAlerts > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", m.CriticalAlerts))
	}
	parts = append(parts, fmt.Sprintf("%d alert%s in %dh", m.TotalAlerts, plural(m.TotalAlerts), m.Hours))
	if m.SpikeTotal > 0 {
		parts = append(parts, fmt.Sprintf("%d traffic spike%s", m.SpikeTotal, plural(m.SpikeTotal)))
	}
	parts = append(parts, fmt.Sprintf("%.2f%% fleet uptime", m.FleetUptimePct))
	m.StatusDetail = strings.Join(parts, " · ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isCriticalAlert(a models.Alert) bool {
	return strings.EqualFold(a.Severity, "critical")
}

// barsFromTalkers converts IfaceTraffic to display bars scaled within the set.
func barsFromTalkers(deviceName string, talkers []IfaceTraffic, includeDevice bool) []TopTalker {
	var maxBytes float64
	for _, t := range talkers {
		if t.TotalBytes > maxBytes {
			maxBytes = t.TotalBytes
		}
	}
	out := make([]TopTalker, 0, len(talkers))
	for _, t := range talkers {
		name := deviceName
		if !includeDevice {
			name = ""
		}
		out = append(out, TopTalker{
			DeviceName: name,
			IfaceName:  t.Name,
			TotalHuman: formatBytes(t.TotalBytes),
			PeakHuman:  formatThroughput(t.PeakBps),
			BarPct:     pctOf(t.TotalBytes, maxBytes),
		})
	}
	return out
}

// spikeItem pairs a spike with its device for fleet-level aggregation.
type spikeItem struct {
	device string
	s      TrafficSpike
}

// groupSpikes collapses individual spike events into one SpikeGroup per
// device+interface: count, peak rate, worst severity, and time window. Groups
// are sorted critical-first, then by event count, then peak. When showDevice is
// false the device name is omitted (rendered inside a device card). max caps the
// returned groups; the overflow count is returned as `more`.
func groupSpikes(items []spikeItem, loc *time.Location, showDevice bool, limit int) (groups []SpikeGroup, more, total, crit, warn int) {
	type agg struct {
		device, iface string
		count, crit   int
		peak          float64
		first, last   time.Time
	}
	type key struct{ device, iface string }

	order := make([]key, 0)
	byKey := make(map[key]*agg)
	for _, it := range items {
		total++
		isCrit := it.s.Severity == "critical"
		if isCrit {
			crit++
		} else {
			warn++
		}
		k := key{it.device, it.s.Interface}
		a, ok := byKey[k]
		if !ok {
			a = &agg{device: it.device, iface: it.s.Interface, first: it.s.Timestamp, last: it.s.Timestamp}
			byKey[k] = a
			order = append(order, k)
		}
		a.count++
		if isCrit {
			a.crit++
		}
		if it.s.Value > a.peak {
			a.peak = it.s.Value
		}
		if !it.s.Timestamp.IsZero() {
			if a.first.IsZero() || it.s.Timestamp.Before(a.first) {
				a.first = it.s.Timestamp
			}
			if it.s.Timestamp.After(a.last) {
				a.last = it.s.Timestamp
			}
		}
	}

	for _, k := range order {
		a := byKey[k]
		g := SpikeGroup{
			Interface:  a.iface,
			Count:      a.count,
			Critical:   a.crit,
			PeakHuman:  formatThroughput(a.peak),
			IsCritical: a.crit > 0,
			WorstSev:   "warning",
			Window:     windowLabel(a.first, a.last, loc),
		}
		if g.IsCritical {
			g.WorstSev = "critical"
		}
		if showDevice {
			g.DeviceName = a.device
		}
		groups = append(groups, g)
	}

	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].IsCritical != groups[j].IsCritical {
			return groups[i].IsCritical // criticals first
		}
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return false
	})

	if limit > 0 && len(groups) > limit {
		more = len(groups) - limit
		groups = groups[:limit]
	}
	return groups, more, total, crit, warn
}

// windowLabel formats the [first,last] span of a spike group compactly.
func windowLabel(first, last time.Time, loc *time.Location) string {
	if first.IsZero() && last.IsZero() {
		return ""
	}
	a := first.In(loc)
	b := last.In(loc)
	if a.Equal(b) {
		return a.Format("Jan 2 15:04")
	}
	if a.Year() == b.Year() && a.YearDay() == b.YearDay() {
		return a.Format("Jan 2 15:04") + " – " + b.Format("15:04") // same day
	}
	return a.Format("Jan 2 15:04") + " – " + b.Format("Jan 2 15:04")
}

// sparkline normalizes a throughput series into 0..100 column heights, keeping
// at most the last 48 points so the bar strip stays compact.
func sparkline(series []float64) []SparkBar {
	if len(series) == 0 {
		return nil
	}
	if len(series) > 48 {
		series = series[len(series)-48:]
	}
	var max float64
	for _, v := range series {
		if v > max {
			max = v
		}
	}
	bars := make([]SparkBar, 0, len(series))
	for _, v := range series {
		h := 0
		if max > 0 {
			h = int(v / max * 100)
		}
		if h == 0 && v > 0 {
			h = 2 // keep a hairline visible for non-zero buckets
		}
		bars = append(bars, SparkBar{HeightPct: h})
	}
	return bars
}

// bucketAlerts groups alerts into a time histogram. Ported from the old
// go-chart RenderAlertTrend (v0.10.236) so the timeline is pure HTML/CSS.
func bucketAlerts(alerts []models.Alert, hours int) []AlertBucket {
	if len(alerts) == 0 {
		return nil
	}

	bucketDuration := time.Hour
	if hours > 48 {
		bucketDuration = 24 * time.Hour
	}

	now := time.Now()
	start := now.Add(-time.Duration(hours) * time.Hour)
	numBuckets := int(now.Sub(start)/bucketDuration) + 1
	if numBuckets > 100 {
		numBuckets = 100
	}
	if numBuckets < 1 {
		numBuckets = 1
	}

	counts := make([]int, numBuckets)
	crit := make([]bool, numBuckets)
	for _, a := range alerts {
		idx := int(a.Timestamp.Sub(start) / bucketDuration)
		if idx >= 0 && idx < numBuckets {
			counts[idx]++
			if isCriticalAlert(a) {
				crit[idx] = true
			}
		}
	}

	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}

	buckets := make([]AlertBucket, 0, numBuckets)
	for i := 0; i < numBuckets; i++ {
		t := start.Add(time.Duration(i) * bucketDuration)
		label := ""
		if i%6 == 0 {
			if bucketDuration >= 24*time.Hour {
				label = t.Format("Jan 2")
			} else {
				label = t.Format("15:04")
			}
		}

		var toolTip string
		if bucketDuration >= 24*time.Hour {
			toolTip = fmt.Sprintf("Date: %s\nAlerts: %d", t.Format("Jan 2, 2006"), counts[i])
		} else {
			toolTip = fmt.Sprintf("Time: %s\nAlerts: %d", t.Format("Jan 2, 15:04"), counts[i])
		}
		if counts[i] > 0 {
			if crit[i] {
				toolTip += " (Critical)"
			} else {
				toolTip += " (Warning)"
			}
		}

		buckets = append(buckets, AlertBucket{
			Label:   label,
			Count:   counts[i],
			BarPct:  pctOf(float64(counts[i]), float64(maxCount)),
			Crit:    crit[i],
			Tooltip: toolTip,
		})
	}
	return buckets
}

func pctOf(v, max float64) int {
	if max <= 0 {
		return 0
	}
	p := int(v / max * 100)
	return clampPct(float64(p))
}

func clampPct(v float64) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return int(v)
}
