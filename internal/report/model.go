package report

import (
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

	// Bandwidth & Traffic
	PeakThroughput string // human-readable, e.g. "842.0 Mbps"
	TotalTransfer  string // human-readable, e.g. "1.2 TB"
	TopTalkers     []TopTalker
	SpikeCards     []SpikeCard

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

// SpikeCard is a styled callout for a detected throughput anomaly.
type SpikeCard struct {
	DeviceName string
	Interface  string
	TimeLabel  string
	ValueHuman string // spike throughput, human-readable
	MeanHuman  string // rolling mean throughput
	Severity   string // "warning" / "critical"
	Critical   bool
}

// AlertBucket is one column in the alert-frequency timeline.
type AlertBucket struct {
	Label  string
	Count  int
	BarPct int // 0..100, relative to the busiest bucket
	Crit   bool
}

// SparkBar is one column in a device throughput sparkline.
type SparkBar struct {
	HeightPct int // 0..100
}

// DeviceCard is the per-device detail block.
type DeviceCard struct {
	Name         string
	IPAddress    string
	Status       string
	Online       bool
	CPUAvg       float64
	CPUMax       float64
	MemAvg       float64
	MemMax       float64
	DiskUsage    float64
	UptimePct    float64
	UptimeBarPct int
	SessionCount int
	AlertCount   int
	Sparkline    []SparkBar
	HasSparkline bool
	Talkers      []TopTalker
	Spikes       []SpikeCard
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

		cards := spikeCards(device.Name, dd.Spikes, loc)
		card := DeviceCard{
			Name:         device.Name,
			IPAddress:    device.IPAddress,
			Status:       device.Status,
			Online:       online,
			CPUAvg:       dd.CPUAvg,
			CPUMax:       dd.CPUMax,
			MemAvg:       dd.MemAvg,
			MemMax:       dd.MemMax,
			DiskUsage:    dd.DiskUsage,
			UptimePct:    dd.UptimePct,
			UptimeBarPct: clampPct(dd.UptimePct),
			SessionCount: dd.SessionCount,
			AlertCount:   dd.AlertCount,
			Talkers:      barsFromTalkers(device.Name, dd.Talkers, false),
			Sparkline:    sparkline(dd.Sparkline),
			Spikes:       cards,
		}
		card.HasSparkline = len(card.Sparkline) > 0
		m.Devices = append(m.Devices, card)

		m.SpikeCards = append(m.SpikeCards, cards...)
	}

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

	return m
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

func spikeCards(deviceName string, spikes []TrafficSpike, loc *time.Location) []SpikeCard {
	out := make([]SpikeCard, 0, len(spikes))
	for _, s := range spikes {
		out = append(out, SpikeCard{
			DeviceName: deviceName,
			Interface:  s.Interface,
			TimeLabel:  s.Timestamp.In(loc).Format("Jan 2 15:04"),
			ValueHuman: formatThroughput(s.Value),
			MeanHuman:  formatThroughput(s.Mean),
			Severity:   s.Severity,
			Critical:   s.Severity == "critical",
		})
	}
	return out
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
		label := ""
		if i%6 == 0 {
			t := start.Add(time.Duration(i) * bucketDuration)
			if bucketDuration >= 24*time.Hour {
				label = t.Format("Jan 2")
			} else {
				label = t.Format("15:04")
			}
		}
		buckets = append(buckets, AlertBucket{
			Label:  label,
			Count:  counts[i],
			BarPct: pctOf(float64(counts[i]), float64(maxCount)),
			Crit:   crit[i],
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
