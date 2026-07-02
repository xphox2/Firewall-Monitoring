package report

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// safeID returns an HTML/CSS identifier safe for use in IDs and gradient names.
func safeID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	return sb.String()
}

// RenderAlertTimelineSVG renders the main fleet alert timeline as a beautiful SVG chart.
func RenderAlertTimelineSVG(buckets []AlertBucket) template.HTML {
	if len(buckets) == 0 {
		return template.HTML(`
			<div style="border: 1px dashed #cbd5e1; border-radius: 6px; padding: 30px; text-align: center; color: #64748b; font-size: 13px;">
				No alerts recorded in this window.
			</div>
		`)
	}

	maxCount := 0
	for _, b := range buckets {
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}

	width := 640
	height := 200
	plotXStart := 48
	plotXEnd := 624
	plotYStart := 18
	plotYEnd := 158

	plotWidth := plotXEnd - plotXStart
	plotHeight := plotYEnd - plotYStart

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg width="100%%" height="%d" viewBox="0 0 %d %d" style="max-width: %dpx; display: block;" xmlns="http://www.w3.org/2000/svg">`, height, width, height, width))

	// CSS styles for smooth hover effects
	sb.WriteString(`
		<style>
			.grid-line { stroke: #e9edf2; stroke-width: 1; stroke-dasharray: 2,2; }
			.axis-line { stroke: #cbd5e1; stroke-width: 1; }
			.axis-label { fill: #64748b; font-size: 12px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
			.alert-bar { transition: fill-opacity 0.15s; cursor: pointer; }
			.alert-bar:hover { fill-opacity: 0.85; }
			.tooltip-trigger { fill: transparent; cursor: pointer; }
		</style>
	`)

	// 1. Gridlines
	yMid := plotYStart + plotHeight/2
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYStart, plotXEnd, plotYStart))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, yMid, plotXEnd, yMid))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))

	// 2. Y-Axis labels
	if maxCount > 0 {
		midVal := float64(maxCount) / 2.0
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">%d</text>`, plotXStart-8, plotYStart, maxCount))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">%.1f</text>`, plotXStart-8, yMid, midVal))
	}
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">0</text>`, plotXStart-8, plotYEnd))

	// 3. Bars
	barWidth := float64(plotWidth) / float64(len(buckets))
	gap := 1.5
	if barWidth < 3 {
		gap = 0.5
	}

	for i, b := range buckets {
		if b.Count == 0 {
			continue
		}
		hVal := float64(b.Count) / float64(maxCount) * float64(plotHeight)
		// Ensure a minimum height for visibility
		if hVal < 3 {
			hVal = 3
		}

		bx := float64(plotXStart) + float64(i)*barWidth + gap/2
		bw := barWidth - gap
		if bw < 1 {
			bw = 1
		}
		by := float64(plotYEnd) - hVal

		color := "#d97706" // warning amber
		if b.Crit {
			color = "#dc2626" // critical red
		}

		// Draw the bar with tooltip
		sb.WriteString(fmt.Sprintf(`
			<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" rx="1.5" class="alert-bar">
				<title>%s</title>
			</rect>
		`, bx, by, bw, hVal, color, b.Tooltip))
	}

	// 4. X-Axis labels & ticks
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))
	for i, b := range buckets {
		if b.Label != "" {
			tickX := float64(plotXStart) + float64(i)*barWidth + barWidth/2
			sb.WriteString(fmt.Sprintf(`<line x1="%.2f" y1="%d" x2="%.2f" y2="%d" class="axis-line" />`, tickX, plotYEnd, tickX, plotYEnd+5))
			sb.WriteString(fmt.Sprintf(`<text x="%.2f" y="%d" class="axis-label" text-anchor="middle">%s</text>`, tickX, plotYEnd+18, b.Label))
		}
	}

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// RenderThroughputChart renders a beautiful area chart of interface throughput.
func RenderThroughputChart(card DeviceCard, tz string) template.HTML {
	// L8 of the 2026-07-01 audit: need >= 2 points. The X math divides by
	// (nPoints-1), so a single-point series produced NaN path coordinates
	// ("M NaN,NaN") — an invalid SVG path that browsers drop, breaking the
	// report preview / print-to-PDF for that device until a second sample.
	if len(card.SparklineRaw) < 2 {
		return template.HTML(`
			<div style="border: 1px dashed #cbd5e1; border-radius: 6px; padding: 20px; text-align: center; color: #64748b; font-size: 11px;">
				No throughput statistics recorded.
			</div>
		`)
	}

	maxVal := 0.0
	for _, v := range card.SparklineRaw {
		if v > maxVal {
			maxVal = v
		}
	}

	width := 640
	height := 200
	plotXStart := 72
	plotXEnd := 624
	plotYStart := 18
	plotYEnd := 150

	plotWidth := plotXEnd - plotXStart
	plotHeight := plotYEnd - plotYStart
	nPoints := len(card.SparklineRaw)

	idSafe := safeID(card.Name)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg width="100%%" height="%d" viewBox="0 0 %d %d" style="max-width: %dpx; display: block;" xmlns="http://www.w3.org/2000/svg">`, height, width, height, width))

	// CSS and Gradients
	sb.WriteString(fmt.Sprintf(`
		<defs>
			<linearGradient id="tf-grad-%s" x1="0%%" y1="0%%" x2="0%%" y2="100%%">
				<stop offset="0%%" stop-color="#1e3a5f" stop-opacity="0.35"/>
				<stop offset="100%%" stop-color="#1e3a5f" stop-opacity="0.0"/>
			</linearGradient>
			<filter id="shadow-%s" x="-10%%" y="-10%%" width="120%%" height="120%%">
				<feDropShadow dx="0" dy="3.5" stdDeviation="2.5" flood-color="#1e3a5f" flood-opacity="0.2"/>
			</filter>
		</defs>
		<style>
			.grid-line { stroke: #e9edf2; stroke-width: 1; stroke-dasharray: 2,2; }
			.axis-line { stroke: #cbd5e1; stroke-width: 1; }
			.axis-label { fill: #64748b; font-size: 12px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
			.trend-line { stroke: #1e3a5f; stroke-width: 2.25; fill: none; stroke-linejoin: round; stroke-linecap: round; }
			.trend-area { fill: url(#tf-grad-%s); }
			.hover-slice { fill: transparent; cursor: crosshair; }
			.hover-slice:hover { fill: rgba(15, 23, 42, 0.05); }
		</style>
	`, idSafe, idSafe, idSafe))

	// 1. Gridlines
	yMid := plotYStart + plotHeight/2
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYStart, plotXEnd, plotYStart))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, yMid, plotXEnd, yMid))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))

	// 2. Y-Axis labels
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">%s</text>`, plotXStart-8, plotYStart, formatThroughput(maxVal)))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">%s</text>`, plotXStart-8, yMid, formatThroughput(maxVal/2.0)))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">0 bps</text>`, plotXStart-8, plotYEnd))

	// 3. Line and Area paths
	var pathPoints []string
	for i, val := range card.SparklineRaw {
		x := float64(plotXStart) + float64(i)*float64(plotWidth)/float64(nPoints-1)
		y := float64(plotYEnd)
		if maxVal > 0 {
			y = float64(plotYEnd) - (val / maxVal * float64(plotHeight))
		}
		pathPoints = append(pathPoints, fmt.Sprintf("%.2f,%.2f", x, y))
	}

	lineD := "M " + strings.Join(pathPoints, " L ")
	areaD := fmt.Sprintf("%s L %.2f,%d L %d,%d Z", lineD, float64(plotXStart)+float64(nPoints-1)*float64(plotWidth)/float64(nPoints-1), plotYEnd, plotXStart, plotYEnd)

	sb.WriteString(fmt.Sprintf(`<path d="%s" class="trend-area" />`, areaD))
	sb.WriteString(fmt.Sprintf(`<path d="%s" class="trend-line" filter="url(#shadow-%s)" />`, lineD, idSafe))

	// 4. Timezone-specific X-Axis labels
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}

	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))
	if len(card.SparklineTimes) >= 2 {
		startTime := card.SparklineTimes[0].In(loc)
		endTime := card.SparklineTimes[len(card.SparklineTimes)-1].In(loc)
		midTime := card.SparklineTimes[len(card.SparklineTimes)/2].In(loc)

		layout := "15:04"
		// If the span crosses days, show date too
		if startTime.YearDay() != endTime.YearDay() {
			layout = "Jan 2 15:04"
		}

		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="start">%s</text>`, plotXStart, plotYEnd+18, startTime.Format(layout)))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="middle">%s</text>`, plotXStart+plotWidth/2, plotYEnd+18, midTime.Format(layout)))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end">%s</text>`, plotXEnd, plotYEnd+18, endTime.Format(layout)))
	}

	// 5. Interactive Tooltip Overlay slices
	sliceWidth := float64(plotWidth) / float64(nPoints)
	for i, val := range card.SparklineRaw {
		sx := float64(plotXStart) + float64(i)*sliceWidth
		var timestamp string
		if i < len(card.SparklineTimes) {
			timestamp = card.SparklineTimes[i].In(loc).Format("Jan 2 15:04:05 MST")
		} else {
			timestamp = "N/A"
		}
		tooltip := fmt.Sprintf("Time: %s\nThroughput: %s", timestamp, formatThroughput(val))
		sb.WriteString(fmt.Sprintf(`
			<rect x="%.2f" y="%d" width="%.2f" height="%d" class="hover-slice">
				<title>%s</title>
			</rect>
		`, sx, plotYStart, sliceWidth, plotHeight, tooltip))
	}

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// RenderCPUMemSVGChart renders a beautiful dual line chart for CPU and Memory history.
func RenderCPUMemSVGChart(card DeviceCard, tz string) template.HTML {
	// L8: require >= 2 points in at least one series (the X math divides by
	// nPoints-1; a 1-point max produces NaN path coordinates).
	if len(card.CPUHistory) < 2 && len(card.MemHistory) < 2 {
		return template.HTML(`
			<div style="border: 1px dashed #cbd5e1; border-radius: 6px; padding: 20px; text-align: center; color: #64748b; font-size: 11px;">
				No CPU/Memory statistics recorded.
			</div>
		`)
	}

	width := 640
	height := 220
	plotXStart := 72
	plotXEnd := 624
	plotYStart := 18
	plotYEnd := 150

	plotWidth := plotXEnd - plotXStart
	plotHeight := plotYEnd - plotYStart
	nPoints := len(card.CPUHistory)
	if len(card.MemHistory) > nPoints {
		nPoints = len(card.MemHistory)
	}

	idSafe := safeID(card.Name)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg width="100%%" height="%d" viewBox="0 0 %d %d" style="max-width: %dpx; display: block;" xmlns="http://www.w3.org/2000/svg">`, height, width, height, width))

	// Gradients and CSS
	sb.WriteString(fmt.Sprintf(`
		<defs>
			<linearGradient id="cpu-grad-%s" x1="0%%" y1="0%%" x2="0%%" y2="100%%">
				<stop offset="0%%" stop-color="#dc2626" stop-opacity="0.15"/>
				<stop offset="100%%" stop-color="#dc2626" stop-opacity="0.0"/>
			</linearGradient>
			<linearGradient id="mem-grad-%s" x1="0%%" y1="0%%" x2="0%%" y2="100%%">
				<stop offset="0%%" stop-color="#2563eb" stop-opacity="0.15"/>
				<stop offset="100%%" stop-color="#2563eb" stop-opacity="0.0"/>
			</linearGradient>
			<filter id="cpu-shadow-%s" x="-10%%" y="-10%%" width="120%%" height="120%%">
				<feDropShadow dx="0" dy="3" stdDeviation="2.5" flood-color="#dc2626" flood-opacity="0.12"/>
			</filter>
			<filter id="mem-shadow-%s" x="-10%%" y="-10%%" width="120%%" height="120%%">
				<feDropShadow dx="0" dy="3" stdDeviation="2.5" flood-color="#2563eb" flood-opacity="0.12"/>
			</filter>
		</defs>
		<style>
			.grid-line { stroke: #e9edf2; stroke-width: 1; stroke-dasharray: 2,2; }
			.axis-line { stroke: #cbd5e1; stroke-width: 1; }
			.axis-label { fill: #64748b; font-size: 12px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
			.cpu-line { stroke: #dc2626; stroke-width: 2.25; fill: none; stroke-linejoin: round; }
			.cpu-area { fill: url(#cpu-grad-%s); }
			.mem-line { stroke: #2563eb; stroke-width: 2.25; fill: none; stroke-linejoin: round; }
			.mem-area { fill: url(#mem-grad-%s); }
			.hover-slice { fill: transparent; cursor: crosshair; }
			.hover-slice:hover { fill: rgba(15, 23, 42, 0.05); }
		</style>
	`, idSafe, idSafe, idSafe, idSafe, idSafe, idSafe))

	// 1. Gridlines (at 0%, 50%, 100%)
	yMid := plotYStart + plotHeight/2
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYStart, plotXEnd, plotYStart))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, yMid, plotXEnd, yMid))
	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="grid-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))

	// 2. Y-Axis labels
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">100%%</text>`, plotXStart-8, plotYStart))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">50%%</text>`, plotXStart-8, yMid))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end" alignment-baseline="middle">0%%</text>`, plotXStart-8, plotYEnd))

	// 3. Render CPU path
	if len(card.CPUHistory) > 0 {
		var cpuPoints []string
		for i, val := range card.CPUHistory {
			x := float64(plotXStart) + float64(i)*float64(plotWidth)/float64(len(card.CPUHistory)-1)
			y := float64(plotYEnd) - (val / 100.0 * float64(plotHeight))
			if y < float64(plotYStart) {
				y = float64(plotYStart)
			}
			cpuPoints = append(cpuPoints, fmt.Sprintf("%.2f,%.2f", x, y))
		}
		cpuLineD := "M " + strings.Join(cpuPoints, " L ")
		cpuAreaD := fmt.Sprintf("%s L %.2f,%d L %d,%d Z", cpuLineD, float64(plotXStart)+float64(len(card.CPUHistory)-1)*float64(plotWidth)/float64(len(card.CPUHistory)-1), plotYEnd, plotXStart, plotYEnd)
		sb.WriteString(fmt.Sprintf(`<path d="%s" class="cpu-area" />`, cpuAreaD))
		sb.WriteString(fmt.Sprintf(`<path d="%s" class="cpu-line" filter="url(#cpu-shadow-%s)" />`, cpuLineD, idSafe))
	}

	// 4. Render Memory path
	if len(card.MemHistory) > 0 {
		var memPoints []string
		for i, val := range card.MemHistory {
			x := float64(plotXStart) + float64(i)*float64(plotWidth)/float64(len(card.MemHistory)-1)
			y := float64(plotYEnd) - (val / 100.0 * float64(plotHeight))
			if y < float64(plotYStart) {
				y = float64(plotYStart)
			}
			memPoints = append(memPoints, fmt.Sprintf("%.2f,%.2f", x, y))
		}
		memLineD := "M " + strings.Join(memPoints, " L ")
		memAreaD := fmt.Sprintf("%s L %.2f,%d L %d,%d Z", memLineD, float64(plotXStart)+float64(len(card.MemHistory)-1)*float64(plotWidth)/float64(len(card.MemHistory)-1), plotYEnd, plotXStart, plotYEnd)
		sb.WriteString(fmt.Sprintf(`<path d="%s" class="mem-area" />`, memAreaD))
		sb.WriteString(fmt.Sprintf(`<path d="%s" class="mem-line" filter="url(#mem-shadow-%s)" />`, memLineD, idSafe))
	}

	// 5. Timezone-specific X-Axis labels
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}

	sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis-line" />`, plotXStart, plotYEnd, plotXEnd, plotYEnd))
	if len(card.SysTimes) >= 2 {
		startTime := card.SysTimes[0].In(loc)
		endTime := card.SysTimes[len(card.SysTimes)-1].In(loc)
		midTime := card.SysTimes[len(card.SysTimes)/2].In(loc)

		layout := "15:04"
		if startTime.YearDay() != endTime.YearDay() {
			layout = "Jan 2 15:04"
		}

		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="start">%s</text>`, plotXStart, plotYEnd+18, startTime.Format(layout)))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="middle">%s</text>`, plotXStart+plotWidth/2, plotYEnd+18, midTime.Format(layout)))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="axis-label" text-anchor="end">%s</text>`, plotXEnd, plotYEnd+18, endTime.Format(layout)))
	}

	// 6. Interactive Tooltip Overlay slices
	sliceWidth := float64(plotWidth) / float64(nPoints)
	for i := 0; i < nPoints; i++ {
		sx := float64(plotXStart) + float64(i)*sliceWidth

		var timestamp string
		if i < len(card.SysTimes) {
			timestamp = card.SysTimes[i].In(loc).Format("Jan 2 15:04:05 MST")
		} else {
			timestamp = "N/A"
		}

		cpuVal := 0.0
		if i < len(card.CPUHistory) {
			cpuVal = card.CPUHistory[i]
		}
		memVal := 0.0
		if i < len(card.MemHistory) {
			memVal = card.MemHistory[i]
		}

		tooltip := fmt.Sprintf("Time: %s\nCPU Usage: %.1f%%\nMemory Usage: %.1f%%", timestamp, cpuVal, memVal)
		sb.WriteString(fmt.Sprintf(`
			<rect x="%.2f" y="%d" width="%.2f" height="%d" class="hover-slice">
				<title>%s</title>
			</rect>
		`, sx, plotYStart, sliceWidth, plotHeight, tooltip))
	}

	// 7. Legend
	legendY := plotYEnd + 34
	sb.WriteString(fmt.Sprintf(`
		<g transform="translate(%d, %d)">
			<rect x="0" y="-6" width="12" height="4" fill="#dc2626" rx="1" />
			<text x="16" y="0" class="axis-label" alignment-baseline="middle">CPU Usage</text>
			
			<rect x="85" y="-6" width="12" height="4" fill="#2563eb" rx="1" />
			<text x="101" y="0" class="axis-label" alignment-baseline="middle">Memory Usage</text>
		</g>
	`, plotXStart, legendY))

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}
