package main

import (
	"log"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/models"
	"firewall-mon/internal/serverhealth"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// Server self-monitoring: the volumes of the host running this software, as
// distinct from the firewalls it polls.
//
// DISK_HIGH is keyed on a device id and fed from device polling, so the server's
// own disk was never evaluated by anything. On 2026-07-26 the database volume
// filled, Postgres crash-looped on "No space left on device", and nothing
// alerted — the dashboard was reporting "/" (the container overlay, 83%) while
// PGDATA sat on a bind mount at 100%.
const (
	serverHealthInterval = 5 * time.Minute

	// Defaults chosen against the real failure mode rather than a round number:
	// Postgres needs room for a WAL segment (max_wal_size defaults to 1GB), so a
	// 5GB floor leaves real warning time, while the percentage catches slow
	// growth on a volume where 5GB is a rounding error.
	serverDiskThresholdDefault = 85
	serverDiskFreeFloorGBDef   = 5
)

// dataDirLocator caches the database's data directory across ticks. See its type
// docs: the cache is what keeps the DB volume watched while Postgres is down,
// which is exactly when it matters most.
var dataDirLocator serverhealth.DataDirLocator

// collectServerVolumes probes the volumes to evaluate.
//
// The root filesystem is probed UNCONDITIONALLY and independently of the
// database, so a fault locating PGDATA can never leave the server entirely
// unwatched. dataOK reports whether the database volume was measured at all —
// the caller must not treat "not measured" as "healthy".
func (p *Poller) collectServerVolumes() (vols []alerts.ServerVolume, dataOK bool) {
	if v, ok := serverhealth.Usage(serverhealth.RootPath); ok {
		vols = append(vols, alerts.ServerVolume{Label: "root", Volume: v})
	}

	if p.db == nil {
		return vols, false
	}
	dir, have, err := dataDirLocator.DataDirectory(p.db.Gorm())
	// Rate-limited rather than once-per-process: a monitoring probe that goes
	// quiet after one line is the shape of the incident itself. The two cases
	// are reported differently on purpose — with a cached path the volume IS
	// still being watched, which is precisely what the cache is for, and saying
	// otherwise during a crash-loop would send the operator the wrong way.
	if err != nil && dataDirLocator.ShouldWarn(time.Now()) {
		if have {
			log.Printf("server health: cannot read the database data_directory (%v); "+
				"continuing to monitor the last known path %s", err, dir)
		} else {
			log.Printf("server health: cannot read the database data_directory (%v) — the "+
				"DATABASE VOLUME IS NOT BEING MONITORED. Grant pg_read_all_settings to the "+
				"application role. The root filesystem is still watched.", err)
		}
	}
	if !have {
		return vols, false
	}
	v, ok := serverhealth.Usage(dir)
	if !ok {
		// The path exists in the database's world but not this process's — an
		// external database server. Legitimately quiet, but still not "healthy".
		return vols, false
	}
	return append(vols, alerts.ServerVolume{Label: "data", Volume: v}), true
}

// checkServerHealth evaluates the server's own volumes and records a metrics
// sample. One probe, two uses — so there is no second collection path to drift.
func (p *Poller) checkServerHealth() {
	if p.db == nil || p.alertManager == nil {
		return
	}
	vols, dataOK := p.collectServerVolumes()
	if len(vols) == 0 {
		log.Printf("server health: no volume could be probed; the server is UNMONITORED")
		return
	}

	// 0 disables a trigger, checked before any use, so an operator can run on
	// the floor alone or the percentage alone.
	pct := float64(p.db.GetIntSetting("server_disk_threshold", serverDiskThresholdDefault))
	floorGB := p.db.GetIntSetting("server_disk_free_floor_gb", serverDiskFreeFloorGBDef)
	var floorBytes uint64
	if floorGB > 0 {
		floorBytes = uint64(floorGB) << 30
	}
	if pct < 0 {
		pct = 0
	}

	p.alertManager.CheckServerVolumes(vols, pct, floorBytes)
	p.recordServerMetrics(vols, dataOK)
}

// recordServerMetrics stores one sample for the server charts.
//
// dataOK is honoured strictly: when the database volume could not be probed the
// data-disk fields are left NIL, never zeroed. A zero would render as a 0%-used
// flatline — "the probe failed" drawn as "the disk is empty" — which is the same
// failure-reads-as-healthy shape that let the volume fill unnoticed.
func (p *Poller) recordServerMetrics(vols []alerts.ServerVolume, dataOK bool) {
	m := &models.ServerMetric{Timestamp: time.Now()}

	if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
		m.CPUPercent = pcts[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil && vm != nil {
		m.MemPercent = vm.UsedPercent
		m.MemUsedBytes = vm.Used
		m.MemTotalBytes = vm.Total
	}
	if la, err := load.Avg(); err == nil && la != nil {
		m.Load1 = la.Load1
	}

	for _, v := range vols {
		switch v.Label {
		case "root":
			m.RootDiskPercent = v.Volume.Percent
			m.RootDiskFreeBytes = v.Volume.FreeBytes
		case "data":
			if dataOK {
				pct, free := v.Volume.Percent, v.Volume.FreeBytes
				m.DataDiskPercent = &pct
				m.DataDiskFreeBytes = &free
				m.DataDiskPath = v.Volume.Path
			}
		}
	}

	if err := p.db.SaveServerMetric(m); err != nil {
		log.Printf("server health: failed to record metrics sample: %v", err)
	}
}
