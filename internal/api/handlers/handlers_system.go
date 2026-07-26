package handlers

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// systemHealthDBTimeout caps the DB ping in the Server Platform card so a hung
// database can't make the dashboard's health poll hang.
const systemHealthDBTimeout = 1 * time.Second

// buildSystemHealth collects the server-platform health snapshot (process +
// Go runtime + database pool/size/reachability + host CPU/mem/disk/load). Every
// probe is cheap and non-blocking. Shared by GET /api/system and the cached
// dashboard health composite. ctx bounds the DB ping.
func (h *Handler) buildSystemHealth(ctx context.Context, db database.Store) gin.H {
	out := gin.H{}

	// --- App / process ---
	out["version"] = h.version
	if !h.startTime.IsZero() {
		out["uptime_seconds"] = int64(time.Since(h.startTime).Seconds())
	}

	// --- Go runtime ---
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	const mib = 1024 * 1024
	out["runtime"] = gin.H{
		"goroutines":    runtime.NumGoroutine(),
		"heap_alloc_mb": float64(ms.HeapAlloc) / mib,
		"heap_sys_mb":   float64(ms.HeapSys) / mib,
		"num_gc":        ms.NumGC,
	}

	// --- Database: pool stats, reachability, size ---
	dbInfo := gin.H{"reachable": false}
	if db != nil {
		g := db.Gorm()
		if sqlDB, err := g.DB(); err == nil && sqlDB != nil {
			st := sqlDB.Stats()
			dbInfo["pool"] = gin.H{
				"open":       st.OpenConnections,
				"in_use":     st.InUse,
				"idle":       st.Idle,
				"max_open":   st.MaxOpenConnections,
				"wait_count": st.WaitCount,
			}
			pingCtx, cancel := context.WithTimeout(ctx, systemHealthDBTimeout)
			dbInfo["reachable"] = sqlDB.PingContext(pingCtx) == nil
			cancel()
		}
		// pg_database_size is a cheap catalog lookup; Postgres-only.
		if g.Dialector != nil && g.Dialector.Name() == "postgres" {
			var size int64
			if err := g.Raw("SELECT pg_database_size(current_database())").Scan(&size).Error; err == nil {
				dbInfo["size_bytes"] = size
			}
			// Ask Postgres where its data actually lives, rather than assuming.
			// See the data-volume block below for why this matters.
			var dataDir string
			if err := g.Raw("SHOW data_directory").Scan(&dataDir).Error; err == nil {
				dbInfo["data_directory"] = dataDir
			}
		}
	}
	out["db"] = dbInfo

	// --- Host (gopsutil): CPU / memory / disk / load ---
	host := gin.H{}
	// cpu.Percent(0, false) is non-blocking: it reports usage since the previous
	// call (since boot on the first call) rather than sleeping for an interval.
	if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
		host["cpu_percent"] = pcts[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil && vm != nil {
		host["mem_percent"] = vm.UsedPercent
		host["mem_total_bytes"] = vm.Total
		host["mem_used_bytes"] = vm.Used
	}
	if du, err := disk.Usage("/"); err == nil && du != nil {
		host["disk_percent"] = du.UsedPercent
		host["disk_total_bytes"] = du.Total
		host["disk_used_bytes"] = du.Used
	}

	// The DATABASE volume, which is the one that can take the system down, and is
	// usually NOT the root filesystem.
	//
	// Reporting only "/" is how a full disk went unnoticed until Postgres
	// crash-looped on "No space left on device": in the single-container
	// deployment "/" is the image's overlay filesystem while PGDATA is a bind
	// mount, and at the moment of the outage they read 83% and 98% respectively.
	// The dashboard showed the 83%.
	//
	// Located by asking Postgres for its own data_directory rather than assuming a
	// path, so this stays correct across deployment layouts. When the directory is
	// not visible to this process (an external database server) the probe simply
	// yields nothing rather than reporting a misleading filesystem.
	if dir, _ := dbInfo["data_directory"].(string); dir != "" {
		if du, err := disk.Usage(dir); err == nil && du != nil {
			host["data_disk_path"] = dir
			host["data_disk_percent"] = du.UsedPercent
			host["data_disk_total_bytes"] = du.Total
			host["data_disk_used_bytes"] = du.Used
			host["data_disk_free_bytes"] = du.Free
		}
	}
	if la, err := load.Avg(); err == nil && la != nil {
		host["load1"] = la.Load1
		host["load5"] = la.Load5
		host["load15"] = la.Load15
	}
	out["host"] = host

	return out
}

// GetSystemHealth backs the standalone /api/system endpoint (also reused inside
// the cached dashboard health composite). See buildSystemHealth.
func (h *Handler) GetSystemHealth(c *gin.Context) {
	c.JSON(http.StatusOK, response.Success(h.buildSystemHealth(c.Request.Context(), h.reqDB(c))))
}
