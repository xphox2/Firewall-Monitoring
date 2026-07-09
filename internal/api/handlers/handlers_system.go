package handlers

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"firewall-mon/internal/api/response"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// systemHealthDBTimeout caps the DB ping in the Server Platform card so a hung
// database can't make the dashboard's health poll hang.
const systemHealthDBTimeout = 1 * time.Second

// GetSystemHealth backs the dashboard's "Server Platform" card. It reports the
// server process (uptime, version, Go runtime), the database (pool utilization,
// reachability, size), and the host (CPU / memory / disk / load average). Every
// probe here is cheap and non-blocking so the 30s poll never stalls a request.
func (h *Handler) GetSystemHealth(c *gin.Context) {
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
	if db := h.reqDB(c); db != nil {
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
			ctx, cancel := context.WithTimeout(c.Request.Context(), systemHealthDBTimeout)
			dbInfo["reachable"] = sqlDB.PingContext(ctx) == nil
			cancel()
		}
		// pg_database_size is a cheap catalog lookup; Postgres-only.
		if g.Dialector != nil && g.Dialector.Name() == "postgres" {
			var size int64
			if err := g.Raw("SELECT pg_database_size(current_database())").Scan(&size).Error; err == nil {
				dbInfo["size_bytes"] = size
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
	if la, err := load.Avg(); err == nil && la != nil {
		host["load1"] = la.Load1
		host["load5"] = la.Load5
		host["load15"] = la.Load15
	}
	out["host"] = host

	c.JSON(http.StatusOK, response.Success(out))
}
