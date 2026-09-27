package handlers

import (
	"errors"
	"net/http"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// flowReclassView is the progress of the flow-history reclassification, for
// the Flows page status line and the Settings card.
type flowReclassView struct {
	Target  uint16 `json:"target"`
	DoneRev uint16 `json:"done_rev"`
	// Phase: reclassifying, paused, waiting, done — or "pending" when a run
	// is due but the poller has not started it yet.
	Phase        string     `json:"phase"`
	Percent      float64    `json:"percent"`
	Rows         int64      `json:"rows"`
	Estimate     int64      `json:"estimate"`
	Incremental  bool       `json:"incremental"`
	Started      *time.Time `json:"started,omitempty"`
	Finished     *time.Time `json:"finished,omitempty"`
	PausedReason string     `json:"paused_reason,omitempty"`
	ETAHours     float64    `json:"eta_hours,omitempty"`
	VacuumHint   bool       `json:"vacuum_hint,omitempty"`
}

func flowReclassViewOf(db database.Store) flowReclassView {
	st := db.GetFlowReclassStatus()
	v := flowReclassView{
		Target: db.FlowReclassTargetRev(), DoneRev: db.FlowReclassDoneRev(),
		Phase: st.Phase, Rows: st.Rows, Estimate: st.Estimate, Incremental: st.Incremental,
		Started: st.Started, Finished: st.Finished, PausedReason: st.PausedReason, VacuumHint: st.VacuumHint,
	}
	switch {
	case v.DoneRev >= v.Target && (v.Phase == "" || v.Phase == "done"):
		v.Phase, v.Percent = "done", 100
	case v.DoneRev < v.Target && (v.Phase == "" || v.Phase == "done"):
		// Due, but the poller has not written progress for this run yet.
		v.Phase, v.Rows, v.Started, v.Finished, v.VacuumHint = "pending", 0, nil, nil, false
	}
	if v.Phase != "done" && v.Estimate > 0 {
		v.Percent = min(99, float64(v.Rows)*100/float64(v.Estimate))
		if v.Started != nil && v.Rows > 0 {
			rate := float64(v.Rows) / time.Since(*v.Started).Hours()
			if left := v.Estimate - v.Rows; left > 0 && rate > 0 {
				v.ETAHours = float64(left) / rate
			}
		}
	}
	return v
}

// GetFlowReclassStatus reports the reclassification's progress. Viewer-level:
// it carries no network detail.
func (h *Handler) GetFlowReclassStatus(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	c.JSON(http.StatusOK, response.Success(flowReclassViewOf(db)))
}

// ReapplyFlowClassification raises the classification revision so the poller
// re-stamps all stored flow history with the current internal networks. The
// ingest set is rebuilt BEFORE returning, so no new row is stamped with the
// old revision under the new target. Admin-only (adminOnlyRoutes).
func (h *Handler) ReapplyFlowClassification(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	if _, err := db.BumpFlowReclassTargetRev(); err != nil {
		if errors.Is(err, database.ErrReclassRevLimit) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to start the reclassification", err)
		return
	}
	h.RefreshInternalNetworks()
	c.JSON(http.StatusOK, response.Success(flowReclassViewOf(db)))
}
