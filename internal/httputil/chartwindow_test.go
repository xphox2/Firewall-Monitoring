package httputil

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func ctxWithQuery(rawQuery string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/x?"+rawQuery, nil)
	return c
}

// TestParseChartWindow pins the precedence: an explicit from/to pair (epoch ms,
// from the drag-to-zoom selection) wins; otherwise the range preset maps to a
// [now-dur, now] window; junk falls back to the default range.
func TestParseChartWindow(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	t.Run("explicit from/to wins", func(t *testing.T) {
		t.Parallel()
		fromMs := int64(1_700_000_000_000)
		toMs := int64(1_700_003_600_000) // +1h
		c := ctxWithQuery("from=1700000000000&to=1700003600000&range=7d")
		from, to := ParseChartWindow(c, "24h")
		if from.UnixMilli() != fromMs || to.UnixMilli() != toMs {
			t.Errorf("from/to = %d/%d, want %d/%d", from.UnixMilli(), to.UnixMilli(), fromMs, toMs)
		}
	})

	t.Run("range preset maps to [now-dur, now]", func(t *testing.T) {
		t.Parallel()
		c := ctxWithQuery("range=7d")
		from, to := ParseChartWindow(c, "24h")
		dur := to.Sub(from)
		if dur < 167*time.Hour || dur > 169*time.Hour {
			t.Errorf("7d window = %v, want ~168h", dur)
		}
		if time.Since(to) > time.Minute {
			t.Errorf("to should be ~now, got %v ago", time.Since(to))
		}
	})

	t.Run("absent range uses default", func(t *testing.T) {
		t.Parallel()
		c := ctxWithQuery("")
		from, to := ParseChartWindow(c, "24h")
		dur := to.Sub(from)
		if dur < 23*time.Hour || dur > 25*time.Hour {
			t.Errorf("default window = %v, want ~24h", dur)
		}
	})

	t.Run("junk range falls back to default", func(t *testing.T) {
		t.Parallel()
		c := ctxWithQuery("range=bogus")
		from, to := ParseChartWindow(c, "24h")
		dur := to.Sub(from)
		if dur < 23*time.Hour || dur > 25*time.Hour {
			t.Errorf("junk-range window = %v, want default ~24h", dur)
		}
	})

	t.Run("inverted from/to ignored, falls to range", func(t *testing.T) {
		t.Parallel()
		c := ctxWithQuery("from=2000&to=1000&range=1h")
		from, to := ParseChartWindow(c, "24h")
		dur := to.Sub(from)
		if dur < 59*time.Minute || dur > 61*time.Minute {
			t.Errorf("inverted from/to should fall back to range=1h, got %v", dur)
		}
	})
}
