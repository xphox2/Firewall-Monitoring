package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The map's device panel and the connection panel share ONE chart loader, and
// that loader asks for a tunnel GROUP. The map payload therefore has to carry
// the group — it is fetched by a path that does not resolve groups on its own.
//
// This is a regression pin, not a feature test. Leaving the field off while the
// shared loader was made group-keyed did not merely fail to improve the map
// panel: it inverted the fix there. The counter-bearing rows (FortiGate dialup,
// every OPNsense child) would ask for a group matching no member and go blank,
// while the row that charts would be the counterless one that used to be blank.

type vpnMapPayload struct {
	Data map[string]struct {
		Tunnels []struct {
			TunnelName  string `json:"tunnel_name"`
			TunnelGroup string `json:"tunnel_group"`
			BytesIn     uint64 `json:"bytes_in"`
		} `json:"tunnels"`
	} `json:"data"`
}

func fetchVPNMap(t *testing.T, h *Handler) vpnMapPayload {
	t.Helper()
	router := gin.New()
	router.GET("/connections/vpn-map", h.GetVPNMapData)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/connections/vpn-map", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var out vpnMapPayload
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// Every row the map panel offers a chart for must name a group the chart
// endpoint can actually resolve. Asserting the field is merely non-empty would
// pass on a row whose group equals its own name, which is the case that was
// never broken — so this drives the value through the real endpoint.
func TestGetVPNMapData_CounterBearingRowCarriesAResolvableGroup(t *testing.T) {
	h, db := setupTestHandler(t)
	seedGroupedTunnel(t, db)

	payload := fetchVPNMap(t, h)

	var checked int
	for _, dev := range payload.Data {
		for _, tun := range dev.Tunnels {
			if tun.BytesIn == 0 {
				continue // the counterless sibling charts via its group, not itself
			}
			checked++
			if tun.TunnelGroup == "" {
				t.Fatalf("row %q carries counters but no tunnel_group; the panel would "+
					"fall back to its own name and chart blank", tun.TunnelName)
			}
			if tun.TunnelGroup == tun.TunnelName {
				t.Errorf("row %q grouped to itself — the grouping pass did not run, and this "+
					"row's counters are exactly what the group exists to unite", tun.TunnelName)
			}
			_, buckets := doGroupChart(t, h, 1, "?group="+tun.TunnelGroup+"&range=24h")
			if len(buckets) == 0 {
				t.Errorf("group %q (from row %q) resolves to no chartable member", tun.TunnelGroup, tun.TunnelName)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no counter-bearing row in the map payload; the seed or the handler shape changed " +
			"and this test is no longer exercising the case it was written for")
	}
}
