package logfields

import (
	"testing"

	"firewall-mon/internal/models"
)

// benchFortiTraffic is a representative FortiOS forward-traffic line (the
// dominant syslog shape by volume) with the whole body in Message and no
// format hint — the shape of a stored row and of a pre-1.3.48 collector, i.e.
// the path that also pays the header re-join.
const benchFortiTraffic = `date=2026-10-04 time=12:00:01 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579201000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=51514 srcintf="port2" srcintfrole="lan" dstip=203.0.113.20 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Reserved" sessionid=2101301 proto=6 action="close" policyid=12 policytype="policy" poluuid="4b5c6d7e-0000-0000-0000-00000000000c" policyname="LAN-to-WAN" service="HTTPS" trandisp="snat" transip=203.0.113.2 transport=51514 appid=40568 app="HTTPS.BROWSER" appcat="Web.Client" apprisk="medium" applist="default" duration=61 sentbyte=5231 rcvdbyte=12033 sentpkt=22 rcvdpkt=19 srchwvendor="Example" devtype="Computer" osname="Linux" mastersrcmac="00:00:5e:00:53:0a" srcmac="00:00:5e:00:53:0a" srcserver=0 user="alice" group="staff"`

// BenchmarkFields_FortiGate measures the per-message cost of the rule engine's
// field extraction on the dominant FortiGate traffic shape. 0.11.293 added the
// canonical event.* view on top of the native keys: 3646 → 3990 ns/op,
// 9074 → 10832 B/op, 17 → 24 allocs/op on the development machine (Apple M5).
// Re-measure when touching internal/normalize's hot path; the manual
// Benchmark workflow is informational, this is the gate (≤ 1.5x allocs/op).
func BenchmarkFields_FortiGate(b *testing.B) {
	msg := &models.SyslogMessage{Severity: 5, Facility: 20, Hostname: "fw-example-01", Message: benchFortiTraffic}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Fields("fortigate", msg)
	}
}
