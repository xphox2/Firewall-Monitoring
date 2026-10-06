// Package export turns rows of the three archived tables into deterministic
// gzip NDJSON objects (archive plan PR 3, §2.4-2.5). It does no I/O of its own
// beyond the io.Writer each object is written to: the database layer feeds it
// rows in id order and the archive worker (a later release) stages and uploads
// what it writes.
//
// Determinism: one row is one line, the fields are exactly the model's
// persisted columns in struct order (keys = column names), timestamps are
// UTC RFC 3339 with nanoseconds, nothing is HTML-escaped, and rows arrive in
// strictly increasing id order (enforced). The same id range therefore always
// yields the same uncompressed bytes, so its sha256_content is stable; the
// compressed bytes are also identical for one Go version (stdlib gzip at the
// default level, fixed header), but only sha256_content is relied on across
// versions.
package export

import (
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"firewall-mon/internal/models"
)

// Schema versions, per stream. A version is part of every object key
// (<stream>/v<N>/...) and of the gzip header; a change to a stream's field
// list is a new version, never an edit of an existing one.
const (
	// SyslogSchemaV1 is a syslog row without `format`: the rows stored before
	// migration v74 (0.11.298) never had one.
	SyslogSchemaV1 = 1
	// SyslogSchemaV2 adds `format` (the stored collector format code, or null).
	SyslogSchemaV2 = 2
	// FlowSchemaV1 is a flow_samples row (sflow and netflow streams).
	FlowSchemaV1 = 1
	// CounterSchemaV1 is a flow_if_counters row (sflow-counters stream).
	CounterSchemaV1 = 1
)

// rowEncoder appends one JSON object field by field. The first error (an
// invalid UTF-8 string) sticks and is returned by line.
type rowEncoder struct {
	b   []byte
	err error
}

func (e *rowEncoder) begin() { e.b = append(e.b[:0], '{') }

func (e *rowEncoder) key(k string) {
	if len(e.b) > 1 {
		e.b = append(e.b, ',')
	}
	e.b = append(e.b, '"')
	e.b = append(e.b, k...)
	e.b = append(e.b, '"', ':')
}

func (e *rowEncoder) uint(k string, v uint64) {
	e.key(k)
	e.b = strconv.AppendUint(e.b, v, 10)
}

func (e *rowEncoder) int(k string, v int64) {
	e.key(k)
	e.b = strconv.AppendInt(e.b, v, 10)
}

func (e *rowEncoder) bool(k string, v bool) {
	e.key(k)
	e.b = strconv.AppendBool(e.b, v)
}

func (e *rowEncoder) time(k string, v time.Time) {
	e.key(k)
	e.b = append(e.b, '"')
	e.b = v.UTC().AppendFormat(e.b, time.RFC3339Nano)
	e.b = append(e.b, '"')
}

func (e *rowEncoder) timePtr(k string, v *time.Time) {
	if v == nil {
		e.key(k)
		e.b = append(e.b, "null"...)
		return
	}
	e.time(k, *v)
}

func (e *rowEncoder) int16Ptr(k string, v *int16) {
	if v == nil {
		e.key(k)
		e.b = append(e.b, "null"...)
		return
	}
	e.int(k, int64(*v))
}

func (e *rowEncoder) str(k, v string) {
	e.key(k)
	if e.err == nil && !utf8.ValidString(v) {
		// PostgreSQL text cannot hold invalid UTF-8, so this is a SQLite-only
		// (test) state; a lossy replacement would make the archive lie.
		e.err = fmt.Errorf("column %s holds invalid UTF-8", k)
	}
	e.b = appendJSONString(e.b, v)
}

func (e *rowEncoder) line() ([]byte, error) {
	e.b = append(e.b, '}', '\n')
	return e.b, e.err
}

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string exactly as encoding/json does
// with SetEscapeHTML(false): `"` and `\` escaped, \b \f \n \r \t short forms,
// other control characters as \u00XX, U+2028 / U+2029 as \u2028 / \u2029, and
// everything else (including <, > and &) verbatim. s must be valid UTF-8.
func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\b':
				b = append(b, '\\', 'b')
			case '\f':
				b = append(b, '\\', 'f')
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '\u2028' || r == '\u2029' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// encodeSyslog writes one syslog_messages row: the persisted columns of
// models.SyslogMessage in struct order; `format` only from schema 2.
func (e *rowEncoder) encodeSyslog(m *models.SyslogMessage, schema int) {
	e.begin()
	e.uint("id", uint64(m.ID))
	e.time("timestamp", m.Timestamp)
	e.uint("device_id", uint64(m.DeviceID))
	e.uint("probe_id", uint64(m.ProbeID))
	e.str("hostname", m.Hostname)
	e.str("app_name", m.AppName)
	e.str("process_id", m.ProcessID)
	e.str("message_id", m.MessageID)
	e.str("structured_data", m.StructuredData)
	e.str("message", m.Message)
	e.int("priority", int64(m.Priority))
	e.int("facility", int64(m.Facility))
	e.int("severity", int64(m.Severity))
	e.str("source_ip", m.SourceIP)
	e.time("created_at", m.CreatedAt)
	if schema >= SyslogSchemaV2 {
		e.int16Ptr("format", m.StoredFormat)
	}
}

// encodeFlow writes one flow_samples row: the persisted columns of
// models.FlowSample in struct order (class_rev included — it is a column even
// though the API never shows it; the inbound-only BGP fields are not).
func (e *rowEncoder) encodeFlow(f *models.FlowSample) {
	e.begin()
	e.uint("id", uint64(f.ID))
	e.time("timestamp", f.Timestamp)
	e.uint("device_id", uint64(f.DeviceID))
	e.uint("probe_id", uint64(f.ProbeID))
	e.str("sampler_address", f.SamplerAddress)
	e.uint("sequence_number", uint64(f.SequenceNumber))
	e.uint("sampling_rate", uint64(f.SamplingRate))
	e.str("src_addr", f.SrcAddr)
	e.str("dst_addr", f.DstAddr)
	e.uint("src_port", uint64(f.SrcPort))
	e.uint("dst_port", uint64(f.DstPort))
	e.uint("protocol", uint64(f.Protocol))
	e.uint("bytes", f.Bytes)
	e.uint("packets", f.Packets)
	e.uint("input_if_index", uint64(f.InputIfIndex))
	e.uint("output_if_index", uint64(f.OutputIfIndex))
	e.uint("tcp_flags", uint64(f.TCPFlags))
	e.uint("drops", f.Drops)
	e.uint("app_category", uint64(f.AppCategory))
	e.uint("direction", uint64(f.Direction))
	e.uint("service_port", uint64(f.ServicePort))
	e.uint("class_rev", uint64(f.ClassRev))
	e.bool("scope_local", f.ScopeLocal)
	e.str("src_country", f.SrcCountry)
	e.str("dst_country", f.DstCountry)
	e.uint("src_asn", uint64(f.SrcASN))
	e.uint("dst_asn", uint64(f.DstASN))
	e.str("src_asn_org", f.SrcASNOrg)
	e.str("dst_asn_org", f.DstASNOrg)
	e.uint("threat_flag", uint64(f.ThreatFlag))
	e.str("as_path", f.ASPath)
	e.str("next_hop", f.NextHop)
	e.uint("flow_source", uint64(f.FlowSource))
	e.timePtr("flow_start", f.FlowStart)
	e.timePtr("flow_end", f.FlowEnd)
	e.uint("firewall_event", uint64(f.FirewallEvent))
	e.uint("flow_end_reason", uint64(f.FlowEndReason))
	e.str("post_nat_src_addr", f.PostNATSrcAddr)
	e.str("post_nat_dst_addr", f.PostNATDstAddr)
	e.uint("post_nat_src_port", uint64(f.PostNATSrcPort))
	e.uint("post_nat_dst_port", uint64(f.PostNATDstPort))
	e.uint("icmp_type_code", uint64(f.ICMPTypeCode))
	e.uint("tos", uint64(f.TOS))
	e.uint("src_vlan", uint64(f.SrcVLAN))
	e.uint("dst_vlan", uint64(f.DstVLAN))
	e.str("app_name", f.AppName)
	e.time("created_at", f.CreatedAt)
}

// encodeCounter writes one flow_if_counters row: the persisted columns of
// models.FlowInterfaceCounter in struct order.
func (e *rowEncoder) encodeCounter(c *models.FlowInterfaceCounter) {
	e.begin()
	e.uint("id", uint64(c.ID))
	e.time("timestamp", c.Timestamp)
	e.uint("device_id", uint64(c.DeviceID))
	e.uint("probe_id", uint64(c.ProbeID))
	e.str("sampler_address", c.SamplerAddress)
	e.uint("if_index", uint64(c.IfIndex))
	e.uint("if_type", uint64(c.IfType))
	e.uint("if_speed", c.IfSpeed)
	e.uint("if_direction", uint64(c.IfDirection))
	e.uint("if_status", uint64(c.IfStatus))
	e.uint("in_octets", c.InOctets)
	e.uint("in_errors", c.InErrors)
	e.uint("in_discards", c.InDiscards)
	e.uint("out_octets", c.OutOctets)
	e.uint("out_errors", c.OutErrors)
	e.uint("out_discards", c.OutDiscards)
	e.time("created_at", c.CreatedAt)
}
