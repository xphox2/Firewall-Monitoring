package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"firewall-mon/internal/models"
)

// Decoding (archive plan PR 9, restore): a line of an archived object back
// into the model row it was written from. Strict by construction: the decoded
// row is encoded again with the exporter's own encoder and must reproduce the
// line byte for byte, so a field that is missing, extra, renamed, out of
// order, of another type or range, a timestamp not in UTC RFC 3339, or a
// schema mismatch (a v1 syslog line has no "format", a v2 line must have it)
// is an error — never a row restored with a silently defaulted column.

// Decoder decodes the lines of one table's objects of one schema version.
// Not safe for concurrent use (it reuses its encode buffer).
type Decoder struct {
	table  string
	schema int
	enc    rowEncoder
}

// NewDecoder returns a decoder for table's objects of schema (the versions
// NewChunkWriter accepts).
func NewDecoder(table string, schema int) (*Decoder, error) {
	if _, err := NewChunkWriter(table, schema, nil); err != nil {
		return nil, err
	}
	return &Decoder{table: table, schema: schema}, nil
}

// Table is the source table the decoder's lines belong to.
func (d *Decoder) Table() string { return d.table }

// unmarshal decodes line into v, refusing a key v does not have.
func unmarshal(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// same requires the re-encoded row to be the line.
func (d *Decoder) same(line []byte, id uint) error {
	got, err := d.enc.line()
	if err != nil {
		return fmt.Errorf("export: %s row %d: %w", d.table, id, err)
	}
	if !bytes.Equal(got, line) {
		return fmt.Errorf("export: %s row %d: the line is not what the schema-%d exporter writes for the row it decodes to", d.table, id, d.schema)
	}
	return nil
}

func (d *Decoder) want(table string) error {
	if d.table != table {
		return fmt.Errorf("export: a %s decoder cannot decode %s rows", d.table, table)
	}
	return nil
}

// syslogLine is a syslog_messages line (column names as keys).
type syslogLine struct {
	ID             uint      `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity"`
	SourceIP       string    `json:"source_ip"`
	CreatedAt      time.Time `json:"created_at"`
	Format         *int16    `json:"format"`
}

// Syslog decodes one line (with its trailing newline) into m. A schema-1 line
// leaves StoredFormat nil (those rows never had one).
func (d *Decoder) Syslog(line []byte, m *models.SyslogMessage) error {
	if err := d.want(TableSyslog); err != nil {
		return err
	}
	var l syslogLine
	if err := unmarshal(line, &l); err != nil {
		return fmt.Errorf("export: syslog line: %w", err)
	}
	*m = models.SyslogMessage{
		ID: l.ID, Timestamp: l.Timestamp.UTC(), DeviceID: l.DeviceID, ProbeID: l.ProbeID, Hostname: l.Hostname, AppName: l.AppName,
		ProcessID: l.ProcessID, MessageID: l.MessageID, StructuredData: l.StructuredData, Message: l.Message,
		Priority: l.Priority, Facility: l.Facility, Severity: l.Severity, SourceIP: l.SourceIP, CreatedAt: l.CreatedAt.UTC(),
	}
	if d.schema >= SyslogSchemaV2 {
		m.StoredFormat = l.Format
	}
	d.enc.encodeSyslog(m, d.schema)
	return d.same(line, l.ID)
}

// flowLine is a flow_samples line (column names as keys).
type flowLine struct {
	ID             uint       `json:"id"`
	Timestamp      time.Time  `json:"timestamp"`
	DeviceID       uint       `json:"device_id"`
	ProbeID        uint       `json:"probe_id"`
	SamplerAddress string     `json:"sampler_address"`
	SequenceNumber uint32     `json:"sequence_number"`
	SamplingRate   uint32     `json:"sampling_rate"`
	SrcAddr        string     `json:"src_addr"`
	DstAddr        string     `json:"dst_addr"`
	SrcPort        uint16     `json:"src_port"`
	DstPort        uint16     `json:"dst_port"`
	Protocol       uint8      `json:"protocol"`
	Bytes          uint64     `json:"bytes"`
	Packets        uint64     `json:"packets"`
	InputIfIndex   uint32     `json:"input_if_index"`
	OutputIfIndex  uint32     `json:"output_if_index"`
	TCPFlags       uint8      `json:"tcp_flags"`
	Drops          uint64     `json:"drops"`
	AppCategory    uint8      `json:"app_category"`
	Direction      uint8      `json:"direction"`
	ServicePort    uint16     `json:"service_port"`
	ClassRev       uint16     `json:"class_rev"`
	ScopeLocal     bool       `json:"scope_local"`
	SrcCountry     string     `json:"src_country"`
	DstCountry     string     `json:"dst_country"`
	SrcASN         uint32     `json:"src_asn"`
	DstASN         uint32     `json:"dst_asn"`
	SrcASNOrg      string     `json:"src_asn_org"`
	DstASNOrg      string     `json:"dst_asn_org"`
	ThreatFlag     uint8      `json:"threat_flag"`
	ASPath         string     `json:"as_path"`
	NextHop        string     `json:"next_hop"`
	FlowSource     uint8      `json:"flow_source"`
	FlowStart      *time.Time `json:"flow_start"`
	FlowEnd        *time.Time `json:"flow_end"`
	FirewallEvent  uint8      `json:"firewall_event"`
	FlowEndReason  uint8      `json:"flow_end_reason"`
	PostNATSrcAddr string     `json:"post_nat_src_addr"`
	PostNATDstAddr string     `json:"post_nat_dst_addr"`
	PostNATSrcPort uint16     `json:"post_nat_src_port"`
	PostNATDstPort uint16     `json:"post_nat_dst_port"`
	ICMPTypeCode   uint16     `json:"icmp_type_code"`
	TOS            uint8      `json:"tos"`
	SrcVLAN        uint16     `json:"src_vlan"`
	DstVLAN        uint16     `json:"dst_vlan"`
	AppName        string     `json:"app_name"`
	CreatedAt      time.Time  `json:"created_at"`
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// Flow decodes one flow_samples line (sflow or netflow object) into f.
func (d *Decoder) Flow(line []byte, f *models.FlowSample) error {
	if err := d.want(TableFlows); err != nil {
		return err
	}
	var l flowLine
	if err := unmarshal(line, &l); err != nil {
		return fmt.Errorf("export: flow line: %w", err)
	}
	*f = models.FlowSample{
		ID: l.ID, Timestamp: l.Timestamp.UTC(), DeviceID: l.DeviceID, ProbeID: l.ProbeID, SamplerAddress: l.SamplerAddress,
		SequenceNumber: l.SequenceNumber, SamplingRate: l.SamplingRate, SrcAddr: l.SrcAddr, DstAddr: l.DstAddr,
		SrcPort: l.SrcPort, DstPort: l.DstPort, Protocol: l.Protocol, Bytes: l.Bytes, Packets: l.Packets,
		InputIfIndex: l.InputIfIndex, OutputIfIndex: l.OutputIfIndex, TCPFlags: l.TCPFlags, Drops: l.Drops,
		AppCategory: l.AppCategory, Direction: l.Direction, ServicePort: l.ServicePort, ClassRev: l.ClassRev, ScopeLocal: l.ScopeLocal,
		SrcCountry: l.SrcCountry, DstCountry: l.DstCountry, SrcASN: l.SrcASN, DstASN: l.DstASN, SrcASNOrg: l.SrcASNOrg, DstASNOrg: l.DstASNOrg,
		ThreatFlag: l.ThreatFlag, ASPath: l.ASPath, NextHop: l.NextHop, FlowSource: l.FlowSource,
		FlowStart: utcPtr(l.FlowStart), FlowEnd: utcPtr(l.FlowEnd), FirewallEvent: l.FirewallEvent, FlowEndReason: l.FlowEndReason,
		PostNATSrcAddr: l.PostNATSrcAddr, PostNATDstAddr: l.PostNATDstAddr, PostNATSrcPort: l.PostNATSrcPort, PostNATDstPort: l.PostNATDstPort,
		ICMPTypeCode: l.ICMPTypeCode, TOS: l.TOS, SrcVLAN: l.SrcVLAN, DstVLAN: l.DstVLAN, AppName: l.AppName, CreatedAt: l.CreatedAt.UTC(),
	}
	d.enc.encodeFlow(f)
	return d.same(line, l.ID)
}

// counterLine is a flow_if_counters line (column names as keys).
type counterLine struct {
	ID             uint      `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	SamplerAddress string    `json:"sampler_address"`
	IfIndex        uint32    `json:"if_index"`
	IfType         uint32    `json:"if_type"`
	IfSpeed        uint64    `json:"if_speed"`
	IfDirection    uint32    `json:"if_direction"`
	IfStatus       uint32    `json:"if_status"`
	InOctets       uint64    `json:"in_octets"`
	InErrors       uint64    `json:"in_errors"`
	InDiscards     uint64    `json:"in_discards"`
	OutOctets      uint64    `json:"out_octets"`
	OutErrors      uint64    `json:"out_errors"`
	OutDiscards    uint64    `json:"out_discards"`
	CreatedAt      time.Time `json:"created_at"`
}

// Counter decodes one flow_if_counters line into c.
func (d *Decoder) Counter(line []byte, c *models.FlowInterfaceCounter) error {
	if err := d.want(TableCounters); err != nil {
		return err
	}
	var l counterLine
	if err := unmarshal(line, &l); err != nil {
		return fmt.Errorf("export: counter line: %w", err)
	}
	*c = models.FlowInterfaceCounter{
		ID: l.ID, Timestamp: l.Timestamp.UTC(), DeviceID: l.DeviceID, ProbeID: l.ProbeID, SamplerAddress: l.SamplerAddress,
		IfIndex: l.IfIndex, IfType: l.IfType, IfSpeed: l.IfSpeed, IfDirection: l.IfDirection, IfStatus: l.IfStatus,
		InOctets: l.InOctets, InErrors: l.InErrors, InDiscards: l.InDiscards, OutOctets: l.OutOctets, OutErrors: l.OutErrors,
		OutDiscards: l.OutDiscards, CreatedAt: l.CreatedAt.UTC(),
	}
	d.enc.encodeCounter(c)
	return d.same(line, l.ID)
}
