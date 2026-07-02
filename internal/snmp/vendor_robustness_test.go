package snmp

import (
	"math"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Vendor SNMP parsers consume PDUs delivered by the polled device (directly in
// server-poll mode, or relayed by a collector). A malfunctioning or hostile
// device can return arbitrary OIDs, value types, and truncated indices. A panic
// in any Parse* method would take down the poll goroutine, so every parser must
// be total over garbage input.
//
// This suite hammers every registered vendor profile's five parse methods with
// adversarial PDU sets built from the profile's OWN advertised OIDs (so the
// vendor-specific parse branches are actually reached) crossed with a battery of
// hostile value shapes. The property under test is simply: no panic, ever.
//
// Historically only fortigate had any parser test; this covers all six
// registered vendors (firewalla, fortigate, opnsense, paloalto, pfsense,
// sonicwall) against the untrusted-input path.

// adversarialValues is the set of hostile Value payloads a device might deliver
// for any OID, regardless of the ASN.1 type the parser expects.
func adversarialValues() []interface{} {
	return []interface{}{
		nil,
		"",
		"not-a-number",
		"52.5",                       // numeric string (DisplayString) — ToBigInt returns 0
		"-1",                         // negative string
		"99999999999999999999999999", // overflows int64/uint64
		[]byte(nil),
		[]byte{},
		[]byte("\x00\x01\x02\xff"), // non-UTF8 bytes
		int(-1),
		int(math.MaxInt32),
		int64(math.MinInt64),
		int64(math.MaxInt64),
		uint(0),
		uint64(math.MaxUint64),
		uint32(math.MaxUint32),
		float64(-1.5),
		float64(math.Inf(1)),
		float64(math.NaN()),
		true,
		struct{ X int }{X: 1}, // wholly unexpected type
	}
}

// adversarialTypes covers the ASN.1 BER tags a device may set, including the
// SNMP "exception" values that legitimately appear in a GETBULK walk.
func adversarialTypes() []gosnmp.Asn1BER {
	return []gosnmp.Asn1BER{
		gosnmp.Null,
		gosnmp.Integer,
		gosnmp.OctetString,
		gosnmp.Counter32,
		gosnmp.Counter64,
		gosnmp.Gauge32,
		gosnmp.TimeTicks,
		gosnmp.NoSuchObject,
		gosnmp.NoSuchInstance,
		gosnmp.EndOfMibView,
	}
}

// oidsForProfile returns a spread of OID names likely to hit the parser's
// branches: the profile's own advertised base OIDs, each with several index
// suffixes (including malformed ones) to exercise index-extraction code, plus a
// few pathological OID strings.
func oidsForProfile(p VendorProfile) []string {
	bases := []string{}
	bases = append(bases, p.SystemOIDs()...)
	for _, b := range []string{p.VPNBaseOID(), p.HWSensorBaseOID(), p.ProcessorBaseOID(), p.HABaseOID()} {
		if b != "" {
			bases = append(bases, b)
		}
	}

	suffixes := []string{"", ".0", ".1", ".1.1", ".999999999999", ".", ".a", ".-1", ".1.2.3.4.5.6.7.8"}
	oids := []string{
		"",                  // empty OID
		".",                 // bare dot
		"1.3.6.1",           // no leading dot
		".1.3.6.1.4.1.9999", // unrelated OID
	}
	for _, b := range bases {
		for _, s := range suffixes {
			oids = append(oids, b+s)
		}
	}
	return oids
}

// buildAdversarialPDUs cross-products OIDs × types × values into a large PDU
// slice, plus mixes them into one combined slice so parsers that key off
// multiple PDUs together are exercised.
func buildAdversarialPDUs(p VendorProfile) []gosnmp.SnmpPDU {
	oids := oidsForProfile(p)
	types := adversarialTypes()
	values := adversarialValues()

	var pdus []gosnmp.SnmpPDU
	for i, oid := range oids {
		typ := types[i%len(types)]
		val := values[i%len(values)]
		pdus = append(pdus, gosnmp.SnmpPDU{Name: oid, Type: typ, Value: val})
		// Also emit a second PDU for the same OID with a different value shape,
		// so index-collision and last-writer-wins paths are hit.
		pdus = append(pdus, gosnmp.SnmpPDU{
			Name:  oid,
			Type:  types[(i+3)%len(types)],
			Value: values[(i+7)%len(values)],
		})
	}
	return pdus
}

func TestVendorParsers_NoPanicOnHostileInput(t *testing.T) {
	vendors := []string{"firewalla", "fortigate", "opnsense", "paloalto", "pfsense", "sonicwall"}

	// Input variants each parser must survive.
	inputs := map[string]func(p VendorProfile) []gosnmp.SnmpPDU{
		"nil":         func(p VendorProfile) []gosnmp.SnmpPDU { return nil },
		"empty":       func(p VendorProfile) []gosnmp.SnmpPDU { return []gosnmp.SnmpPDU{} },
		"adversarial": buildAdversarialPDUs,
	}

	for _, name := range vendors {
		p := GetVendorProfile(name)
		if p == nil {
			t.Fatalf("vendor %q not registered — registry regression", name)
		}

		for inName, build := range inputs {
			pdus := build(p)

			// Each parse method is called inside its own recover so a panic is
			// reported as a test failure rather than aborting the whole run.
			calls := map[string]func(){
				"ParseSystemStatus":    func() { _ = p.ParseSystemStatus(pdus) },
				"ParseVPNStatus":       func() { _ = p.ParseVPNStatus(pdus) },
				"ParseHardwareSensors": func() { _ = p.ParseHardwareSensors(pdus) },
				"ParseProcessors":      func() { _ = p.ParseProcessors(pdus) },
				"ParseHAStatus":        func() { _ = p.ParseHAStatus(pdus) },
			}
			for method, call := range calls {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("vendor=%s input=%s %s panicked: %v", name, inName, method, r)
						}
					}()
					call()
				}()
			}
		}
	}
}
