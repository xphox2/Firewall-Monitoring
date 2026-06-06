# Adding a custom vendor profile

Firewall-Mon is multi-vendor: each firewall family is described by a
`VendorProfile` that knows which SNMP OIDs to poll and how to turn the raw
PDUs into the shared `models.*` structs. This guide walks through adding a new
vendor end to end. It uses a **shallow** profile (system stats only) as the
worked example — exactly how `pfsense`, `opnsense`, and `firewalla` started —
so you can ship something useful without implementing VPN/HA/sensors on day
one.

> The interface lives in [`internal/snmp/vendor.go`](../internal/snmp/vendor.go).
> Real, copy-pasteable implementations to crib from:
> [`vendor_pfsense.go`](../internal/snmp/vendor_pfsense.go) (shallow) and
> [`vendor_sonicwall.go`](../internal/snmp/vendor_sonicwall.go) /
> [`vendor_fortigate.go`](../internal/snmp/vendor_fortigate.go) (full).

## The `VendorProfile` interface

```go
type VendorProfile interface {
    Name() string                          // the registry key, e.g. "sonicwall"

    SystemOIDs() []string                  // scalar OIDs to GET for CPU/mem/disk/uptime
    ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus

    VPNBaseOID() string                    // table base for an SNMP WALK; "" disables
    ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus

    SSLVPNBaseOID() string
    ParseSSLVPNStatus(pdus []gosnmp.SnmpPDU) (int, int)
    ParseSSLVPNTunnels(pdus []gosnmp.SnmpPDU) []models.VPNStatus
    GetAllVPNTunnels(s *SNMPClient) ([]models.VPNStatus, int, int, error)

    HWSensorBaseOID() string
    ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []models.HardwareSensor

    ProcessorBaseOID() string
    ParseProcessors(pdus []gosnmp.SnmpPDU) []models.ProcessorStats

    HABaseOID() string
    ParseHAStatus(pdus []gosnmp.SnmpPDU) []models.HAStatus

    TrapOIDs() map[string]TrapDef          // vendor enterprise trap OID -> {Type, Severity}
}
```

You implement **every** method, but the ones for features your device doesn't
expose are one-line stubs: return `""` for a `*BaseOID()` and `nil` for the
matching `Parse*` (the poller skips a feature whose base OID is empty). See
`pfsense` for the canonical "system stats only" shape.

## Step 1 — create the profile file

Create `internal/snmp/vendor_acme.go`. Declare the OID constants (find them in
the vendor's MIB; the enterprise arc is `.1.3.6.1.4.1.<PEN>`), then a profile
struct, and register it in `init()`:

```go
package snmp

import (
    "firewall-mon/internal/models"
    "github.com/gosnmp/gosnmp"
)

// Acme enterprise OID arc: .1.3.6.1.4.1.99999
var (
    acmeOIDSysName  = ".1.3.6.1.2.1.1.5.0"   // standard SNMPv2-MIB sysName
    acmeOIDUpTime   = ".1.3.6.1.2.1.1.3.0"   // standard sysUpTime
    acmeOIDCPUUtil  = ".1.3.6.1.4.1.99999.1.1.0"
    acmeOIDMemUtil  = ".1.3.6.1.4.1.99999.1.2.0"
)

type AcmeProfile struct{}

// init registers the profile at package load — importing internal/snmp is
// enough for the device to become pollable.
func init() { RegisterVendor(&AcmeProfile{}) }

func (a *AcmeProfile) Name() string { return "acme" }
```

## Step 2 — implement system status

This is the one method that pays for itself immediately:

```go
func (a *AcmeProfile) SystemOIDs() []string {
    return []string{acmeOIDSysName, acmeOIDUpTime, acmeOIDCPUUtil, acmeOIDMemUtil}
}

func (a *AcmeProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus {
    s := &models.SystemStatus{}
    for _, pdu := range pdus {
        if !isValidPDU(pdu) { // skip NoSuchObject/NoSuchInstance/EndOfMibView
            continue
        }
        switch {
        case strings.HasPrefix(pdu.OID, acmeOIDCPUUtil):
            s.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
        case strings.HasPrefix(pdu.OID, acmeOIDMemUtil):
            s.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
        // ... uptime, hostname, etc.
        }
    }
    return s
}
```

(`isValidPDU` is provided in `vendor.go`. Coerce gosnmp values with
`gosnmp.ToBigInt(pdu.Value).Int64()`/`.Uint64()` — the pattern every existing
profile uses; `models.SystemStatus.CPUUsage`/`MemoryUsage` are `float64`.)

## Step 3 — stub the rest (for a shallow profile)

```go
func (a *AcmeProfile) VPNBaseOID() string                                  { return "" }
func (a *AcmeProfile) ParseVPNStatus(_ []gosnmp.SnmpPDU) []models.VPNStatus { return nil }
func (a *AcmeProfile) SSLVPNBaseOID() string                               { return "" }
func (a *AcmeProfile) ParseSSLVPNStatus(_ []gosnmp.SnmpPDU) (int, int)     { return 0, 0 }
func (a *AcmeProfile) ParseSSLVPNTunnels(_ []gosnmp.SnmpPDU) []models.VPNStatus { return nil }
func (a *AcmeProfile) GetAllVPNTunnels(_ *SNMPClient) ([]models.VPNStatus, int, int, error) {
    return nil, 0, 0, nil
}
func (a *AcmeProfile) HWSensorBaseOID() string                                       { return "" }
func (a *AcmeProfile) ParseHardwareSensors(_ []gosnmp.SnmpPDU) []models.HardwareSensor { return nil }
func (a *AcmeProfile) ProcessorBaseOID() string                                      { return "" }
func (a *AcmeProfile) ParseProcessors(_ []gosnmp.SnmpPDU) []models.ProcessorStats    { return nil }
func (a *AcmeProfile) HABaseOID() string                                             { return "" }
func (a *AcmeProfile) ParseHAStatus(_ []gosnmp.SnmpPDU) []models.HAStatus            { return nil }
func (a *AcmeProfile) TrapOIDs() map[string]TrapDef                                  { return nil }
```

Fill these in later as you map more of the vendor's MIB — the poller will pick
up each feature the moment its base OID is non-empty.

## Step 4 — allow the vendor name in the API

Add the new name to the `validVendors` allow-list in
[`internal/api/handlers/handlers.go`](../internal/api/handlers/handlers.go) so
the API accepts devices tagged with it:

```go
var validVendors = map[string]bool{
    "fortigate": true,
    // ...
    "acme": true, // <- add this
}
```

Without this, `POST /admin/api/devices` with `"vendor":"acme"` is rejected.

## Step 5 — (optional) config-backup normalization

If you also use config-backup change detection, add a normalizer under
[`internal/configdiff/`](../internal/configdiff/) so volatile content (the
`! Last configuration change ...` line, encrypted secrets, timestamps) is
stripped before hashing — otherwise every backup of an `acme` device
false-alerts on encrypted-field drift. Vendors without a rich normalizer fall
through to identity hashing; `configdiff.HasRichNormalizer("acme")` reports
which path a vendor takes. `vendor_fortigate.go` / `vendor_paloalto.go` /
`vendor_cisco_asa.go` in that package are the worked examples.

## Step 6 — build, test, tag a device

```bash
go build ./...
go test ./internal/snmp/...
```

Then create a device with `"vendor":"acme"` and watch the poller. The startup
vendor audit (`Database.auditDeviceVendors`) logs the fleet's vendor
distribution and warns about identity-normalizer vendors, so you'll see your
new vendor accounted for in the logs.

## Checklist

- [ ] `internal/snmp/vendor_<name>.go` with OID constants + `<Name>Profile`
- [ ] `Name()` returns the registry key
- [ ] `SystemOIDs()` + `ParseSystemStatus()` implemented
- [ ] every other interface method implemented (stub `""`/`nil` if unsupported)
- [ ] `init()` calls `RegisterVendor(&<Name>Profile{})`
- [ ] vendor name added to `validVendors` in `handlers.go`
- [ ] (optional) a `configdiff` normalizer for config-backup
- [ ] `go build ./...` and `go test ./internal/snmp/...` pass
```
