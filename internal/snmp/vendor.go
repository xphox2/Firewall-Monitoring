package snmp

import (
	"sync"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// TrapDef describes a vendor-specific trap OID mapping.
type TrapDef struct {
	Type     string
	Severity string
}

// VendorProfile defines the interface for vendor-specific SNMP behavior.
type VendorProfile interface {
	Name() string

	// System status
	SystemOIDs() []string
	ParseSystemStatus(pdus []gosnmp.SnmpPDU) *models.SystemStatus

	// VPN
	VPNBaseOID() string
	ParseVPNStatus(pdus []gosnmp.SnmpPDU) []models.VPNStatus

	// Hardware sensors
	HWSensorBaseOID() string
	ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []models.HardwareSensor

	// HA
	HABaseOID() string
	ParseHAStatus(pdus []gosnmp.SnmpPDU) []models.HAStatus

	// Traps
	TrapOIDs() map[string]TrapDef
}

var (
	vendorMu       sync.RWMutex
	vendorRegistry = make(map[string]VendorProfile)
)

// RegisterVendor adds a vendor profile to the registry.
func RegisterVendor(profile VendorProfile) {
	vendorMu.Lock()
	defer vendorMu.Unlock()
	vendorRegistry[profile.Name()] = profile
}

// GetVendorProfile returns the profile for the given vendor name.
func GetVendorProfile(name string) VendorProfile {
	vendorMu.RLock()
	defer vendorMu.RUnlock()
	if p, ok := vendorRegistry[name]; ok {
		return p
	}
	return nil
}

// DefaultVendor returns the FortiGate vendor profile.
func DefaultVendor() VendorProfile {
	p := GetVendorProfile("fortigate")
	if p != nil {
		return p
	}
	// Fallback: return first registered profile
	vendorMu.RLock()
	defer vendorMu.RUnlock()
	for _, v := range vendorRegistry {
		return v
	}
	return nil
}
