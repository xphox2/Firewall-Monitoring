package snmp

// UniFiProfile is the SNMP profile for Ubiquiti UniFi gateways (UDM / UXG /
// UCG lines) and USW switches — untested on real hardware, built from vendor
// docs. The UniFi Network app exposes SNMPv2-MIB, IF-MIB and HOST-RESOURCES
// (CPU / memory on Gen2 switches); the vendor UI-MIB is thin and not polled.
// That is exactly the standards-only GenericProfile surface, so this profile
// is a registered clone of it under its own name: a device tagged `unifi`
// polls the same MIB-II scalars and interface tables, keeps its vendor for
// rules, capability profiles and the device form, and gains enterprise OIDs
// here the day a UI-MIB mapping is verified against real hardware.
type UniFiProfile struct {
	GenericProfile
}

func init() {
	RegisterVendor(&UniFiProfile{})
}

func (u *UniFiProfile) Name() string { return "unifi" }
