package normalize

import (
	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// The enums below are the smallint vocabularies the normalized tables (S-3)
// store and the rule engine's `event.*` view spells out by name. Class ids
// follow OCSF 1.x numbering so an export is free later; nothing OCSF-shaped is
// stored. cmd/api/static/js/enums.js mirrors every map here — TestEnumsJSMirror
// fails when the two drift.

// Class is the canonical event class (roadmap §1.1).
type Class int16

const (
	ClassNetwork      Class = 4001 // session / packet / flow log, URL and DNS requests
	ClassFinding      Class = 2004 // IPS / AV / app-control / threat-feed detections
	ClassAuth         Class = 3002 // admin login, VPN user auth, 802.1X, client association
	ClassConfigChange Class = 5019 // who changed what
	ClassVPNSession   Class = 4014 // tunnel up/down, client connect/disconnect, tunnel stats
	ClassDeviceHealth Class = 5001 // WAN down/latency/loss, HA, conserve mode, device offline
)

var classNames = map[Class]string{
	ClassNetwork: "network", ClassFinding: "finding", ClassAuth: "auth",
	ClassConfigChange: "config_change", ClassVPNSession: "vpn_session", ClassDeviceHealth: "device_health",
}

// String returns the class name used by the `event.class` rule field.
func (c Class) String() string { return enumName(classNames, int64(c)) }

// Activity refines a Class. Values are grouped by the class they belong to;
// 0 is "not stated".
type Activity int16

const (
	ActivityUnknown Activity = 0
	// network
	ActivityOpen    Activity = 1 // session start
	ActivityClose   Activity = 2 // session end (close / reset / timeout)
	ActivityTraffic Activity = 3 // one-shot session record (allow or deny verdict)
	ActivityHTTP    Activity = 4 // URL request
	ActivityDNS     Activity = 5 // DNS query
	ActivityPacket  Activity = 6 // per-packet verdict (filterlog, netfilter)
	ActivityDHCP    Activity = 7 // DHCP lease (identity source)
	// finding
	ActivityDetect Activity = 10
	// auth
	ActivityLogon      Activity = 20
	ActivityLogoff     Activity = 21
	ActivityConnect    Activity = 22 // client joined the network (WiFi association, 802.1X)
	ActivityDisconnect Activity = 23
	ActivityRoam       Activity = 24
	// config_change
	ActivityCreate Activity = 30
	ActivityUpdate Activity = 31
	ActivityDelete Activity = 32
	// vpn_session
	ActivityTunnelUp         Activity = 40
	ActivityTunnelDown       Activity = 41
	ActivityClientConnect    Activity = 42
	ActivityClientDisconnect Activity = 43
	ActivityTunnelStats      Activity = 44
	// device_health
	ActivityWANDown       Activity = 50
	ActivityWANUp         Activity = 51
	ActivityLatency       Activity = 52
	ActivityPacketLoss    Activity = 53
	ActivityHAState       Activity = 54
	ActivityDeviceOffline Activity = 55
	ActivityDeviceOnline  Activity = 56
	ActivityResource      Activity = 57 // conserve mode, memory/CPU pressure
	ActivityFailover      Activity = 58
	ActivitySoftware      Activity = 59 // firmware / application updated
)

var activityNames = map[Activity]string{
	ActivityUnknown: "unknown",
	ActivityOpen:    "open", ActivityClose: "close", ActivityTraffic: "traffic", ActivityHTTP: "http",
	ActivityDNS: "dns", ActivityPacket: "packet", ActivityDHCP: "dhcp",
	ActivityDetect: "detect",
	ActivityLogon:  "logon", ActivityLogoff: "logoff", ActivityConnect: "connect",
	ActivityDisconnect: "disconnect", ActivityRoam: "roam",
	ActivityCreate: "create", ActivityUpdate: "update", ActivityDelete: "delete",
	ActivityTunnelUp: "tunnel_up", ActivityTunnelDown: "tunnel_down", ActivityClientConnect: "client_connect",
	ActivityClientDisconnect: "client_disconnect", ActivityTunnelStats: "tunnel_stats",
	ActivityWANDown: "wan_down", ActivityWANUp: "wan_up", ActivityLatency: "latency",
	ActivityPacketLoss: "packet_loss", ActivityHAState: "ha_state", ActivityDeviceOffline: "device_offline",
	ActivityDeviceOnline: "device_online", ActivityResource: "resource", ActivityFailover: "failover",
	ActivitySoftware: "software",
}

// String returns the activity name used by the `event.activity` rule field.
func (a Activity) String() string { return enumName(activityNames, int64(a)) }

// Action is the verdict. For auth events allow = success and deny = failure.
type Action int16

const (
	ActionUnknown      Action = 0
	ActionAllow        Action = 1
	ActionDeny         Action = 2
	ActionReject       Action = 3 // deny with a reset / ICMP unreachable
	ActionTimeoutClose Action = 4 // allowed session that ended by timeout
	ActionOther        Action = 99
)

var actionNames = map[Action]string{
	ActionUnknown: "unknown", ActionAllow: "allow", ActionDeny: "deny",
	ActionReject: "reject", ActionTimeoutClose: "timeout_close", ActionOther: "other",
}

// String returns the action name used by the `event.action` rule field.
func (a Action) String() string { return enumName(actionNames, int64(a)) }

// Role is the vendor-reported interface role; the values are
// models.IntfRole* so DeniedEvent.SrcIntfRole and net_events.src_role agree.
type Role int16

const (
	RoleUnknown   Role = Role(models.IntfRoleUnknown)
	RoleWAN       Role = Role(models.IntfRoleWAN)
	RoleLAN       Role = Role(models.IntfRoleLAN)
	RoleDMZ       Role = Role(models.IntfRoleDMZ)
	RoleUndefined Role = Role(models.IntfRoleUndefined)
)

var roleNames = map[Role]string{
	RoleUnknown: "unknown", RoleWAN: "wan", RoleLAN: "lan", RoleDMZ: "dmz", RoleUndefined: "undefined",
}

// String returns the role name used by the `event.src_role` rule field.
func (r Role) String() string { return enumName(roleNames, int64(r)) }

// Direction reuses classify.Dir* (flow_samples.direction) so the two tables
// share one vocabulary. Only a vendor-stated direction is mapped; nothing is
// inferred from addresses at normalize time.
type Direction int16

const (
	DirectionUnknown  Direction = Direction(classify.DirUnknown)
	DirectionInbound  Direction = Direction(classify.DirInbound)
	DirectionOutbound Direction = Direction(classify.DirOutbound)
	DirectionInternal Direction = Direction(classify.DirInternal)
	DirectionExternal Direction = Direction(classify.DirExternal)
)

var directionNames = map[Direction]string{
	DirectionUnknown: "unknown", DirectionInbound: "inbound", DirectionOutbound: "outbound",
	DirectionInternal: "internal", DirectionExternal: "external",
}

// String returns the direction name used by the `event.direction` rule field.
func (d Direction) String() string { return enumName(directionNames, int64(d)) }

func enumName[K ~int16](names map[K]string, v int64) string {
	if n, ok := names[K(v)]; ok {
		return n
	}
	return "unknown"
}

// EnumTables lists every enum map by the name the JS mirror uses, for the
// drift guard and for the capability API later.
func EnumTables() map[string]map[string]int64 {
	out := map[string]map[string]int64{
		"CLASS": {}, "ACTIVITY": {}, "ACTION": {}, "ROLE": {}, "DIRECTION": {},
	}
	for k, v := range classNames {
		out["CLASS"][v] = int64(k)
	}
	for k, v := range activityNames {
		out["ACTIVITY"][v] = int64(k)
	}
	for k, v := range actionNames {
		out["ACTION"][v] = int64(k)
	}
	for k, v := range roleNames {
		out["ROLE"][v] = int64(k)
	}
	for k, v := range directionNames {
		out["DIRECTION"][v] = int64(k)
	}
	return out
}
