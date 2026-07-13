package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func ipsecCreateBody() string {
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	in := ipsec.TunnelIntent{
		Enabled: true, IKEVersion: m.IKEVersion, Mode: ipsec.ModeRouteBased,
		IKE: m.IKE, ESP: m.ESP, IKELifetimeSecs: m.IKELifetimeSecs,
		DPD: ipsec.DPD{DelaySecs: 30},
		Ends: [2]ipsec.EndpointSpec{
			{DeviceID: 1, Vendor: "fortigate", PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}, ProtectedSubnets: []string{"10.10.10.0/24"}, MSSClamp: 1350},
			{DeviceID: 2, Vendor: "opnsense", PeerIP: "198.51.100.1", Dynamic: true, EgressIface: "wan", LANIface: "lan",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}, ProtectedSubnets: []string{"192.168.50.0/24"}, MSSClamp: 1350},
		},
	}
	b, _ := json.Marshal(&in)
	return string(b)
}

func decodeTunnel(t *testing.T, body []byte) tunnelResponse {
	t.Helper()
	var resp struct {
		Data tunnelResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return resp.Data
}

func TestIPSec_CreateGetPreview(t *testing.T) {
	h, db := setupTestHandler(t)

	// Create → PSK generated + masked, VTI + name hydrated, no blocks.
	c, rec := jsonReq(http.MethodPost, "/admin/api/ipsec/tunnels", ipsecCreateBody())
	h.CreateIPSecTunnel(c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d (%s)", rec.Code, rec.Body.String())
	}
	created := decodeTunnel(t, rec.Body.Bytes())
	if created.Intent.ID == 0 || created.Intent.Name != "fwm-t"+strconv.Itoa(int(created.Intent.ID)) {
		t.Fatalf("name not hydrated: %+v", created.Intent)
	}
	if created.Intent.PSK != ipsecPSKMask {
		t.Errorf("create response must mask the PSK, got %q", created.Intent.PSK)
	}
	if created.Intent.VTISubnet == "" || created.Intent.Ends[0].InnerIP == "" {
		t.Errorf("VTI not hydrated: %+v", created.Intent)
	}
	if ipsec.HasBlock(created.Validation) {
		t.Errorf("clean intent should have no validation blocks: %+v", created.Validation)
	}
	id := created.Intent.ID

	// The stored PSK is real (not the mask) — a generated 256-bit key.
	stored, err := db.GetIPSecTunnel(id)
	if err != nil || stored.PSK == "" || stored.PSK == ipsecPSKMask || len(stored.PSK) < 40 {
		t.Fatalf("stored PSK looks wrong: %q err=%v", stored.PSK, err)
	}

	// Get → masked.
	c2, rec2 := jsonReq(http.MethodGet, "/x", "")
	c2.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecTunnel(c2)
	if rec2.Code != http.StatusOK || decodeTunnel(t, rec2.Body.Bytes()).Intent.PSK != ipsecPSKMask {
		t.Fatalf("get should return masked PSK; status=%d", rec2.Code)
	}

	// Preview → both ends rendered, PSK never present.
	c3, rec3 := jsonReq(http.MethodGet, "/x", "")
	c3.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.PreviewIPSecTunnel(c3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("preview status = %d (%s)", rec3.Code, rec3.Body.String())
	}
	body := rec3.Body.String()
	if !strings.Contains(body, "fortigate") || !strings.Contains(body, "opnsense") {
		t.Errorf("preview should render both vendors")
	}
	if strings.Contains(body, stored.PSK) {
		t.Errorf("preview leaked the real PSK")
	}
	if !strings.Contains(body, "aes256gcm") {
		t.Errorf("preview should contain the modern proposal; got %s", body)
	}
}

func TestIPSec_Capabilities(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/admin/api/ipsec/capabilities?a=fortigate&b=opnsense", "")
	h.IPSecCapabilities(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "allowed") || !strings.Contains(rec.Body.String(), "aes256gcm16") {
		t.Errorf("capabilities should return the allowed intersection: %s", rec.Body.String())
	}

	// Unknown vendor → 400.
	c2, rec2 := jsonReq(http.MethodGet, "/x?a=fortigate&b=nope", "")
	h.IPSecCapabilities(c2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("unknown vendor should 400, got %d", rec2.Code)
	}
}

func TestIPSec_CreateRejectsUnknownVendor(t *testing.T) {
	h, _ := setupTestHandler(t)
	body := strings.Replace(ipsecCreateBody(), `"opnsense"`, `"nintendo"`, 1)
	c, rec := jsonReq(http.MethodPost, "/x", body)
	h.CreateIPSecTunnel(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown vendor should 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestIPSec_EndpointHints: the wizard hints endpoint turns a device's polled
// interfaces + addresses into dropdown data — real interfaces, is_lan flags,
// derived LAN CIDRs, and egress/LAN suggestions — and returns empty (not an
// error) for a never-polled device.
func TestIPSec_EndpointHints(t *testing.T) {
	h, db := setupTestHandler(t)

	dev := &models.Device{Name: "fg", IPAddress: "203.0.113.9", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	ts := time.Now()
	ifaces := []models.InterfaceStats{
		{DeviceID: dev.ID, Timestamp: ts, Name: "port1", Index: 1, TypeName: "ethernet", Status: "up"},   // WAN (bears device IP)
		{DeviceID: dev.ID, Timestamp: ts, Name: "internal", Index: 3, TypeName: "bridge", Status: "up"},  // LAN
		{DeviceID: dev.ID, Timestamp: ts, Name: "tunnel.1", Index: 9, TypeName: "tunnel", Status: "up"},  // NOT a LAN segment
		{DeviceID: dev.ID, Timestamp: ts, Name: "sw0", Index: 4, TypeName: "propVirtual", Status: "up"},  // LAN (dead-entry fix)
		{DeviceID: dev.ID, Timestamp: ts, Name: "tun0", Index: 7, TypeName: "propVirtual", Status: "up"}, // OpenVPN tun (propVirtual) — NOT a LAN
	}
	if err := db.Gorm().Create(&ifaces).Error; err != nil {
		t.Fatalf("create ifaces: %v", err)
	}
	addrs := []models.InterfaceAddress{
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 1, IPAddress: "203.0.113.9", NetMask: "255.255.255.0"}, // WAN (bears device IP) → transit, excluded from lan_subnets
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 3, IPAddress: "10.20.30.1", NetMask: "255.255.255.0"},  // LAN → 10.20.30.0/24
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 4, IPAddress: "192.168.9.1", NetMask: "255.255.255.0"}, // propVirtual LAN → 192.168.9.0/24
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 9, IPAddress: "169.254.0.2", NetMask: "255.255.255.0"}, // tunnel/fabric → excluded
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 7, IPAddress: "10.99.99.1", NetMask: "255.255.255.0"},  // tun0 VPN /24 → must NOT be a protected LAN
	}
	if err := db.Gorm().Create(&addrs).Error; err != nil {
		t.Fatalf("create addrs: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(dev.ID))}}
	h.GetIPSecEndpointHints(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var wrap struct {
		Data ipsecHintsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	resp := wrap.Data

	if resp.WANIP != "203.0.113.9" {
		t.Errorf("wan_ip = %q, want 203.0.113.9", resp.WANIP)
	}
	if resp.SuggestedEgress != "port1" {
		t.Errorf("suggested_egress = %q, want port1 (bears the device IP)", resp.SuggestedEgress)
	}
	if resp.SuggestedLAN != "internal" {
		t.Errorf("suggested_lan = %q, want internal (first up LAN iface, sorted)", resp.SuggestedLAN)
	}
	// The peer/public endpoint suggestion is the egress (WAN) interface's public IP.
	if resp.SuggestedPeerIP != "203.0.113.9" {
		t.Errorf("suggested_peer_ip = %q, want 203.0.113.9 (public IP on the egress iface)", resp.SuggestedPeerIP)
	}
	wantSubnets := map[string]bool{"10.20.30.0/24": true, "192.168.9.0/24": true}
	if len(resp.LANSubnets) != 2 {
		t.Fatalf("lan_subnets = %v, want the two LAN /24s (WAN + tunnel excluded)", resp.LANSubnets)
	}
	for _, s := range resp.LANSubnets {
		if !wantSubnets[s] {
			t.Errorf("unexpected lan_subnet %q", s)
		}
	}
	byName := map[string]ipsecHintIface{}
	for _, hi := range resp.Interfaces {
		byName[hi.Name] = hi
	}
	if !byName["internal"].IsLAN || !byName["sw0"].IsLAN {
		t.Error("bridge + propVirtual interfaces must be flagged is_lan")
	}
	if byName["tunnel.1"].IsLAN {
		t.Error("tunnel interface must NOT be flagged is_lan")
	}
	// The public WAN address is flagged public; private LAN addresses are not.
	if !byName["port1"].Addresses[0].Public {
		t.Errorf("port1 address 203.0.113.9 must be flagged public")
	}
	if byName["internal"].Addresses[0].Public {
		t.Errorf("internal address 10.20.30.1 (RFC1918) must NOT be flagged public")
	}
	// A propVirtual OpenVPN tun device must NOT be classified LAN (the poller/wizard
	// share this: else two VPN peers get a spurious direct connection).
	if byName["tun0"].IsLAN {
		t.Error("propVirtual tun0 (VPN carrier) must NOT be flagged is_lan")
	}
	for _, s := range resp.LANSubnets {
		if s == "10.99.99.0/24" {
			t.Error("VPN tun subnet 10.99.99.0/24 must NOT be a protected lan_subnet")
		}
	}
	// port1 bears the device's WAN IP: its /24 IS a valid network (CIDR present on
	// the address) but must be excluded from lan_subnets as transit, not protected.
	if got := byName["port1"].Addresses[0].CIDR; got != "203.0.113.0/24" {
		t.Errorf("port1 address CIDR = %q, want 203.0.113.0/24", got)
	}
	for _, s := range resp.LANSubnets {
		if s == "203.0.113.0/24" {
			t.Error("WAN/egress transit subnet 203.0.113.0/24 must NOT be a protected lan_subnet")
		}
	}

	// Egress-exclusion for suggested_lan: when the WAN interface sorts BEFORE the
	// LAN one and is itself a LAN-type (e.g. OPNsense igb0=WAN, igb1=LAN, both
	// ethernet), the LAN suggestion must skip the WAN interface.
	devO := &models.Device{Name: "opn", IPAddress: "198.51.100.7", Vendor: "opnsense"}
	if err := db.Gorm().Create(devO).Error; err != nil {
		t.Fatalf("create opn device: %v", err)
	}
	oif := []models.InterfaceStats{
		{DeviceID: devO.ID, Timestamp: ts, Name: "igb0", Index: 1, TypeName: "ethernet", Status: "up"}, // WAN
		{DeviceID: devO.ID, Timestamp: ts, Name: "igb1", Index: 2, TypeName: "ethernet", Status: "up"}, // LAN
	}
	if err := db.Gorm().Create(&oif).Error; err != nil {
		t.Fatalf("create opn ifaces: %v", err)
	}
	oaddr := []models.InterfaceAddress{
		{DeviceID: devO.ID, Timestamp: ts, IfIndex: 1, IPAddress: "198.51.100.7", NetMask: "255.255.255.0"}, // WAN
		{DeviceID: devO.ID, Timestamp: ts, IfIndex: 2, IPAddress: "192.168.20.1", NetMask: "255.255.255.0"}, // LAN
	}
	if err := db.Gorm().Create(&oaddr).Error; err != nil {
		t.Fatalf("create opn addrs: %v", err)
	}
	cO, recO := jsonReq(http.MethodGet, "/x", "")
	cO.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(devO.ID))}}
	h.GetIPSecEndpointHints(cO)
	var wrapO struct {
		Data ipsecHintsResponse `json:"data"`
	}
	if err := json.Unmarshal(recO.Body.Bytes(), &wrapO); err != nil {
		t.Fatal(err)
	}
	if wrapO.Data.SuggestedEgress != "igb0" {
		t.Errorf("opn suggested_egress = %q, want igb0", wrapO.Data.SuggestedEgress)
	}
	if wrapO.Data.SuggestedLAN != "igb1" {
		t.Errorf("opn suggested_lan = %q, want igb1 (must skip the WAN interface)", wrapO.Data.SuggestedLAN)
	}
	if len(wrapO.Data.LANSubnets) != 1 || wrapO.Data.LANSubnets[0] != "192.168.20.0/24" {
		t.Errorf("opn lan_subnets = %v, want [192.168.20.0/24] (WAN transit excluded)", wrapO.Data.LANSubnets)
	}

	// Never-polled device → empty hints, HTTP 200 (wizard falls back to editable).
	dev2 := &models.Device{Name: "bare", IPAddress: "1.2.3.4"}
	if err := db.Gorm().Create(dev2).Error; err != nil {
		t.Fatalf("create dev2: %v", err)
	}
	c2, rec2 := jsonReq(http.MethodGet, "/x", "")
	c2.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(dev2.ID))}}
	h.GetIPSecEndpointHints(c2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("never-polled status = %d", rec2.Code)
	}
	var wrap2 struct {
		Data ipsecHintsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &wrap2); err != nil {
		t.Fatal(err)
	}
	resp2 := wrap2.Data
	if len(resp2.Interfaces) != 0 || len(resp2.LANSubnets) != 0 || resp2.SuggestedEgress != "" {
		t.Errorf("never-polled device should yield empty hints, got %+v", resp2)
	}
}

// TestIPSec_EndpointHints_PolledOverLAN pins the phantom-self-lockout fix: a
// firewall monitored over a LAN/mgmt IP (not its WAN) must still resolve the real
// public WAN interface as egress/peer, and must NEVER auto-suggest the WAN's own
// subnet as a protected subnet — else the wizard would trip its own self_lockout
// guard on its own suggestions.
func TestIPSec_EndpointHints_PolledOverLAN(t *testing.T) {
	h, db := setupTestHandler(t)

	// device.IPAddress is the LAN/mgmt address (10.0.0.1), NOT the WAN.
	dev := &models.Device{Name: "fg-lanpoll", IPAddress: "10.0.0.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	ts := time.Now()
	ifaces := []models.InterfaceStats{
		{DeviceID: dev.ID, Timestamp: ts, Name: "port1", Index: 1, TypeName: "ethernet", Status: "up"},  // real WAN (public)
		{DeviceID: dev.ID, Timestamp: ts, Name: "mgmt", Index: 2, TypeName: "bridge", Status: "up"},     // LAN/mgmt (bears the polled IP)
		{DeviceID: dev.ID, Timestamp: ts, Name: "internal", Index: 3, TypeName: "bridge", Status: "up"}, // another LAN
	}
	if err := db.Gorm().Create(&ifaces).Error; err != nil {
		t.Fatalf("create ifaces: %v", err)
	}
	addrs := []models.InterfaceAddress{
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 1, IPAddress: "66.179.9.155", NetMask: "255.255.255.0"}, // WAN /24 (would-be self-lockout)
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 2, IPAddress: "10.0.0.1", NetMask: "255.255.255.0"},     // mgmt LAN
		{DeviceID: dev.ID, Timestamp: ts, IfIndex: 3, IPAddress: "172.16.5.1", NetMask: "255.255.255.0"},   // real LAN
	}
	if err := db.Gorm().Create(&addrs).Error; err != nil {
		t.Fatalf("create addrs: %v", err)
	}

	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(dev.ID))}}
	h.GetIPSecEndpointHints(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var wrap struct {
		Data ipsecHintsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
		t.Fatal(err)
	}
	resp := wrap.Data

	// The real public WAN interface is the egress/peer, not the mgmt iface it's polled over.
	if resp.SuggestedEgress != "port1" {
		t.Errorf("suggested_egress = %q, want port1 (the public WAN uplink, not the mgmt iface)", resp.SuggestedEgress)
	}
	if resp.SuggestedPeerIP != "66.179.9.155" {
		t.Errorf("suggested_peer_ip = %q, want 66.179.9.155 (the WAN public IP)", resp.SuggestedPeerIP)
	}
	// The WAN subnet must NOT be a protected subnet; the real LANs are.
	for _, s := range resp.LANSubnets {
		if s == "66.179.9.0/24" {
			t.Error("the WAN subnet 66.179.9.0/24 must NEVER be an auto-suggested protected subnet (phantom self-lockout)")
		}
	}
	// Belt-and-suspenders: no auto-suggested subnet may contain the peer's WAN IP.
	peer := net.ParseIP(resp.SuggestedPeerIP)
	for _, s := range resp.LANSubnets {
		if _, n, err := net.ParseCIDR(s); err == nil && peer != nil && n.Contains(peer) {
			t.Errorf("lan_subnet %s contains the peer WAN IP %s — would self-lockout", s, resp.SuggestedPeerIP)
		}
	}
	// The genuine LAN behind the firewall is suggested.
	found := false
	for _, s := range resp.LANSubnets {
		if s == "172.16.5.0/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the real LAN 172.16.5.0/24 in lan_subnets, got %v", resp.LANSubnets)
	}
}
