package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// ErrIPSecConcurrentDeploy is returned by TransitionIPSecDeploy when the tunnel's
// status isn't in the expected set — i.e. a concurrent deploy/rollback already
// moved it, or it's in a state that forbids the transition. Handlers map it to
// HTTP 409 so a second concurrent deploy can't double-write the device.
var ErrIPSecConcurrentDeploy = errors.New("ipsec: tunnel busy or not in a deployable state")

// IPSec tunnel persistence for the provisioning wizard. The structured
// vendor-neutral intent (ipsec.TunnelIntent) is stored as IntentJSON WITHOUT the
// PSK; the PSK lives in its own column, encrypted at rest via the field crypto,
// and is never serialized into IntentJSON or returned unmasked by handlers.

// redactedMask mirrors httputil.RedactedMask; duplicated here to keep the
// database layer from importing the http layer. A PSK equal to this on update
// means "unchanged".
const redactedMask = "********"

// IPSecIntentToModel serializes a vendor-neutral intent into a persistable row.
// The PSK is split out of IntentJSON into the (to-be-encrypted) PSK column.
func IPSecIntentToModel(t *ipsec.TunnelIntent) (*models.IPSecTunnel, error) {
	clone := *t
	clone.PSK = "" // never persist the PSK inside IntentJSON
	blob, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("marshal ipsec intent: %w", err)
	}
	return &models.IPSecTunnel{
		ID:         t.ID,
		Name:       t.Name,
		Enabled:    t.Enabled,
		ADeviceID:  t.Ends[0].DeviceID,
		BDeviceID:  t.Ends[1].DeviceID,
		AVendor:    t.Ends[0].Vendor,
		BVendor:    t.Ends[1].Vendor,
		IntentJSON: string(blob),
		PSK:        t.PSK, // plaintext here; encrypted by the store on write
	}, nil
}

// IPSecModelToIntent reconstructs the runtime intent from a stored row, folding
// the (already-decrypted) PSK back in.
func IPSecModelToIntent(m *models.IPSecTunnel) (*ipsec.TunnelIntent, error) {
	var t ipsec.TunnelIntent
	if m.IntentJSON != "" {
		if err := json.Unmarshal([]byte(m.IntentJSON), &t); err != nil {
			return nil, fmt.Errorf("unmarshal ipsec intent %d: %w", m.ID, err)
		}
	}
	t.ID = m.ID
	t.Name = m.Name
	t.Enabled = m.Enabled
	t.PSK = m.PSK
	return &t, nil
}

// CreateIPSecTunnel persists a new tunnel row, encrypting the PSK at rest.
func (d *Database) CreateIPSecTunnel(m *models.IPSecTunnel) error {
	psk, err := d.EncryptField(m.PSK)
	if err != nil {
		return fmt.Errorf("create ipsec tunnel: %w", err)
	}
	m.PSK = psk
	if m.Status == "" {
		m.Status = "draft"
	}
	return d.db.Create(m).Error
}

// GetIPSecTunnel loads a tunnel and decrypts its PSK in place.
func (d *Database) GetIPSecTunnel(id uint) (*models.IPSecTunnel, error) {
	var m models.IPSecTunnel
	if err := d.db.First(&m, id).Error; err != nil {
		return nil, err
	}
	m.PSK = d.DecryptField(m.PSK)
	return &m, nil
}

// ListIPSecTunnels returns all tunnels (newest first). PSK is left encrypted —
// list responses never expose it.
func (d *Database) ListIPSecTunnels() ([]models.IPSecTunnel, error) {
	var ms []models.IPSecTunnel
	err := d.db.Order("id DESC").Find(&ms).Error
	for i := range ms {
		ms[i].PSK = "" // never leak even the ciphertext in a list
	}
	return ms, err
}

// ProvisionedTunnelPair is the authoritative endpoint pair of a tunnel THIS
// system deployed, keyed by its name.
//
// Subnets carries each end's protected selectors so a caller can recognise an
// unnamed tunnel row by the traffic it carries. They are resolved here rather
// than by the caller because they live inside the serialized intent, not in a
// promoted column, and reading them correctly means going through the intent
// accessors — which is this package's job, not the poller's.
type ProvisionedTunnelPair struct {
	Name string
	A    uint
	B    uint
	// ASubnets/BSubnets are the protected subnets of ends A and B respectively.
	ASubnets []string
	BSubnets []string
	// EnabledPaths are the (A-side, B-side) subnet pairs the tunnel actually
	// provisions, once individually disabled paths are removed.
	//
	// Carried as PAIRS because the enabled set generally cannot be expressed as
	// two lists: disable one path of a 2x2 and the surviving three are not the
	// cross product of any pair of lists. Filtering ASubnets/BSubnets instead
	// would be a no-op precisely when it matters, since every subnet still has
	// at least one enabled path.
	//
	// Meaningful only when PathDetail is true.
	EnabledPaths [][2]string
	// PathDetail says EnabledPaths is authoritative. It exists because an empty
	// EnabledPaths is otherwise ambiguous between "route-based, so there are no
	// pairs and the flat lists are what to match on" and "policy-based with
	// every path switched off, so this tunnel carries nothing" — opposite
	// answers to the same question.
	PathDetail bool
}

// PathsFor returns this tunnel's enabled subnet pairs oriented for deviceID —
// (local, remote) from that device's point of view. ok is false if deviceID is
// not an endpoint, or if the tunnel has no pair-level detail (route-based).
func (p ProvisionedTunnelPair) PathsFor(deviceID uint) (paths [][2]string, ok bool) {
	if !p.PathDetail {
		return nil, false
	}
	switch deviceID {
	case p.A:
		return p.EnabledPaths, true
	case p.B:
		flipped := make([][2]string, 0, len(p.EnabledPaths))
		for _, pr := range p.EnabledPaths {
			flipped = append(flipped, [2]string{pr[1], pr[0]})
		}
		return flipped, true
	}
	return nil, false
}

// SubnetsFor returns the protected subnets of whichever end is deviceID, and
// those of its peer. ok is false if deviceID is not part of this tunnel.
func (p ProvisionedTunnelPair) SubnetsFor(deviceID uint) (local, remote []string, ok bool) {
	switch deviceID {
	case p.A:
		return p.ASubnets, p.BSubnets, true
	case p.B:
		return p.BSubnets, p.ASubnets, true
	}
	return nil, nil, false
}

// GetProvisionedTunnelPairs returns lower(name) → endpoint pair for every tunnel
// whose configuration may currently be on the devices.
//
// It exists so the connection-map detector can stop *guessing* who a tunnel
// connects. Peer attribution is otherwise derived from the tunnel's remote IP,
// which is structurally wrong for a dialup peer behind NAT: the address observed
// by the responder is the NAT gateway's, so the tunnel is attributed to whatever
// monitored device owns that public IP rather than to the peer sitting behind
// it. For a tunnel we provisioned, the endpoints are a recorded fact.
//
// STATE FILTER: only draft and rolled_back are excluded — the two states where
// the config is definitively not on the devices. Everything else (including
// rollback_failed and error, where config is very likely still live) is trusted,
// because if a device reports a tunnel by that name the recorded pair is the
// truth about it.
//
// Callers MUST additionally check that the device reporting the tunnel is one of
// the returned pair. vpn_status.tunnel_name is free text read off a device and
// only ipsec_tunnels.name is unique, so an unrelated device reporting a
// same-named tunnel would otherwise attribute a pair it has nothing to do with.
func (d *Database) GetProvisionedTunnelPairs() (map[string]ProvisionedTunnelPair, error) {
	var ms []models.IPSecTunnel
	err := d.db.
		Select("name", "a_device_id", "b_device_id", "intent_json").
		Where("status NOT IN ?", []string{"draft", "rolled_back"}).
		Find(&ms).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]ProvisionedTunnelPair, len(ms))
	for i := range ms {
		m := ms[i]
		// A tunnel with an unresolved endpoint can't attribute anything.
		if m.Name == "" || m.ADeviceID == 0 || m.BDeviceID == 0 {
			continue
		}
		p := ProvisionedTunnelPair{Name: m.Name, A: m.ADeviceID, B: m.BDeviceID}
		// Selectors are best-effort: a tunnel whose intent won't decode can still
		// attribute by name, which is the primary job. Losing the subnets only
		// costs the caller the ability to recognise unnamed rows.
		if in, ierr := IPSecModelToIntent(&m); ierr == nil && in != nil {
			p.ASubnets = append([]string(nil), in.Ends[0].ProtectedSubnets...)
			p.BSubnets = append([]string(nil), in.Ends[1].ProtectedSubnets...)
			// Pair-level detail only where pairs exist. Route-based negotiates a
			// single 0.0.0.0/0 selector, and PathsFor reports exactly that — which
			// would match every row on the box if used for attribution, so it is
			// deliberately left nil and the subnet lists stay authoritative there.
			if in.Mode == ipsec.ModePolicyBased {
				p.PathDetail = true
				for _, path := range in.PathsFor(0) {
					if path.Enabled {
						p.EnabledPaths = append(p.EnabledPaths, [2]string{path.Local, path.Remote})
					}
				}
			}
		}
		out[strings.ToLower(m.Name)] = p
	}
	return out, nil
}

// UpdateIPSecTunnel updates a tunnel. A PSK equal to the redaction mask (or
// empty) is treated as "leave unchanged" so a round-tripped masked value can't
// clobber the stored secret; any other value is re-encrypted.
func (d *Database) UpdateIPSecTunnel(m *models.IPSecTunnel) error {
	fields := map[string]interface{}{
		"name":        m.Name,
		"enabled":     m.Enabled,
		"status":      m.Status,
		"last_error":  m.LastError,
		"a_device_id": m.ADeviceID,
		"b_device_id": m.BDeviceID,
		"a_vendor":    m.AVendor,
		"b_vendor":    m.BVendor,
		"intent_json": m.IntentJSON,
	}
	if m.PSK != "" && m.PSK != redactedMask {
		psk, err := d.EncryptField(m.PSK)
		if err != nil {
			return fmt.Errorf("update ipsec tunnel: %w", err)
		}
		fields["psk"] = psk
	}
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", m.ID).Updates(fields).Error
}

// UpdateIPSecTunnelStatus is the deploy-saga fast path: set status + last_error
// without touching config or deploy state. Use MarkIPSecTunnelDeployed when a
// transition to a deployed state must also stamp last_deployed_at.
func (d *Database) UpdateIPSecTunnelStatus(id uint, status, lastErr string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr}).Error
}

// MarkIPSecTunnelDeployed sets status + last_error AND stamps last_deployed_at =
// now — the deploy-succeeded path (fixes the old UpdateIPSecTunnelStatus, whose
// doc claimed to set last_deployed_at but never did).
func (d *Database) MarkIPSecTunnelDeployed(id uint, status, lastErr string) error {
	now := time.Now()
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr, "last_deployed_at": now}).Error
}

// ClearIPSecDeployState sets status + last_error AND clears deploy_json — the
// successful-rollback path, so the tunnel becomes eligible for edit/delete again
// (the "delete-allowed-from-empty-deploy" rule).
func (d *Database) ClearIPSecDeployState(id uint, status, lastErr string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "last_error": lastErr, "deploy_json": ""}).Error
}

// SetIPSecRollbackState updates status + deploy_json only (records the rollback
// command IDs on an existing deploy record). Used when the rollback poll needs to
// persist intermediate state without touching last_deployed_at.
func (d *Database) SetIPSecRollbackState(id uint, status, deployJSON string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "deploy_json": deployJSON}).Error
}

// SetIPSecPreflightState records the per-end preflight command IDs on the tunnel
// (AUDIT-258). Written after the preflight commands are enqueued so the status
// poll can read each end's OWN command by ID (tunnel-scoped) rather than the
// device's latest preflight command. Touches only preflight_json — never status
// or deploy_json, so it is independent of the deploy saga.
func (d *Database) SetIPSecPreflightState(id uint, preflightJSON string) error {
	return d.db.Model(&models.IPSecTunnel{}).Where("id = ?", id).
		Update("preflight_json", preflightJSON).Error
}

// TransitionIPSecDeploy atomically (1) UPDATEs the tunnel's status + last_error +
// deploy_json (+ last_deployed_at when setDeployedAt), guarded on its current
// status being in fromStatuses (optimistic lock — 0 rows affected ⇒
// ErrIPSecConcurrentDeploy), and (2) enqueues each command in the SAME
// transaction. Either all of it commits or none does, so a status poll can never
// observe a deploy_json whose command rows don't exist yet, two concurrent
// deploys can't both pass the guard and double-write, and every terminal poll
// outcome (deploying/degraded/error/rolling_back) is exactly ONE guarded write —
// the caller must NEVER chain a second status/deploy_json setter after this (that
// reopens the terminal-write race). The caller pre-generates each cmd.CommandID
// and records it in deployJSON before calling.
func (d *Database) TransitionIPSecDeploy(id uint, fromStatuses []string, toStatus, lastErr, deployJSON string, setDeployedAt bool, cmds []*models.ProbeCommand) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		fields := map[string]interface{}{
			"status":      toStatus,
			"last_error":  lastErr,
			"deploy_json": deployJSON,
		}
		if setDeployedAt {
			fields["last_deployed_at"] = time.Now()
		}
		res := tx.Model(&models.IPSecTunnel{}).
			Where("id = ? AND status IN ?", id, fromStatuses).
			Updates(fields)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrIPSecConcurrentDeploy
		}
		for _, cmd := range cmds {
			if err := d.enqueueProbeCommandTx(tx, cmd); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteIPSecTunnel removes a tunnel row.
func (d *Database) DeleteIPSecTunnel(id uint) error {
	return d.db.Delete(&models.IPSecTunnel{}, id).Error
}

// IPSecRollbackStatusRollingBack is the one status a rollback can be resolved
// from. Kept as a literal here rather than imported from the handler package:
// the database layer must not depend on the http layer.
const IPSecRollbackStatusRollingBack = "rolling_back"

// IPSecRollbackStatusRolledBack / IPSecRollbackStatusRollbackFailed are the two
// terminals a rollback can reach.
const (
	IPSecRollbackStatusRolledBack     = "rolled_back"
	IPSecRollbackStatusRollbackFailed = "rollback_failed"
)

// ipsecRollbackReportView is the minimal shape of the collector's apply report
// the rollback terminal evaluation needs. It carries no secrets.
type ipsecRollbackReportView struct {
	Applied bool   `json:"applied"`
	Error   string `json:"error"`
}

// ipsecFirstNonEmpty returns the first non-blank value, or "".
func ipsecFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ResolveIPSecRollback advances a rolling_back tunnel to its terminal state.
//
// done=false while commands are still in flight. Performs EXACTLY ONE guarded
// write when it reaches a terminal (the F2 invariant at TransitionIPSecDeploy) —
// the caller must never chain a second status/deploy_json setter.
//
// This is the ONE implementation of the rollback terminal rules. It is called
// by the deploy poll, by the bulk orphaned-rollback endpoint and by the
// background reconciler, so all three agree on what "rolled back" means.
//
// Terminal rules (preserved verbatim from the poll):
//   - a SKIPPED end (its device was retired or purged, so there is nothing left
//     to clean) counts as DONE, not as a failure — its reason is appended to
//     the terminal reason so the operator sees what was not touched;
//   - a non-skipped end marked RollbackUnproven still forces rollback_failed
//     even on a clean-looking report — a skipped OPNsense remove proves
//     nothing about the device's state;
//   - a lost race (another writer already wrote the terminal) is benign: the
//     guarded write affects 0 rows and the current row is re-read.
func (d *Database) ResolveIPSecRollback(id uint) (status, reason string, done bool, err error) {
	var m models.IPSecTunnel
	if e := d.db.First(&m, id).Error; e != nil {
		return "", "", false, e
	}
	if m.Status != IPSecRollbackStatusRollingBack {
		// Not ours to resolve — already terminal, or never started.
		return m.Status, m.LastError, true, nil
	}

	var st ipsec.DeployState
	if strings.TrimSpace(m.DeployJSON) != "" {
		if e := json.Unmarshal([]byte(m.DeployJSON), &st); e != nil {
			return m.Status, "", false, fmt.Errorf("decode deploy state %d: %w", id, e)
		}
	}
	if st.Rollback == nil || len(st.Ends) == 0 {
		// A rollback was started but its record is gone/malformed. Nothing can be
		// proven, so this is an honest failure — never a silent clean.
		return d.writeIPSecRollbackTerminal(id, m, IPSecRollbackStatusRollbackFailed,
			"the rollback record is missing — verify the device manually", m.DeployJSON)
	}

	doneEnds, anyFail := 0, false
	var reasons []string
	for i := range st.Ends {
		e := st.Ends[i]
		label := fmt.Sprintf("end %c", 'A'+e.End)
		cid, skipped, skipReason, failReason := "", false, "", ""
		if i < len(st.Rollback.Ends) {
			re := st.Rollback.Ends[i]
			cid, skipped, skipReason, failReason = re.CommandID, re.Skipped, re.SkipReason, re.FailReason
		} else if i < len(st.Rollback.CommandIDs) {
			// LEGACY fallback: records written before per-end rollbacks carry only
			// the index-aligned CommandIDs.
			cid = st.Rollback.CommandIDs[i]
		}
		if skipped {
			// The device is gone (retired or purged): there is nothing to clean,
			// so this is DONE — not a failure. The reason is surfaced so the
			// operator knows which objects (if any) may still be on the device.
			doneEnds++
			if skipReason != "" {
				reasons = append(reasons, skipReason)
			}
			continue
		}
		if failReason != "" {
			// The end was attempted but could not be built — a live device that
			// genuinely cannot be cleaned. A real failure.
			doneEnds++
			anyFail = true
			reasons = append(reasons, failReason)
			continue
		}
		if cid == "" {
			doneEnds++
			anyFail = true
			reasons = append(reasons, label+": a rollback command was not recorded — verify the device")
			continue
		}
		cmd, cerr := d.GetProbeCommandByCommandID(cid)
		if cerr != nil {
			return m.Status, "", false, cerr
		}
		if cmd == nil { // pruned/missing → terminal-unknown
			doneEnds++
			anyFail = true
			reasons = append(reasons, label+": a rollback command result was lost — verify the device")
			continue
		}
		switch cmd.Status {
		case ProbeCommandStatusSucceeded:
			doneEnds++
			var rv ipsecRollbackReportView
			if json.Unmarshal([]byte(cmd.Result), &rv) != nil {
				anyFail = true
				reasons = append(reasons, label+": rollback report unparseable")
			} else if !rv.Applied {
				anyFail = true
				reasons = append(reasons, label+": "+ipsecFirstNonEmpty(rv.Error, "some objects could not be removed"))
			} else if e.RollbackUnproven {
				anyFail = true
				reasons = append(reasons, label+" apply outcome was unknown and rollback could not prove the device is clean — verify manually")
			}
		case ProbeCommandStatusFailed, ProbeCommandStatusExpired:
			doneEnds++
			anyFail = true
			reasons = append(reasons, label+": "+ipsecFirstNonEmpty(cmd.Result, "rollback command failed"))
		default:
			// pending/dispatched — the command is still in flight.
		}
	}

	if doneEnds < len(st.Ends) {
		// Still rolling back.
		return m.Status, "", false, nil
	}

	if anyFail {
		msg := strings.Join(reasons, "; ")
		return d.writeIPSecRollbackTerminal(id, m, IPSecRollbackStatusRollbackFailed, msg, m.DeployJSON)
	}
	// Preserve WHY we rolled back: the deploy→rolling_back transition stored the
	// deploy-failure reason (or "operator-initiated rollback") in last_error.
	base := "rolled back — " + ipsecFirstNonEmpty(m.LastError, "deploy failed")
	if len(reasons) > 0 {
		base += " (" + strings.Join(reasons, "; ") + ")"
	}
	// The deploy_json record is CLEARED on a clean rollback so the tunnel becomes
	// eligible for edit/delete again (the "delete-allowed-from-empty-deploy" rule).
	return d.writeIPSecRollbackTerminal(id, m, IPSecRollbackStatusRolledBack, base, "")
}

// writeIPSecRollbackTerminal performs the ONE guarded write that moves a
// rolling_back tunnel to its terminal status. A lost race (another writer — the
// UI poll or the reconciler — already wrote the terminal) is benign: the guarded
// write affects 0 rows and the current row is re-read so the caller still sees
// the winner's status and reason.
func (d *Database) writeIPSecRollbackTerminal(id uint, m models.IPSecTunnel, status, reason, deployJSON string) (string, string, bool, error) {
	terr := d.TransitionIPSecDeploy(id, []string{IPSecRollbackStatusRollingBack}, status, reason, deployJSON, false, nil)
	if terr == nil {
		return status, reason, true, nil
	}
	if errors.Is(terr, ErrIPSecConcurrentDeploy) {
		var cur models.IPSecTunnel
		if e := d.db.First(&cur, id).Error; e != nil {
			return status, reason, true, e
		}
		return cur.Status, cur.LastError, true, nil
	}
	return status, reason, false, terr
}

// ListIPSecTunnelsByStatus returns the ids of every tunnel in one of the given
// statuses. It is the focused query the rollback reconciler uses — deliberately
// NOT ListIPSecTunnels, which loads every intent (and every PSK ciphertext)
// just to find the handful of rows that are rolling back.
func (d *Database) ListIPSecTunnelsByStatus(statuses []string) ([]uint, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	var ids []uint
	err := d.db.Model(&models.IPSecTunnel{}).
		Where("status IN ?", statuses).
		Order("id ASC").
		Pluck("id", &ids).Error
	return ids, err
}
