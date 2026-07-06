package database

import (
	"net/netip"
	"time"

	"firewall-mon/internal/models"
)

// GeoBackfillResult reports the progress/outcome of BackfillFlowGeo.
type GeoBackfillResult struct {
	Scanned uint64 // rows examined
	Updated uint64 // rows that gained geo/ASN
	LastID  uint64 // highest flow_samples.id processed (pass as fromID to resume)
}

// backfillPublicIP reports whether ip is a public address worth a geo lookup
// (mirrors the resolver's own skip logic — private/loopback/link-local IPs have
// no geo).
func backfillPublicIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsValid() {
		return false
	}
	return !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!a.IsLinkLocalMulticast() && !a.IsUnspecified() && !a.IsMulticast()
}

// BackfillFlowGeo re-resolves country/ASN/org for flow_samples rows still missing
// them and writes only the changed rows, in ascending-id batches. It is
// idempotent (a re-run is a fast no-op once everything is filled) and resumable
// (pass the previous LastID as fromID). resolve returns (country, asn, org) for
// one IP. between is a pause after each batch to spare a busy prod DB.
func (d *Database) BackfillFlowGeo(resolve func(ip string) (string, uint32, string), fromID uint64, batch int, between time.Duration, progress func(GeoBackfillResult)) (GeoBackfillResult, error) {
	if batch <= 0 {
		batch = 5000
	}
	var res GeoBackfillResult
	cursor := fromID

	type row struct {
		ID         uint
		SrcAddr    string
		DstAddr    string
		SrcCountry string
		DstCountry string
		SrcASN     uint32
		DstASN     uint32
		SrcASNOrg  string
		DstASNOrg  string
	}

	// apply resolves one endpoint and stages any newly-available geo columns.
	apply := func(ip, curCC string, curASN uint32, curOrg, ccCol, asnCol, orgCol string, upd map[string]any) {
		if !backfillPublicIP(ip) || (curCC != "" && curASN != 0 && curOrg != "") {
			return
		}
		cc, asn, org := resolve(ip)
		if curCC == "" && cc != "" {
			upd[ccCol] = cc
		}
		if curASN == 0 && asn != 0 {
			upd[asnCol] = asn
		}
		if curOrg == "" && org != "" {
			upd[orgCol] = org
		}
	}

	for {
		var rows []row
		if err := d.db.Model(&models.FlowSample{}).
			Select("id, src_addr, dst_addr, src_country, dst_country, src_asn, dst_asn, src_asn_org, dst_asn_org").
			Where("id > ?", cursor).Order("id").Limit(batch).Scan(&rows).Error; err != nil {
			return res, err
		}
		if len(rows) == 0 {
			break
		}
		tx := d.db.Begin()
		for i := range rows {
			r := rows[i]
			cursor = uint64(r.ID)
			res.Scanned++
			upd := map[string]any{}
			apply(r.SrcAddr, r.SrcCountry, r.SrcASN, r.SrcASNOrg, "src_country", "src_asn", "src_asn_org", upd)
			apply(r.DstAddr, r.DstCountry, r.DstASN, r.DstASNOrg, "dst_country", "dst_asn", "dst_asn_org", upd)
			if len(upd) == 0 {
				continue
			}
			if err := tx.Model(&models.FlowSample{}).Where("id = ?", r.ID).Updates(upd).Error; err != nil {
				tx.Rollback()
				return res, err
			}
			res.Updated++
		}
		if err := tx.Commit().Error; err != nil {
			return res, err
		}
		res.LastID = cursor
		if progress != nil {
			progress(res)
		}
		if between > 0 {
			time.Sleep(between)
		}
	}
	res.LastID = cursor
	return res, nil
}
