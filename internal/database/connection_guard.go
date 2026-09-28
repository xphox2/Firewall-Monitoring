package database

import (
	"fmt"
	"log"
	"sync"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// autoConnSkipLog records the device pairs an auto-connection upsert refused
// because an endpoint is retired or missing. It exists to log each pair once
// per process (the poller would otherwise repeat the line every cycle) and to
// let callers prove a detector never offered such a pair.
//
// A POINTER on Database for the same reason as ingest: WithContext
// shallow-copies the struct, and every copy must share one record.
// nil-receiver-safe, so a Database{} literal still works.
type autoConnSkipLog struct {
	pairs sync.Map // pairKey -> struct{}
	mu    sync.Mutex
	count int
}

func newAutoConnSkipLog() *autoConnSkipLog { return &autoConnSkipLog{} }

func (l *autoConnSkipLog) record(sourceID, destID uint, connType string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.count++
	l.mu.Unlock()
	key := fmt.Sprintf("%d:%d:%s", sourceID, destID, connType)
	if _, seen := l.pairs.LoadOrStore(key, struct{}{}); !seen {
		log.Printf("Auto-connection: skipped %s pair %d <-> %d (an endpoint is retired or missing); logged once per process", connType, sourceID, destID)
	}
}

// AutoConnectionSkipCount reports how many auto-connection upserts were
// refused because an endpoint is retired or missing. The poller filters such
// pairs itself, so a non-zero value means a detector offered a pair it should
// have dropped. Diagnostic; the poller's tests assert it stays zero.
func (d *Database) AutoConnectionSkipCount() int {
	if d.connSkips == nil {
		return 0
	}
	d.connSkips.mu.Lock()
	defer d.connSkips.mu.Unlock()
	return d.connSkips.count
}

// bothDevicesActive reports whether both ids are existing, non-retired devices.
// It is the backstop behind the poller's own filter: whatever path offers a
// pair, a connection to a retired device is never written.
func (d *Database) bothDevicesActive(a, b uint) (bool, error) {
	want := int64(2)
	if a == b {
		want = 1
	}
	var n int64
	if err := d.db.Model(&models.Device{}).Scopes(ActiveDevices).
		Where("id IN ?", []uint{a, b}).Count(&n).Error; err != nil {
		return false, err
	}
	return n == want, nil
}

// ActiveConnections limits a device_connections query to rows whose two
// endpoints are active devices. RetireDevice deletes a retired device's
// connections, but a row can predate that or be written by a path that missed
// it; the lists, maps and status reads must never show it.
func ActiveConnections(db *gorm.DB) *gorm.DB {
	return db.Where("source_device_id IN (SELECT id FROM devices WHERE retired_at IS NULL) AND dest_device_id IN (SELECT id FROM devices WHERE retired_at IS NULL)")
}
