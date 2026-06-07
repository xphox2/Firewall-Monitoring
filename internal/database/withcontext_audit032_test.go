package database

import (
	"context"
	"errors"
	"testing"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// TestWithContext_AUDIT032 pins the request-context propagation mechanism: a
// Database bound via WithContext runs its queries on the given context (so a
// client disconnect cancels them), the original Database is untouched, and the
// single bound copy is safely reusable across many queries + a transaction
// (gorm's WithContext returns a reusable session).
func TestWithContext_AUDIT032(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// (a) Structural: WithContext binds ctx onto the session, original untouched.
	ctx, cancel := context.WithCancel(context.Background())
	cdb := d.WithContext(ctx)
	if cdb == d {
		t.Fatal("WithContext returned the same *Database, not a copy (AUDIT-032)")
	}
	if cdb.Gorm().Statement.Context != ctx {
		t.Fatalf("WithContext did not bind the context onto the gorm session (AUDIT-032)")
	}
	if d.Gorm().Statement.Context == ctx {
		t.Fatal("WithContext mutated the original Database's context (AUDIT-032)")
	}

	// (b) Behavioral: an already-cancelled context fails the query.
	cancel()
	if err := cdb.Gorm().Exec("SELECT 1").Error; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context did not cancel the query (AUDIT-032): got %v", err)
	}

	// (c) Reuse: one live-ctx copy runs several independent queries + a tx.
	live := d.WithContext(context.Background())
	var n int64
	if err := live.Gorm().Model(&models.Device{}).Count(&n).Error; err != nil {
		t.Fatalf("count on reused session: %v", err)
	}
	var devices []models.Device
	if err := live.Gorm().Where("1 = 1").Find(&devices).Error; err != nil {
		t.Fatalf("find on reused session: %v", err)
	}
	if err := live.Gorm().Transaction(func(tx *gorm.DB) error { return nil }); err != nil {
		t.Fatalf("transaction on reused session: %v", err)
	}
}
