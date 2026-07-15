package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestBuildPGXURL_UnixSocketHost is the regression for the silent pgxpool
// downgrade: the single-container prod deployment sets DB_HOST to the unix
// socket directory (/var/run/postgresql), which the old postgres:// URL form
// mangled into database "run/postgresql:5432/firewall_mon" — the pool failed
// its ping and SaveFlowSamples ran on the ~2x slower GORM fallback. The DSN
// must parse to the same fields the GORM key=value DSN carries.
func TestBuildPGXURL_UnixSocketHost(t *testing.T) {
	cfg := &config.Config{}
	cfg.Database.Host = "/var/run/postgresql"
	cfg.Database.Port = 5432
	cfg.Database.User = "fwmon"
	cfg.Database.Password = "p w'd\\x" // space, quote, backslash — pgQuote territory
	cfg.Database.Name = "firewall_mon"
	cfg.Database.SSLMode = "disable"
	cfg.Database.StatementTimeout = 30 * time.Second

	pc, err := pgxpool.ParseConfig(buildPGXURL(cfg))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cc := pc.ConnConfig
	if cc.Host != "/var/run/postgresql" {
		t.Errorf("Host = %q, want /var/run/postgresql", cc.Host)
	}
	if cc.Database != "firewall_mon" {
		t.Errorf("Database = %q, want firewall_mon", cc.Database)
	}
	if cc.User != "fwmon" {
		t.Errorf("User = %q, want fwmon", cc.User)
	}
	if cc.Password != "p w'd\\x" {
		t.Errorf("Password not round-tripped: %q", cc.Password)
	}
	if cc.Port != 5432 {
		t.Errorf("Port = %d, want 5432", cc.Port)
	}
}

// TestBuildPGXURL_TCPHost: the ordinary host:port shape keeps working.
func TestBuildPGXURL_TCPHost(t *testing.T) {
	cfg := &config.Config{}
	cfg.Database.Host = "db.example.internal"
	cfg.Database.Port = 5433
	cfg.Database.User = "fwmon"
	cfg.Database.Password = "plain"
	cfg.Database.Name = "firewall_mon"
	cfg.Database.SSLMode = "require"

	pc, err := pgxpool.ParseConfig(buildPGXURL(cfg))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if pc.ConnConfig.Host != "db.example.internal" || pc.ConnConfig.Port != 5433 {
		t.Errorf("host/port = %q/%d", pc.ConnConfig.Host, pc.ConnConfig.Port)
	}
}
