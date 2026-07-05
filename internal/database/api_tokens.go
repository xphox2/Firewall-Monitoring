package database

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// API-token persistence (P0-2). Same at-rest discipline as probe registration
// keys (probekey.go): hashed with a "sha256:" marker prefix, deliberately
// non-idempotent hashing, by-value lookup plus constant-time compare. The two
// credential domains stay separate on purpose (distinct functions, distinct
// plaintext shapes — tokens carry the "fwm_" prefix, probe keys are bare hex)
// so neither can ever be accepted where the other is expected.

const apiTokenHashPrefix = "sha256:"

// APITokenPlaintextPrefix marks every API-token plaintext. It guarantees a
// token can never collide with a probe registration key and lets the auth
// middleware cheaply decide whether a Bearer value is even a candidate.
const APITokenPlaintextPrefix = "fwm_"

// HashAPIToken returns the at-rest form: "sha256:"+hex(SHA-256(plaintext)).
// Like HashProbeKey this ALWAYS hashes — presenting a leaked stored hash as
// the bearer token double-hashes and fails to match (see probekey.go for the
// full rationale).
func HashAPIToken(s string) string {
	if s == "" {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return apiTokenHashPrefix + hex.EncodeToString(sum[:])
}

// LookupAPIToken resolves a presented plaintext bearer token to its row, or
// nil when it does not exist. Hashing happens here so callers (the auth
// middleware) never handle hashes; the trailing constant-time compare is
// belt-and-braces on top of the by-value lookup, matching the probe-key auth
// path. Validity (expiry/revocation) is the caller's decision — this is pure
// resolution.
func (d *Database) LookupAPIToken(plaintext string) (*models.ApiToken, error) {
	if !strings.HasPrefix(plaintext, APITokenPlaintextPrefix) {
		return nil, nil
	}
	hash := HashAPIToken(plaintext)
	var tok models.ApiToken
	err := d.db.Where("token_hash = ?", hash).First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(tok.TokenHash), []byte(hash)) != 1 {
		return nil, nil
	}
	return &tok, nil
}

func (d *Database) CreateAPIToken(tok *models.ApiToken) error {
	return d.db.Create(tok).Error
}

func (d *Database) ListAPITokens() ([]models.ApiToken, error) {
	var toks []models.ApiToken
	err := d.db.Order("created_at DESC").Find(&toks).Error
	return toks, err
}

// RevokeAPIToken soft-revokes (sets revoked_at) so the row keeps its identity
// for the audit trail; the auth middleware rejects any token with RevokedAt
// set.
func (d *Database) RevokeAPIToken(id uint) error {
	return d.db.Model(&models.ApiToken{}).Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", time.Now()).Error
}

// revokeAPITokensForAdmin soft-revokes every live token the given admin
// created (LC-15, defense in depth). Runs on the passed handle so the
// disable/delete flows can include it in their own transaction; the
// authoritative enforcement is the auth middleware re-checking the creator's
// state on every bearer request.
func revokeAPITokensForAdmin(tx *gorm.DB, adminID uint) error {
	return tx.Model(&models.ApiToken{}).
		Where("created_by_id = ? AND revoked_at IS NULL", adminID).
		Update("revoked_at", time.Now()).Error
}

func (d *Database) TouchAPITokenLastUsed(id uint, t time.Time) error {
	return d.db.Model(&models.ApiToken{}).Where("id = ?", id).
		UpdateColumn("last_used_at", t).Error
}
