package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
)

// runResetAuthCmd implements the break-glass `fwmon-api reset-auth --user
// <name> [--keep-2fa] [--keep-passkeys]` (v0.11.277). It works with
// no web UI and no running API: it connects straight to the database and, in
// one transaction (database.ResetAuth), sets a new random temporary password
// (printed once), flags must_change_password, clears TOTP + recovery codes
// (unless --keep-2fa), deletes every passkey (unless --keep-passkeys), bumps
// token_version (ending every session) and writes an audit_logs row.
//
// In the container it is run through the fwmon-reset-auth wrapper, which
// loads the same DB environment entrypoint.sh exports:
//
//	docker exec -it <container> fwmon-reset-auth --user <name>
//
// Returns the process exit code.
func runResetAuthCmd(args []string) int {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "reset-auth: configuration error: %v\n", err)
		return 1
	}
	return resetAuth(cfg, args, os.Stdout, os.Stderr, func() (resetAuthStore, error) {
		db, err := database.Connect(cfg)
		if err != nil {
			return nil, err
		}
		return db, nil
	})
}

// resetAuthStore is the slice of *database.Database the command needs.
type resetAuthStore interface {
	ResetAuth(username, passwordHash string, keep2FA, keepPasskeys bool) (*database.ResetAuthResult, error)
	Close() error
}

// resetAuth is the testable core of runResetAuthCmd.
func resetAuth(cfg *config.Config, args []string, stdout, stderr io.Writer, open func() (resetAuthStore, error)) int {
	fs := flag.NewFlagSet("reset-auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	user := fs.String("user", "", "username of the account to reset (required)")
	keep2FA := fs.Bool("keep-2fa", false, "keep the account's TOTP 2FA and recovery codes")
	keepPasskeys := fs.Bool("keep-passkeys", false, "keep the account's passkeys")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: fwmon-api reset-auth --user <name> [--keep-2fa] [--keep-passkeys]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	username := strings.TrimSpace(*user)
	if username == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}

	tempPassword, err := auth.GenerateSecureToken(20)
	if err != nil {
		fmt.Fprintf(stderr, "reset-auth: generate password: %v\n", err)
		return 1
	}
	hash, err := auth.NewAuthManager(cfg, nil).HashPassword(tempPassword)
	if err != nil {
		fmt.Fprintf(stderr, "reset-auth: hash password: %v\n", err)
		return 1
	}

	db, err := open()
	if err != nil {
		fmt.Fprintf(stderr, "reset-auth: connect to database: %v\n", err)
		return 1
	}
	defer db.Close()

	res, err := db.ResetAuth(username, hash, *keep2FA, *keepPasskeys)
	if err != nil {
		fmt.Fprintf(stderr, "reset-auth: %v (nothing was changed)\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Account %q (id %d) has been reset.\n", username, res.AdminID)
	fmt.Fprintf(stdout, "  Temporary password (shown ONCE): %s\n", tempPassword)
	fmt.Fprintln(stdout, "  The user must choose a new password at the next login.")
	if res.TOTPCleared {
		fmt.Fprintf(stdout, "  Two-factor authentication: removed (%d recovery code(s) deleted).\n", res.RecoveryCodesDel)
	} else {
		fmt.Fprintln(stdout, "  Two-factor authentication: kept (--keep-2fa).")
	}
	switch {
	case *keepPasskeys:
		fmt.Fprintln(stdout, "  Passkeys: kept (--keep-passkeys).")
	case res.PasskeysSkipped:
		fmt.Fprintln(stdout, "  Passkeys: none (the passkey table does not exist yet).")
	default:
		fmt.Fprintf(stdout, "  Passkeys: %d deleted.\n", res.PasskeysDeleted)
	}
	fmt.Fprintln(stdout, "  Every existing session of this account has been ended.")
	if res.Disabled {
		fmt.Fprintln(stdout, "  WARNING: this account is DISABLED; reset-auth does not re-enable it.")
	}
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Login lockouts are kept in API memory: restart the API container to clear")
	fmt.Fprintln(stdout, "them if this account is currently locked out (docker restart <container>).")
	return 0
}
