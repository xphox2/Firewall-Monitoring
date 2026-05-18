// Package notifier — SMTP auth helpers (v0.10.222, bundle J).
//
// Go's stdlib `net/smtp` ships PLAIN and CRAM-MD5 auth implementations
// but not LOGIN. Many Postfix/Cyrus/Dovecot deployments advertise only
// LOGIN on submission/587 because the operator's SASL backend (Dovecot,
// Active Directory bridge, etc.) doesn't surface plaintext password
// verification the way PLAIN expects. Without LOGIN support every
// alert email to such a server fails with "504 5.7.4 unrecognized
// authentication type" or just times out at AUTH.
//
// This file provides:
//
//   - LoginAuth(username, password) smtp.Auth
//     A correct LOGIN implementation. Doesn't try to parse the server's
//     prompt text (which varies across servers — some send "Username:",
//     some "User Name", some translated localised text). Instead it
//     tracks which step it's on internally: step 0 = username, step 1
//     = password.
//
//   - CompoundAuth(username, password, host) smtp.Auth
//     Inspects server.Auth in Start() and chooses PLAIN (preferred) or
//     LOGIN based on what the server advertises. Returns a clear error
//     when neither is offered. Use this anywhere an smtp.Auth is needed
//     so the same binary works against PLAIN-only and LOGIN-only
//     submission servers without operator reconfiguration.
package notifier

import (
	"errors"
	"fmt"
	"net/smtp"
	"strings"
)

// LoginAuth returns an smtp.Auth that implements the LOGIN mechanism.
//
// NOTE: LOGIN is *not* in RFC 4954 — it lives in the expired
// draft-murchison-sasl-login-00 and is widely deployed for Postfix
// + Dovecot/Cyrus despite that. RFC 4954 §4's plaintext-over-TLS
// requirement still applies here because LOGIN sends the password
// in cleartext, just split over two server prompts.
type loginAuth struct {
	username, password, host string
	step                     int
}

func LoginAuth(username, password, host string) smtp.Auth {
	return &loginAuth{username: username, password: password, host: host}
}

// Start declares the mechanism. Two safety gates, both mirroring the
// stdlib's smtp.PlainAuth:
//
//  1. server.Name == host — refuse to send credentials to a server
//     that doesn't match the host the caller asked to connect to.
//     Without this a MITM with a redirected DNS / connection could
//     terminate the TLS handshake on a *different* host that also
//     advertises LOGIN and harvest the password under that identity.
//     stdlib PlainAuth gates on this; v0.10.223 was missing it.
//
//  2. server.TLS — refuse to send credentials over a cleartext
//     connection. Same rule as PlainAuth.
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, fmt.Errorf("wrong host name (server presented %q, expected %q)", server.Name, a.host)
	}
	if !server.TLS {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

// Next answers the server's prompts in order. We deliberately ignore
// the prompt text because different SASL backends emit different
// strings ("Username:", "User Name", base64-encoded variants…) and
// matching on text is fragile. The protocol only ever asks for exactly
// two values in this order.
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		return []byte(a.username), nil
	case 1:
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("LOGIN auth: unexpected additional server challenge %q", string(fromServer))
	}
}

// CompoundAuth picks PLAIN or LOGIN based on server.Auth advertisement.
// Designed to be a drop-in for smtp.PlainAuth in any code path that
// passes the result to smtp.SendMail or smtp.Client.Auth.
//
// Order of preference: PLAIN, then LOGIN. PLAIN first because it's the
// modern default and runs in one server round-trip vs LOGIN's two —
// only fall back when PLAIN isn't on the menu.
type compoundAuth struct {
	username, password, host string
	chosenName               string    // populated during Start() for trace purposes
	inner                    smtp.Auth // resolved during Start()
}

func CompoundAuth(username, password, host string) smtp.Auth {
	return &compoundAuth{username: username, password: password, host: host}
}

func (a *compoundAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	var hasPlain, hasLogin bool
	for _, m := range server.Auth {
		switch strings.ToUpper(strings.TrimSpace(m)) {
		case "PLAIN":
			hasPlain = true
		case "LOGIN":
			hasLogin = true
		}
	}
	switch {
	case hasPlain:
		a.chosenName = "PLAIN"
		a.inner = smtp.PlainAuth("", a.username, a.password, a.host)
	case hasLogin:
		a.chosenName = "LOGIN"
		a.inner = LoginAuth(a.username, a.password, a.host)
	default:
		return "", nil, fmt.Errorf("no supported AUTH mechanism (server offered: %s)",
			strings.Join(server.Auth, ", "))
	}
	return a.inner.Start(server)
}

func (a *compoundAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if a.inner == nil {
		return nil, errors.New("CompoundAuth: Next called before Start")
	}
	return a.inner.Next(fromServer, more)
}

// ChosenMechanism returns the auth mechanism CompoundAuth selected at
// Start(), or "" if Start() hasn't run yet. Lets the verbose test
// trace report which mechanism was actually used so an operator can
// confirm their server is doing what they expected.
func (a *compoundAuth) ChosenMechanism() string {
	return a.chosenName
}
