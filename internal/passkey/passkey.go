// Package passkey holds the WebAuthn (passkey) configuration, its non-fatal
// validation, and the in-memory ceremony store. The HTTP handlers live in
// internal/api/handlers; persistence in internal/database (passkeys.go).
//
// The feature ships DISABLED. Setup returns nil — and every passkey endpoint
// then answers 404 — unless WEBAUTHN_ENABLED=true AND the relying-party ID and
// origins validate. Validation never stops the server: a bad value disables
// passkeys with a loud log line, and password login is unaffected.
package passkey

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"firewall-mon/internal/config"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CeremonyTimeout bounds both ceremonies: the library enforces it on the
// session (Timeouts.*.Enforce) and the ceremony store expires entries at the
// same age.
const CeremonyTimeout = 5 * time.Minute

// RPDisplayName is the relying-party name shown by authenticators.
const RPDisplayName = "Firewall-Mon"

// Settings is the validated relying-party configuration.
type Settings struct {
	RPID    string
	Origins []string
}

// ResolveSettings derives and validates the relying-party ID and origins from
// configuration only (never from request headers):
//   - RP ID: WEBAUTHN_RP_ID, else the PUBLIC_BASE_URL host. It must be a DNS
//     name — an IP address is rejected — and pass the library's domain check.
//   - Origins: WEBAUTHN_ORIGINS (comma list), else the PUBLIC_BASE_URL origin.
//     Each must be https://host[:port] (or http://localhost[:port]) with no
//     path, query, fragment or userinfo, and its host must equal the RP ID or
//     be a subdomain of it.
func ResolveSettings(rpID, originsRaw, publicBaseURL string) (Settings, error) {
	var base *url.URL
	if strings.TrimSpace(publicBaseURL) != "" {
		u, err := url.Parse(strings.TrimSpace(publicBaseURL))
		if err != nil || u.Host == "" {
			return Settings{}, fmt.Errorf("PUBLIC_BASE_URL %q is not an absolute URL", publicBaseURL)
		}
		base = u
	}

	rpID = strings.ToLower(strings.TrimSpace(rpID))
	if rpID == "" {
		if base == nil {
			return Settings{}, errors.New("WEBAUTHN_RP_ID is empty and PUBLIC_BASE_URL is not set")
		}
		rpID = strings.ToLower(base.Hostname())
	}
	if net.ParseIP(strings.Trim(rpID, "[]")) != nil {
		return Settings{}, fmt.Errorf("relying-party ID %q is an IP address; passkeys need a DNS name", rpID)
	}
	if err := protocol.ValidateRPID(rpID); err != nil {
		return Settings{}, fmt.Errorf("relying-party ID %q is not a valid domain name: %v", rpID, err)
	}

	var rawOrigins []string
	for _, o := range strings.Split(originsRaw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			rawOrigins = append(rawOrigins, o)
		}
	}
	if len(rawOrigins) == 0 {
		if base == nil {
			return Settings{}, errors.New("WEBAUTHN_ORIGINS is empty and PUBLIC_BASE_URL is not set")
		}
		rawOrigins = []string{base.Scheme + "://" + base.Host}
	}

	seen := map[string]bool{}
	origins := make([]string, 0, len(rawOrigins))
	for _, raw := range rawOrigins {
		o, err := validateOrigin(raw, rpID)
		if err != nil {
			return Settings{}, err
		}
		if !seen[o] {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	return Settings{RPID: rpID, Origins: origins}, nil
}

// validateOrigin checks one origin against the RP ID and returns its
// canonical scheme://host[:port] form.
func validateOrigin(raw, rpID string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("WEBAUTHN_ORIGINS entry %q is not an absolute origin", raw)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("WEBAUTHN_ORIGINS entry %q must be scheme://host[:port] only", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	switch {
	case scheme == "https":
	case scheme == "http" && host == "localhost":
	default:
		return "", fmt.Errorf("WEBAUTHN_ORIGINS entry %q must use https (http is allowed only for localhost)", raw)
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("WEBAUTHN_ORIGINS entry %q has an IP host; passkeys need a DNS name", raw)
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return "", fmt.Errorf("WEBAUTHN_ORIGINS entry %q is not within the relying-party ID %q", raw, rpID)
	}
	origin := scheme + "://" + host
	if p := u.Port(); p != "" {
		origin += ":" + p
	}
	return origin, nil
}

// Service is the enabled passkey feature: the configured library instance,
// the ceremony store and the per-user re-authentication limiter.
type Service struct {
	WebAuthn   *webauthn.WebAuthn
	Ceremonies *CeremonyStore
	Reauth     *ReauthLimiter
	Settings   Settings
}

// New builds a Service from validated settings with the security-relevant
// library options pinned: resident key and user verification REQUIRED, no
// attestation requested, and the 5-minute timeouts ENFORCED on the session
// (the library only checks UV and expiry when these are set).
func New(s Settings) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          s.RPID,
		RPDisplayName: RPDisplayName,
		RPOrigins:     s.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTimeout, TimeoutUVD: CeremonyTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTimeout, TimeoutUVD: CeremonyTimeout},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		WebAuthn:   wa,
		Ceremonies: NewCeremonyStore(CeremonyTimeout, DefaultCeremonyCap),
		Reauth:     NewReauthLimiter(),
		Settings:   s,
	}, nil
}

// Setup is the startup entry point. It returns nil — passkeys disabled — when
// WEBAUTHN_ENABLED is false, or when the configuration does not validate (in
// which case it logs loudly). It never fails the process: the caller keeps
// starting, and password login is untouched either way.
func Setup(cfg *config.Config) *Service {
	if cfg == nil || !cfg.Auth.WebAuthnEnabled {
		log.Printf("passkeys: disabled (WEBAUTHN_ENABLED is not true)")
		return nil
	}
	settings, err := ResolveSettings(cfg.Auth.WebAuthnRPID, cfg.Auth.WebAuthnOrigins, cfg.Alerts.PublicBaseURL)
	if err == nil {
		var svc *Service
		if svc, err = New(settings); err == nil {
			log.Printf("passkeys: ENABLED for relying-party ID %q, origins %v", settings.RPID, settings.Origins)
			return svc
		}
	}
	log.Println("============================================================")
	log.Printf("ERROR: passkeys DISABLED — invalid WebAuthn configuration: %v", err)
	log.Println("       WEBAUTHN_ENABLED=true was ignored. Fix WEBAUTHN_RP_ID /")
	log.Println("       WEBAUTHN_ORIGINS (or PUBLIC_BASE_URL) and restart the API.")
	log.Println("       Password login is unaffected.")
	log.Println("============================================================")
	return nil
}
