package broker

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// Config configures a Broker; New applies defaults, so the zero Config works for local development.
type Config struct {
	BaseURL string // this broker's own externally-reachable origin, used to build verification_uri

	SessionTTL      time.Duration // default 5 minutes
	PollInterval    time.Duration // "interval" returned to clients; default 3s
	StartRatePerSec rate.Limit    // per-key /auth/start budget; default 1/5s
	StartRateBurst  int           // default 5
	ArtifactTTL     time.Duration // returned artifact's own lifetime; default 120s

	IdentityNormalizer Normalizer // maps an identity claim value for comparison against login_hint

	AbuseWebhookURL string // optional: POSTed a SecurityEvent JSON body on suspected_abuse

	// ClientAuthenticator, if set, gates /auth/start (mitigations 7, 15).
	ClientAuthenticator ClientAuthenticator

	// TrustedProxies: peers allowed to set X-Forwarded-For; unset means direct RemoteAddr only.
	TrustedProxies []netip.Prefix
	// AllowedClientCIDRs: if set, only these networks may call /auth/start (mitigation 8).
	AllowedClientCIDRs []netip.Prefix

	Logger *slog.Logger
}

func (c *Config) applyDefaults() {
	if c.SessionTTL <= 0 {
		c.SessionTTL = 5 * time.Minute
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 3 * time.Second
	}
	if c.StartRatePerSec <= 0 {
		c.StartRatePerSec = rate.Every(5 * time.Second)
	}
	if c.StartRateBurst <= 0 {
		c.StartRateBurst = 5
	}
	if c.ArtifactTTL <= 0 {
		c.ArtifactTTL = 120 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Broker owns session state, the IdP client (OIDC or SAML), and the HTTP handlers.
type Broker struct {
	cfg         Config
	store       store.Store
	idp         IdentityProvider
	ipLimiter   *keyedLimiter
	hintLimiter *keyedLimiter
	detector    *detector
	webhook     *abuseWebhook // nil if AbuseWebhookURL is unset
}

// New builds a Broker. The caller owns st's and idp's lifecycle.
func New(cfg Config, st store.Store, idp IdentityProvider) *Broker {
	cfg.applyDefaults()
	idleTTL := cfg.SessionTTL * 4
	b := &Broker{
		cfg:         cfg,
		store:       st,
		idp:         idp,
		ipLimiter:   newKeyedLimiter(cfg.StartRatePerSec, cfg.StartRateBurst, idleTTL),
		hintLimiter: newKeyedLimiter(cfg.StartRatePerSec, cfg.StartRateBurst, idleTTL),
	}
	if cfg.AbuseWebhookURL != "" {
		b.webhook = newAbuseWebhook(cfg.AbuseWebhookURL, nil)
	}
	b.detector = newDetector(defaultAbuseThresholds(), b.onSecurityEvent)
	return b
}

// onSecurityEvent logs every abuse signal and forwards suspected_abuse to the webhook.
func (b *Broker) onSecurityEvent(evt SecurityEvent) {
	logTransition(context.Background(), b.cfg.Logger, evt.SessionID, evt.Kind,
		"severity", "warn", "key", evt.Key)
	if evt.Kind == EventSuspectedAbuse && b.webhook != nil {
		b.webhook.fire(evt)
	}
}

// Router returns the broker's HTTP handler, ready to serve.
func (b *Broker) Router() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	r.Route("/auth", func(r chi.Router) {
		r.Use(noStoreMiddleware, cspMiddleware)
		r.Post("/start", b.handleStart)
		r.Get("/verify/{session_id}", b.handleVerify)
		r.Get("/callback", b.handleIdPResponse)
		r.Post("/saml/acs", b.handleIdPResponse)
		r.Post("/approve", b.handleApprove)
		r.Post("/poll", b.handlePoll)
	})
	return r
}

// noStoreMiddleware sets Cache-Control: no-store on every auth page and API response.
func noStoreMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// cspMiddleware sets a strict CSP with no script-src: the pages have no JavaScript by design.
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
