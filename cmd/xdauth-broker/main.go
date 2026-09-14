// Command xdauth-broker runs the xdauth broker server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rupivbluegreen/xdauth/internal/broker"
	"github.com/rupivbluegreen/xdauth/internal/oidc"
	"github.com/rupivbluegreen/xdauth/internal/saml"
	"github.com/rupivbluegreen/xdauth/internal/store"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	os.Exit(run())
}

func run() int {
	listenAddr := flag.String("listen", envOr("XDAUTH_LISTEN_ADDR", ":8080"), "address to listen on")
	baseURL := flag.String("base-url", os.Getenv("XDAUTH_BASE_URL"), "this broker's externally-reachable base URL, no trailing slash (env XDAUTH_BASE_URL)")
	protocol := flag.String("protocol", envOr("XDAUTH_PROTOCOL", "oidc"), "identity provider protocol: oidc or saml (env XDAUTH_PROTOCOL)")
	sessionTTL := flag.Int("session-ttl-seconds", envIntOr("XDAUTH_SESSION_TTL_SECONDS", 300), "session TTL in seconds (env XDAUTH_SESSION_TTL_SECONDS)")
	pollInterval := flag.Int("poll-interval-seconds", envIntOr("XDAUTH_POLL_INTERVAL_SECONDS", 3), "poll interval in seconds (env XDAUTH_POLL_INTERVAL_SECONDS)")
	artifactTTL := flag.Int("artifact-ttl-seconds", envIntOr("XDAUTH_ARTIFACT_TTL_SECONDS", 120), "returned artifact's own lifetime in seconds (env XDAUTH_ARTIFACT_TTL_SECONDS)")
	abuseWebhookURL := flag.String("abuse-webhook-url", os.Getenv("XDAUTH_ABUSE_WEBHOOK_URL"), "optional URL POSTed a SecurityEvent JSON body on suspected abuse (env XDAUTH_ABUSE_WEBHOOK_URL)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "xdauth-broker: --base-url is required")
		return 2
	}
	trimmedBaseURL := strings.TrimRight(*baseURL, "/")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var idp broker.IdentityProvider
	switch *protocol {
	case "oidc":
		p, code := newOIDCProvider(ctx, logger, trimmedBaseURL)
		if code != 0 {
			return code
		}
		idp = p
	case "saml":
		p, code := newSAMLProvider(ctx, logger, trimmedBaseURL)
		if code != 0 {
			return code
		}
		idp = p
	default:
		fmt.Fprintf(os.Stderr, "xdauth-broker: --protocol must be \"oidc\" or \"saml\", got %q\n", *protocol)
		return 2
	}

	sessionStore := store.NewMemory(30 * time.Second)
	defer sessionStore.Close()

	b := broker.New(broker.Config{
		BaseURL:         trimmedBaseURL,
		SessionTTL:      time.Duration(*sessionTTL) * time.Second,
		PollInterval:    time.Duration(*pollInterval) * time.Second,
		ArtifactTTL:     time.Duration(*artifactTTL) * time.Second,
		AbuseWebhookURL: *abuseWebhookURL,
		Logger:          logger,
	}, sessionStore, idp)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           b.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("xdauth-broker starting", "addr", *listenAddr, "base_url", *baseURL, "protocol", *protocol)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		return 1
	}
	return 0
}

// newOIDCProvider returns (provider, 0) on success, or (nil, exit code) on failure.
func newOIDCProvider(ctx context.Context, logger *slog.Logger, baseURL string) (*oidc.Provider, int) {
	issuerURL := os.Getenv("XDAUTH_ISSUER_URL")
	clientID := os.Getenv("XDAUTH_CLIENT_ID")
	identityClaim := envOr("XDAUTH_IDENTITY_CLAIM", "preferred_username")
	scopes := envOr("XDAUTH_SCOPES", "openid,profile")

	clientSecret := os.Getenv("XDAUTH_CLIENT_SECRET")
	if path := os.Getenv("XDAUTH_CLIENT_SECRET_FILE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- operator-supplied config path, not user input
		if err != nil {
			logger.Error("read client secret file", "error", err)
			return nil, 1
		}
		clientSecret = strings.TrimSpace(string(b))
	}

	if issuerURL == "" || clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "xdauth-broker: --protocol=oidc needs XDAUTH_ISSUER_URL, XDAUTH_CLIENT_ID and a client secret (XDAUTH_CLIENT_SECRET[_FILE])")
		return nil, 2
	}

	provider, err := retryDiscovery(ctx, logger, "oidc discovery", func() (*oidc.Provider, error) {
		return oidc.New(ctx, oidc.Config{
			IssuerURL:     issuerURL,
			ClientID:      clientID,
			ClientSecret:  clientSecret,
			RedirectURL:   baseURL + "/auth/callback",
			Scopes:        strings.Split(scopes, ","),
			IdentityClaim: identityClaim,
		})
	})
	if err != nil {
		logger.Error("discover oidc provider", "error", err)
		return nil, 1
	}
	return provider, 0
}

// retryDiscovery retries fn with backoff for up to 30s, so a slow-starting IdP (e.g. a
// container that isn't ready yet) doesn't crash the broker on its very first attempt.
func retryDiscovery[T any](ctx context.Context, logger *slog.Logger, what string, fn func() (T, error)) (T, error) {
	backoff := 500 * time.Millisecond
	deadline := time.Now().Add(30 * time.Second)
	for {
		v, err := fn()
		if err == nil {
			return v, nil
		}
		if time.Now().After(deadline) {
			return v, err
		}
		logger.Warn("retrying "+what, "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// newSAMLProvider returns (provider, 0) on success, or (nil, exit code) on failure.
func newSAMLProvider(ctx context.Context, logger *slog.Logger, baseURL string) (*saml.Provider, int) {
	metadataURL := os.Getenv("XDAUTH_SAML_IDP_METADATA_URL")
	metadataFile := os.Getenv("XDAUTH_SAML_IDP_METADATA_FILE")
	identityAttribute := os.Getenv("XDAUTH_SAML_IDENTITY_ATTRIBUTE")
	entityID := os.Getenv("XDAUTH_SAML_ENTITY_ID")
	acsURL := os.Getenv("XDAUTH_SAML_ACS_URL")

	if (metadataURL == "") == (metadataFile == "") {
		fmt.Fprintln(os.Stderr, "xdauth-broker: --protocol=saml needs exactly one of XDAUTH_SAML_IDP_METADATA_URL or XDAUTH_SAML_IDP_METADATA_FILE")
		return nil, 2
	}

	var metadataXML []byte
	if metadataFile != "" {
		b, err := os.ReadFile(metadataFile) // #nosec G304 G703 -- operator-supplied config path, not user input
		if err != nil {
			logger.Error("read saml idp metadata file", "error", err)
			return nil, 1
		}
		metadataXML = b
	}

	provider, err := retryDiscovery(ctx, logger, "saml idp metadata fetch", func() (*saml.Provider, error) {
		return saml.New(ctx, saml.Config{
			BaseURL:           baseURL,
			EntityID:          entityID,
			ACSURL:            acsURL,
			IDPMetadataURL:    metadataURL,
			IDPMetadataXML:    metadataXML,
			IdentityAttribute: identityAttribute,
		})
	})
	if err != nil {
		logger.Error("configure saml provider", "error", err)
		return nil, 1
	}
	return provider, 0
}
