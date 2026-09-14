package broker

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

const sessionCookieName = "xdauth_session"
const approvalCookieName = "xdauth_approve"

type startRequest struct {
	LoginHint           string `json:"login_hint"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ClientKind          string `json:"client_kind"`
	ClientHost          string `json:"client_host"`
}

type startResponse struct {
	SessionID       string `json:"session_id"`
	VerificationURI string `json:"verification_uri"`
	UserCode        string `json:"user_code"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (b *Broker) handleStart(w http.ResponseWriter, r *http.Request) {
	var verifiedClient string
	if b.cfg.ClientAuthenticator != nil {
		id, err := b.cfg.ClientAuthenticator.Authenticate(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
		verifiedClient = id
	}

	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.LoginHint == "" || req.CodeChallenge == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "login_hint and code_challenge are required")
		return
	}
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "only S256 code_challenge_method is supported")
		return
	}

	b.detector.Observe(EventRepeatedStart, req.LoginHint, "", time.Now())

	ip := resolveClientIP(r, b.cfg.TrustedProxies)
	if !isAllowedClient(ip, b.cfg.AllowedClientCIDRs) {
		writeJSONError(w, http.StatusForbidden, "network_not_allowed", "this network is not permitted to start sign-ins")
		return
	}
	if !b.ipLimiter.Allow(ip) || !b.hintLimiter.Allow(req.LoginHint) {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many session starts; try again later")
		return
	}

	sess, err := newSession(StartParams{
		LoginHint:      req.LoginHint,
		CodeChallenge:  req.CodeChallenge,
		ClientKind:     req.ClientKind,
		ClientHost:     req.ClientHost,
		ClientIP:       ip,
		VerifiedClient: verifiedClient,
	}, b.cfg.SessionTTL, b.cfg.PollInterval)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "could not create session")
		return
	}
	if err := b.store.Create(r.Context(), sess); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "could not persist session")
		return
	}

	logTransition(r.Context(), b.cfg.Logger, sess.ID, "session_started",
		"severity", "info", "client_host", sess.ClientHost, "client_kind", sess.ClientKind, "client_ip", sess.ClientIP)

	writeJSON(w, http.StatusOK, startResponse{
		SessionID:       sess.ID,
		VerificationURI: b.cfg.BaseURL + "/auth/verify/" + sess.ID,
		UserCode:        sess.UserCode,
		ExpiresIn:       int(b.cfg.SessionTTL.Seconds()),
		Interval:        int(b.cfg.PollInterval.Seconds()),
	})
}

func (b *Broker) handleVerify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "session_id")
	sess, err := b.store.Get(r.Context(), id)
	if err != nil {
		renderResult(w, http.StatusNotFound, "Link not found", "This sign-in link is invalid or has already been used.")
		return
	}
	now := time.Now()
	if expireIfNeeded(sess, now) {
		_ = b.store.Update(r.Context(), sess)
		renderResult(w, http.StatusGone, "Link expired", "This sign-in request has expired. Go back to the client and try again.")
		return
	}

	switch sess.State {
	case store.StateAwaitingApproval:
		if !approvalBindingMatches(r, sess) {
			// not the browser that authenticated: refuse, no cookie
			renderResult(w, http.StatusForbidden, "Continue on your device",
				"This sign-in is waiting for approval on the browser where you signed in. Please continue there.")
			return
		}
		setSessionCookie(w, r, sess.ID)
		renderApprove(w, sess, b.cfg.BaseURL)
		return
	case store.StateDenied:
		renderResult(w, http.StatusOK, "Sign-in denied", "This sign-in request was already denied.")
		return
	case store.StateApproved:
		renderResult(w, http.StatusOK, "Already approved", "This sign-in request was already approved.")
		return
	case store.StatePending:
		// fall through to start the IdP leg below
	default:
		renderResult(w, http.StatusOK, "Unavailable", "This sign-in request is no longer available.")
		return
	}

	redirectURL, err := b.idp.BeginLogin(sess)
	if err != nil {
		renderResult(w, http.StatusInternalServerError, "Error", "Could not start sign-in. Please try again.")
		return
	}
	if err := b.store.Update(r.Context(), sess); err != nil {
		renderResult(w, http.StatusInternalServerError, "Error", "Could not start sign-in. Please try again.")
		return
	}

	setSessionCookie(w, r, sess.ID)
	http.Redirect(w, r, redirectURL, http.StatusFound) // #nosec G710 -- redirectURL comes from the broker's own configured IdP, never from the request
}

// handleIdPResponse completes login for either protocol: GET /auth/callback (OIDC) or
// POST /auth/saml/acs (SAML). Each IdentityProvider's CompleteLogin does its own protocol-specific
// correlation check (OIDC: state param; SAML: RelayState + InResponseTo) against sess.
func (b *Broker) handleIdPResponse(w http.ResponseWriter, r *http.Request) {
	sessID, ok := readSessionCookie(r)
	if !ok {
		renderResult(w, http.StatusBadRequest, "Error", "Missing sign-in cookie; please restart from the client.")
		return
	}
	sess, err := b.store.Get(r.Context(), sessID)
	if err != nil {
		renderResult(w, http.StatusNotFound, "Link not found", "This sign-in link is invalid or has already been used.")
		return
	}
	now := time.Now()
	if expireIfNeeded(sess, now) {
		_ = b.store.Update(r.Context(), sess)
		renderResult(w, http.StatusGone, "Link expired", "This sign-in request has expired. Go back to the client and try again.")
		return
	}
	if sess.State != store.StatePending {
		renderResult(w, http.StatusConflict, "Already in progress", "This sign-in request was already completed.")
		return
	}

	ident, err := b.idp.CompleteLogin(r.Context(), r, sess)
	if err != nil {
		logTransition(r.Context(), b.cfg.Logger, sess.ID, "callback_exchange_failed", "severity", "warn")
		renderResult(w, http.StatusBadGateway, "Sign-in failed", "The identity provider rejected this sign-in attempt.")
		return
	}

	approvalSecret, err := newApprovalSecret()
	if err != nil {
		renderResult(w, http.StatusInternalServerError, "Error", "This sign-in request could not be completed.")
		return
	}
	bindErr := bindIdentity(sess, ident, b.cfg.IdentityNormalizer, now, hashBinding(approvalSecret))
	_ = b.store.Update(r.Context(), sess)

	if bindErr != nil {
		if errors.Is(bindErr, ErrIdentityMismatch) {
			b.detector.Observe(EventIdentityMismatch, sess.LoginHint, sess.ID, now)
			renderResult(w, http.StatusForbidden, "Identity mismatch", "You are signed in as a different account than the one this request is for. The request has been denied.")
			return
		}
		renderResult(w, http.StatusConflict, "Error", "This sign-in request could not be completed.")
		return
	}

	setApprovalCookie(w, r, approvalSecret)
	logTransition(r.Context(), b.cfg.Logger, sess.ID, "identity_bound", "severity", "info")
	renderApprove(w, sess, b.cfg.BaseURL)
}

type approveRequest struct {
	SessionID string
	UserCode  string
	CSRFToken string
	Approve   bool
}

func (b *Broker) handleApprove(w http.ResponseWriter, r *http.Request) {
	sessID, ok := readSessionCookie(r)
	if !ok {
		renderResult(w, http.StatusBadRequest, "Error", "Missing sign-in cookie; please restart from the client.")
		return
	}
	if err := r.ParseForm(); err != nil {
		renderResult(w, http.StatusBadRequest, "Error", "Malformed request.")
		return
	}
	req := approveRequest{
		SessionID: sessID,
		UserCode:  r.FormValue("user_code"),
		CSRFToken: r.FormValue("csrf_token"),
		Approve:   r.FormValue("decision") == "approve",
	}

	sess, err := b.store.Get(r.Context(), req.SessionID)
	if err != nil {
		renderResult(w, http.StatusNotFound, "Link not found", "This sign-in link is invalid or has already been used.")
		return
	}
	if !constantTimeStringEqual(req.CSRFToken, sess.CSRFToken) {
		renderResult(w, http.StatusForbidden, "Error", "Invalid form submission; please reload the page and try again.")
		return
	}

	approvalSecret, _ := readApprovalCookie(r)
	now := time.Now()
	appErr := approve(sess, req.UserCode, req.Approve, now, approvalSecret)
	_ = b.store.Update(r.Context(), sess)

	switch {
	case appErr == nil && sess.State == store.StateApproved:
		logTransition(r.Context(), b.cfg.Logger, sess.ID, "approved", "severity", "info")
		renderResult(w, http.StatusOK, "Approved", "Sign-in approved. Return to the client to continue.")
	case sess.State == store.StateDenied:
		logTransition(r.Context(), b.cfg.Logger, sess.ID, "denied", "severity", "info")
		renderResult(w, http.StatusOK, "Denied", "Sign-in denied.")
	case errors.Is(appErr, ErrExpired):
		renderResult(w, http.StatusGone, "Expired", "This sign-in request has expired.")
	case errors.Is(appErr, ErrApprovalNotBound):
		logTransition(r.Context(), b.cfg.Logger, sess.ID, "approval_not_bound", "severity", "warn")
		renderResult(w, http.StatusForbidden, "Continue on your device", "This sign-in is waiting for approval on the browser where you signed in. Please continue there.")
	case appErr != nil:
		b.detector.Observe(EventWrongCode, resolveClientIP(r, b.cfg.TrustedProxies), sess.ID, now)
		renderApprove(w, sess, b.cfg.BaseURL)
	default:
		renderResult(w, http.StatusOK, "Done", "This request has been processed.")
	}
}

type pollRequest struct {
	SessionID    string `json:"session_id"`
	CodeVerifier string `json:"code_verifier"`
}

type pollResponse struct {
	Status   string        `json:"status"`
	Artifact *artifactJSON `json:"artifact,omitempty"`
	Error    string        `json:"error,omitempty"`
}

type artifactJSON struct {
	Subject    string         `json:"subject"`
	Identity   string         `json:"identity"`
	Claims     map[string]any `json:"claims"`
	ApprovedAt time.Time      `json:"approved_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

func (b *Broker) handlePoll(w http.ResponseWriter, r *http.Request) {
	var req pollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	sess, err := b.store.Get(r.Context(), req.SessionID)
	if err != nil {
		writeJSON(w, http.StatusOK, pollResponse{Status: string(PollExpired)}) // don't distinguish unknown from expired
		return
	}

	wasConsumed := sess.Consumed
	result, pollErr := poll(sess, req.CodeVerifier, time.Now(), b.cfg.ArtifactTTL)
	_ = b.store.Update(r.Context(), sess)

	if wasConsumed && result.Status == PollExpired {
		b.detector.Observe(EventConsumedReplay, resolveClientIP(r, b.cfg.TrustedProxies), sess.ID, time.Now())
	}

	if pollErr != nil {
		if errors.Is(pollErr, ErrInvalidVerifier) {
			logTransition(r.Context(), b.cfg.Logger, sess.ID, "poll_invalid_verifier", "severity", "warn")
			writeJSONError(w, http.StatusForbidden, "invalid_verifier", "code_verifier does not match")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "server_error", "could not evaluate session")
		return
	}

	resp := pollResponse{Status: string(result.Status)}
	if result.Status == PollApproved && result.Artifact != nil {
		logTransition(r.Context(), b.cfg.Logger, sess.ID, "consumed", "severity", "info")
		resp.Artifact = &artifactJSON{
			Subject:    result.Artifact.Subject,
			Identity:   result.Artifact.Identity,
			Claims:     result.Artifact.Claims,
			ApprovedAt: result.Artifact.ApprovedAt,
			ExpiresAt:  result.Artifact.ExpiresAt,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- helpers ---

// setSessionCookie marks Secure only over an actual TLS (or TLS-terminated-upstream) request.
func setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	// SAML's HTTP-POST binding submits the ACS callback as a cross-site POST, which browsers never attach a SameSite=Lax (or default) cookie to, so this must be None; None requires Secure or browsers drop it, so fall back to Lax on plain-HTTP local dev where Secure is false.
	sameSite := http.SameSiteNoneMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure/HttpOnly/SameSite are all set below, gosec can't see the conditional
		Name:  sessionCookieName,
		Value: sessionID,
		// Path "/" not "/auth": XDAUTH_SAML_ACS_URL/ACSURL can point the IdP callback at an arbitrary path (e.g. to match an SP already registered elsewhere), and the browser matches cookie Path against that public path, not the broker's internal route.
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
	// Clear any cookie a pre-fix broker (Path "/auth") left behind: with both present, browsers send the more specific "/auth" one first on any /auth/* request, shadowing the new one with a stale session ID.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure/HttpOnly/SameSite are all set below, gosec can't see the conditional
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
	// this cookie only binds the browser to a session id; the separate csrf_token field checked in handleApprove is the actual CSRF defense, so relaxing SameSite here does not weaken CSRF protection.
}

func readSessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// setApprovalCookie binds this browser to sess's later approval.
func setApprovalCookie(w http.ResponseWriter, r *http.Request, secret string) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	sameSite := http.SameSiteNoneMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- flags set explicitly below
		Name:     approvalCookieName,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func readApprovalCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(approvalCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// approvalBindingMatches: true iff r carries the secret bound at bindIdentity.
func approvalBindingMatches(r *http.Request, sess *store.Session) bool {
	secret, ok := readApprovalCookie(r)
	if !ok || sess.ApprovalBindingHash == "" {
		return false
	}
	return constantTimeStringEqual(hashBinding(secret), sess.ApprovalBindingHash)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, pollResponse{Status: "error", Error: code + ": " + msg})
}

func renderResult(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = templates.ExecuteTemplate(w, "result.html", resultPage{Title: title, Message: message})
}

func renderApprove(w http.ResponseWriter, sess *store.Session, baseURL string) {
	identity := ""
	if sess.Identity != nil {
		identity = sess.Identity.Value
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = templates.ExecuteTemplate(w, "approve.html", approvePage{
		Identity:       identity,
		ClientHost:     sess.ClientHost,
		ClientKind:     sess.ClientKind,
		ClientIP:       sess.ClientIP,
		VerifiedClient: sess.VerifiedClient,
		StartedAt:      sess.CreatedAt.Format(time.RFC1123),
		CSRFToken:      sess.CSRFToken,
		ApproveAction:  baseURL + "/auth/approve",
	})
}

// constantTimeStringEqual avoids leaking CSRF-token comparison timing.
func constantTimeStringEqual(a, b string) bool {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
