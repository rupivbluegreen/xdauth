package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// SecurityEvent is an abuse signal; never carries codes, verifiers, or tokens.
type SecurityEvent struct {
	Kind      string    `json:"kind"`
	SessionID string    `json:"session_id,omitempty"`
	Key       string    `json:"key,omitempty"`
	At        time.Time `json:"at"`
}

// Event kinds observed by the detector.
const (
	EventWrongCode        = "wrong_code"
	EventRepeatedStart    = "repeated_start"
	EventConsumedReplay   = "consumed_replay"
	EventIdentityMismatch = "identity_mismatch"
	EventSuspectedAbuse   = "suspected_abuse" // emitted once a threshold trips
)

// abuseThresholds: count within Window that trips suspected_abuse per kind.
type abuseThresholds struct {
	WrongCode        int
	RepeatedStart    int
	IdentityMismatch int
	Window           time.Duration
}

func defaultAbuseThresholds() abuseThresholds {
	return abuseThresholds{WrongCode: 3, RepeatedStart: 5, IdentityMismatch: 3, Window: 5 * time.Minute}
}

type counterEntry struct {
	count     int
	windowEnd time.Time
}

// detector counts abuse signals per key and emits suspected_abuse once.
type detector struct {
	mu         sync.Mutex
	counts     map[string]*counterEntry
	thresholds abuseThresholds
	onEvent    func(SecurityEvent)
}

func newDetector(thresholds abuseThresholds, onEvent func(SecurityEvent)) *detector {
	return &detector{counts: map[string]*counterEntry{}, thresholds: thresholds, onEvent: onEvent}
}

// Observe records one occurrence of kind for key; may also emit suspected_abuse.
func (d *detector) Observe(kind, key, sessionID string, now time.Time) {
	if d.onEvent != nil {
		d.onEvent(SecurityEvent{Kind: kind, SessionID: sessionID, Key: key, At: now})
	}
	threshold := d.thresholdFor(kind)
	if threshold <= 0 {
		return
	}
	if d.tripped(kind, key, threshold, now) && d.onEvent != nil {
		d.onEvent(SecurityEvent{Kind: EventSuspectedAbuse, SessionID: sessionID, Key: kind + ":" + key, At: now})
	}
}

func (d *detector) tripped(kind, key string, threshold int, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	mapKey := kind + "|" + key
	e, ok := d.counts[mapKey]
	if !ok || now.After(e.windowEnd) {
		e = &counterEntry{windowEnd: now.Add(d.thresholds.Window)}
		d.counts[mapKey] = e
	}
	e.count++
	return e.count == threshold
}

func (d *detector) thresholdFor(kind string) int {
	switch kind {
	case EventWrongCode:
		return d.thresholds.WrongCode
	case EventRepeatedStart:
		return d.thresholds.RepeatedStart
	case EventIdentityMismatch:
		return d.thresholds.IdentityMismatch
	default:
		return 0
	}
}

// abuseWebhook posts suspected_abuse events; never blocks the caller for long.
type abuseWebhook struct {
	url    string
	client *http.Client
}

func newAbuseWebhook(url string, client *http.Client) *abuseWebhook {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &abuseWebhook{url: url, client: client}
}

func (h *abuseWebhook) fire(evt SecurityEvent) {
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	go func() {
		resp, err := h.client.Do(req) // #nosec G107 -- URL is operator config, not user input
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}
