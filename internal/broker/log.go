package broker

import (
	"context"
	"log/slog"
)

// logTransition records a session state-machine transition; never pass a code, verifier, token, or secret in attrs.
func logTransition(ctx context.Context, logger *slog.Logger, sessionID, event string, attrs ...any) {
	base := []any{"session_id", sessionID, "event", event}
	logger.InfoContext(ctx, event, append(base, attrs...)...)
}
