package broker

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApproveTemplate_AlwaysShowsRequesterContext is check 3: the fields must render unconditionally.
func TestApproveTemplate_AlwaysShowsRequesterContext(t *testing.T) {
	var buf bytes.Buffer
	err := templates.ExecuteTemplate(&buf, "approve.html", approvePage{
		Identity:      "alice",
		ClientHost:    "host-42",
		ClientKind:    "ssh",
		ClientIP:      "10.1.2.3",
		StartedAt:     "some time",
		CSRFToken:     "csrf-abc",
		ApproveAction: "https://broker.example/auth/approve",
	})
	require.NoError(t, err)
	out := buf.String()

	for _, want := range []string{"alice", "host-42", "ssh", "10.1.2.3", "some time", "csrf-abc"} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "<script", "the verification page must ship no JavaScript")
}
