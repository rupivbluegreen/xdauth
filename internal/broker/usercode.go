package broker

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strings"
)

// userCodeAlphabet excludes 0/O and 1/I so the code can't be misread or mistyped.
const userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateUserCode returns an 8-character code formatted "XXXX-XXXX".
func GenerateUserCode() (string, error) {
	raw := make([]byte, 8)
	idx := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate user code: %w", err)
	}
	for i, b := range raw {
		idx[i] = userCodeAlphabet[int(b)%len(userCodeAlphabet)]
	}
	return fmt.Sprintf("%s-%s", idx[:4], idx[4:]), nil
}

// normalizeUserCode uppercases and strips whitespace/dashes so equivalent codes compare equal.
func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// codesEqual compares two user codes in constant time after normalisation.
func codesEqual(submitted, expected string) bool {
	a := []byte(normalizeUserCode(submitted))
	b := []byte(normalizeUserCode(expected))
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
