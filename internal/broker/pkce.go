package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// verifyClientPKCE implements check 1: SHA256(code_verifier) base64url == code_challenge.
func verifyClientPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
