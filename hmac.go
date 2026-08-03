package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// ================================================================
// HMAC Operations - Simplified package-level interface
// ================================================================

// HMAC size constant - SHA256 HMAC produces 32-byte output
const HMACSize = 32

// GenerateHMAC creates the guardian share commitment tag. This is a pure-Go
// implementation on the consensus path (no cgo): transaction validity in
// x/secrets depends on it, so it must never route through a native library.
//
// Normative construction (spec.md "Multi-Layer Encryption Protection"),
// byte-for-byte identical to rust/src/utils.rs generate_guardian_hmac and
// pinned by the shared vectors/hmac.json corpus:
//
//	key = SHA256("secrets" || secret_id || guardian_address || "hmac_salt")
//	tag = HMAC-SHA256(key, share_data || guardian_address || secret_id)
func GenerateHMAC(secretID, guardianAddress string, shareData []byte) ([]byte, error) {
	if secretID == "" {
		return nil, fmt.Errorf("secret ID cannot be empty")
	}
	if guardianAddress == "" {
		return nil, fmt.Errorf("guardian address cannot be empty")
	}
	if len(shareData) == 0 {
		return nil, fmt.Errorf("share data cannot be empty")
	}

	keyHash := sha256.New()
	keyHash.Write([]byte("secrets"))
	keyHash.Write([]byte(secretID))
	keyHash.Write([]byte(guardianAddress))
	keyHash.Write([]byte("hmac_salt"))
	hmacKey := keyHash.Sum(nil)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(shareData)
	mac.Write([]byte(guardianAddress))
	mac.Write([]byte(secretID))

	return mac.Sum(nil), nil
}

// VerifyHMAC checks if the provided HMAC matches the expected value for the given inputs
func VerifyHMAC(secretID, guardianAddress string, shareData []byte, expectedHMAC []byte) bool {
	computedHMAC, err := GenerateHMAC(secretID, guardianAddress, shareData)
	if err != nil {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal(computedHMAC, expectedHMAC)
}
