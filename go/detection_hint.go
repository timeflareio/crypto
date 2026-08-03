package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Recipient detection hints (chain repo docs/spec.md, "Recipient Discovery — Detection
// Hints"). A secret carries a fresh X25519 ephemeral public key R and an
// 8-byte tag over the Diffie–Hellman shared value; only the holder of the
// recipient's PRIVATE key can recompute the tag, so no observer can link
// secrets to a recipient or to each other.
//
// Deriving a hint is client-side work (the chain never sees a recipient's
// long-term key). What lives here is the tag arithmetic both sides must agree
// on byte-for-byte: clients derive tags when sealing and scanning, and the
// chain recomputes one when a recipient proves recipiency to collect a rebate.
// Byte-compatibility with rust/src/detect.rs is pinned by
// vectors/detection_hint.json.

const (
	// DetectionHintDomain is the normative domain-separation string. MUST
	// match rust/src/detect.rs and the TypeScript client byte-for-byte.
	DetectionHintDomain = "timeflare/detect/v1"
	// DetectionTagLength is the tag size in bytes: 8 puts scan false
	// positives at 2^-64.
	DetectionTagLength = 8
)

// DetectionTag derives a hint tag from an X25519 shared value:
// SHA256(domain ‖ shared)[:8].
//
// The caller supplies the shared value, not a key: sealing computes it as
// X25519(e, A) from a fresh ephemeral private key, scanning and rebate
// collection compute the same value as X25519(a, R).
func DetectionTag(shared []byte) []byte {
	h := sha256.New()
	h.Write([]byte(DetectionHintDomain))
	h.Write(shared)
	return h.Sum(nil)[:DetectionTagLength]
}

// DetectionTagMatches reports whether a shared value derives the given tag. A
// constant-time comparison, so a wrong proof leaks nothing about how wrong it
// was. A tag of the wrong length never matches.
func DetectionTagMatches(shared, tag []byte) bool {
	if len(tag) != DetectionTagLength {
		return false
	}
	return subtle.ConstantTimeCompare(DetectionTag(shared), tag) == 1
}
