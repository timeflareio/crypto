package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Rebate collection is commit–reveal (docs/spec.md "Recipient Rebate"). The
// recipiency proof `z` is a bearer secret: once it is in a transaction it is
// public, and a rebate paid to whoever presents `z` could be front-run by any
// observer — a validator most easily of all. So a collector first publishes a
// commitment binding `z` to their own address, and only reveals `z` in a later
// block. An observer who sees `z` cannot produce a commitment for it after the
// fact, and cannot age one retroactively, so the reveal is safe to be public.
//
// The commitment is deliberately trivial arithmetic over public-format inputs,
// mirrored byte-for-byte in rust/src/detect.rs and pinned by
// vectors/rebate_commitment.json.

// RebateCommitmentDomain separates this hash from every other use of `z`,
// including the detection tag itself — so a commitment can never be mistaken
// for, or replayed as, a hint tag.
const RebateCommitmentDomain = "timeflare/rebate-commit/v1"

// RebateCommitment binds a recipiency proof to the address that will collect
// with it: SHA256(domain ‖ z ‖ collector address bytes).
//
// The address is the raw account bytes, not its bech32 rendering, so the
// commitment does not depend on a prefix a future network might change.
func RebateCommitment(z, collector []byte) []byte {
	h := sha256.New()
	h.Write([]byte(RebateCommitmentDomain))
	h.Write(z)
	h.Write(collector)
	return h.Sum(nil)
}

// RebateCommitmentMatches reports whether a proof and collector reproduce a
// stored commitment. Constant-time: a near-miss must leak nothing.
func RebateCommitmentMatches(z, collector, commitment []byte) bool {
	if len(commitment) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(RebateCommitment(z, collector), commitment) == 1
}
