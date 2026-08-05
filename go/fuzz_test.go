package crypto

import (
	"bytes"
	"testing"
)

// Fuzz targets for the parsers that take attacker-controlled bytes.
//
// The guardian daemon runs this package server-side against envelopes and
// HMACs read straight from chain state, so every input here is chosen by
// someone else. What each target asserts is the same pair of properties: the
// call returns rather than panicking, and it does not accept anything it should
// reject.
//
// Seeds live in testdata/fuzz/ and replay as ordinary tests under
// `go test ./...`, so a crash found once is asserted for good, offline and
// without a fuzzing run. `make fuzz` is what searches for new ones.

// fixedKey turns arbitrary fuzz bytes into the [32]byte a key argument needs.
// Short input is zero-padded and long input truncated, so no input is rejected
// before it reaches the function under test.
func fixedKey(b []byte) [32]byte {
	var key [32]byte
	copy(key[:], b)
	return key
}

// FuzzDecryptShareWithPrivateKey feeds arbitrary bytes to the envelope parser
// the guardian daemon points at chain state.
//
// Decryption must never succeed here: forging an envelope means producing a
// valid Poly1305 tag under a key derived from an X25519 exchange, which the
// fuzzer cannot do by search.
func FuzzDecryptShareWithPrivateKey(f *testing.F) {
	keypair, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("generate keypair: %v", err)
	}

	stranger, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("generate stranger keypair: %v", err)
	}

	valid, err := EncryptShareWithPublicKey([]byte("share"), keypair.PublicKey)
	if err != nil {
		f.Fatalf("encrypt: %v", err)
	}

	extended := make([]byte, 0, len(valid)+1)
	extended = append(append(extended, valid...), 0)

	// A well-formed envelope is the most useful thing to hand the mutator, but
	// it is seeded against a key that cannot open it — this target asserts that
	// decryption always fails, so the one pairing that legitimately succeeds
	// does not belong in the corpus.
	f.Add(valid, stranger.PrivateKey[:])
	f.Add(valid[:len(valid)-1], keypair.PrivateKey[:])
	f.Add(extended, keypair.PrivateKey[:])
	f.Add([]byte{}, keypair.PrivateKey[:])
	f.Add(make([]byte, encryptionOverhead), keypair.PrivateKey[:])

	f.Fuzz(func(t *testing.T, envelope, privateKey []byte) {
		plaintext, err := DecryptShareWithPrivateKey(envelope, fixedKey(privateKey))
		if err == nil {
			t.Fatalf("decrypted %d arbitrary bytes to %q", len(envelope), plaintext)
		}
		if plaintext != nil {
			t.Fatalf("plaintext returned alongside error: %q", plaintext)
		}
	})
}

// FuzzDecryptShareRoundTrip checks the other direction: whatever a caller
// encrypts, the holder of the private key gets back unchanged, and nobody else
// gets anything at all.
func FuzzDecryptShareRoundTrip(f *testing.F) {
	f.Add([]byte("share data"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		keypair, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}

		envelope, err := EncryptShareWithPublicKey(data, keypair.PublicKey)

		// This implementation refuses an empty payload. The Rust one encrypts
		// it, so the two disagree on the empty input alone; the shared corpus
		// pins agreed outputs and has no case for a rejection, which is how the
		// difference has stayed invisible. Asserted in both directions here so
		// that whichever way it is reconciled, it is reconciled deliberately.
		if len(data) == 0 {
			if err == nil {
				t.Fatal("an empty payload was encrypted, which this side refuses")
			}
			return
		}
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", len(data), err)
		}

		decrypted, err := DecryptShareWithPrivateKey(envelope, keypair.PrivateKey)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Fatalf("round trip changed the data: got %q, want %q", decrypted, data)
		}

		stranger, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("generate stranger keypair: %v", err)
		}
		if _, err := DecryptShareWithPrivateKey(envelope, stranger.PrivateKey); err == nil {
			t.Fatal("an unrelated private key decrypted the envelope")
		}
	})
}

// FuzzVerifyHMAC feeds arbitrary identifiers, share data and tags to the
// verifier the chain's reveal path depends on. A tag that was not produced by
// GenerateHMAC over the same three inputs must be rejected.
func FuzzVerifyHMAC(f *testing.F) {
	secretID := "9f2c1a34-0000-4000-8000-000000000001"
	address := "tmflr1guardian00"
	share := []byte("share")

	valid, err := GenerateHMAC(secretID, address, share)
	if err != nil {
		f.Fatalf("generate hmac: %v", err)
	}

	f.Add(secretID, address, share, valid)
	f.Add(secretID, address, share, []byte{})
	f.Add("", "", []byte{}, []byte{})
	f.Add(secretID, address, share, valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, secretID, address string, share, tag []byte) {
		accepted := VerifyHMAC(secretID, address, share, tag)
		if !accepted {
			return
		}

		// Acceptance is only correct when the tag is the one GenerateHMAC
		// produces for these exact inputs.
		expected, err := GenerateHMAC(secretID, address, share)
		if err != nil {
			t.Fatalf("verification accepted inputs that generation rejects: %v", err)
		}
		if !bytes.Equal(expected, tag) {
			t.Fatalf("accepted a tag GenerateHMAC did not produce for (%q, %q)", secretID, address)
		}
	})
}

// FuzzGenerateHMACAgreesWithVerify checks the pair is consistent: anything
// GenerateHMAC accepts round-trips through VerifyHMAC, and a single flipped bit
// in the tag breaks it.
func FuzzGenerateHMACAgreesWithVerify(f *testing.F) {
	f.Add("secret-id", "tmflr1guardian00", []byte("share"), 0)
	f.Add("", "", []byte{}, 0)

	f.Fuzz(func(t *testing.T, secretID, address string, share []byte, flip int) {
		tag, err := GenerateHMAC(secretID, address, share)
		if err != nil {
			// Generation refuses some inputs; verification must refuse them too.
			if VerifyHMAC(secretID, address, share, tag) {
				t.Fatalf("verification accepted inputs generation rejected: %v", err)
			}
			return
		}

		if !VerifyHMAC(secretID, address, share, tag) {
			t.Fatal("a freshly generated tag failed verification")
		}

		if flip < 0 {
			flip = -flip
		}
		tampered := append(tag[:0:0], tag...)
		tampered[flip%len(tampered)] ^= 1 << (flip % 8)
		if VerifyHMAC(secretID, address, share, tampered) {
			t.Fatal("verification accepted a tampered tag")
		}
	})
}

// FuzzValidateX25519PublicKey generalises the fixed low-order corpus to
// arbitrary key bytes. The guard the SDK calls early must agree with the
// authoritative rejection inside encryption for every input, not only the
// vectors — a key the guard accepts but encryption refuses would surface as an
// opaque failure with no guardian to blame.
func FuzzValidateX25519PublicKey(f *testing.F) {
	keypair, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("generate keypair: %v", err)
	}

	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(keypair.PublicKey[:])
	f.Add(bytes.Repeat([]byte{0xff}, 32))

	f.Fuzz(func(t *testing.T, key []byte) {
		valid := ValidateX25519PublicKey(key) == nil

		if len(key) != 32 {
			if valid {
				t.Fatalf("accepted a %d-byte key", len(key))
			}
			return
		}

		_, err := EncryptShareWithPublicKey([]byte("payload"), fixedKey(key))
		if valid != (err == nil) {
			t.Fatalf("guard says valid=%v but encryption says err=%v", valid, err)
		}
	})
}

// FuzzDetectionTagMatches feeds arbitrary shared secrets and tags to the
// scanning comparison. A scan runs over hints taken from chain state, so both
// arguments are attacker-chosen and neither length is trustworthy.
func FuzzDetectionTagMatches(f *testing.F) {
	shared := bytes.Repeat([]byte{0x11}, 32)

	f.Add(shared, DetectionTag(shared))
	f.Add([]byte{}, []byte{})
	f.Add(shared, []byte{})

	f.Fuzz(func(t *testing.T, shared, tag []byte) {
		matched := DetectionTagMatches(shared, tag)
		if matched && !bytes.Equal(DetectionTag(shared), tag) {
			t.Fatal("reported a match against a tag DetectionTag did not produce")
		}
	})
}

// FuzzRebateCommitmentMatches does the same for the commitment arithmetic the
// mobile client reimplements in TypeScript.
func FuzzRebateCommitmentMatches(f *testing.F) {
	z := bytes.Repeat([]byte{0x22}, 32)
	collector := []byte("tmflr1collector")

	f.Add(z, collector, RebateCommitment(z, collector))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(z, collector, []byte{})

	f.Fuzz(func(t *testing.T, z, collector, commitment []byte) {
		matched := RebateCommitmentMatches(z, collector, commitment)
		if matched && !bytes.Equal(RebateCommitment(z, collector), commitment) {
			t.Fatal("reported a match against a commitment RebateCommitment did not produce")
		}
	})
}
