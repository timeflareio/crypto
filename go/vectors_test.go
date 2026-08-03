package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// vectors/ holds a VENDORED copy of the cross-implementation corpus, pinned by
// VECTORS_VERSION and verified by `make vectors-verify`. It is consumed by this
// suite AND the Rust test suite (rust/src/utils.rs, rust/src/crypto.rs). If
// either implementation drifts — even by one byte — the vectors fail on the
// side that changed.
//
// The corpus is OWNED BY THE CHAIN REPO (timeflareio/chain, testdata/vectors/),
// which is where vector changes land and from which releases publish the
// tarball this copy is synced from. Never hand-edit vectors/ — use
// `make vectors-sync`.
//
// Vectors are append-only. The generator below remains for local iteration
// when ADDING cases:
//
//	TIMEFLARE_GENERATE_VECTORS=1 go test ./go/ -run TestGenerateVectors
//
// It writes into the vendored copy, so `make vectors-verify` will fail against
// the pinned manifest until the same addition lands in the chain repo and
// VECTORS_VERSION is bumped — that failure is the mechanism working, not a
// defect. Verify the Rust side too: cd rust && cargo test vectors

const vectorsDir = "../vectors"

type hmacVector struct {
	Name            string `json:"name"`
	SecretID        string `json:"secret_id"`
	GuardianAddress string `json:"guardian_address"`
	ShareDataHex    string `json:"share_data_hex"`
	ExpectedHMACHex string `json:"expected_hmac_hex"`
}

type encryptionVector struct {
	Name                string `json:"name"`
	RecipientPrivateHex string `json:"recipient_private_hex"`
	RecipientPublicHex  string `json:"recipient_public_hex"`
	EphemeralPrivateHex string `json:"ephemeral_private_hex"`
	NonceHex            string `json:"nonce_hex"`
	PlaintextHex        string `json:"plaintext_hex"`
	CiphertextHex       string `json:"ciphertext_hex"`
}

func TestHMACVectors(t *testing.T) {
	var vectors []hmacVector
	loadVectors(t, "hmac.json", &vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			shareData := mustHex(t, v.ShareDataHex)
			expected := mustHex(t, v.ExpectedHMACHex)

			got, err := GenerateHMAC(v.SecretID, v.GuardianAddress, shareData)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("HMAC drifted from pinned vector\n got: %x\nwant: %x", got, expected)
			}
			if !VerifyHMAC(v.SecretID, v.GuardianAddress, shareData, expected) {
				t.Fatal("VerifyHMAC rejected the pinned vector")
			}
		})
	}
}

func TestEncryptionVectors(t *testing.T) {
	var vectors []encryptionVector
	loadVectors(t, "encryption.json", &vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			var recipientPriv, recipientPub, ephemeralPriv [32]byte
			copy(recipientPriv[:], mustHex(t, v.RecipientPrivateHex))
			copy(recipientPub[:], mustHex(t, v.RecipientPublicHex))
			copy(ephemeralPriv[:], mustHex(t, v.EphemeralPrivateHex))
			nonce := mustHex(t, v.NonceHex)
			plaintext := mustHex(t, v.PlaintextHex)
			ciphertext := mustHex(t, v.CiphertextHex)

			derivedPub, err := DerivePublicKey(recipientPriv)
			if err != nil {
				t.Fatalf("DerivePublicKey failed: %v", err)
			}
			if derivedPub != recipientPub {
				t.Fatalf("public key derivation drifted\n got: %x\nwant: %x", derivedPub, recipientPub)
			}

			gotCiphertext, err := encryptWithParts(plaintext, recipientPub, ephemeralPriv, nonce)
			if err != nil {
				t.Fatalf("encryptWithParts failed: %v", err)
			}
			if !bytes.Equal(gotCiphertext, ciphertext) {
				t.Fatalf("encryption drifted from pinned vector\n got: %x\nwant: %x", gotCiphertext, ciphertext)
			}

			gotPlaintext, err := DecryptShareWithPrivateKey(ciphertext, recipientPriv)
			if err != nil {
				t.Fatalf("DecryptShareWithPrivateKey failed: %v", err)
			}
			if !bytes.Equal(gotPlaintext, plaintext) {
				t.Fatalf("decryption drifted from pinned vector\n got: %x\nwant: %x", gotPlaintext, plaintext)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func loadVectors(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile(vectorsDir + "/" + name)
	if err != nil {
		t.Fatalf("failed to read vector file %s: %v", name, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("failed to parse vector file %s: %v", name, err)
	}
}

// TestGenerateVectors regenerates the corpus. It never runs in a normal test
// pass — vectors are append-only, and any regeneration must be re-verified
// against the Rust suite before commit.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("TIMEFLARE_GENERATE_VECTORS") != "1" {
		t.Skip("set TIMEFLARE_GENERATE_VECTORS=1 to regenerate the vector corpus")
	}

	fixed := func(fill byte) (b [32]byte) {
		for i := range b {
			b[i] = fill + byte(i)
		}
		return b
	}

	// --- HMAC vectors ---
	hmacInputs := []struct {
		name, secretID, guardianAddress string
		shareData                       []byte
	}{
		{
			name:            "uuid-secret-34B-envelope",
			secretID:        "550e8400-e29b-41d4-a716-446655440000",
			guardianAddress: "tmflr1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu",
			shareData:       append([]byte{0x01, 0x07}, bytes.Repeat([]byte{0xAB}, 32)...),
		},
		{
			name:            "single-byte-share",
			secretID:        "test-secret-123",
			guardianAddress: "tmflr1guardian1address",
			shareData:       []byte{0x00},
		},
		{
			name:            "long-share-all-byte-values",
			secretID:        "another-secret-456",
			guardianAddress: "tmflr1anotherguardian456",
			shareData: func() []byte {
				b := make([]byte, 256)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			}(),
		},
	}
	var hmacVectors []hmacVector
	for _, in := range hmacInputs {
		tag, err := GenerateHMAC(in.secretID, in.guardianAddress, in.shareData)
		if err != nil {
			t.Fatalf("GenerateHMAC failed: %v", err)
		}
		hmacVectors = append(hmacVectors, hmacVector{
			Name:            in.name,
			SecretID:        in.secretID,
			GuardianAddress: in.guardianAddress,
			ShareDataHex:    hex.EncodeToString(in.shareData),
			ExpectedHMACHex: hex.EncodeToString(tag),
		})
	}
	writeVectors(t, "hmac.json", hmacVectors)

	// --- Encryption vectors ---
	encInputs := []struct {
		name                     string
		recipientPriv, ephemeral [32]byte
		nonce                    []byte
		plaintext                []byte
	}{
		{
			name:          "34B-key-share-envelope",
			recipientPriv: fixed(0x10),
			ephemeral:     fixed(0x40),
			nonce:         bytes.Repeat([]byte{0x24}, 12),
			plaintext:     append([]byte{0x01, 0x03}, bytes.Repeat([]byte{0xCD}, 32)...),
		},
		{
			name:          "single-byte",
			recipientPriv: fixed(0x80),
			ephemeral:     fixed(0xC0),
			nonce:         bytes.Repeat([]byte{0x01}, 12),
			plaintext:     []byte{0xFF},
		},
		{
			name:          "payload-sized-4kB",
			recipientPriv: fixed(0x33),
			ephemeral:     fixed(0x77),
			nonce: func() []byte {
				n := make([]byte, 12)
				for i := range n {
					n[i] = byte(i)
				}
				return n
			}(),
			plaintext: func() []byte {
				b := make([]byte, 4096)
				for i := range b {
					b[i] = byte(i % 251)
				}
				return b
			}(),
		},
	}
	var encVectors []encryptionVector
	for _, in := range encInputs {
		pub, err := DerivePublicKey(in.recipientPriv)
		if err != nil {
			t.Fatalf("DerivePublicKey failed: %v", err)
		}
		ct, err := encryptWithParts(in.plaintext, pub, in.ephemeral, in.nonce)
		if err != nil {
			t.Fatalf("encryptWithParts failed: %v", err)
		}
		encVectors = append(encVectors, encryptionVector{
			Name:                in.name,
			RecipientPrivateHex: hex.EncodeToString(in.recipientPriv[:]),
			RecipientPublicHex:  hex.EncodeToString(pub[:]),
			EphemeralPrivateHex: hex.EncodeToString(in.ephemeral[:]),
			NonceHex:            hex.EncodeToString(in.nonce),
			PlaintextHex:        hex.EncodeToString(in.plaintext),
			CiphertextHex:       hex.EncodeToString(ct),
		})
	}
	writeVectors(t, "encryption.json", encVectors)
}

func writeVectors(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(vectorsDir, 0755); err != nil {
		t.Fatalf("failed to create vectors dir: %v", err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal vectors: %v", err)
	}
	if err := os.WriteFile(vectorsDir+"/"+name, append(data, '\n'), 0644); err != nil {
		t.Fatalf("failed to write vector file %s: %v", name, err)
	}
	t.Logf("wrote %s/%s", vectorsDir, name)
}

// ---------------------------------------------------------------------------
// Hostile-input corpus: low_order_keys.json
//
// The other vector files pin the two implementations to agreement on VALID
// inputs. That is exactly why the low-order defect survived: Go errored on a
// small-order key while Rust silently derived an all-zero shared secret, and no
// vector exercised a hostile input to notice. This corpus pins agreement on
// REJECTION, so the same class of divergence cannot reopen silently.
// ---------------------------------------------------------------------------

type lowOrderKeyCase struct {
	Name      string `json:"name"`
	KeyHex    string `json:"key_hex"`
	Order     int    `json:"order"`
	Canonical bool   `json:"canonical"`
	Note      string `json:"note"`
}

type lowOrderVectors struct {
	Description string            `json:"description"`
	Reject      []lowOrderKeyCase `json:"reject"`
	Accept      []lowOrderKeyCase `json:"accept"`
}

func loadLowOrderVectors(t *testing.T) lowOrderVectors {
	t.Helper()
	raw, err := os.ReadFile(vectorsDir + "/low_order_keys.json")
	if err != nil {
		t.Fatalf("reading low_order_keys.json: %v", err)
	}
	var v lowOrderVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing low_order_keys.json: %v", err)
	}
	if len(v.Reject) == 0 || len(v.Accept) == 0 {
		t.Fatal("low_order_keys.json must carry both reject and accept cases")
	}
	return v
}

func TestLowOrderVectors_RejectedByValidator(t *testing.T) {
	v := loadLowOrderVectors(t)
	for _, c := range v.Reject {
		key, err := hex.DecodeString(c.KeyHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", c.Name, err)
		}
		if err := ValidateX25519PublicKey(key); err == nil {
			t.Errorf("%s (order %d, canonical=%v) was accepted; it must be rejected",
				c.Name, c.Order, c.Canonical)
		}
	}
}

func TestLowOrderVectors_RejectedByEncryption(t *testing.T) {
	// The validator and the real encryption path must agree, or validation could
	// pass a key the crypto then refuses (or worse, the reverse).
	v := loadLowOrderVectors(t)
	for _, c := range v.Reject {
		key, _ := hex.DecodeString(c.KeyHex)
		var pub [32]byte
		copy(pub[:], key)
		if _, err := EncryptShareWithPublicKey([]byte("share"), pub); err == nil {
			t.Errorf("%s: encryption succeeded against a small-order key", c.Name)
		}
	}
}

func TestLowOrderVectors_AcceptedKeysStillWork(t *testing.T) {
	v := loadLowOrderVectors(t)
	for _, c := range v.Accept {
		key, err := hex.DecodeString(c.KeyHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", c.Name, err)
		}
		if err := ValidateX25519PublicKey(key); err != nil {
			t.Errorf("%s must be accepted, got: %v (%s)", c.Name, err, c.Note)
		}
		var pub [32]byte
		copy(pub[:], key)
		if _, err := EncryptShareWithPublicKey([]byte("share"), pub); err != nil {
			t.Errorf("%s: encryption failed for a valid key: %v", c.Name, err)
		}
	}
}

type detectionHintVector struct {
	Name                string `json:"name"`
	RecipientPrivateHex string `json:"recipient_private_hex"`
	EphemeralPublicHex  string `json:"ephemeral_public_hex"`
	TagHex              string `json:"tag_hex"`
}

// TestDetectionHintVectors pins the hint tag arithmetic to the shared corpus:
// the recipient's own view (X25519(a, R) → tag) is the computation a client
// performs when scanning and the chain performs when a recipient proves
// recipiency to collect a rebate. Drift here silently breaks both.
func TestDetectionHintVectors(t *testing.T) {
	var vectors []detectionHintVector
	loadVectors(t, "detection_hint.json", &vectors)

	if len(vectors) == 0 {
		t.Fatal("detection_hint.json carried no vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			recipientPriv := mustHex(t, v.RecipientPrivateHex)
			ephemeralPub := mustHex(t, v.EphemeralPublicHex)
			expected := mustHex(t, v.TagHex)

			shared, err := curve25519.X25519(recipientPriv, ephemeralPub)
			if err != nil {
				t.Fatalf("X25519 against the pinned ephemeral key failed: %v", err)
			}

			got := DetectionTag(shared)
			if !bytes.Equal(got, expected) {
				t.Fatalf("detection tag drifted from pinned vector\n got: %x\nwant: %x", got, expected)
			}
			if !DetectionTagMatches(shared, expected) {
				t.Fatal("DetectionTagMatches rejected the pinned vector")
			}
			if DetectionTagMatches(shared, expected[:DetectionTagLength-1]) {
				t.Fatal("DetectionTagMatches accepted a short tag")
			}

			// A different shared value must not derive this tag: the property
			// the rebate proof rests on.
			other := append([]byte(nil), shared...)
			other[0] ^= 0x01
			if DetectionTagMatches(other, expected) {
				t.Fatal("DetectionTagMatches accepted a shared value it should not have")
			}
		})
	}
}

type rebateCommitmentVector struct {
	Name                string `json:"name"`
	RecipientPrivateHex string `json:"recipient_private_hex"`
	EphemeralPublicHex  string `json:"ephemeral_public_hex"`
	ProofHex            string `json:"proof_hex"`
	CollectorAddressHex string `json:"collector_address_hex"`
	CommitmentHex       string `json:"commitment_hex"`
}

// TestRebateCommitmentVectors pins the commit–reveal arithmetic across
// implementations: the recipient's client computes both values (rust/src/detect.rs
// via WASM) and the chain recomputes the commitment to authorise payment. Drift
// would make every rebate uncollectable.
func TestRebateCommitmentVectors(t *testing.T) {
	var vectors []rebateCommitmentVector
	loadVectors(t, "rebate_commitment.json", &vectors)

	if len(vectors) == 0 {
		t.Fatal("rebate_commitment.json carried no vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			recipientPriv := mustHex(t, v.RecipientPrivateHex)
			ephemeralPub := mustHex(t, v.EphemeralPublicHex)
			collector := mustHex(t, v.CollectorAddressHex)
			wantProof := mustHex(t, v.ProofHex)
			wantCommitment := mustHex(t, v.CommitmentHex)

			// The proof is the recipient's own view of the hint exchange.
			proof, err := curve25519.X25519(recipientPriv, ephemeralPub)
			if err != nil {
				t.Fatalf("X25519 failed: %v", err)
			}
			if !bytes.Equal(proof, wantProof) {
				t.Fatalf("recipiency proof drifted\n got: %x\nwant: %x", proof, wantProof)
			}

			got := RebateCommitment(proof, collector)
			if !bytes.Equal(got, wantCommitment) {
				t.Fatalf("rebate commitment drifted\n got: %x\nwant: %x", got, wantCommitment)
			}
			if !RebateCommitmentMatches(proof, collector, wantCommitment) {
				t.Fatal("RebateCommitmentMatches rejected the pinned vector")
			}

			// A different collector must not satisfy the same commitment: this is
			// what binds a proof to one address.
			other := append([]byte(nil), collector...)
			other[0] ^= 0x01
			if RebateCommitmentMatches(proof, other, wantCommitment) {
				t.Fatal("the commitment did not bind to the collector's address")
			}

			// Nor must a different proof.
			wrongProof := append([]byte(nil), proof...)
			wrongProof[0] ^= 0x01
			if RebateCommitmentMatches(wrongProof, collector, wantCommitment) {
				t.Fatal("the commitment did not bind to the proof")
			}
		})
	}
}
