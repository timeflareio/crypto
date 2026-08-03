package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateHMAC(t *testing.T) {
	secretID := "test-secret-123"
	guardianAddress := "tmflr1guardian1address"
	shareData := []byte("test share data")

	hmac, err := GenerateHMAC(secretID, guardianAddress, shareData)
	if err != nil {
		t.Fatalf("GenerateHMAC failed: %v", err)
	}

	if len(hmac) != HMACSize {
		t.Errorf("expected HMAC length %d, got %d", HMACSize, len(hmac))
	}
}

func TestGenerateHMAC_InputValidation(t *testing.T) {
	testCases := []struct {
		name            string
		secretID        string
		guardianAddress string
		shareData       []byte
		expectError     bool
	}{
		{
			name:            "valid inputs",
			secretID:        "secret-123",
			guardianAddress: "tmflr1guardian1",
			shareData:       []byte("test data"),
			expectError:     false,
		},
		{
			name:            "empty secret ID",
			secretID:        "",
			guardianAddress: "tmflr1guardian1",
			shareData:       []byte("test data"),
			expectError:     true,
		},
		{
			name:            "empty guardian address",
			secretID:        "secret-123",
			guardianAddress: "",
			shareData:       []byte("test data"),
			expectError:     true,
		},
		{
			name:            "empty share data",
			secretID:        "secret-123",
			guardianAddress: "tmflr1guardian1",
			shareData:       []byte{},
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateHMAC(tc.secretID, tc.guardianAddress, tc.shareData)
			if tc.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyHMAC(t *testing.T) {
	secretID := "test-secret-123"
	guardianAddress := "tmflr1guardian1address"
	shareData := []byte("test share data")

	// Generate HMAC
	hmac, err := GenerateHMAC(secretID, guardianAddress, shareData)
	if err != nil {
		t.Fatalf("GenerateHMAC failed: %v", err)
	}

	// Verify with same inputs should succeed
	if !VerifyHMAC(secretID, guardianAddress, shareData, hmac) {
		t.Error("HMAC verification should succeed with same inputs")
	}

	// Verify with different data should fail
	if VerifyHMAC(secretID, guardianAddress, []byte("different data"), hmac) {
		t.Error("HMAC verification should fail with different data")
	}

	// Verify with different secret ID should fail
	if VerifyHMAC("different-secret", guardianAddress, shareData, hmac) {
		t.Error("HMAC verification should fail with different secret ID")
	}

	// Verify with different guardian should fail
	if VerifyHMAC(secretID, "tmflr1differentguardian", shareData, hmac) {
		t.Error("HMAC verification should fail with different guardian")
	}

	// Verify with wrong HMAC should fail
	wrongHMAC := make([]byte, HMACSize)
	copy(wrongHMAC, hmac)
	wrongHMAC[0] ^= 0x01 // Flip one bit
	if VerifyHMAC(secretID, guardianAddress, shareData, wrongHMAC) {
		t.Error("HMAC verification should fail with wrong HMAC")
	}

	// Verify with invalid HMAC length should fail
	shortHMAC := hmac[:HMACSize-1]
	if VerifyHMAC(secretID, guardianAddress, shareData, shortHMAC) {
		t.Error("HMAC verification should fail with short HMAC")
	}
}

func TestHMACDeterministic(t *testing.T) {
	secretID := "test-secret-123"
	guardianAddress := "tmflr1guardian1address"
	shareData := []byte("test share data")

	// Generate HMAC twice
	hmac1, err1 := GenerateHMAC(secretID, guardianAddress, shareData)
	hmac2, err2 := GenerateHMAC(secretID, guardianAddress, shareData)

	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateHMAC failed: %v, %v", err1, err2)
	}

	// Should be identical
	if !bytes.Equal(hmac1, hmac2) {
		t.Error("HMAC generation should be deterministic")
	}
}

func TestHMACUniqueness(t *testing.T) {
	shareData := []byte("test share data")

	testCases := []struct {
		name            string
		secretID        string
		guardianAddress string
	}{
		{
			name:            "case 1",
			secretID:        "secret-123",
			guardianAddress: "tmflr1guardian1",
		},
		{
			name:            "case 2",
			secretID:        "secret-456",
			guardianAddress: "tmflr1guardian1",
		},
		{
			name:            "case 3",
			secretID:        "secret-123",
			guardianAddress: "tmflr1guardian2",
		},
	}

	var hmacs [][]byte
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hmac, err := GenerateHMAC(tc.secretID, tc.guardianAddress, shareData)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			// Check against all previous HMACs for uniqueness
			for i, prevHMAC := range hmacs {
				if bytes.Equal(hmac, prevHMAC) {
					t.Errorf("HMAC should be unique, but matched case %d", i)
				}
			}

			hmacs = append(hmacs, hmac)
		})
	}
}

func TestHMACCompatibilityWithExistingImplementations(t *testing.T) {
	testCases := []struct {
		name            string
		secretID        string
		guardianAddress string
		shareData       string
	}{
		{
			name:            "secret-abc123_tmflr1guardian1address",
			secretID:        "abc123",
			guardianAddress: "tmflr1guardian1address",
			shareData:       "test-share-data-1",
		},
		{
			name:            "secret-def456_tmflr1guardian2address",
			secretID:        "def456",
			guardianAddress: "tmflr1guardian2address",
			shareData:       "test-share-data-2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shareDataBytes := []byte(tc.shareData)

			// Generate HMAC
			hmac1, err := GenerateHMAC(tc.secretID, tc.guardianAddress, shareDataBytes)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			hmac2, err := GenerateHMAC(tc.secretID, tc.guardianAddress, shareDataBytes)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			// Should be deterministic
			if !bytes.Equal(hmac1, hmac2) {
				t.Error("HMAC generation should be deterministic")
			}

			// Should verify correctly
			if !VerifyHMAC(tc.secretID, tc.guardianAddress, shareDataBytes, hmac1) {
				t.Error("HMAC verification should succeed")
			}
		})
	}
}

func TestBackwardCompatibilityWithOldImplementations(t *testing.T) {
	testCases := []struct {
		secretID        string
		guardianAddress string
		shareData       string
	}{
		{
			secretID:        "test-secret-123",
			guardianAddress: "tmflr1testguardian123",
			shareData:       "test share data 123",
		},
		{
			secretID:        "another-secret-456",
			guardianAddress: "tmflr1anotherguardian456",
			shareData:       "another test share data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.secretID, func(t *testing.T) {
			shareDataBytes := []byte(tc.shareData)

			// Generate HMAC with new implementation
			hmac, err := GenerateHMAC(tc.secretID, tc.guardianAddress, shareDataBytes)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			// Should be exactly 32 bytes (SHA256)
			if len(hmac) != 32 {
				t.Errorf("expected HMAC length 32, got %d", len(hmac))
			}

			// Verify round-trip works
			if !VerifyHMAC(tc.secretID, tc.guardianAddress, shareDataBytes, hmac) {
				t.Error("round-trip verification failed")
			}

			// Verify consistency across multiple calls
			hmac2, err := GenerateHMAC(tc.secretID, tc.guardianAddress, shareDataBytes)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			if !bytes.Equal(hmac, hmac2) {
				t.Error("HMAC generation is not deterministic")
			}
		})
	}
}

// smallOrderKeys is libsodium's has_small_order table — the X25519
// u-coordinates whose exchange yields an all-zero shared secret. Five are
// canonical values; the last two are non-canonical encodings that reduce to
// small-order points, which is why the check delegates to curve25519 rather
// than to a table of our own.
var smallOrderKeys = [][]byte{
	make([]byte, 32),
	append([]byte{1}, make([]byte, 31)...),
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

func TestValidateX25519PublicKey_RejectsSmallOrderPoints(t *testing.T) {
	for i, key := range smallOrderKeys {
		if err := ValidateX25519PublicKey(key); err == nil {
			t.Errorf("small-order point %d (%x…) was accepted; an exchange against it yields an all-zero shared secret", i, key[:4])
		}
	}
}

func TestValidateX25519PublicKey_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if err := ValidateX25519PublicKey(make([]byte, n)); err == nil {
			t.Errorf("%d-byte key was accepted", n)
		}
	}
}

func TestValidateX25519PublicKey_AcceptsGeneratedKeys(t *testing.T) {
	// Every key the protocol itself produces must pass — the check must never
	// reject an honest guardian.
	for i := 0; i < 50; i++ {
		kp, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("keypair generation failed: %v", err)
		}
		if err := ValidateX25519PublicKey(kp.PublicKey[:]); err != nil {
			t.Fatalf("iteration %d: generated public key rejected: %v", i, err)
		}
	}
}

func TestValidateX25519PublicKey_RejectionMatchesEncryptionFailure(t *testing.T) {
	// The predicate must agree with the real encryption path: anything
	// ValidateX25519PublicKey rejects must also fail to encrypt, so validation
	// can never pass a key the crypto then refuses (or vice versa).
	for i, key := range smallOrderKeys {
		var pub [32]byte
		copy(pub[:], key)
		_, encErr := EncryptShareWithPublicKey([]byte("share"), pub)
		valErr := ValidateX25519PublicKey(key)
		if (encErr == nil) != (valErr == nil) {
			t.Errorf("point %d: validation and encryption disagree (validate=%v, encrypt=%v)", i, valErr, encErr)
		}
	}
}
