package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ================================================================
// Encryption - Public/Private key encryption
// ================================================================
//
// Pure-Go implementation of the Timeflare asymmetric encryption scheme,
// byte-for-byte compatible with rust/src/crypto.rs (the client/WASM
// reference implementation) and pinned by the shared
// vectors/encryption.json corpus.
//
// Normative wire format (spec.md "Multi-Layer Encryption Protection"):
//
//	ephemeral_public(32) || nonce(12) || ChaCha20-Poly1305 ciphertext+tag
//	key = SHA256(X25519(ephemeral_private, recipient_public) || "timeflare_encryption")

const (
	encryptionKeyDomain = "timeflare_encryption"
	encryptionOverhead  = 32 + chacha20poly1305.NonceSize + chacha20poly1305.Overhead
)

// EncryptShareWithPublicKey encrypts data for a specific public key
func EncryptShareWithPublicKey(data []byte, publicKey [32]byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data to encrypt cannot be empty")
	}

	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	return encryptWithParts(data, publicKey, ephemeralPriv, nonce)
}

// encryptWithParts performs the encryption with caller-supplied ephemeral key
// and nonce. Production callers go through EncryptShareWithPublicKey, which
// draws both from crypto/rand; the deterministic entry point exists so the
// shared cross-implementation test vectors can pin the full wire format.
func encryptWithParts(data []byte, publicKey, ephemeralPriv [32]byte, nonce []byte) ([]byte, error) {
	ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("ephemeral public key derivation failed: %w", err)
	}

	shared, err := curve25519.X25519(ephemeralPriv[:], publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	cipher, err := chacha20poly1305.New(deriveEncryptionKey(shared))
	if err != nil {
		return nil, fmt.Errorf("cipher initialisation failed: %w", err)
	}

	result := make([]byte, 0, len(data)+encryptionOverhead)
	result = append(result, ephemeralPub...)
	result = append(result, nonce...)
	return cipher.Seal(result, nonce, data, nil), nil
}

// DecryptShareWithPrivateKey decrypts encrypted share data using a private key
func DecryptShareWithPrivateKey(encryptedShare []byte, privateKey [32]byte) ([]byte, error) {
	if len(encryptedShare) == 0 {
		return nil, fmt.Errorf("encrypted share data is empty")
	}
	if len(encryptedShare) < 32+chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedShare))
	}

	ephemeralPub := encryptedShare[0:32]
	nonce := encryptedShare[32 : 32+chacha20poly1305.NonceSize]
	ciphertext := encryptedShare[32+chacha20poly1305.NonceSize:]

	shared, err := curve25519.X25519(privateKey[:], ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	cipher, err := chacha20poly1305.New(deriveEncryptionKey(shared))
	if err != nil {
		return nil, fmt.Errorf("cipher initialisation failed: %w", err)
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data")
	}
	return plaintext, nil
}

func deriveEncryptionKey(shared []byte) []byte {
	h := sha256.New()
	h.Write(shared)
	h.Write([]byte(encryptionKeyDomain))
	return h.Sum(nil)
}

// ================================================================
// Key Generation and Management
// ================================================================

// KeyPair represents a Timeflare encryption keypair
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeypair generates a new Timeflare encryption keypair
func GenerateKeypair() (*KeyPair, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("private key generation failed: %w", err)
	}

	// Derive public key from private key
	publicKey, err := DerivePublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// DerivePublicKey derives the X25519 public key from a private key. Private
// keys are stored as the raw 32-byte scalar exactly as generated; clamping
// applies at Diffie-Hellman time (RFC 7748), matching the Rust implementation.
func DerivePublicKey(privateKey [32]byte) ([32]byte, error) {
	var publicKey [32]byte

	publicKeyBytes, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return publicKey, fmt.Errorf("public key derivation failed: %w", err)
	}

	copy(publicKey[:], publicKeyBytes)
	return publicKey, nil
}

// PublicKeyLength is the byte length of an X25519 public key (the u-coordinate).
const PublicKeyLength = 32

// validationScalar is an arbitrary clamped X25519 scalar used only by
// ValidateX25519PublicKey. Any clamped scalar works: X25519 clamps scalars to a
// multiple of 8, so s·P is the identity for every P whose order divides 8, which
// is exactly the set we want rejected. It is a fixed constant so the predicate
// is a pure function of its input and every node reaches the same verdict.
var validationScalar = [32]byte{
	0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
	0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
}

// ValidateX25519PublicKey reports whether key is usable as an X25519 public key
// for Timeflare share encryption: exactly PublicKeyLength bytes, and not a
// small-order point.
//
// ⚠️ Why the small-order check is load-bearing, not hygiene: an X25519 exchange
// against a small-order point yields an ALL-ZERO shared secret, so every key
// derived from it — including this protocol's
// SHA256(shared || "timeflare_encryption") — is publicly computable, and
// anything "encrypted" to such a public key is readable by any observer. The
// curve has a torsion subgroup of order 8; there are five canonical u-encodings
// of small order plus non-canonical encodings that reduce to them.
//
// The predicate is DELEGATED to curve25519.X25519 rather than compared against a
// hand-maintained table (libsodium keeps a seven-entry blacklist): the library
// rejects the non-canonical encodings too, and a table that ships one entry
// short fails silently in precisely the direction this check exists to prevent.
//
// Consensus-critical: a pure byte-in/error-out function with no randomness and
// no state, so it is safe on the consensus path and in genesis validation.
// See the chain repository's docs/spec.md, "Common Attack Vectors",
// Small-Order Key Registration.
func ValidateX25519PublicKey(key []byte) error {
	if len(key) != PublicKeyLength {
		return fmt.Errorf("x25519 public key must be exactly %d bytes, got %d", PublicKeyLength, len(key))
	}
	if _, err := curve25519.X25519(validationScalar[:], key); err != nil {
		// The only error X25519 returns for a well-formed 32-byte peer key is
		// the low-order rejection, so the cause is unambiguous here.
		return fmt.Errorf("x25519 public key is not usable: %w", err)
	}
	return nil
}
