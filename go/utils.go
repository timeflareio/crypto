package crypto

import "encoding/hex"

// ================================================================
// Utility Functions
// ================================================================

// BytesToHex converts bytes to a lowercase hex string
func BytesToHex(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	return hex.EncodeToString(data), nil
}
