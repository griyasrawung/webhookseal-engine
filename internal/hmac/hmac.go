package hmac

import (
	cryptohmac "crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

// Compute returns the raw HMAC digest for the supported algorithm.
func Compute(algorithm string, secret, payload []byte) ([]byte, error) {
	var newHash func() hash.Hash

	switch algorithm {
	case "hmac-sha256":
		newHash = sha256.New
	case "hmac-sha1":
		newHash = sha1.New
	default:
		return nil, fmt.Errorf("unsupported hmac algorithm %q", algorithm)
	}

	mac := cryptohmac.New(newHash, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}
