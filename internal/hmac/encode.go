package hmac

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Encode converts raw signature bytes to a supported textual encoding.
func Encode(raw []byte, encoding string) (string, error) {
	switch encoding {
	case "hex":
		return hex.EncodeToString(raw), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(raw), nil
	default:
		return "", fmt.Errorf("unsupported signature encoding %q", encoding)
	}
}

// Decode converts a supported textual signature encoding back to raw bytes.
func Decode(encoded string, encoding string) ([]byte, error) {
	switch encoding {
	case "hex":
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode hex signature: %w", err)
		}
		return decoded, nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode base64 signature: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported signature encoding %q", encoding)
	}
}
