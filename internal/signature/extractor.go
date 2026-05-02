package signature

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/webhookseal/webhookseal-engine/internal/hmac"
	"github.com/webhookseal/webhookseal-engine/internal/specs"
)

var (
	ErrMissingSignature = errors.New("missing signature")
	ErrBadFormat        = errors.New("bad signature format")
)

// Extract finds, parses, and decodes signature values from headers.
func Extract(spec *specs.ProviderSpec, headers map[string]string) ([][]byte, error) {
	if spec == nil {
		return nil, fmt.Errorf("%w: nil provider spec", ErrBadFormat)
	}

	rawHeader, ok := getHeaderCaseInsensitive(headers, spec.SignatureHeader)
	if !ok {
		return nil, ErrMissingSignature
	}
	if strings.TrimSpace(rawHeader) == "" {
		return nil, fmt.Errorf("%w: empty signature", ErrBadFormat)
	}

	encodedValues, err := extractEncodedValues(spec, rawHeader)
	if err != nil {
		return nil, err
	}

	out := make([][]byte, 0, len(encodedValues))
	for _, encoded := range encodedValues {
		decoded, decErr := hmac.Decode(encoded, spec.SignatureEncoding)
		if decErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadFormat, decErr)
		}
		out = append(out, decoded)
	}

	return out, nil
}

func extractEncodedValues(spec *specs.ProviderSpec, value string) ([]string, error) {
	if spec.SignatureParsePattern != "" {
		re, err := regexp.Compile(spec.SignatureParsePattern)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid parse pattern: %v", ErrBadFormat, err)
		}

		matches := re.FindAllStringSubmatch(value, -1)
		if len(matches) == 0 {
			return nil, fmt.Errorf("%w: no captures", ErrBadFormat)
		}

		captures := make([]string, 0)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			for i := 1; i < len(m); i++ {
				capture := strings.TrimSpace(m[i])
				if capture != "" {
					captures = append(captures, capture)
				}
			}
		}
		if len(captures) == 0 {
			return nil, fmt.Errorf("%w: no captures", ErrBadFormat)
		}
		return captures, nil
	}

	trimmed := strings.TrimSpace(value)
	if spec.SignaturePrefix != "" {
		if !strings.HasPrefix(trimmed, spec.SignaturePrefix) {
			return nil, fmt.Errorf("%w: prefix mismatch", ErrBadFormat)
		}
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, spec.SignaturePrefix))
	}

	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty signature", ErrBadFormat)
	}

	return []string{trimmed}, nil
}

func getHeaderCaseInsensitive(headers map[string]string, key string) (string, bool) {
	if len(headers) == 0 || strings.TrimSpace(key) == "" {
		return "", false
	}

	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}

	return "", false
}
