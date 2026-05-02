package timestamp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/griyasrawung/webhookseal-engine/internal/specs"
)

var (
	ErrMissingTimestamp = fmt.Errorf("missing timestamp")
	ErrBadFormat        = fmt.Errorf("bad timestamp format")
)

// Extract extracts and parses timestamp from headers according to provider spec.
// Returns (time.Time{}, 0, nil) when provider has no timestamp semantics.
// Returns ErrMissingTimestamp when required timestamp header is missing.
// Returns ErrBadFormat for parse failures.
func Extract(spec *specs.ProviderSpec, headers map[string]string) (time.Time, int64, error) {
	if spec == nil {
		return time.Time{}, 0, fmt.Errorf("%w: nil provider spec", ErrBadFormat)
	}

	// Check if provider has timestamp semantics
	hasTimestampHeader := spec.TimestampHeader != nil && strings.TrimSpace(*spec.TimestampHeader) != ""
	hasTimestampFormat := spec.TimestampFormat != nil && strings.TrimSpace(*spec.TimestampFormat) != ""
	hasTimestampLocation := spec.TimestampLocation != nil && strings.TrimSpace(*spec.TimestampLocation) != ""

	// No timestamp semantics - return zero values with nil error
	if !hasTimestampHeader && !hasTimestampFormat && !hasTimestampLocation {
		return time.Time{}, 0, nil
	}

	// Embedded timestamp mode (Stripe-style)
	if !hasTimestampHeader && hasTimestampFormat && hasTimestampLocation {
		return extractEmbedded(spec, headers)
	}

	// Separate header timestamp mode (Slack-style)
	if hasTimestampHeader && hasTimestampFormat && hasTimestampLocation {
		return extractFromHeader(spec, headers)
	}

	// Invalid configuration (should have been caught by spec validation)
	return time.Time{}, 0, fmt.Errorf("%w: invalid timestamp configuration", ErrBadFormat)
}

// extractFromHeader extracts timestamp from a dedicated header
func extractFromHeader(spec *specs.ProviderSpec, headers map[string]string) (time.Time, int64, error) {
	rawValue, ok := getHeaderCaseInsensitive(headers, *spec.TimestampHeader)
	if !ok || strings.TrimSpace(rawValue) == "" {
		return time.Time{}, 0, ErrMissingTimestamp
	}

	return parseTimestamp(strings.TrimSpace(rawValue), *spec.TimestampFormat)
}

// extractEmbedded extracts timestamp embedded in signature header using regex
func extractEmbedded(spec *specs.ProviderSpec, headers map[string]string) (time.Time, int64, error) {
	if spec.TimestampParsePattern == "" {
		return time.Time{}, 0, fmt.Errorf("%w: missing timestamp_parse_pattern for embedded mode", ErrBadFormat)
	}

	// Get signature header value
	rawHeader, ok := getHeaderCaseInsensitive(headers, spec.SignatureHeader)
	if !ok || strings.TrimSpace(rawHeader) == "" {
		return time.Time{}, 0, ErrMissingTimestamp
	}

	// Compile and apply regex pattern
	re, err := regexp.Compile(spec.TimestampParsePattern)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("%w: invalid timestamp_parse_pattern: %v", ErrBadFormat, err)
	}

	matches := re.FindStringSubmatch(rawHeader)
	if len(matches) < 2 {
		return time.Time{}, 0, fmt.Errorf("%w: timestamp not found in signature header", ErrBadFormat)
	}

	// Use first capture group
	timestampStr := strings.TrimSpace(matches[1])
	if timestampStr == "" {
		return time.Time{}, 0, fmt.Errorf("%w: empty timestamp capture", ErrBadFormat)
	}

	return parseTimestamp(timestampStr, *spec.TimestampFormat)
}

// parseTimestamp parses timestamp string according to format
func parseTimestamp(value string, format string) (time.Time, int64, error) {
	switch format {
	case "epoch_seconds":
		epoch, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("%w: invalid epoch_seconds: %v", ErrBadFormat, err)
		}
		return time.Unix(epoch, 0).UTC(), epoch, nil

	case "epoch_ms":
		epochMs, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("%w: invalid epoch_ms: %v", ErrBadFormat, err)
		}
		seconds := epochMs / 1000
		nanos := (epochMs % 1000) * 1000000
		return time.Unix(seconds, nanos).UTC(), epochMs, nil

	case "iso8601":
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("%w: invalid iso8601: %v", ErrBadFormat, err)
		}
		return t.UTC(), t.Unix(), nil

	default:
		return time.Time{}, 0, fmt.Errorf("%w: unsupported timestamp format: %s", ErrBadFormat, format)
	}
}

// getHeaderCaseInsensitive performs case-insensitive header lookup
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
