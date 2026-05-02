package timestamp

import (
	"errors"
	"testing"
	"time"

	"github.com/griyasrawung/webhookseal-engine/internal/specs"
)

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

func strPtr(v string) *string { return &v }

func TestExtract_StripeEmbeddedTimestamp(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:       "Stripe-Signature",
		TimestampFormat:       strPtr("epoch_seconds"),
		TimestampLocation:     strPtr("embedded_in_signature"),
		TimestampParsePattern: `t=(\d+)`,
	}

	headers := map[string]string{
		"Stripe-Signature": "t=1712345678,v1=abcdef",
	}

	ts, raw, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if raw != 1712345678 {
		t.Fatalf("raw mismatch: got %d want %d", raw, int64(1712345678))
	}
	if ts.Unix() != 1712345678 {
		t.Fatalf("timestamp mismatch: got %d want %d", ts.Unix(), int64(1712345678))
	}
}

func TestExtract_SlackSeparateHeader(t *testing.T) {
	spec := &specs.ProviderSpec{
		TimestampHeader:   strPtr("X-Slack-Request-Timestamp"),
		TimestampFormat:   strPtr("epoch_seconds"),
		TimestampLocation: strPtr("header"),
	}

	headers := map[string]string{
		"x-slack-request-timestamp": "1712345678",
	}

	ts, raw, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if raw != 1712345678 {
		t.Fatalf("raw mismatch: got %d want %d", raw, int64(1712345678))
	}
	if ts.Unix() != 1712345678 {
		t.Fatalf("timestamp mismatch: got %d want %d", ts.Unix(), int64(1712345678))
	}
}

func TestValidateWindow_ExpiredTimestampRejection(t *testing.T) {
	clock := fixedClock{now: time.Unix(200, 0).UTC()}
	ts := time.Unix(100, 0).UTC()
	window := 30 * time.Second

	err := ValidateWindow(clock, ts, window)
	if !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired, got %v", err)
	}
}

func TestValidateWindow_WithinWindowSuccess(t *testing.T) {
	clock := fixedClock{now: time.Unix(200, 0).UTC()}
	ts := time.Unix(190, 0).UTC()
	window := 30 * time.Second

	if err := ValidateWindow(clock, ts, window); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestExtract_MissingHeaderError(t *testing.T) {
	spec := &specs.ProviderSpec{
		TimestampHeader:   strPtr("X-Slack-Request-Timestamp"),
		TimestampFormat:   strPtr("epoch_seconds"),
		TimestampLocation: strPtr("header"),
	}

	_, _, err := Extract(spec, map[string]string{"X-Other": "value"})
	if !errors.Is(err, ErrMissingTimestamp) {
		t.Fatalf("expected ErrMissingTimestamp, got %v", err)
	}
}

func TestExtract_BadFormatError(t *testing.T) {
	spec := &specs.ProviderSpec{
		TimestampHeader:   strPtr("X-Slack-Request-Timestamp"),
		TimestampFormat:   strPtr("epoch_seconds"),
		TimestampLocation: strPtr("header"),
	}

	_, _, err := Extract(spec, map[string]string{"X-Slack-Request-Timestamp": "not-a-number"})
	if !errors.Is(err, ErrBadFormat) {
		t.Fatalf("expected ErrBadFormat, got %v", err)
	}
}
