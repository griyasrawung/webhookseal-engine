package webhookseal

import (
	"testing"
	"time"
)

func TestResultZeroValue(t *testing.T) {
	var r Result

	if r.Valid != false {
		t.Errorf("Result.Valid zero value = %v, want false", r.Valid)
	}
	if r.Provider != "" {
		t.Errorf("Result.Provider zero value = %q, want empty string", r.Provider)
	}
	if !r.Timestamp.IsZero() {
		t.Errorf("Result.Timestamp zero value = %v, want zero time", r.Timestamp)
	}
	if r.Algorithm != "" {
		t.Errorf("Result.Algorithm zero value = %q, want empty string", r.Algorithm)
	}
	if r.ReplayDetected != false {
		t.Errorf("Result.ReplayDetected zero value = %v, want false", r.ReplayDetected)
	}
	if r.Reason != "" {
		t.Errorf("Result.Reason zero value = %q, want empty string", r.Reason)
	}
	if r.SignatureID != "" {
		t.Errorf("Result.SignatureID zero value = %q, want empty string", r.SignatureID)
	}
}

func TestResultMetadataFields(t *testing.T) {
	now := time.Now()
	r := Result{
		Valid:          true,
		Provider:       "github",
		Timestamp:      now,
		Algorithm:      "sha256",
		ReplayDetected: false,
		Reason:         "signature valid",
		SignatureID:    "sig_123",
	}

	if r.Valid != true {
		t.Errorf("Result.Valid = %v, want true", r.Valid)
	}
	if r.Provider != "github" {
		t.Errorf("Result.Provider = %q, want %q", r.Provider, "github")
	}
	if !r.Timestamp.Equal(now) {
		t.Errorf("Result.Timestamp = %v, want %v", r.Timestamp, now)
	}
	if r.Algorithm != "sha256" {
		t.Errorf("Result.Algorithm = %q, want %q", r.Algorithm, "sha256")
	}
	if r.ReplayDetected != false {
		t.Errorf("Result.ReplayDetected = %v, want false", r.ReplayDetected)
	}
	if r.Reason != "signature valid" {
		t.Errorf("Result.Reason = %q, want %q", r.Reason, "signature valid")
	}
	if r.SignatureID != "sig_123" {
		t.Errorf("Result.SignatureID = %q, want %q", r.SignatureID, "sig_123")
	}
}

func TestResultReplayDetection(t *testing.T) {
	r := Result{
		Valid:          false,
		Provider:       "stripe",
		ReplayDetected: true,
		Reason:         "duplicate message ID",
	}

	if r.Valid != false {
		t.Errorf("Result.Valid = %v, want false for replay", r.Valid)
	}
	if r.ReplayDetected != true {
		t.Errorf("Result.ReplayDetected = %v, want true", r.ReplayDetected)
	}
	if r.Reason != "duplicate message ID" {
		t.Errorf("Result.Reason = %q, want %q", r.Reason, "duplicate message ID")
	}
}
