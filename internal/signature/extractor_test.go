package signature

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/webhookseal/webhookseal-engine/internal/specs"
)

func TestExtract_GitHub(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Hub-Signature-256",
		SignaturePrefix:   "sha256=",
		SignatureEncoding: "hex",
	}

	rawSig := []byte{0xde, 0xad, 0xbe, 0xef}
	hexSig := hex.EncodeToString(rawSig)

	headers := map[string]string{
		"X-Hub-Signature-256": "sha256=" + hexSig,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig) {
		t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
	}
}

func TestExtract_Shopify(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Shopify-Hmac-Sha256",
		SignaturePrefix:   "",
		SignatureEncoding: "base64",
	}

	rawSig := []byte{0xca, 0xfe, 0xba, 0xbe}
	b64Sig := base64.StdEncoding.EncodeToString(rawSig)

	headers := map[string]string{
		"X-Shopify-Hmac-Sha256": b64Sig,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig) {
		t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
	}
}

func TestExtract_Stripe_SingleSignature(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:       "Stripe-Signature",
		SignaturePrefix:       "",
		SignatureEncoding:     "hex",
		SignatureParsePattern: `v1=([a-f0-9]+)`,
	}

	rawSig := []byte{0x12, 0x34, 0x56, 0x78}
	hexSig := hex.EncodeToString(rawSig)

	headers := map[string]string{
		"Stripe-Signature": "t=1234567890,v1=" + hexSig,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig) {
		t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
	}
}

func TestExtract_Stripe_MultipleSignatures(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:       "Stripe-Signature",
		SignaturePrefix:       "",
		SignatureEncoding:     "hex",
		SignatureParsePattern: `v1=([a-f0-9]+)`,
	}

	rawSig1 := []byte{0xaa, 0xbb}
	rawSig2 := []byte{0xcc, 0xdd}
	hexSig1 := hex.EncodeToString(rawSig1)
	hexSig2 := hex.EncodeToString(rawSig2)

	headers := map[string]string{
		"Stripe-Signature": "t=1234567890,v1=" + hexSig1 + ",v1=" + hexSig2,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig1) {
		t.Errorf("signature[0] mismatch: got %x, want %x", sigs[0], rawSig1)
	}
	if string(sigs[1]) != string(rawSig2) {
		t.Errorf("signature[1] mismatch: got %x, want %x", sigs[1], rawSig2)
	}
}

func TestExtract_Slack(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Slack-Signature",
		SignaturePrefix:   "v0=",
		SignatureEncoding: "hex",
	}

	rawSig := []byte{0x11, 0x22, 0x33, 0x44}
	hexSig := hex.EncodeToString(rawSig)

	headers := map[string]string{
		"X-Slack-Signature": "v0=" + hexSig,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig) {
		t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
	}
}

func TestExtract_Twilio(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Twilio-Signature",
		SignaturePrefix:   "",
		SignatureEncoding: "base64",
	}

	rawSig := []byte{0xff, 0xee, 0xdd, 0xcc}
	b64Sig := base64.StdEncoding.EncodeToString(rawSig)

	headers := map[string]string{
		"X-Twilio-Signature": b64Sig,
	}

	sigs, err := Extract(spec, headers)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if string(sigs[0]) != string(rawSig) {
		t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
	}
}

func TestExtract_CaseInsensitiveHeader(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Hub-Signature-256",
		SignaturePrefix:   "sha256=",
		SignatureEncoding: "hex",
	}

	rawSig := []byte{0xab, 0xcd}
	hexSig := hex.EncodeToString(rawSig)

	tests := []struct {
		name       string
		headerKey  string
		wantErr    bool
	}{
		{"exact case", "X-Hub-Signature-256", false},
		{"lowercase", "x-hub-signature-256", false},
		{"uppercase", "X-HUB-SIGNATURE-256", false},
		{"mixed case", "x-HuB-sIgNaTuRe-256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{
				tt.headerKey: "sha256=" + hexSig,
			}

			sigs, err := Extract(spec, headers)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			if len(sigs) != 1 {
				t.Fatalf("expected 1 signature, got %d", len(sigs))
			}
			if string(sigs[0]) != string(rawSig) {
				t.Errorf("signature mismatch: got %x, want %x", sigs[0], rawSig)
			}
		})
	}
}

func TestExtract_MissingSignature(t *testing.T) {
	spec := &specs.ProviderSpec{
		SignatureHeader:   "X-Signature",
		SignaturePrefix:   "",
		SignatureEncoding: "hex",
	}

	tests := []struct {
		name    string
		headers map[string]string
		wantErr error
	}{
		{"nil headers", nil, ErrMissingSignature},
		{"empty headers", map[string]string{}, ErrMissingSignature},
		{"different header", map[string]string{"X-Other": "value"}, ErrMissingSignature},
		{"empty value", map[string]string{"X-Signature": ""}, ErrBadFormat},
		{"whitespace only", map[string]string{"X-Signature": "   "}, ErrBadFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Extract(spec, tt.headers)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestExtract_BadFormat(t *testing.T) {
	tests := []struct {
		name    string
		spec    *specs.ProviderSpec
		headers map[string]string
	}{
		{
			name: "prefix mismatch",
			spec: &specs.ProviderSpec{
				SignatureHeader:   "X-Sig",
				SignaturePrefix:   "sha256=",
				SignatureEncoding: "hex",
			},
			headers: map[string]string{"X-Sig": "sha1=deadbeef"},
		},
		{
			name: "invalid hex",
			spec: &specs.ProviderSpec{
				SignatureHeader:   "X-Sig",
				SignaturePrefix:   "",
				SignatureEncoding: "hex",
			},
			headers: map[string]string{"X-Sig": "notvalidhex!"},
		},
		{
			name: "invalid base64",
			spec: &specs.ProviderSpec{
				SignatureHeader:   "X-Sig",
				SignaturePrefix:   "",
				SignatureEncoding: "base64",
			},
			headers: map[string]string{"X-Sig": "not!!!valid!!!base64"},
		},
		{
			name: "regex no captures",
			spec: &specs.ProviderSpec{
				SignatureHeader:       "X-Sig",
				SignaturePrefix:       "",
				SignatureEncoding:     "hex",
				SignatureParsePattern: `v1=([a-f0-9]+)`,
			},
			headers: map[string]string{"X-Sig": "t=1234567890"},
		},
		{
			name: "empty after prefix removal",
			spec: &specs.ProviderSpec{
				SignatureHeader:   "X-Sig",
				SignaturePrefix:   "prefix=",
				SignatureEncoding: "hex",
			},
			headers: map[string]string{"X-Sig": "prefix="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Extract(tt.spec, tt.headers)
			if !errors.Is(err, ErrBadFormat) {
				t.Errorf("expected ErrBadFormat, got %v", err)
			}
		})
	}
}

func TestExtract_NilSpec(t *testing.T) {
	headers := map[string]string{"X-Sig": "value"}
	_, err := Extract(nil, headers)
	if !errors.Is(err, ErrBadFormat) {
		t.Errorf("expected ErrBadFormat for nil spec, got %v", err)
	}
}
