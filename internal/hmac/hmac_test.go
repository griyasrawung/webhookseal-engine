package hmac

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCompute_KnownVectors(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		secret    []byte
		payload   []byte
		wantHex   string
	}{
		{
			name:      "sha256 rfc4231 test case 1",
			algorithm: "hmac-sha256",
			secret:    bytesOf(0x0b, 20),
			payload:   []byte("Hi There"),
			wantHex:   "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			name:      "sha1 rfc2202 test case 1",
			algorithm: "hmac-sha1",
			secret:    bytesOf(0x0b, 20),
			payload:   []byte("Hi There"),
			wantHex:   "b617318655057264e28bc0b6fb378c8ef146be00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compute(tt.algorithm, tt.secret, tt.payload)
			if err != nil {
				t.Fatalf("Compute returned error: %v", err)
			}

			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Fatalf("digest mismatch\nwant %s\n got %s", tt.wantHex, gotHex)
			}
		})
	}
}

func TestCompute_UnsupportedAlgorithm(t *testing.T) {
	_, err := Compute("hmac-sha512", []byte("secret"), []byte("payload"))
	if err == nil {
		t.Fatalf("expected unsupported algorithm error")
	}
	if !strings.Contains(err.Error(), "unsupported hmac algorithm") {
		t.Fatalf("expected unsupported algorithm error, got: %v", err)
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 0x10, 0xfe, 0xff}

	for _, encoding := range []string{"hex", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			encoded, err := Encode(raw, encoding)
			if err != nil {
				t.Fatalf("Encode returned error: %v", err)
			}

			decoded, err := Decode(encoded, encoding)
			if err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}

			if !TimingSafeEqual(raw, decoded) {
				t.Fatalf("roundtrip mismatch for %s", encoding)
			}
		})
	}
}

func TestEncode_UnsupportedEncoding(t *testing.T) {
	_, err := Encode([]byte("raw"), "base32")
	if err == nil {
		t.Fatalf("expected unsupported encoding error")
	}
	if !strings.Contains(err.Error(), "unsupported signature encoding") {
		t.Fatalf("expected unsupported encoding error, got: %v", err)
	}
}

func TestDecode_Errors(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		encoding string
		want     string
	}{
		{name: "invalid hex", encoded: "not-hex", encoding: "hex", want: "decode hex signature"},
		{name: "invalid base64", encoded: "!!!", encoding: "base64", want: "decode base64 signature"},
		{name: "unsupported", encoded: "abc", encoding: "base32", want: "unsupported signature encoding"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.encoded, tt.encoding)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got: %v", tt.want, err)
			}
		})
	}
}

func TestTimingSafeEqual(t *testing.T) {
	tests := []struct {
		name     string
		computed []byte
		received []byte
		want     bool
	}{
		{name: "equal", computed: []byte{0x01, 0x02, 0x03}, received: []byte{0x01, 0x02, 0x03}, want: true},
		{name: "not equal", computed: []byte{0x01, 0x02, 0x03}, received: []byte{0x01, 0x02, 0x04}, want: false},
		{name: "length mismatch", computed: []byte{0x01, 0x02, 0x03}, received: []byte{0x01, 0x02}, want: false},
		{name: "empty equal", computed: []byte{}, received: []byte{}, want: true},
		{name: "nil and empty equal", computed: nil, received: []byte{}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TimingSafeEqual(tt.computed, tt.received)
			if got != tt.want {
				t.Fatalf("TimingSafeEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
