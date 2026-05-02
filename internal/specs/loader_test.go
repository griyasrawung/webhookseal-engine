package specs

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadAll_ProvidersLoad(t *testing.T) {
	specs, err := LoadAll(ProviderFS)
	if err != nil {
		t.Fatalf("expected providers to load, got error: %v", err)
	}

	if len(specs) == 0 {
		t.Fatalf("expected non-empty specs map")
	}

	for _, id := range []string{"github", "shopify", "slack", "stripe", "twilio"} {
		if _, ok := specs[id]; !ok {
			t.Fatalf("expected provider %q in loaded specs", id)
		}
	}
}

func TestLoadAll_MissingRequiredFieldFails(t *testing.T) {
	fsys := fstest.MapFS{
		"providers/bad.yaml": &fstest.MapFile{Data: []byte(`
provider_id: "bad-provider"
display_name: "Bad"
algorithm: "hmac-sha256"
signature_header: "X-Sig"
signature_prefix: "sha256="
signature_encoding: "hex"
timestamp_header: null
timestamp_format: null
timestamp_location: null
payload_construction: "raw_body"
payload_template: null
replay_window_seconds: null
source_docs:
  - url: "https://example.com"
    retrieved_date: "2026-05-02"
notes: "missing spec_version"
`)},
	}

	_, err := LoadAll(fsys)
	if err == nil {
		t.Fatalf("expected error for missing required field")
	}
	if !strings.Contains(err.Error(), "spec_version") {
		t.Fatalf("expected error to mention spec_version, got: %v", err)
	}
}

func TestLoadAll_DuplicateProviderIDFails(t *testing.T) {
	fsys := fstest.MapFS{
		"providers/one.yaml": &fstest.MapFile{Data: []byte(validSpecYAML("dup-id"))},
		"providers/two.yaml": &fstest.MapFile{Data: []byte(validSpecYAML("dup-id"))},
	}

	_, err := LoadAll(fsys)
	if err == nil {
		t.Fatalf("expected error for duplicate provider_id")
	}
	if !strings.Contains(err.Error(), "duplicate provider_id") {
		t.Fatalf("expected duplicate provider_id error, got: %v", err)
	}
}

func TestLoadAll_InvalidRegexFails(t *testing.T) {
	fsys := fstest.MapFS{
		"providers/badregex.yaml": &fstest.MapFile{Data: []byte(`
spec_version: "1.0.0"
provider_id: "bad-regex"
display_name: "Bad Regex"
algorithm: "hmac-sha256"
signature_header: "X-Sig"
signature_prefix: "sha256="
signature_encoding: "hex"
signature_parse_pattern: "(["
timestamp_header: null
timestamp_format: null
timestamp_location: null
payload_construction: "raw_body"
payload_template: null
replay_window_seconds: null
source_docs:
  - url: "https://example.com"
    retrieved_date: "2026-05-02"
notes: "invalid regex"
`)},
	}

	_, err := LoadAll(fsys)
	if err == nil {
		t.Fatalf("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid signature_parse_pattern") {
		t.Fatalf("expected invalid signature_parse_pattern error, got: %v", err)
	}
}

func validSpecYAML(providerID string) string {
	return `
spec_version: "1.0.0"
provider_id: "` + providerID + `"
display_name: "Valid"
algorithm: "hmac-sha256"
signature_header: "X-Sig"
signature_prefix: "sha256="
signature_encoding: "hex"
timestamp_header: null
timestamp_format: null
timestamp_location: null
payload_construction: "raw_body"
payload_template: null
replay_window_seconds: null
source_docs:
  - url: "https://example.com"
    retrieved_date: "2026-05-02"
notes: "ok"
`
}
