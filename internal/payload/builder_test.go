package payload

import (
	"testing"

	"github.com/webhookseal/webhookseal-engine/internal/specs"
)

func TestSortedParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{
			name:   "nil map",
			params: nil,
			want:   "",
		},
		{
			name:   "empty map",
			params: map[string]string{},
			want:   "",
		},
		{
			name:   "single param",
			params: map[string]string{"key": "value"},
			want:   "keyvalue",
		},
		{
			name:   "multiple params sorted",
			params: map[string]string{"B": "2", "A": "1"},
			want:   "A1B2",
		},
		{
			name:   "lexicographic sort",
			params: map[string]string{"z": "last", "a": "first", "m": "middle"},
			want:   "afirstmmiddlezlast",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortedParams(tt.params)
			if got != tt.want {
				t.Errorf("SortedParams() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuild_RawBody(t *testing.T) {
	spec := &specs.ProviderSpec{
		PayloadConstruction: "raw_body",
	}

	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "simple json",
			body: []byte(`{"key":"value"}`),
		},
		{
			name: "preserves whitespace",
			body: []byte(`{
  "key": "value"
}`),
		},
		{
			name: "preserves newlines",
			body: []byte("line1\nline2\nline3"),
		},
		{
			name: "empty body",
			body: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Body: tt.body}
			got, err := Build(spec, input, 1234567890)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if string(got) != string(tt.body) {
				t.Errorf("Build() = %q, want %q", got, tt.body)
			}
		})
	}
}

func TestBuild_CustomStripe(t *testing.T) {
	template := "{timestamp}.{body}"
	spec := &specs.ProviderSpec{
		PayloadConstruction: "custom",
		PayloadTemplate:     &template,
	}

	input := Input{
		Body: []byte(`{"event":"test"}`),
	}

	got, err := Build(spec, input, 1234567890)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `1234567890.{"event":"test"}`
	if string(got) != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestBuild_CustomSlack(t *testing.T) {
	template := "v0:{timestamp}:{body}"
	spec := &specs.ProviderSpec{
		PayloadConstruction: "custom",
		PayloadTemplate:     &template,
	}

	input := Input{
		Body: []byte(`{"type":"url_verification"}`),
	}

	got, err := Build(spec, input, 1531420618)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `v0:1531420618:{"type":"url_verification"}`
	if string(got) != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestBuild_CustomTwilio(t *testing.T) {
	template := "{url}{sorted_params}"
	spec := &specs.ProviderSpec{
		PayloadConstruction: "custom",
		PayloadTemplate:     &template,
	}

	input := Input{
		URL:    "https://mycompany.com/myapp.php?foo=1&bar=2",
		Params: map[string]string{"B": "2", "A": "1"},
	}

	got, err := Build(spec, input, 0)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := "https://mycompany.com/myapp.php?foo=1&bar=2A1B2"
	if string(got) != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestBuild_Errors(t *testing.T) {
	tests := []struct {
		name    string
		spec    *specs.ProviderSpec
		input   Input
		wantErr string
	}{
		{
			name: "unsupported payload_construction",
			spec: &specs.ProviderSpec{
				PayloadConstruction: "unknown",
			},
			input:   Input{Body: []byte("test")},
			wantErr: "unsupported payload_construction: unknown",
		},
		{
			name: "custom without template",
			spec: &specs.ProviderSpec{
				PayloadConstruction: "custom",
				PayloadTemplate:     nil,
			},
			input:   Input{Body: []byte("test")},
			wantErr: "custom payload_construction requires payload_template",
		},
		{
			name: "custom with empty template",
			spec: &specs.ProviderSpec{
				PayloadConstruction: "custom",
				PayloadTemplate:     stringPtr(""),
			},
			input:   Input{Body: []byte("test")},
			wantErr: "custom payload_construction requires payload_template",
		},
		{
			name: "missing URL when required",
			spec: &specs.ProviderSpec{
				PayloadConstruction: "custom",
				PayloadTemplate:     stringPtr("{url}"),
			},
			input:   Input{URL: ""},
			wantErr: "template requires {url} but URL is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(tt.spec, tt.input, 0)
			if err == nil {
				t.Fatal("Build() expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Build() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
