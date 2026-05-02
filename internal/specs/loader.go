package specs

import (
	"fmt"
	"io/fs"
	pathpkg "path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProviderSpec represents a parsed provider YAML specification
type ProviderSpec struct {
	SpecVersion          string   `yaml:"spec_version"`
	ProviderID           string   `yaml:"provider_id"`
	DisplayName          string   `yaml:"display_name"`
	Algorithm            string   `yaml:"algorithm"`
	SignatureHeader      string   `yaml:"signature_header"`
	SignaturePrefix      string   `yaml:"signature_prefix"`
	SignatureEncoding    string   `yaml:"signature_encoding"`
	SignatureParsePattern string  `yaml:"signature_parse_pattern"`
	TimestampHeader      *string  `yaml:"timestamp_header"`
	TimestampFormat      *string  `yaml:"timestamp_format"`
	TimestampLocation    *string  `yaml:"timestamp_location"`
	TimestampParsePattern string  `yaml:"timestamp_parse_pattern"`
	PayloadConstruction  string   `yaml:"payload_construction"`
	PayloadTemplate      *string  `yaml:"payload_template"`
	ReplayWindowSeconds  *int     `yaml:"replay_window_seconds"`
	MultipleSignatures   bool     `yaml:"multiple_signatures"`
	ExtraHeaders         []string `yaml:"extra_headers"`
	SourceDocs           []struct {
		URL           string `yaml:"url"`
		RetrievedDate string `yaml:"retrieved_date"`
	} `yaml:"source_docs"`
	Notes string `yaml:"notes"`

	// Compiled regex patterns
	signatureParseRegex  *regexp.Regexp
	timestampParseRegex  *regexp.Regexp
}

var (
	providerIDRegex  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	specVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	
	validAlgorithms = map[string]bool{
		"hmac-sha256": true,
		"hmac-sha1":   true,
	}
	
	validEncodings = map[string]bool{
		"hex":    true,
		"base64": true,
	}
)

// LoadAll loads and validates all provider specs from the given filesystem
func LoadAll(fsys fs.FS) (map[string]*ProviderSpec, error) {
	specs := make(map[string]*ProviderSpec)
	
	entries, err := fs.ReadDir(fsys, "providers")
	if err != nil {
		return nil, fmt.Errorf("failed to read providers directory: %w", err)
	}
	
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		
		path := pathpkg.Join("providers", entry.Name())
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}
		
		var spec ProviderSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		
		if err := validateSpec(&spec, path); err != nil {
			return nil, fmt.Errorf("validation failed for %s: %w", path, err)
		}
		
		// Check for duplicate provider_id
		if _, exists := specs[spec.ProviderID]; exists {
			return nil, fmt.Errorf("duplicate provider_id '%s' found in %s", spec.ProviderID, path)
		}
		
		specs[spec.ProviderID] = &spec
	}
	
	if len(specs) == 0 {
		return nil, fmt.Errorf("no provider specs found")
	}
	
	return specs, nil
}

func validateSpec(spec *ProviderSpec, path string) error {
	// Required string fields
	requiredFields := map[string]string{
		"spec_version":         spec.SpecVersion,
		"provider_id":          spec.ProviderID,
		"display_name":         spec.DisplayName,
		"algorithm":            spec.Algorithm,
		"signature_header":     spec.SignatureHeader,
		"signature_encoding":   spec.SignatureEncoding,
		"payload_construction": spec.PayloadConstruction,
		"notes":                spec.Notes,
	}

	
	for field, value := range requiredFields {
		if value == "" {
			return fmt.Errorf("required field '%s' is missing or empty", field)
		}
	}
	
	// Validate spec_version format
	if !specVersionRegex.MatchString(spec.SpecVersion) {
		return fmt.Errorf("spec_version '%s' does not match semver pattern", spec.SpecVersion)
	}
	
	// Validate provider_id format
	if !providerIDRegex.MatchString(spec.ProviderID) {
		return fmt.Errorf("provider_id '%s' does not match pattern ^[a-z][a-z0-9-]*$", spec.ProviderID)
	}
	
	// Validate algorithm
	if !validAlgorithms[spec.Algorithm] {
		return fmt.Errorf("algorithm '%s' is not valid (must be hmac-sha256 or hmac-sha1)", spec.Algorithm)
	}
	
	// Validate signature_encoding
	if !validEncodings[spec.SignatureEncoding] {
		return fmt.Errorf("signature_encoding '%s' is not valid (must be hex or base64)", spec.SignatureEncoding)
	}
	
	// Validate source_docs is not empty
	if len(spec.SourceDocs) == 0 {
		return fmt.Errorf("source_docs must contain at least one entry")
	}
	
	// Compile signature_parse_pattern if present
	if spec.SignatureParsePattern != "" {
		re, err := regexp.Compile(spec.SignatureParsePattern)
		if err != nil {
			return fmt.Errorf("invalid signature_parse_pattern: %w", err)
		}
		spec.signatureParseRegex = re
	}
	
	// Compile timestamp_parse_pattern if present
	if spec.TimestampParsePattern != "" {
		re, err := regexp.Compile(spec.TimestampParsePattern)
		if err != nil {
			return fmt.Errorf("invalid timestamp_parse_pattern: %w", err)
		}
		spec.timestampParseRegex = re
	}

	hasTimestampHeader := spec.TimestampHeader != nil && strings.TrimSpace(*spec.TimestampHeader) != ""
	hasTimestampFormat := spec.TimestampFormat != nil && strings.TrimSpace(*spec.TimestampFormat) != ""
	hasTimestampLocation := spec.TimestampLocation != nil && strings.TrimSpace(*spec.TimestampLocation) != ""
	hasTimestampPattern := strings.TrimSpace(spec.TimestampParsePattern) != ""

	// No timestamp semantics at all is valid.
	if !hasTimestampHeader && !hasTimestampFormat && !hasTimestampLocation {
		if hasTimestampPattern {
			return fmt.Errorf("timestamp_parse_pattern requires timestamp fields")
		}
		return nil
	}

	// Standard timestamp-in-header shape: all three non-empty.
	if hasTimestampHeader && hasTimestampFormat && hasTimestampLocation {
		return nil
	}

	// Stripe-style embedded timestamp shape.
	if !hasTimestampHeader && hasTimestampFormat && hasTimestampLocation {
		if *spec.TimestampFormat != "epoch_seconds" {
			return fmt.Errorf("embedded timestamp requires timestamp_format 'epoch_seconds'")
		}
		if *spec.TimestampLocation != "embedded_in_signature" {
			return fmt.Errorf("embedded timestamp requires timestamp_location 'embedded_in_signature'")
		}
		if !hasTimestampPattern {
			return fmt.Errorf("embedded timestamp requires timestamp_parse_pattern")
		}
		return nil
	}

	return fmt.Errorf("invalid timestamp field combination")
}
