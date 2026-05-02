package payload

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/griyasrawung/webhookseal-engine/internal/specs"
)

// Input contains all data needed to construct a payload
type Input struct {
	Body   []byte            // Raw request body bytes
	URL    string            // Full request URL (for Twilio-style construction)
	Params map[string]string // Query/form parameters (for Twilio-style construction)
}

// Build constructs the payload bytes according to the provider's specification.
// For raw_body mode, returns Body unchanged.
// For custom mode, applies the payload_template with substitutions.
// Returns error for unsupported payload_construction values or missing required data.
func Build(spec *specs.ProviderSpec, input Input, timestamp int64) ([]byte, error) {
	switch spec.PayloadConstruction {
	case "raw_body":
		return input.Body, nil

	case "custom":
		if spec.PayloadTemplate == nil || *spec.PayloadTemplate == "" {
			return nil, fmt.Errorf("custom payload_construction requires payload_template")
		}
		return buildCustom(*spec.PayloadTemplate, input, timestamp)

	default:
		return nil, fmt.Errorf("unsupported payload_construction: %s", spec.PayloadConstruction)
	}
}

// buildCustom applies template substitutions for custom payload construction
func buildCustom(template string, input Input, timestamp int64) ([]byte, error) {
	result := template

	// Replace {timestamp}
	if strings.Contains(result, "{timestamp}") {
		result = strings.ReplaceAll(result, "{timestamp}", strconv.FormatInt(timestamp, 10))
	}

	// Replace {body}
	if strings.Contains(result, "{body}") {
		result = strings.ReplaceAll(result, "{body}", string(input.Body))
	}

	// Replace {url}
	if strings.Contains(result, "{url}") {
		if input.URL == "" {
			return nil, fmt.Errorf("template requires {url} but URL is empty")
		}
		result = strings.ReplaceAll(result, "{url}", input.URL)
	}

	// Replace {sorted_params}
	if strings.Contains(result, "{sorted_params}") {
		sorted := SortedParams(input.Params)
		result = strings.ReplaceAll(result, "{sorted_params}", sorted)
	}

	return []byte(result), nil
}
