package payload

import (
	"sort"
	"strings"
)

// SortedParams returns a deterministic string representation of parameters
// by sorting keys lexicographically and concatenating key+value pairs.
// Used for Twilio-style payload construction.
// Returns empty string for nil or empty maps.
func SortedParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(params[k])
	}

	return sb.String()
}
