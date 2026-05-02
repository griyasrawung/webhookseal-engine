package webhookseal

import "time"

// Result contains normalized webhook verification output metadata.
type Result struct {
	Valid          bool
	Provider       string
	Timestamp      time.Time
	Algorithm      string
	ReplayDetected bool
	Reason         string
	SignatureID    string
}
