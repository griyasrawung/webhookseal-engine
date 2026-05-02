package webhookseal

// VerifyOption configures provider-specific verification inputs.
type VerifyOption func(*verifyConfig) error

type verifyConfig struct {
	url         string
	params      map[string]string
	replayID    string
	replayScope string
}

func defaultVerifyConfig() *verifyConfig {
	return &verifyConfig{}
}

// WithURL sets the full URL used by providers with URL-based signing.
func WithURL(url string) VerifyOption {
	return func(c *verifyConfig) error {
		c.url = url
		return nil
	}
}

// WithParams sets query or form parameters used by providers with parameter canonicalization.
func WithParams(params map[string]string) VerifyOption {
	return func(c *verifyConfig) error {
		c.params = params
		return nil
	}
}

// WithReplayID sets the unique event identifier for replay detection.
func WithReplayID(id string) VerifyOption {
	return func(c *verifyConfig) error {
		c.replayID = id
		return nil
	}
}

// WithReplayScope sets the replay-detection scope. Defaults to provider when empty.
func WithReplayScope(scope string) VerifyOption {
	return func(c *verifyConfig) error {
		c.replayScope = scope
		return nil
	}
}
