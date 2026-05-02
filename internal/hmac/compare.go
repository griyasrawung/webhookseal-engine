package hmac

import "crypto/subtle"

// TimingSafeEqual compares raw signature bytes without leaking prefix matches.
func TimingSafeEqual(computed, received []byte) bool {
	if len(computed) != len(received) {
		return false
	}
	return subtle.ConstantTimeCompare(computed, received) == 1
}
