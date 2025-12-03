package rotation

import "time"

// Policy defines a secret rotation policy
type Policy struct {
	Enabled      bool
	Interval     time.Duration
	Provider     string
	NextRotation time.Time
}

// NewPolicy creates a new rotation policy
func NewPolicy(interval time.Duration, provider string) *Policy {
	return &Policy{
		Enabled:      true,
		Interval:     interval,
		Provider:     provider,
		NextRotation: time.Now().Add(interval),
	}
}
