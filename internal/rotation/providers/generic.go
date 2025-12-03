package providers

// GenericProvider handles generic secret rotation
type GenericProvider struct {
	// TODO: Implement generic secret rotation
}

// NewGenericProvider creates a new generic rotation provider
func NewGenericProvider() *GenericProvider {
	return &GenericProvider{}
}

// Rotate rotates a generic secret
func (p *GenericProvider) Rotate(secretPath string) (string, error) {
	// TODO: Implement generic secret rotation
	return "", nil
}
