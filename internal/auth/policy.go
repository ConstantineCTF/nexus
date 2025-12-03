package auth

// PolicyEngine handles role-based access control
type PolicyEngine struct {
	policies map[string]*Policy
}

// Policy defines access rules for a role
type Policy struct {
	Role        string
	Permissions []Permission
}

// Permission defines a specific permission
type Permission struct {
	Resource string // e.g., "secrets/*", "secrets/prod/*"
	Actions  []string // e.g., ["read", "write", "delete"]
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*Policy),
	}
}

// AddPolicy adds a policy for a role
func (p *PolicyEngine) AddPolicy(policy *Policy) {
	p.policies[policy.Role] = policy
}

// CanAccess checks if a role can perform an action on a resource
func (p *PolicyEngine) CanAccess(role, resource, action string) bool {
	policy, exists := p.policies[role]
	if !exists {
		return false
	}

	// Admin role has full access
	if role == "admin" {
		return true
	}

	for _, perm := range policy.Permissions {
		if matchesResource(perm.Resource, resource) {
			for _, a := range perm.Actions {
				if a == action || a == "*" {
					return true
				}
			}
		}
	}

	return false
}

// matchesResource checks if a pattern matches a resource
func matchesResource(pattern, resource string) bool {
	// Simple wildcard matching
	if pattern == "*" || pattern == resource {
		return true
	}

	// Handle trailing wildcard
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(resource) >= len(prefix) && resource[:len(prefix)] == prefix
	}

	return false
}
