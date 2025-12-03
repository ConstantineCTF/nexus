package audit

// EventType represents types of audit events
type EventType string

const (
	EventSecretCreate  EventType = "secret.create"
	EventSecretRead    EventType = "secret.read"
	EventSecretUpdate  EventType = "secret.update"
	EventSecretDelete  EventType = "secret.delete"
	EventSecretList    EventType = "secret.list"
	EventSecretVersion EventType = "secret.versions"
	EventAuthLogin     EventType = "auth.login"
	EventAuthRefresh   EventType = "auth.refresh"
	EventAPIKeyCreate  EventType = "apikey.create"
	EventAPIKeyRevoke  EventType = "apikey.revoke"
	EventAuditList     EventType = "audit.list"
)

// Event represents an audit event
type Event struct {
	Type       EventType
	UserID     string
	SecretID   string
	SecretPath string
	IPAddress  string
	UserAgent  string
	Success    bool
	Error      string
	Metadata   map[string]string
}
