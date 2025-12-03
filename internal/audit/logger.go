package audit

import (
	"context"

	"github.com/ConstantineCTF/nexus/internal/storage"
)

// Logger handles audit logging
type Logger struct {
	storage storage.Storage
}

// NewLogger creates a new audit logger
func NewLogger(store storage.Storage) *Logger {
	return &Logger{
		storage: store,
	}
}

// Log logs an audit event
func (l *Logger) Log(ctx context.Context, event *Event) error {
	log := &storage.AuditLog{
		Action:     string(event.Type),
		User:       event.UserID,
		SecretID:   event.SecretID,
		SecretPath: event.SecretPath,
		IPAddress:  event.IPAddress,
		UserAgent:  event.UserAgent,
		Success:    event.Success,
		Error:      event.Error,
		Metadata:   event.Metadata,
	}

	return l.storage.CreateAuditLog(ctx, log)
}
