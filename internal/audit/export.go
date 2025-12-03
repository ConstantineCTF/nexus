package audit

import (
	"context"
	"encoding/json"
	"io"

	"github.com/ConstantineCTF/nexus/internal/storage"
)

// Exporter handles audit log export
type Exporter struct {
	storage storage.Storage
}

// NewExporter creates a new audit log exporter
func NewExporter(store storage.Storage) *Exporter {
	return &Exporter{
		storage: store,
	}
}

// ExportJSON exports audit logs as JSON
func (e *Exporter) ExportJSON(ctx context.Context, filter storage.AuditFilter, w io.Writer) error {
	logs, err := e.storage.GetAuditLogs(ctx, filter)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(logs)
}
