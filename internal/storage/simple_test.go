package storage

import (
	"context"
	"testing"
	"time"
)

func TestSimple(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	secret := &Secret{
		Path:      "test/simple",
		Value:     []byte("test-value"),
		Metadata:  map[string]string{},
		Version:   1,
		CreatedAt: time.Now(),
		CreatedBy: "admin",
		UpdatedAt: time.Now(),
		UpdatedBy: "admin",
	}

	if err := storage.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("Failed: %v", err)
	}

	t.Log("Success!")
}
