package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ConstantineCTF/nexus/internal/crypto"
	"github.com/ConstantineCTF/nexus/internal/server"
	"github.com/ConstantineCTF/nexus/internal/storage"
)

func main() {
	addr := flag.String("addr", ":9000", "Server address")
	storageType := flag.String("storage", "memory", "Storage backend: memory or sqlite")
	dbPath := flag.String("db", "./nexus. db", "SQLite database path (when storage=sqlite)")
	flag.Parse()

	// Load or create keyring
	var keyring *crypto.Keyring
	var err error

	keyringDir := "./data/keys"
	keyringPassword := os.Getenv("NEXUS_KEY_PASSWORD")
	if keyringPassword == "" {
		keyringPassword = "changeme-in-production" // Default password
	}

	// Try to load existing keyring
	keyring, err = crypto.LoadFromFiles(keyringDir, keyringPassword)
	if err != nil {
		// Keyring doesn't exist, create new one
		log.Println("No existing keyring found, creating new one...")
		keyring, err = crypto.NewKeyring()
		if err != nil {
			log.Fatalf("Failed to create keyring: %v", err)
		}

		// Save keyring to disk
		if err := keyring.SaveToFiles(keyringDir, keyringPassword); err != nil {
			log.Fatalf("Failed to save keyring: %v", err)
		}
		log.Printf("✓ Keyring saved to %s", keyringDir)
	} else {
		log.Printf("✓ Loaded existing keyring from %s", keyringDir)
	}

	// Initialize storage based on flag
	var store storage.Storage

	switch *storageType {
	case "sqlite":
		store, err = storage.NewSQLiteStorage(*dbPath)
		if err != nil {
			log.Fatalf("Failed to create SQLite storage: %v", err)
		}
		log.Printf("Using SQLite storage: %s", *dbPath)
	case "memory":
		store = storage.NewMemoryStorage()
		log.Println("WARNING: Using in-memory storage - all data will be lost on restart!")
	default:
		log.Fatalf("Unknown storage type: %s", *storageType)
	}
	defer store.Close()

	// Create server config
	cfg := server.Config{
		Address:      *addr,
		JWTSecret:    []byte("dev-secret-key-do-not-use-in-production"),
		JWTExpiry:    24 * time.Hour,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Create and start server
	srv := server.NewServer(cfg, store, keyring)

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Starting NEXUS server on %s", *addr)
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	<-done
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server stopped")
}
