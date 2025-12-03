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
	flag.Parse()

	// Initialize storage
	store, err := storage.NewSQLiteStorage(":memory:")
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Initialize keyring
	keyring, err := crypto.NewKeyring()
	if err != nil {
		log.Fatalf("Failed to initialize keyring: %v", err)
	}

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
