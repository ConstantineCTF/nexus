package cmd

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var (
	backupOutputDir string
	backupFile      string
)

// stdinReader is a shared bufio.Reader for stdin to avoid consuming multiple buffers
var stdinReader *bufio.Reader

// backupCmd represents the backup command
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore NEXUS data",
	Long: `Backup and restore NEXUS data including the database and encryption keys.

Backups are encrypted using AES-256-GCM with a password-derived key (Argon2id).`,
}

// backupCreateCmd represents the backup create command
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an encrypted backup",
	Long: `Create an encrypted backup of the NEXUS database and keys.

The backup includes:
- nexus.db (SQLite database)
- data/keys/ directory (encryption keys)

The backup is encrypted with AES-256-GCM using a password-derived key.

Example:
  nexusctl backup create --output ./backups`,
	RunE: runBackupCreate,
}

// backupRestoreCmd represents the backup restore command
var backupRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore from an encrypted backup",
	Long: `Restore NEXUS data from an encrypted backup file.

WARNING: The server must be stopped before restoring.

The restore process will:
1. Decrypt the backup file
2. Show the files to be restored
3. Ask for confirmation before overwriting

Example:
  nexusctl backup restore --file ./backups/nexus-backup-2025-12-03-235959.tar.gz.enc`,
	RunE: runBackupRestore,
}

func init() {
	rootCmd.AddCommand(backupCmd)
	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupRestoreCmd)

	backupCreateCmd.Flags().StringVarP(&backupOutputDir, "output", "o", ".", "Output directory for the backup file")
	backupRestoreCmd.Flags().StringVarP(&backupFile, "file", "f", "", "Backup file to restore from")
	backupRestoreCmd.MarkFlagRequired("file")
}

// readPassword prompts the user for a password
func readPassword(prompt string) (string, error) {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}

	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print(prompt)
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // Print newline after hidden input
		return string(passwordBytes), nil
	}

	// Non-interactive mode: read from stdin
	fmt.Print(prompt)
	input, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return strings.TrimSpace(input), nil
}

// readConfirmation prompts the user for a yes/no confirmation
func readConfirmation(prompt string) (bool, error) {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	fmt.Print(prompt)
	input, err := stdinReader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y", nil
}

// deriveKey derives an encryption key from a password using Argon2id
func deriveKey(password string, salt []byte) []byte {
	// Argon2id parameters: time=1, memory=64MB, threads=4, keyLen=32
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// encryptBackup encrypts data using AES-256-GCM
func encryptBackup(plaintext []byte, password string) ([]byte, error) {
	// Generate salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := deriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: salt (16 bytes) + nonce (12 bytes) + ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptBackup decrypts data using AES-256-GCM
func decryptBackup(encrypted []byte, password string) ([]byte, error) {
	// Minimum size: salt (16) + nonce (12) + tag (16) + data (at least 1)
	if len(encrypted) < 45 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt and nonce
	salt := encrypted[:16]
	nonce := encrypted[16:28]
	ciphertext := encrypted[28:]

	// Derive key from password
	key := deriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt (wrong password?): %w", err)
	}

	return plaintext, nil
}

// createTarGz creates a tar.gz archive from the given files/directories
func createTarGz(sources map[string]string) ([]byte, error) {
	var buf strings.Builder
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for archivePath, srcPath := range sources {
		info, err := os.Stat(srcPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip non-existent files
			}
			return nil, fmt.Errorf("failed to stat %s: %w", srcPath, err)
		}

		if info.IsDir() {
			// Walk directory and add all files
			err = filepath.Walk(srcPath, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Create relative path in archive
				relPath, err := filepath.Rel(srcPath, path)
				if err != nil {
					return err
				}
				if relPath == "." {
					relPath = ""
				}
				fullArchivePath := filepath.Join(archivePath, relPath)
				fullArchivePath = filepath.ToSlash(fullArchivePath) // Use forward slashes in archive

				header, err := tar.FileInfoHeader(fi, "")
				if err != nil {
					return err
				}
				header.Name = fullArchivePath

				if err := tw.WriteHeader(header); err != nil {
					return err
				}

				if !fi.IsDir() {
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()
					if _, err := io.Copy(tw, f); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to archive %s: %w", srcPath, err)
			}
		} else {
			// Add single file
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return nil, fmt.Errorf("failed to create header for %s: %w", srcPath, err)
			}
			header.Name = filepath.ToSlash(archivePath) // Use forward slashes in archive

			if err := tw.WriteHeader(header); err != nil {
				return nil, fmt.Errorf("failed to write header for %s: %w", srcPath, err)
			}

			f, err := os.Open(srcPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open %s: %w", srcPath, err)
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return nil, fmt.Errorf("failed to copy %s: %w", srcPath, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return []byte(buf.String()), nil
}

// extractTarGz extracts a tar.gz archive to a directory
func extractTarGz(data []byte, destDir string) (map[string]int64, error) {
	files := make(map[string]int64)

	gr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security check: prevent path traversal
		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") {
			return nil, fmt.Errorf("invalid path in archive: %s", header.Name)
		}

		targetPath := filepath.Join(destDir, cleanName)
		files[cleanName] = header.Size

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0700); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
				return nil, fmt.Errorf("failed to create parent directory: %w", err)
			}

			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return nil, fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			f.Close()
		}
	}

	return files, nil
}

// copyDir copies a directory recursively
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		return copyFile(path, targetPath)
	})
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func runBackupCreate(cmd *cobra.Command, args []string) error {
	// Check if output directory exists
	if err := os.MkdirAll(backupOutputDir, 0700); err != nil {
		printError("Failed to create output directory: %v", err)
		return nil
	}

	// Get backup password
	password, err := readPassword("Enter backup password: ")
	if err != nil {
		printError("%v", err)
		return nil
	}

	if password == "" {
		printError("Password cannot be empty")
		return nil
	}

	// Confirm password
	confirmPassword, err := readPassword("Confirm backup password: ")
	if err != nil {
		printError("%v", err)
		return nil
	}

	if password != confirmPassword {
		printError("Passwords do not match")
		return nil
	}

	// Define sources for backup
	sources := map[string]string{
		"nexus.db":   "./nexus.db",
		"data/keys/": "./data/keys/",
	}

	// Check if at least one source exists
	foundSources := false
	for _, srcPath := range sources {
		if _, err := os.Stat(srcPath); err == nil {
			foundSources = true
			break
		}
	}

	if !foundSources {
		printError("No backup sources found (nexus.db or data/keys/)")
		return nil
	}

	// Create tar.gz archive
	printInfo("Creating backup archive...")
	archiveData, err := createTarGz(sources)
	if err != nil {
		printError("Failed to create archive: %v", err)
		return nil
	}

	// Encrypt the archive
	printInfo("Encrypting backup...")
	encryptedData, err := encryptBackup(archiveData, password)
	if err != nil {
		printError("Failed to encrypt backup: %v", err)
		return nil
	}

	// Generate backup filename
	timestamp := time.Now().Format("2006-01-02-150405")
	backupFilename := fmt.Sprintf("nexus-backup-%s.tar.gz.enc", timestamp)
	backupPath := filepath.Join(backupOutputDir, backupFilename)

	// Write backup file
	if err := os.WriteFile(backupPath, encryptedData, 0600); err != nil {
		printError("Failed to write backup file: %v", err)
		return nil
	}

	printSuccess("Backup created: %s", backupPath)
	return nil
}

func runBackupRestore(cmd *cobra.Command, args []string) error {
	// Check if backup file exists
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		printError("Backup file not found: %s", backupFile)
		return nil
	}

	printWarning("Server must be stopped before restore")

	// Get backup password
	password, err := readPassword("Enter backup password: ")
	if err != nil {
		printError("%v", err)
		return nil
	}

	// Read backup file
	encryptedData, err := os.ReadFile(backupFile)
	if err != nil {
		printError("Failed to read backup file: %v", err)
		return nil
	}

	// Decrypt backup
	printInfo("Decrypting backup...")
	archiveData, err := decryptBackup(encryptedData, password)
	if err != nil {
		printError("Failed to decrypt backup: %v", err)
		return nil
	}

	// Create temp directory for extraction
	tempDir, err := os.MkdirTemp("", "nexus-restore-*")
	if err != nil {
		printError("Failed to create temp directory: %v", err)
		return nil
	}
	defer os.RemoveAll(tempDir)

	// Extract to temp directory
	printInfo("Extracting backup...")
	files, err := extractTarGz(archiveData, tempDir)
	if err != nil {
		printError("Failed to extract backup: %v", err)
		return nil
	}

	// Show extracted files
	fmt.Println("\nFiles in backup:")
	fileCount := 0
	var totalSize int64
	for path, size := range files {
		totalSize += size
		fileCount++
		sizeStr := formatSize(size)
		fmt.Printf("  %s (%s)\n", path, sizeStr)
	}
	fmt.Printf("\nTotal: %d files, %s\n", fileCount, formatSize(totalSize))

	// Ask for confirmation
	confirmed, err := readConfirmation("\nOverwrite current data? (yes/no): ")
	if err != nil {
		printError("%v", err)
		return nil
	}

	if !confirmed {
		printInfo("Restore cancelled")
		return nil
	}

	// Restore files
	printInfo("Restoring files...")

	// Check for nexus.db
	tempDBPath := filepath.Join(tempDir, "nexus.db")
	if _, err := os.Stat(tempDBPath); err == nil {
		if err := copyFile(tempDBPath, "./nexus.db"); err != nil {
			printError("Failed to restore nexus.db: %v", err)
			return nil
		}
	}

	// Check for data/keys/ directory
	tempKeysPath := filepath.Join(tempDir, "data", "keys")
	if info, err := os.Stat(tempKeysPath); err == nil && info.IsDir() {
		// Create data/keys directory if it doesn't exist
		if err := os.MkdirAll("./data/keys", 0700); err != nil {
			printError("Failed to create data/keys directory: %v", err)
			return nil
		}
		if err := copyDir(tempKeysPath, "./data/keys"); err != nil {
			printError("Failed to restore data/keys: %v", err)
			return nil
		}
	}

	printSuccess("Restored successfully. Restart the server.")
	return nil
}

// formatSize formats a file size in a human-readable format
func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(size)/(1024*1024))
	}
	return fmt.Sprintf("%.1fGB", float64(size)/(1024*1024*1024))
}
