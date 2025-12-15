package tpmops

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/awnumar/memguard"
)

// MockKeyDecryptor implements KeyDecryptor for testing.
type MockKeyDecryptor struct {
	decryptionFunc func(ciphertext []byte) ([]byte, error)
}

func (m *MockKeyDecryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if m.decryptionFunc != nil {
		return m.decryptionFunc(ciphertext)
	}
	// Default behavior: return ciphertext as plaintext (identity)
	// We must return a copy because the caller might zero it out
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

func TestXChaCha20Poly1305Encryptor(t *testing.T) {
	// Prevent memguard from locking memory during tests if needed,
	// or just let it run. It should be fine.
	memguard.Purge()

	// 32-byte key for XChaCha20-Poly1305
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	mockLoader := &MockKeyDecryptor{}

	// Initialize Encryptor
	// We pass 'key' as 'encryptedKey'. The mock loader returns it as is.
	encryptor, err := NewXChaCha20Poly1305Encryptor(key, mockLoader)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Test Encryption
	plaintext := []byte("Hello, World! This is a test message.")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Errorf("ciphertext should be longer than plaintext (nonce + tag)")
	}

	// Test Decryption
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text does not match plaintext.\nGot: %s\nWant: %s", decrypted, plaintext)
	}

	// Test Decryption with tampered ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF // Flip last bit
	_, err = encryptor.Decrypt(tampered)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext, got nil")
	}
}

func TestAES256GCMEncryptor(t *testing.T) {
	memguard.Purge()

	// 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	mockLoader := &MockKeyDecryptor{}

	// Initialize Encryptor
	encryptor, err := NewAES256GCMEncryptor(key, mockLoader)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Test Encryption
	plaintext := []byte("Hello, AES-GCM! This is a test message.")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Errorf("ciphertext should be longer than plaintext (nonce + tag)")
	}

	// Test Decryption
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text does not match plaintext.\nGot: %s\nWant: %s", decrypted, plaintext)
	}

	// Test Decryption with tampered ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF // Flip last bit
	_, err = encryptor.Decrypt(tampered)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext, got nil")
	}
}
