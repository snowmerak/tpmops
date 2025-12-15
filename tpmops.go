package tpmops

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// TPMOps orchestrates the TPM, storage, and encryption layers.
type TPMOps struct {
	client *TPMClient
	store  Store
}

// NewTPMOps creates a new TPMOps instance.
func NewTPMOps(store Store) (*TPMOps, error) {
	client, err := NewTPMClient()
	if err != nil {
		return nil, fmt.Errorf("initializing TPM client: %w", err)
	}

	return &TPMOps{
		client: client,
		store:  store,
	}, nil
}

// Close closes the TPM connection and the store.
func (ops *TPMOps) Close() error {
	var errs []error
	if err := ops.client.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing TPM client: %w", err))
	}
	if err := ops.store.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing store: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing TPMOps: %v", errs)
	}
	return nil
}

// EnsureKEK ensures that a Key Encryption Key (KEK) with the given name exists.
// If it exists in the store, it is loaded into the TPM.
// If not, a new key is created in the TPM and saved to the store.
// The returned LoadedKey must be closed by the caller.
func (ops *TPMOps) EnsureKEK(keyName string) (*LoadedKey, error) {
	// Try to load from store
	sk, err := ops.store.LoadKey(keyName)
	if err == nil {
		// Found in store, load into TPM
		return ops.client.LoadKey(sk.Private, sk.Public)
	}

	if !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("checking for existing KEK: %w", err)
	}

	// Not found, create new key
	priv, pub, err := ops.client.CreateAESKey()
	if err != nil {
		return nil, fmt.Errorf("creating new KEK: %w", err)
	}

	// Save to store
	sk = StoredKey{Private: priv, Public: pub}
	if err := ops.store.SaveKey(keyName, sk); err != nil {
		return nil, fmt.Errorf("saving new KEK: %w", err)
	}

	// Load into TPM
	return ops.client.LoadKey(priv, pub)
}

// CreateDEK generates a new Data Encryption Key (DEK), encrypts it with the specified KEK,
// and returns an Encryptor initialized with the DEK, along with the encrypted DEK blob.
// The encrypted DEK blob should be stored by the caller alongside the data.
func (ops *TPMOps) CreateDEK(kekName string, algo string) (Encryptor, []byte, error) {
	kek, err := ops.EnsureKEK(kekName)
	if err != nil {
		return nil, nil, fmt.Errorf("ensuring KEK: %w", err)
	}
	defer kek.Close()

	var keySize int
	switch algo {
	case "AES256GCM", "XChaCha20Poly1305":
		keySize = 32
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}

	// Generate random DEK
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("generating DEK: %w", err)
	}

	// Encrypt DEK with KEK (Envelope Encryption)
	encryptedDEK, err := kek.Encrypt(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting DEK with KEK: %w", err)
	}

	// Create Encryptor (this will securely store DEK in memguard)
	var encryptor Encryptor
	switch algo {
	case "AES256GCM":
		// We need to pass the encrypted DEK and the KEK to the constructor.
		// The constructor will decrypt it immediately.
		// Note: Our constructors take 'encryptedKey' and 'loadedKey'.
		// Here 'encryptedKey' is 'encryptedDEK'.
		encryptor, err = NewAES256GCMEncryptor(encryptedDEK, kek)
	case "XChaCha20Poly1305":
		encryptor, err = NewXChaCha20Poly1305Encryptor(encryptedDEK, kek)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("creating encryptor: %w", err)
	}

	return encryptor, encryptedDEK, nil
}

// RestoreDEK restores an Encryptor from an encrypted DEK blob using the specified KEK.
func (ops *TPMOps) RestoreDEK(kekName string, encryptedDEK []byte, algo string) (Encryptor, error) {
	kek, err := ops.EnsureKEK(kekName)
	if err != nil {
		return nil, fmt.Errorf("ensuring KEK: %w", err)
	}
	defer kek.Close()

	switch algo {
	case "AES256GCM":
		return NewAES256GCMEncryptor(encryptedDEK, kek)
	case "XChaCha20Poly1305":
		return NewXChaCha20Poly1305Encryptor(encryptedDEK, kek)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
