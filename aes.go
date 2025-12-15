package tpmops

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// TPMClient manages the connection to the TPM and the Storage Root Key (SRK).
type TPMClient struct {
	rwc       transport.TPMCloser
	srkHandle tpm2.TPMHandle
	srkName   tpm2.TPM2BName
}

// NewTPMClient establishes a connection to the TPM and prepares the SRK.
func NewTPMClient() (*TPMClient, error) {
	rwc, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}

	client := &TPMClient{rwc: rwc}
	if err := client.initSRK(); err != nil {
		rwc.Close()
		return nil, err
	}

	return client, nil
}

// Close closes the TPM connection.
func (c *TPMClient) Close() error {
	return c.rwc.Close()
}

// initSRK finds the shared SRK or creates a temporary one.
func (c *TPMClient) initSRK() error {
	// Windows shared SRK handle
	srkHandle := tpm2.TPMHandle(0x81000001)

	// Check if SRK exists
	srkPub, err := tpm2.ReadPublic{ObjectHandle: srkHandle}.Execute(c.rwc)
	if err == nil {
		c.srkHandle = srkHandle
		c.srkName = srkPub.Name
		return nil
	}

	// If not found, create a temporary SRK (for demo purposes)
	// In production, you should ensure the SRK is provisioned.
	srkTemplate := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				KeyBits: 2048,
			},
		),
	})

	createPrimaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      srkTemplate,
	}.Execute(c.rwc)
	if err != nil {
		return fmt.Errorf("failed to create temporary SRK: %w", err)
	}

	c.srkHandle = createPrimaryResp.ObjectHandle
	c.srkName = createPrimaryResp.Name
	return nil
}

// CreateAESKey creates a new AES-128 CFB key under the SRK.
// Returns the private and public blobs.
func (c *TPMClient) CreateAESKey() ([]byte, []byte, error) {
	aesTemplate := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
			},
		),
	})

	createResp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: c.srkHandle,
			Name:   c.srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{},
			},
		},
		InPublic: aesTemplate,
	}.Execute(c.rwc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %w", err)
	}

	privBytes := tpm2.Marshal(createResp.OutPrivate)
	pubBytes := tpm2.Marshal(createResp.OutPublic)

	return privBytes, pubBytes, nil
}

// StoredKey represents the JSON structure for storing a key on disk.
type StoredKey struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// CreateAESKeyToFile creates a new key and saves the blobs to a single JSON file.
func (c *TPMClient) CreateAESKeyToFile(filePath string) error {
	priv, pub, err := c.CreateAESKey()
	if err != nil {
		return err
	}

	keyData := StoredKey{
		Private: priv,
		Public:  pub,
	}

	jsonData, err := json.Marshal(keyData)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// LoadedKey represents a key loaded into the TPM.
type LoadedKey struct {
	client *TPMClient
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// LoadKey loads a key from private and public blobs into the TPM.
func (c *TPMClient) LoadKey(privBytes, pubBytes []byte) (*LoadedKey, error) {
	privPtr, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private blob: %w", err)
	}
	pubPtr, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public blob: %w", err)
	}

	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: c.srkHandle,
			Name:   c.srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *privPtr,
		InPublic:  *pubPtr,
	}.Execute(c.rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	return &LoadedKey{
		client: c,
		handle: loadResp.ObjectHandle,
		name:   loadResp.Name,
	}, nil
}

// LoadKeyFromFile loads a key from a single JSON file.
func (c *TPMClient) LoadKeyFromFile(filePath string) (*LoadedKey, error) {
	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyData StoredKey
	if err := json.Unmarshal(jsonData, &keyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	return c.LoadKey(keyData.Private, keyData.Public)
}

// Close flushes the key from the TPM.
func (k *LoadedKey) Close() error {
	_, err := tpm2.FlushContext{FlushHandle: k.handle}.Execute(k.client.rwc)
	return err
}

// Encrypt encrypts data using the loaded key.
func (k *LoadedKey) Encrypt(data []byte) ([]byte, error) {
	iv := make([]byte, 16) // Zero IV for demo; in production, use random IV and prepend it.

	encryptResp, err := tpm2.EncryptDecrypt2{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   k.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Message: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Mode:    tpm2.TPMAlgCFB,
		Decrypt: false,
		IV:      tpm2.TPM2BIV{Buffer: iv},
	}.Execute(k.client.rwc)

	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return encryptResp.OutData.Buffer, nil
}

// Decrypt decrypts data using the loaded key.
func (k *LoadedKey) Decrypt(ciphertext []byte) ([]byte, error) {
	iv := make([]byte, 16) // Must match IV used in encryption

	decryptResp, err := tpm2.EncryptDecrypt2{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   k.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Message: tpm2.TPM2BMaxBuffer{
			Buffer: ciphertext,
		},
		Mode:    tpm2.TPMAlgCFB,
		Decrypt: true,
		IV:      tpm2.TPM2BIV{Buffer: iv},
	}.Execute(k.client.rwc)

	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decryptResp.OutData.Buffer, nil
}
