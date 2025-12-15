package tpmops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/awnumar/memguard"
)

type AES256GCMEncryptor struct {
	keyEnclave *memguard.Enclave
}

func NewAES256GCMEncryptor(encryptedKey []byte, loadedKey *LoadedKey) (*AES256GCMEncryptor, error) {
	k, err := loadedKey.Decrypt(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting AES-256-GCM key: %w", err)
	}
	defer func() {
		for i := range k {
			k[i] = 0
		}
	}()

	lb := memguard.NewBufferFromBytes(k)
	defer lb.Destroy()

	return &AES256GCMEncryptor{
		keyEnclave: lb.Seal(),
	}, nil
}

func (e *AES256GCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	lb, err := e.keyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("opening key enclave: %w", err)
	}
	defer lb.Destroy()

	block, err := aes.NewCipher(lb.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func (e *AES256GCMEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	lb, err := e.keyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("opening key enclave: %w", err)
	}
	defer lb.Destroy()

	block, err := aes.NewCipher(lb.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertextData := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return plaintext, nil
}
