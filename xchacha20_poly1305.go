package tpmops

import (
	"crypto/rand"
	"fmt"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type XChaCha20Poly1305Encryptor struct {
	keyEnclave *memguard.Enclave
}

func NewXChaCha20Poly1305Encryptor(encryptedKey []byte, loadedKey *LoadedKey) (*XChaCha20Poly1305Encryptor, error) {
	k, err := loadedKey.Decrypt(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting XChaCha20-Poly1305 key: %w", err)
	}
	defer func() {
		for i := range k {
			k[i] = 0
		}
	}()

	lb := memguard.NewBufferFromBytes(k)
	defer lb.Destroy()

	return &XChaCha20Poly1305Encryptor{
		keyEnclave: lb.Seal(),
	}, nil
}

func (e *XChaCha20Poly1305Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	lb, err := e.keyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("opening key enclave: %w", err)
	}
	defer lb.Destroy()

	aead, err := chacha20poly1305.NewX(lb.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating XChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func (e *XChaCha20Poly1305Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	lb, err := e.keyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("opening key enclave: %w", err)
	}
	defer lb.Destroy()

	aead, err := chacha20poly1305.NewX(lb.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating XChaCha20-Poly1305 cipher: %w", err)
	}

	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	ciphertextData := ciphertext[chacha20poly1305.NonceSizeX:]

	plaintext, err := aead.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return plaintext, nil
}
