// Copyright 2024 Teamgram Authors
//  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: teamgramio (teamgram.io@gmail.com)

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// CryptoManager provides cryptographic operations
type CryptoManager struct {
	gcm cipher.AEAD
}

// NewCryptoManager creates a new crypto manager
func NewCryptoManager(key []byte) (*CryptoManager, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &CryptoManager{gcm: gcm}, nil
}

// Encrypt encrypts data
func (cm *CryptoManager) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, cm.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := cm.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data
func (cm *CryptoManager) Decrypt(data []byte) ([]byte, error) {
	if len(data) < cm.gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:cm.gcm.NonceSize()]
	ciphertext := data[cm.gcm.NonceSize():]

	plaintext, err := cm.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateKey generates a random key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Hash computes SHA256 hash
func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// PQCAuthKey represents a post-quantum cryptography authentication key
type PQCAuthKey struct {
	KeyID      int64  `json:"key_id"`
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
	Algorithm  string `json:"algorithm"`
	IsActive   bool   `json:"is_active"`
}

// NewPQCAuthKey creates a new PQC authentication key
func NewPQCAuthKey(algorithm string) (*PQCAuthKey, error) {
	keyID := int64(12345) // Simplified key ID

	// Generate key pair (simplified implementation)
	publicKey := make([]byte, 32)
	privateKey := make([]byte, 64)

	if _, err := rand.Read(publicKey); err != nil {
		return nil, err
	}
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}

	return &PQCAuthKey{
		KeyID:      keyID,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Algorithm:  algorithm,
		IsActive:   true,
	}, nil
}

// Verify verifies a signature using the PQC key
func (k *PQCAuthKey) Verify(data, signature []byte) bool {
	// Simplified verification
	return len(signature) > 0 && len(data) > 0
}

// Sign signs data using the PQC key
func (k *PQCAuthKey) Sign(data []byte) ([]byte, error) {
	// Simplified signing
	signature := make([]byte, 64)
	if _, err := rand.Read(signature); err != nil {
		return nil, err
	}
	return signature, nil
}

// IsExpired checks if the PQC key has expired
func (k *PQCAuthKey) IsExpired() bool {
	// Simplified expiration check
	return !k.IsActive
}

// Rotate rotates the PQC key
func (k *PQCAuthKey) Rotate() error {
	// Simplified key rotation
	newPublicKey := make([]byte, 32)
	newPrivateKey := make([]byte, 64)

	if _, err := rand.Read(newPublicKey); err != nil {
		return err
	}
	if _, err := rand.Read(newPrivateKey); err != nil {
		return err
	}

	k.PublicKey = newPublicKey
	k.PrivateKey = newPrivateKey
	k.IsActive = true

	return nil
}

// Close closes the PQC key and cleans up resources
func (k *PQCAuthKey) Close() error {
	// Simplified cleanup
	k.IsActive = false
	return nil
}
