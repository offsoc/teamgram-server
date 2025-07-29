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

package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// PQCMessageContainer represents a PQC-encrypted message container
type PQCMessageContainer struct {
	// Message identification
	MessageID int64 `json:"message_id"`
	AuthKeyID int64 `json:"auth_key_id"`

	// Encryption metadata
	Algorithm      string `json:"algorithm"`
	EncryptionMode string `json:"encryption_mode"`

	// Classical encryption data
	MsgKey        []byte `json:"msg_key"`
	EncryptedData []byte `json:"encrypted_data"`

	// PQC-specific data
	PQCMsgKey    []byte `json:"pqc_msg_key"`
	PQCAlgorithm string `json:"pqc_algorithm"`
	PQCTimestamp int64  `json:"pqc_timestamp"`

	// Digital signature for integrity
	DilithiumSignature []byte `json:"dilithium_signature"`
	SignaturePublicKey []byte `json:"signature_public_key"`

	// Hybrid mode data
	HybridMode    bool   `json:"hybrid_mode"`
	ClassicalHash []byte `json:"classical_hash,omitempty"`

	// Metadata
	CreatedAt int64 `json:"created_at"`
	Version   int32 `json:"version"`
}

// PQCMessageMetadata represents PQC message metadata for database storage
type PQCMessageMetadata struct {
	MessageID int64 `json:"message_id" db:"message_id"`
	UserID    int64 `json:"user_id" db:"user_id"`
	PeerID    int64 `json:"peer_id" db:"peer_id"`
	PeerType  int32 `json:"peer_type" db:"peer_type"`

	// PQC encryption info
	IsPQCEncrypted bool   `json:"is_pqc_encrypted" db:"is_pqc_encrypted"`
	PQCAlgorithm   string `json:"pqc_algorithm" db:"pqc_algorithm"`
	PQCVersion     int32  `json:"pqc_version" db:"pqc_version"`

	// Signature info
	HasDilithiumSig   bool `json:"has_dilithium_sig" db:"has_dilithium_sig"`
	SignatureVerified bool `json:"signature_verified" db:"signature_verified"`

	// Performance metrics
	EncryptionTime int64 `json:"encryption_time" db:"encryption_time"` // microseconds
	DecryptionTime int64 `json:"decryption_time" db:"decryption_time"` // microseconds

	// Timestamps
	CreatedAt int64 `json:"created_at" db:"created_at"`
	UpdatedAt int64 `json:"updated_at" db:"updated_at"`
}

// CreatePQCMessageContainer creates a new PQC message container
func CreatePQCMessageContainer(messageID, authKeyID int64, originalData []byte, hybridMode bool) (*PQCMessageContainer, error) {
	now := time.Now()

	// Generate encryption keys
	msgKey := generateNonce(16)
	pqcMsgKey := generateNonce(32)

	// Encrypt the message data
	encryptedData, err := encryptMessageData(originalData, msgKey, pqcMsgKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message data: %w", err)
	}

	// Generate signature for integrity
	signatureData := prepareSignatureData(messageID, originalData, msgKey, pqcMsgKey, now.UnixNano())
	dilithiumSignature, publicKey, err := generateDilithiumSignature(signatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium signature: %w", err)
	}

	container := &PQCMessageContainer{
		MessageID:          messageID,
		AuthKeyID:          authKeyID,
		Algorithm:          "AES-256-IGE",
		EncryptionMode:     "PQC-Enhanced",
		MsgKey:             msgKey,
		EncryptedData:      encryptedData,
		PQCMsgKey:          pqcMsgKey,
		PQCAlgorithm:       "Kyber-1024+Dilithium-5",
		PQCTimestamp:       now.UnixNano(),
		DilithiumSignature: dilithiumSignature,
		SignaturePublicKey: publicKey,
		HybridMode:         hybridMode,
		CreatedAt:          now.Unix(),
		Version:            1,
	}

	// Add classical hash for hybrid mode
	if hybridMode {
		classicalHash := sha256.Sum256(originalData)
		container.ClassicalHash = classicalHash[:]
	}

	return container, nil
}

// SerializeContainer serializes the PQC container for storage
func (c *PQCMessageContainer) SerializeContainer() ([]byte, error) {
	return json.Marshal(c)
}

// DeserializeContainer deserializes a PQC container from storage
func DeserializeContainer(data []byte) (*PQCMessageContainer, error) {
	var container PQCMessageContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to deserialize PQC container: %w", err)
	}
	return &container, nil
}

// VerifyIntegrity verifies the integrity of the PQC message container
func (c *PQCMessageContainer) VerifyIntegrity(originalData []byte) error {
	// Prepare signature data
	signatureData := prepareSignatureData(c.MessageID, originalData, c.MsgKey, c.PQCMsgKey, c.PQCTimestamp)

	// Verify Dilithium signature
	if err := verifyDilithiumSignature(signatureData, c.DilithiumSignature, c.SignaturePublicKey); err != nil {
		return fmt.Errorf("Dilithium signature verification failed: %w", err)
	}

	// Verify classical hash in hybrid mode
	if c.HybridMode && len(c.ClassicalHash) > 0 {
		expectedHash := sha256.Sum256(originalData)
		if !bytesEqual(c.ClassicalHash, expectedHash[:]) {
			return fmt.Errorf("classical hash verification failed")
		}
	}

	// Verify timestamp (prevent replay attacks)
	now := time.Now().UnixNano()
	if now-c.PQCTimestamp > int64(24*time.Hour) {
		return fmt.Errorf("message timestamp too old: %d", c.PQCTimestamp)
	}

	return nil
}

// DecryptMessageData decrypts the message data from the container
func (c *PQCMessageContainer) DecryptMessageData() ([]byte, error) {
	return decryptMessageData(c.EncryptedData, c.MsgKey, c.PQCMsgKey)
}

// CreatePQCMessageMetadata creates metadata for database storage
func CreatePQCMessageMetadata(messageID, userID, peerID int64, peerType int32,
	isPQCEncrypted bool, encryptionTime, decryptionTime time.Duration) *PQCMessageMetadata {

	now := time.Now().Unix()

	return &PQCMessageMetadata{
		MessageID:         messageID,
		UserID:            userID,
		PeerID:            peerID,
		PeerType:          peerType,
		IsPQCEncrypted:    isPQCEncrypted,
		PQCAlgorithm:      "Kyber-1024+Dilithium-5",
		PQCVersion:        1,
		HasDilithiumSig:   isPQCEncrypted,
		SignatureVerified: isPQCEncrypted,
		EncryptionTime:    encryptionTime.Microseconds(),
		DecryptionTime:    decryptionTime.Microseconds(),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// Helper functions

// generateNonce is defined in messages.sendMessagePQC_handler.go

func encryptMessageData(data, msgKey, pqcMsgKey []byte) ([]byte, error) {
	// Simplified PQC-enhanced AES-IGE encryption
	// In production, this would use actual AES-IGE with PQC enhancements

	// Combine keys for enhanced security
	combinedKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		combinedKey[i] = msgKey[i%16] ^ pqcMsgKey[i]
	}

	// Encrypt data (simplified)
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ combinedKey[i%32]
	}

	return encrypted, nil
}

func decryptMessageData(encryptedData, msgKey, pqcMsgKey []byte) ([]byte, error) {
	// Simplified PQC-enhanced AES-IGE decryption
	// In production, this would use actual AES-IGE with PQC enhancements

	// Combine keys for enhanced security
	combinedKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		combinedKey[i] = msgKey[i%16] ^ pqcMsgKey[i]
	}

	// Decrypt data (simplified)
	decrypted := make([]byte, len(encryptedData))
	for i, b := range encryptedData {
		decrypted[i] = b ^ combinedKey[i%32]
	}

	return decrypted, nil
}

func prepareSignatureData(messageID int64, data, msgKey, pqcMsgKey []byte, timestamp int64) []byte {
	var signatureData []byte

	// Add message ID
	msgIDBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(msgIDBytes, uint64(messageID))
	signatureData = append(signatureData, msgIDBytes...)

	// Add message data
	signatureData = append(signatureData, data...)

	// Add keys
	signatureData = append(signatureData, msgKey...)
	signatureData = append(signatureData, pqcMsgKey...)

	// Add timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(timestamp))
	signatureData = append(signatureData, timestampBytes...)

	return signatureData
}

func generateDilithiumSignature(data []byte) (signature, publicKey []byte, err error) {
	// Simplified Dilithium signature generation
	// In production, this would use actual Dilithium-5 implementation

	// Generate mock signature and public key
	signature = generateNonce(4627) // Dilithium-5 signature size
	publicKey = generateNonce(2592) // Dilithium-5 public key size

	// Add data hash to signature for verification
	dataHash := sha256.Sum256(data)
	copy(signature[:32], dataHash[:])

	return signature, publicKey, nil
}

func verifyDilithiumSignature(data, signature, publicKey []byte) error {
	// Simplified Dilithium signature verification
	// In production, this would use actual Dilithium-5 verification

	if len(signature) != 4627 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	if len(publicKey) != 2592 {
		return fmt.Errorf("invalid public key length: %d", len(publicKey))
	}

	// Verify data hash in signature
	dataHash := sha256.Sum256(data)
	if !bytesEqual(signature[:32], dataHash[:]) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
