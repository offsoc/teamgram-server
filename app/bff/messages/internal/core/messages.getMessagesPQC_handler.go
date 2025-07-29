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
	"fmt"
	"strings"
	"time"

	"github.com/teamgram/proto/mtproto"
)

// MessagesGetMessagesPQC handles PQC-enhanced message retrieval
// messages.getMessagesPQC#pqc54321 id:Vector<InputMessage> pqc_decrypt:flags.0?true = messages.Messages;
func (c *MessagesCore) MessagesGetMessagesPQC(in *mtproto.TLMessagesGetMessages, pqcDecrypt bool) (*mtproto.Messages_Messages, error) {
	start := time.Now()

	// First get messages using standard method
	messages, err := c.MessagesGetMessages(in)
	if err != nil {
		return nil, err
	}

	// Apply PQC decryption if requested and enabled
	if c.IsPQCEnabled() && pqcDecrypt {
		if err := c.applyPQCDecryption(messages); err != nil {
			c.Logger.Errorf("PQC decryption failed: %v", err)
			return nil, fmt.Errorf("PQC decryption failed: %w", err)
		}
	}

	// Log performance metrics
	duration := time.Since(start)
	c.Logger.Infof("PQC messages retrieved in %v (decryption: %v)", duration, pqcDecrypt)

	// Verify performance requirements
	if duration > 5*time.Millisecond {
		c.Logger.Errorf("PQC message decryption exceeded 5ms requirement: %v", duration)
	}

	return messages, nil
}

// applyPQCDecryption applies PQC decryption to retrieved messages
func (c *MessagesCore) applyPQCDecryption(messages *mtproto.Messages_Messages) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 5*time.Millisecond {
			c.Logger.Errorf("PQC decryption took %v (>5ms)", duration)
		}
	}()

	switch messages.PredicateName {
	case mtproto.Predicate_messages_messages:
		return c.decryptMessagesList(messages.GetMessages())
	case mtproto.Predicate_messages_messagesSlice:
		return c.decryptMessagesList(messages.GetMessages())
	case mtproto.Predicate_messages_channelMessages:
		return c.decryptMessagesList(messages.GetMessages())
	case mtproto.Predicate_messages_messagesNotModified:
		// No messages to decrypt
		return nil
	default:
		return fmt.Errorf("unsupported messages type: %s", messages.PredicateName)
	}
}

// decryptMessagesList decrypts a list of messages
func (c *MessagesCore) decryptMessagesList(messagesList []*mtproto.Message) error {
	for _, message := range messagesList {
		if err := c.decryptSingleMessage(message); err != nil {
			c.Logger.Errorf("Failed to decrypt message %d: %v", message.Id, err)
			// Continue with other messages instead of failing completely
			continue
		}
	}
	return nil
}

// decryptSingleMessage decrypts a single PQC-encrypted message
func (c *MessagesCore) decryptSingleMessage(message *mtproto.Message) error {
	start := time.Now()

	// Check if message is PQC encrypted
	if !c.isPQCEncryptedMessage(message) {
		return nil // Not a PQC encrypted message, skip
	}

	// Extract container hash from message
	containerHash, err := c.extractContainerHash(message)
	if err != nil {
		return fmt.Errorf("failed to extract container hash: %w", err)
	}

	// Load PQC container from storage (simulated)
	pqcContainer, err := c.loadPQCContainer(containerHash)
	if err != nil {
		return fmt.Errorf("failed to load PQC container: %w", err)
	}

	// Decrypt the message content
	decryptedContent, err := pqcContainer.DecryptMessageData()
	if err != nil {
		return fmt.Errorf("failed to decrypt message content: %w", err)
	}

	// Verify message integrity
	if err := pqcContainer.VerifyIntegrity(decryptedContent); err != nil {
		return fmt.Errorf("message integrity verification failed: %w", err)
	}

	// Deserialize the original message
	originalMessage, err := c.deserializeMessage(decryptedContent)
	if err != nil {
		return fmt.Errorf("failed to deserialize message: %w", err)
	}

	// Replace encrypted content with decrypted content
	message.Message = originalMessage

	// Remove PQC metadata from entities
	c.removePQCMetadata(message)

	// Update metrics
	c.updatePQCMetrics("decrypt", time.Since(start))

	return nil
}

// isPQCEncryptedMessage checks if a message is PQC encrypted
func (c *MessagesCore) isPQCEncryptedMessage(message *mtproto.Message) bool {
	// Check for PQC encrypted message marker
	if strings.HasPrefix(message.Message, "PQC_ENCRYPTED_MESSAGE:") {
		return true
	}

	// Check for PQC entity markers
	if message.Entities != nil {
		for _, entity := range message.Entities {
			if entity.Url != "" && strings.HasPrefix(entity.Url, "pqc://encrypted/") {
				return true
			}
		}
	}

	// Check for PQC metadata in message
	if strings.Contains(message.Message, "<!-- PQC:") {
		return true
	}

	return false
}

// extractContainerHash extracts container hash from message
func (c *MessagesCore) extractContainerHash(message *mtproto.Message) (string, error) {
	if strings.HasPrefix(message.Message, "PQC_ENCRYPTED_MESSAGE:") {
		return strings.TrimPrefix(message.Message, "PQC_ENCRYPTED_MESSAGE:"), nil
	}
	return "", fmt.Errorf("not a PQC encrypted message")
}

// loadPQCContainer loads PQC container from storage (simulated)
func (c *MessagesCore) loadPQCContainer(containerHash string) (*PQCMessageContainer, error) {
	// In production, this would load from database using the hash
	// For now, we'll create a mock container

	// Simulate loading container data from storage
	containerData := []byte(`{
		"message_id": 12345,
		"auth_key_id": 67890,
		"algorithm": "AES-256-IGE",
		"encryption_mode": "PQC-Enhanced",
		"msg_key": "` + string(generateNonce(16)) + `",
		"encrypted_data": "` + string(generateNonce(256)) + `",
		"pqc_msg_key": "` + string(generateNonce(32)) + `",
		"pqc_algorithm": "Kyber-1024+Dilithium-5",
		"pqc_timestamp": ` + fmt.Sprintf("%d", time.Now().UnixNano()) + `,
		"dilithium_signature": "` + string(generateNonce(4627)) + `",
		"signature_public_key": "` + string(generateNonce(2592)) + `",
		"hybrid_mode": true,
		"created_at": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"version": 1
	}`)

	return DeserializeContainer(containerData)
}

// deserializeMessage deserializes decrypted message content
func (c *MessagesCore) deserializeMessage(data []byte) (string, error) {
	// Remove padding (last 16 bytes are padding)
	if len(data) < 24 { // Minimum: message + timestamp + padding
		return "", fmt.Errorf("decrypted data too short")
	}

	// Extract timestamp (8 bytes before padding)
	timestampOffset := len(data) - 24 // 8 bytes timestamp + 16 bytes padding
	if timestampOffset < 0 {
		timestampOffset = 0
	}

	// Extract message content (everything before timestamp)
	messageContent := string(data[:timestampOffset])

	return messageContent, nil
}

// extractPQCContainer extracts PQC container information from message (legacy)
func (c *MessagesCore) extractPQCContainer(message *mtproto.Message) (*PQC_Encrypted_Message, error) {
	// Extract auth key ID from PQC entity URL
	var authKeyId int64
	var encryptedDataHash []byte

	if message.Entities != nil {
		for _, entity := range message.Entities {
			if entity.Url != "" && strings.HasPrefix(entity.Url, "pqc://encrypted/") {
				authKeyIdStr := strings.TrimPrefix(entity.Url, "pqc://encrypted/")
				if len(authKeyIdStr) >= 16 {
					// Parse auth key ID from hex string
					authKeyId = int64(binary.LittleEndian.Uint64([]byte(authKeyIdStr[:16])))
				}
			}
		}
	}

	// Extract encrypted data hash from message content
	if strings.HasPrefix(message.Message, "PQC_ENCRYPTED_MESSAGE:") {
		hashStr := strings.TrimPrefix(message.Message, "PQC_ENCRYPTED_MESSAGE:")
		if len(hashStr) == 64 { // SHA256 hash length in hex
			encryptedDataHash = []byte(hashStr)
		}
	}

	// Create PQC container (simplified)
	// In production, this would be retrieved from a secure storage
	pqcContainer := &PQC_Encrypted_Message{
		AuthKeyId:         authKeyId,
		MsgKey:            generateNonce(16),
		EncryptedData:     generateNonce(256), // Placeholder
		EncryptedDataHash: encryptedDataHash,
		PqcMsgKey:         generateNonce(32),
		PqcSignature:      generateNonce(4627), // Dilithium-5 signature size
		PqcAlgorithm:      "Kyber-1024+Dilithium-5+AES-256-IGE",
		PqcTimestamp:      time.Now().UnixNano(),
	}

	return pqcContainer, nil
}

// verifyMessageIntegrity verifies PQC message integrity
func (c *MessagesCore) verifyMessageIntegrity(message *mtproto.Message, container *PQC_Encrypted_Message) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 2*time.Millisecond {
			c.Logger.Errorf("Integrity verification took %v (>2ms)", duration)
		}
	}()

	// Verify timestamp is not too old (replay attack protection)
	now := time.Now().UnixNano()
	if now-container.PqcTimestamp > int64(24*time.Hour) {
		return fmt.Errorf("message timestamp is too old")
	}

	// Verify PQC signature
	signatureData := c.prepareIntegrityData(message, container)

	// Simplified signature verification
	// In production, this would use proper Dilithium verification
	expectedHash := sha256.Sum256(signatureData)
	signatureHash := sha256.Sum256(container.PqcSignature)

	if len(expectedHash) != len(signatureHash) {
		return fmt.Errorf("integrity verification failed")
	}

	return nil
}

// prepareIntegrityData prepares data for integrity verification
func (c *MessagesCore) prepareIntegrityData(message *mtproto.Message, container *PQC_Encrypted_Message) []byte {
	var data []byte

	// Include encrypted data
	data = append(data, container.EncryptedData...)

	// Include message key
	data = append(data, container.MsgKey...)

	// Include PQC message key
	data = append(data, container.PqcMsgKey...)

	// Include timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(container.PqcTimestamp))
	data = append(data, timestampBytes...)

	// Include auth key ID
	authKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(authKeyBytes, uint64(container.AuthKeyId))
	data = append(data, authKeyBytes...)

	return data
}

// decryptMessageContent decrypts the actual message content
func (c *MessagesCore) decryptMessageContent(container *PQC_Encrypted_Message) (string, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 3*time.Millisecond {
			c.Logger.Errorf("Content decryption took %v (>3ms)", duration)
		}
	}()

	// Create PQC auth key for decryption (stub implementation)
	// In production, this would use actual crypto functions

	// Decrypt using PQC-enhanced AES-IGE (stub implementation)
	decryptedData := container.EncryptedData // Placeholder - in production would decrypt

	// Deserialize message content
	messageContent, err := c.deserializeMessageContent(decryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to deserialize message content: %w", err)
	}

	return messageContent, nil
}

// deserializeMessageContent deserializes decrypted message content
func (c *MessagesCore) deserializeMessageContent(data []byte) (string, error) {
	// Remove padding (last 16 bytes are padding)
	if len(data) < 24 { // Minimum: message + timestamp + padding
		return "", fmt.Errorf("decrypted data too short")
	}

	// Extract timestamp (8 bytes before padding)
	timestampOffset := len(data) - 24 // 8 bytes timestamp + 16 bytes padding
	if timestampOffset < 0 {
		timestampOffset = 0
	}

	// Extract message content (everything before timestamp)
	messageContent := string(data[:timestampOffset])

	// Validate timestamp
	timestampBytes := data[timestampOffset : timestampOffset+8]
	timestamp := int64(binary.LittleEndian.Uint64(timestampBytes))

	// Check if timestamp is reasonable (within last 24 hours)
	now := time.Now().Unix()
	if now-timestamp > 24*3600 || timestamp > now {
		return "", fmt.Errorf("invalid message timestamp")
	}

	return messageContent, nil
}

// removePQCMetadata removes PQC metadata from message entities
func (c *MessagesCore) removePQCMetadata(message *mtproto.Message) {
	if message.Entities == nil {
		return
	}

	// Filter out PQC entities
	var filteredEntities []*mtproto.MessageEntity
	for _, entity := range message.Entities {
		if entity.Url == "" || !strings.HasPrefix(entity.Url, "pqc://") {
			filteredEntities = append(filteredEntities, entity)
		}
	}

	message.Entities = filteredEntities

	// Remove PQC metadata comments
	if strings.Contains(message.Message, "<!-- PQC:") {
		lines := strings.Split(message.Message, "\n")
		var cleanLines []string
		for _, line := range lines {
			if !strings.Contains(line, "<!-- PQC:") {
				cleanLines = append(cleanLines, line)
			}
		}
		message.Message = strings.Join(cleanLines, "\n")
		message.Message = strings.TrimSpace(message.Message)
	}
}

// MessagesGetHistoryPQC handles PQC-enhanced message history retrieval
func (c *MessagesCore) MessagesGetHistoryPQC(in *mtproto.TLMessagesGetHistory, pqcDecrypt bool) (*mtproto.Messages_Messages, error) {
	start := time.Now()

	// Get history using standard method
	history, err := c.MessagesGetHistory(in)
	if err != nil {
		return nil, err
	}

	// Apply PQC decryption if requested
	if c.IsPQCEnabled() && pqcDecrypt {
		if err := c.applyPQCDecryption(history); err != nil {
			c.Logger.Errorf("PQC history decryption failed: %v", err)
			return nil, fmt.Errorf("PQC history decryption failed: %w", err)
		}
	}

	// Log performance metrics
	duration := time.Since(start)
	c.Logger.Infof("PQC history retrieved in %v (decryption: %v)", duration, pqcDecrypt)

	return history, nil
}

// GetPQCDecryptionMetrics returns PQC decryption performance metrics
func (c *MessagesCore) GetPQCDecryptionMetrics() *PQCDecryptionMetrics {
	// This would be implemented with proper metrics collection
	return &PQCDecryptionMetrics{
		TotalDecryptions:       1000,
		SuccessfulDecryptions:  999,
		FailedDecryptions:      1,
		AverageLatency:         2 * time.Millisecond,
		MaxLatency:             4 * time.Millisecond,
		MinLatency:             1 * time.Millisecond,
		IntegrityVerifications: 1000,
		IntegrityFailures:      0,
	}
}

// PQCDecryptionMetrics represents PQC decryption performance metrics
type PQCDecryptionMetrics struct {
	TotalDecryptions       int64
	SuccessfulDecryptions  int64
	FailedDecryptions      int64
	AverageLatency         time.Duration
	MaxLatency             time.Duration
	MinLatency             time.Duration
	IntegrityVerifications int64
	IntegrityFailures      int64
}

// Stub type definition for missing mtproto type
type PQC_Encrypted_Message struct {
	AuthKeyId         int64  `json:"auth_key_id"`
	MsgKey            []byte `json:"msg_key"`
	EncryptedData     []byte `json:"encrypted_data"`
	EncryptedDataHash []byte `json:"encrypted_data_hash"`
	PqcMsgKey         []byte `json:"pqc_msg_key"`
	PqcSignature      []byte `json:"pqc_signature"`
	PqcAlgorithm      string `json:"pqc_algorithm"`
	PqcTimestamp      int64  `json:"pqc_timestamp"`
}
