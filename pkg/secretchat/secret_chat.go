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

package secretchat

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// SecretChatManager manages end-to-end encrypted secret chats
type SecretChatManager struct {
	config              *Config
	keyManager          *KeyManager
	messageManager      *MessageManager
	screenshotDetector  *ScreenshotDetector
	selfDestructManager *SelfDestructManager
	mutex               sync.RWMutex
	logger              logx.Logger
}

// Config represents secret chat configuration
type Config struct {
	// Encryption settings
	KeyExchangeTimeout time.Duration `json:"key_exchange_timeout"`
	MessageTTL         time.Duration `json:"message_ttl"`
	MaxMessageLength   int           `json:"max_message_length"`

	// Security settings
	EnableScreenshotDetection bool `json:"enable_screenshot_detection"`
	EnableSelfDestruct        bool `json:"enable_self_destruct"`
	EnableForwardRestriction  bool `json:"enable_forward_restriction"`

	// Performance settings
	KeyCacheSize int64         `json:"key_cache_size"`
	KeyCacheTTL  time.Duration `json:"key_cache_ttl"`
}

// SecretChat represents an end-to-end encrypted chat
type SecretChat struct {
	ID             int64  `json:"id"`
	UserID         int64  `json:"user_id"`
	PeerID         int64  `json:"peer_id"`
	AdminID        int64  `json:"admin_id"`
	ParticipantID  int64  `json:"participant_id"`
	GAOrB          []byte `json:"g_a_or_b"`
	KeyFingerprint int64  `json:"key_fingerprint"`
	State          int    `json:"state"`
	Date           int    `json:"date"`
	StartDate      int    `json:"start_date"`
	AuthKey        []byte `json:"auth_key"`
	TTL            int    `json:"ttl"`
	Layer          int    `json:"layer"`

	// Extended properties
	IsOutgoing      bool  `json:"is_outgoing"`
	IsConfirmed     bool  `json:"is_confirmed"`
	IsDeleted       bool  `json:"is_deleted"`
	LastMessageDate int   `json:"last_message_date"`
	LastMessageID   int64 `json:"last_message_id"`
	UnreadCount     int   `json:"unread_count"`
}

// SecretMessage represents an encrypted message
type SecretMessage struct {
	ID               int64               `json:"id"`
	ChatID           int64               `json:"chat_id"`
	Date             int                 `json:"date"`
	DecryptedMessage string              `json:"decrypted_message"`
	TTL              int                 `json:"ttl"`
	Out              bool                `json:"out"`
	Media            *SecretMessageMedia `json:"media"`

	// Encryption properties
	RandomID      []byte `json:"random_id"`
	EncryptedData []byte `json:"encrypted_data"`
	MessageHash   []byte `json:"message_hash"`
}

// SecretMessageMedia represents encrypted media
type SecretMessageMedia struct {
	Type          string     `json:"type"`
	EncryptedData []byte     `json:"encrypted_data"`
	DecryptedData []byte     `json:"decrypted_data"`
	MimeType      string     `json:"mime_type"`
	FileSize      int64      `json:"file_size"`
	Thumb         *PhotoSize `json:"thumb"`
}

// PhotoSize represents photo size information
type PhotoSize struct {
	Type   string `json:"type"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Size   int    `json:"size"`
}

// KeyManager handles encryption key management
type KeyManager struct {
	config *Config
	keys   map[int64]*EncryptionKey
	mutex  sync.RWMutex
}

// EncryptionKey represents encryption keys
type EncryptionKey struct {
	ChatID      int64     `json:"chat_id"`
	Key         []byte    `json:"key"`
	Fingerprint int64     `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MessageManager handles encrypted message operations
type MessageManager struct {
	config *Config
	mutex  sync.RWMutex
}

// ScreenshotDetector detects screenshot attempts
type ScreenshotDetector struct {
	config *Config
	mutex  sync.RWMutex
}

// SelfDestructManager manages self-destructing messages
type SelfDestructManager struct {
	config *Config
	mutex  sync.RWMutex
}

// mtproto constants
const (
	SecretChatStateRequested = 0
	SecretChatStateAccepted  = 1
	SecretChatStateDeleted   = 2
	SecretChatLayer          = 143
)

// NewSecretChatManager creates a new secret chat manager
func NewSecretChatManager(config *Config) *SecretChatManager {
	if config == nil {
		config = DefaultConfig()
	}

	return &SecretChatManager{
		config:              config,
		keyManager:          NewKeyManager(config),
		messageManager:      NewMessageManager(config),
		screenshotDetector:  NewScreenshotDetector(config),
		selfDestructManager: NewSelfDestructManager(config),
		logger:              logx.WithContext(context.Background()),
	}
}

// CreateSecretChat creates a new secret chat
func (m *SecretChatManager) CreateSecretChat(ctx context.Context, userID, peerID int64) (*SecretChat, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Creating secret chat: user=%d, peer=%d", userID, peerID)

	// Generate encryption keys
	privateKey, publicKey, err := m.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create secret chat
	secretChat := &SecretChat{
		ID:             m.generateChatID(),
		UserID:         userID,
		PeerID:         peerID,
		AdminID:        userID,
		ParticipantID:  peerID,
		GAOrB:          publicKey,
		KeyFingerprint: m.calculateFingerprint(publicKey),
		State:          SecretChatStateRequested,
		Date:           int(time.Now().Unix()),
		StartDate:      int(time.Now().Unix()),
		Layer:          SecretChatLayer,
		IsOutgoing:     true,
		TTL:            int(m.config.MessageTTL.Seconds()),
	}

	// Store encryption key
	err = m.keyManager.StoreKey(secretChat.ID, privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to store encryption key: %w", err)
	}

	m.logger.Infof("Secret chat created: id=%d", secretChat.ID)
	return secretChat, nil
}

// AcceptSecretChat accepts a secret chat request
func (m *SecretChatManager) AcceptSecretChat(ctx context.Context, chatID int64, userID int64) (*SecretChat, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Accepting secret chat: id=%d, user=%d", chatID, userID)

	// Get existing chat
	chat, err := m.getSecretChat(chatID)
	if err != nil {
		return nil, fmt.Errorf("secret chat not found: %w", err)
	}

	if chat.State != SecretChatStateRequested {
		return nil, fmt.Errorf("invalid chat state: %d", chat.State)
	}

	// Generate response keys
	privateKey, publicKey, err := m.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Calculate shared secret
	sharedSecret, err := m.calculateSharedSecret(privateKey, chat.GAOrB)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate shared secret: %w", err)
	}

	// Update chat state
	chat.State = SecretChatStateAccepted
	chat.GAOrB = publicKey
	chat.KeyFingerprint = m.calculateFingerprint(publicKey)
	chat.AuthKey = sharedSecret
	chat.IsConfirmed = true

	// Store encryption key
	err = m.keyManager.StoreKey(chat.ID, privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to store encryption key: %w", err)
	}

	m.logger.Infof("Secret chat accepted: id=%d", chat.ID)
	return chat, nil
}

// SendSecretMessage sends an encrypted message
func (m *SecretChatManager) SendSecretMessage(ctx context.Context, chatID int64, message string, ttl int) (*SecretMessage, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Sending secret message: chat=%d, ttl=%d", chatID, ttl)

	// Get secret chat
	chat, err := m.getSecretChat(chatID)
	if err != nil {
		return nil, fmt.Errorf("secret chat not found: %w", err)
	}

	if chat.State != SecretChatStateAccepted {
		return nil, fmt.Errorf("chat not ready: state=%d", chat.State)
	}

	// Validate message
	if err := m.validateMessage(message); err != nil {
		return nil, fmt.Errorf("message validation failed: %w", err)
	}

	// Encrypt message
	encryptedData, randomID, err := m.encryptMessage(chat.AuthKey, message)
	if err != nil {
		return nil, fmt.Errorf("message encryption failed: %w", err)
	}

	// Create secret message
	secretMessage := &SecretMessage{
		ID:               m.generateMessageID(),
		ChatID:           chatID,
		Date:             int(time.Now().Unix()),
		DecryptedMessage: message,
		TTL:              ttl,
		Out:              true,
		RandomID:         randomID,
		EncryptedData:    encryptedData,
		MessageHash:      m.calculateMessageHash(encryptedData),
	}

	// Store message
	err = m.messageManager.StoreMessage(secretMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to store message: %w", err)
	}

	// Setup self-destruct if TTL > 0
	if ttl > 0 && m.config.EnableSelfDestruct {
		m.selfDestructManager.ScheduleDestruct(secretMessage.ID, time.Duration(ttl)*time.Second)
	}

	m.logger.Infof("Secret message sent: id=%d", secretMessage.ID)
	return secretMessage, nil
}

// ReceiveSecretMessage receives and decrypts a message
func (m *SecretChatManager) ReceiveSecretMessage(ctx context.Context, chatID int64, encryptedData, randomID []byte) (*SecretMessage, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Receiving secret message: chat=%d", chatID)

	// Get secret chat
	chat, err := m.getSecretChat(chatID)
	if err != nil {
		return nil, fmt.Errorf("secret chat not found: %w", err)
	}

	if chat.State != SecretChatStateAccepted {
		return nil, fmt.Errorf("chat not ready: state=%d", chat.State)
	}

	// Decrypt message
	decryptedMessage, err := m.decryptMessage(chat.AuthKey, encryptedData, randomID)
	if err != nil {
		return nil, fmt.Errorf("message decryption failed: %w", err)
	}

	// Create secret message
	secretMessage := &SecretMessage{
		ID:               m.generateMessageID(),
		ChatID:           chatID,
		Date:             int(time.Now().Unix()),
		DecryptedMessage: decryptedMessage,
		TTL:              chat.TTL,
		Out:              false,
		RandomID:         randomID,
		EncryptedData:    encryptedData,
		MessageHash:      m.calculateMessageHash(encryptedData),
	}

	// Store message
	err = m.messageManager.StoreMessage(secretMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to store message: %w", err)
	}

	// Setup self-destruct if TTL > 0
	if chat.TTL > 0 && m.config.EnableSelfDestruct {
		m.selfDestructManager.ScheduleDestruct(secretMessage.ID, time.Duration(chat.TTL)*time.Second)
	}

	m.logger.Infof("Secret message received: id=%d", secretMessage.ID)
	return secretMessage, nil
}

// DeleteSecretChat deletes a secret chat
func (m *SecretChatManager) DeleteSecretChat(ctx context.Context, chatID int64) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Deleting secret chat: id=%d", chatID)

	// Get secret chat
	chat, err := m.getSecretChat(chatID)
	if err != nil {
		return fmt.Errorf("secret chat not found: %w", err)
	}

	// Mark as deleted
	chat.IsDeleted = true
	chat.State = SecretChatStateDeleted

	// Delete encryption keys
	m.keyManager.DeleteKey(chatID)

	// Delete all messages
	err = m.messageManager.DeleteAllMessages(chatID)
	if err != nil {
		return fmt.Errorf("failed to delete messages: %w", err)
	}

	m.logger.Infof("Secret chat deleted: id=%d", chatID)
	return nil
}

// Helper methods

func (m *SecretChatManager) generateKeyPair() ([]byte, []byte, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func (m *SecretChatManager) calculateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	// Derive encryption key using HKDF
	key := make([]byte, 32)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("SecretChat"))
	if _, err := kdf.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

func (m *SecretChatManager) calculateFingerprint(key []byte) int64 {
	hash := sha256.Sum256(key)
	return int64(binary.LittleEndian.Uint64(hash[:8]))
}

func (m *SecretChatManager) encryptMessage(key []byte, message string) ([]byte, []byte, error) {
	// Generate random ID
	randomID := make([]byte, 16)
	if _, err := rand.Read(randomID); err != nil {
		return nil, nil, err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(message), randomID)
	return encrypted, randomID, nil
}

func (m *SecretChatManager) decryptMessage(key []byte, encryptedData, randomID []byte) (string, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt
	decrypted, err := gcm.Open(nil, nonce, ciphertext, randomID)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (m *SecretChatManager) calculateMessageHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (m *SecretChatManager) validateMessage(message string) error {
	if len(message) == 0 {
		return fmt.Errorf("message cannot be empty")
	}

	if len(message) > m.config.MaxMessageLength {
		return fmt.Errorf("message too long: %d > %d", len(message), m.config.MaxMessageLength)
	}

	return nil
}

func (m *SecretChatManager) generateChatID() int64 {
	return time.Now().UnixNano()
}

func (m *SecretChatManager) generateMessageID() int64 {
	return time.Now().UnixNano()
}

func (m *SecretChatManager) getSecretChat(chatID int64) (*SecretChat, error) {
	// Implementation depends on storage
	return nil, fmt.Errorf("not implemented")
}

// NewKeyManager creates a new key manager
func NewKeyManager(config *Config) *KeyManager {
	return &KeyManager{
		config: config,
		keys:   make(map[int64]*EncryptionKey),
	}
}

// StoreKey stores an encryption key
func (km *KeyManager) StoreKey(chatID int64, privateKey, publicKey []byte) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	km.keys[chatID] = &EncryptionKey{
		ChatID:      chatID,
		Key:         privateKey,
		Fingerprint: 0, // Calculate fingerprint
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(km.config.KeyCacheTTL),
	}

	return nil
}

// DeleteKey deletes an encryption key
func (km *KeyManager) DeleteKey(chatID int64) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	delete(km.keys, chatID)
}

// NewMessageManager creates a new message manager
func NewMessageManager(config *Config) *MessageManager {
	return &MessageManager{
		config: config,
	}
}

// StoreMessage stores a secret message
func (mm *MessageManager) StoreMessage(message *SecretMessage) error {
	// Implementation depends on storage
	return nil
}

// DeleteAllMessages deletes all messages for a chat
func (mm *MessageManager) DeleteAllMessages(chatID int64) error {
	// Implementation depends on storage
	return nil
}

// NewScreenshotDetector creates a new screenshot detector
func NewScreenshotDetector(config *Config) *ScreenshotDetector {
	return &ScreenshotDetector{
		config: config,
	}
}

// NewSelfDestructManager creates a new self-destruct manager
func NewSelfDestructManager(config *Config) *SelfDestructManager {
	return &SelfDestructManager{
		config: config,
	}
}

// ScheduleDestruct schedules message self-destruction
func (sdm *SelfDestructManager) ScheduleDestruct(messageID int64, ttl time.Duration) {
	// Implementation for self-destruct scheduling
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		KeyExchangeTimeout:        30 * time.Second,
		MessageTTL:                7 * 24 * time.Hour, // 7 days
		MaxMessageLength:          4096,
		EnableScreenshotDetection: true,
		EnableSelfDestruct:        true,
		EnableForwardRestriction:  true,
		KeyCacheSize:              1024,
		KeyCacheTTL:               24 * time.Hour,
	}
}
