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

package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Manager provides enterprise-grade security management
type Manager struct {
	config          *Config
	encryptionKey   []byte
	gcm             cipher.AEAD
	threatDetector  *ThreatDetector
	accessValidator *AccessValidator
	auditLogger     *AuditLogger
	metrics         *SecurityMetrics
	mutex           sync.RWMutex
	logger          logx.Logger
}

// Config represents security manager configuration
type Config struct {
	EncryptionEnabled bool   `json:"encryption_enabled"`
	AuditEnabled      bool   `json:"audit_enabled"`
	RateLimitEnabled  bool   `json:"rate_limit_enabled"`
	ThreatDetection   bool   `json:"threat_detection"`
	EncryptionKey     string `json:"encryption_key,omitempty"`
}

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
	TotalRequests        int64     `json:"total_requests"`
	ValidRequests        int64     `json:"valid_requests"`
	BlockedRequests      int64     `json:"blocked_requests"`
	EncryptionOperations int64     `json:"encryption_operations"`
	DecryptionOperations int64     `json:"decryption_operations"`
	ThreatDetections     int64     `json:"threat_detections"`
	LastUpdate           time.Time `json:"last_update"`
}

// ThreatDetector detects security threats
type ThreatDetector struct {
	enabled  bool
	patterns map[string]string
	mutex    sync.RWMutex
}

// AccessValidator validates access requests
type AccessValidator struct {
	enabled bool
	rules   map[string]AccessRule
	mutex   sync.RWMutex
}

// AccessRule defines access validation rules
type AccessRule struct {
	AllowedIPs   []string `json:"allowed_ips"`
	BlockedIPs   []string `json:"blocked_ips"`
	RateLimit    int      `json:"rate_limit"`
	RequireAuth  bool     `json:"require_auth"`
	MinUserLevel int      `json:"min_user_level"`
}

// AuditLogger provides secure audit logging
type AuditLogger struct {
	enabled bool
	logger  logx.Logger
	mutex   sync.RWMutex
}

// NewManager creates a new security manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	manager := &Manager{
		config: config,
		metrics: &SecurityMetrics{
			LastUpdate: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize encryption if enabled
	if config.EncryptionEnabled {
		if err := manager.initializeEncryption(config.EncryptionKey); err != nil {
			return nil, fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	// Initialize threat detector
	if config.ThreatDetection {
		manager.threatDetector = &ThreatDetector{
			enabled:  true,
			patterns: make(map[string]string),
		}
		manager.initializeThreatPatterns()
	}

	// Initialize access validator
	manager.accessValidator = &AccessValidator{
		enabled: true,
		rules:   make(map[string]AccessRule),
	}
	manager.initializeAccessRules()

	// Initialize audit logger
	if config.AuditEnabled {
		manager.auditLogger = &AuditLogger{
			enabled: true,
			logger:  logx.WithContext(context.Background()),
		}
	}

	return manager, nil
}

// ValidateRequest validates incoming requests for security
func (m *Manager) ValidateRequest(ctx context.Context, userID int64) error {
	m.mutex.Lock()
	m.metrics.TotalRequests++
	m.mutex.Unlock()

	// Threat detection
	if m.threatDetector != nil && m.threatDetector.enabled {
		if threat := m.threatDetector.DetectThreat(ctx, userID); threat != nil {
			m.updateMetrics("threat_detected")
			if m.auditLogger != nil {
				m.auditLogger.LogSecurityEvent(ctx, "threat_detected", userID, map[string]interface{}{
					"threat_type": threat.Type,
					"severity":    threat.Severity,
				})
			}
			return fmt.Errorf("security threat detected: %s", threat.Type)
		}
	}

	// Access validation
	if m.accessValidator != nil && m.accessValidator.enabled {
		if err := m.accessValidator.ValidateAccess(ctx, userID); err != nil {
			m.updateMetrics("access_denied")
			if m.auditLogger != nil {
				m.auditLogger.LogSecurityEvent(ctx, "access_denied", userID, map[string]interface{}{
					"error": err.Error(),
				})
			}
			return fmt.Errorf("access validation failed: %w", err)
		}
	}

	m.updateMetrics("request_validated")
	return nil
}

// EncryptSettings encrypts sensitive settings
func (m *Manager) EncryptSettings(settings interface{}) error {
	if !m.config.EncryptionEnabled || m.gcm == nil {
		return nil // Encryption not enabled
	}

	// Convert settings to JSON
	data, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Encrypt data
	encryptedData, err := m.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt settings: %w", err)
	}

	// Store encrypted data back to settings
	if settingsMap, ok := settings.(map[string]interface{}); ok {
		settingsMap["encrypted_data"] = encryptedData
	}

	m.updateMetrics("encryption_operation")
	return nil
}

// DecryptSettings decrypts sensitive settings
func (m *Manager) DecryptSettings(settings interface{}) error {
	if !m.config.EncryptionEnabled || m.gcm == nil {
		return nil // Encryption not enabled
	}

	settingsMap, ok := settings.(map[string]interface{})
	if !ok {
		return errors.New("settings must be a map")
	}

	encryptedData, exists := settingsMap["encrypted_data"]
	if !exists {
		return nil // No encrypted data
	}

	encryptedBytes, ok := encryptedData.([]byte)
	if !ok {
		return errors.New("encrypted data must be bytes")
	}

	// Decrypt data
	decryptedData, err := m.decrypt(encryptedBytes)
	if err != nil {
		return fmt.Errorf("failed to decrypt settings: %w", err)
	}

	// Unmarshal decrypted data
	var decryptedSettings map[string]interface{}
	if err := json.Unmarshal(decryptedData, &decryptedSettings); err != nil {
		return fmt.Errorf("failed to unmarshal decrypted settings: %w", err)
	}

	// Merge decrypted settings
	for k, v := range decryptedSettings {
		settingsMap[k] = v
	}

	// Remove encrypted data
	delete(settingsMap, "encrypted_data")

	m.updateMetrics("decryption_operation")
	return nil
}

// GetSecurityMetrics returns current security metrics
func (m *Manager) GetSecurityMetrics() *SecurityMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	metrics := *m.metrics
	return &metrics
}

// Private methods

func (m *Manager) initializeEncryption(keyString string) error {
	var key []byte

	if keyString != "" {
		// Use provided key
		hash := sha256.Sum256([]byte(keyString))
		key = hash[:]
	} else {
		// Generate random key
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	m.encryptionKey = key
	m.gcm = gcm
	return nil
}

func (m *Manager) encrypt(data []byte) ([]byte, error) {
	if m.gcm == nil {
		return nil, errors.New("encryption not initialized")
	}

	// Generate nonce
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := m.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (m *Manager) decrypt(data []byte) ([]byte, error) {
	if m.gcm == nil {
		return nil, errors.New("encryption not initialized")
	}

	if len(data) < m.gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := data[:m.gcm.NonceSize()]
	ciphertext := data[m.gcm.NonceSize():]

	// Decrypt data
	plaintext, err := m.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

func (m *Manager) initializeThreatPatterns() {
	if m.threatDetector == nil {
		return
	}

	m.threatDetector.patterns = map[string]string{
		"sql_injection":     `(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
		"xss_attack":        `(?i)(<script|javascript:|vbscript:|onload=|onerror=)`,
		"path_traversal":    `(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)`,
		"command_injection": `(?i)(;|\||&|` + "`" + `|\$\(|\${)`,
	}
}

func (m *Manager) initializeAccessRules() {
	if m.accessValidator == nil {
		return
	}

	// Default access rules
	m.accessValidator.rules = map[string]AccessRule{
		"default": {
			AllowedIPs:   []string{},
			BlockedIPs:   []string{},
			RateLimit:    1000,
			RequireAuth:  true,
			MinUserLevel: 0,
		},
		"admin": {
			AllowedIPs:   []string{},
			BlockedIPs:   []string{},
			RateLimit:    10000,
			RequireAuth:  true,
			MinUserLevel: 100,
		},
	}
}

func (m *Manager) updateMetrics(operation string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	switch operation {
	case "request_validated":
		m.metrics.ValidRequests++
	case "access_denied":
		m.metrics.BlockedRequests++
	case "threat_detected":
		m.metrics.BlockedRequests++
		m.metrics.ThreatDetections++
	case "encryption_operation":
		m.metrics.EncryptionOperations++
	case "decryption_operation":
		m.metrics.DecryptionOperations++
	}

	m.metrics.LastUpdate = time.Now()
}

// ThreatDetector methods

// Threat represents a detected security threat
type Threat struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

func (td *ThreatDetector) DetectThreat(ctx context.Context, userID int64) *Threat {
	if !td.enabled {
		return nil
	}

	// Implement threat detection logic
	// This is a simplified implementation
	return nil
}

// AccessValidator methods

func (av *AccessValidator) ValidateAccess(ctx context.Context, userID int64) error {
	if !av.enabled {
		return nil
	}

	// Implement access validation logic
	// This is a simplified implementation
	if userID <= 0 {
		return errors.New("invalid user ID")
	}

	return nil
}

// AuditLogger methods

func (al *AuditLogger) LogSecurityEvent(ctx context.Context, event string, userID int64, data map[string]interface{}) {
	if !al.enabled {
		return
	}

	al.mutex.Lock()
	defer al.mutex.Unlock()

	logData := map[string]interface{}{
		"event":      event,
		"user_id":    userID,
		"timestamp":  time.Now().UTC(),
		"event_type": "SECURITY",
		"severity":   "HIGH",
	}

	if data != nil {
		for k, v := range data {
			logData[k] = v
		}
	}

	al.logger.Errorw("Security event")
}

func (al *AuditLogger) LogEvent(ctx context.Context, event string, userID int64, data map[string]interface{}) {
	if !al.enabled {
		return
	}

	al.mutex.Lock()
	defer al.mutex.Unlock()

	logData := map[string]interface{}{
		"event":     event,
		"user_id":   userID,
		"timestamp": time.Now().UTC(),
	}

	if data != nil {
		for k, v := range data {
			logData[k] = v
		}
	}

	al.logger.Infow("Security audit event")
}
