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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// SecurityManager manages video call security
type SecurityManager struct {
	config         *SecurityConfig
	contexts       map[string]*SecurityContext
	mutex          sync.RWMutex
	logger         logx.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	isRunning      bool
	threatDetector *ThreatDetector
	accessControl  *AccessControl
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	EnableThreatDetection bool          `json:"enable_threat_detection"`
	EnableAccessControl   bool          `json:"enable_access_control"`
	EnableAuditLogging    bool          `json:"enable_audit_logging"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	MaxFailedAttempts     int           `json:"max_failed_attempts"`
	BlockDuration         time.Duration `json:"block_duration"`
	RequireAuthentication bool          `json:"require_authentication"`
	AllowedNetworks       []string      `json:"allowed_networks"`
}

// SecurityContext represents a security context for a call
type SecurityContext struct {
	ID               string            `json:"id"`
	CallID           int64             `json:"call_id"`
	UserID           int64             `json:"user_id"`
	PeerID           int64             `json:"peer_id"`
	SessionToken     string            `json:"session_token"`
	AuthLevel        AuthLevel         `json:"auth_level"`
	Permissions      []Permission      `json:"permissions"`
	ThreatLevel      ThreatLevel       `json:"threat_level"`
	AccessAttempts   int               `json:"access_attempts"`
	FailedAttempts   int               `json:"failed_attempts"`
	LastAccess       time.Time         `json:"last_access"`
	CreatedAt        time.Time         `json:"created_at"`
	ExpiresAt        time.Time         `json:"expires_at"`
	IsBlocked        bool              `json:"is_blocked"`
	BlockedUntil     time.Time         `json:"blocked_until"`
	Metadata         map[string]string `json:"metadata"`
	mutex            sync.RWMutex
}

// ThreatDetector detects security threats
type ThreatDetector struct {
	enabled       bool
	patterns      map[string]ThreatPattern
	detectedThreats map[string]*DetectedThreat
	mutex         sync.RWMutex
}

// AccessControl manages access control
type AccessControl struct {
	enabled       bool
	rules         map[string]AccessRule
	blockedIPs    map[string]time.Time
	allowedIPs    map[string]bool
	mutex         sync.RWMutex
}

// Security enums and types
type AuthLevel string
type Permission string
type ThreatLevel string

const (
	AuthLevelNone     AuthLevel = "none"
	AuthLevelBasic    AuthLevel = "basic"
	AuthLevelStrong   AuthLevel = "strong"
	AuthLevelExtreme  AuthLevel = "extreme"

	PermissionJoinCall    Permission = "join_call"
	PermissionStartCall   Permission = "start_call"
	PermissionEndCall     Permission = "end_call"
	PermissionShareScreen Permission = "share_screen"
	PermissionRecord      Permission = "record"
	PermissionAdmin       Permission = "admin"

	ThreatLevelNone     ThreatLevel = "none"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// ThreatPattern represents a threat detection pattern
type ThreatPattern struct {
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Action      string    `json:"action"`
}

// DetectedThreat represents a detected threat
type DetectedThreat struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	Level       ThreatLevel `json:"level"`
	Source      string      `json:"source"`
	Description string      `json:"description"`
	DetectedAt  time.Time   `json:"detected_at"`
	Resolved    bool        `json:"resolved"`
}

// AccessRule represents an access control rule
type AccessRule struct {
	Name        string      `json:"name"`
	Condition   string      `json:"condition"`
	Action      string      `json:"action"`
	Priority    int         `json:"priority"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *SecurityConfig) (*SecurityManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &SecurityManager{
		config:   config,
		contexts: make(map[string]*SecurityContext),
		logger:   logx.WithContext(ctx),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize threat detector
	if config.EnableThreatDetection {
		manager.threatDetector = &ThreatDetector{
			enabled:         true,
			patterns:        make(map[string]ThreatPattern),
			detectedThreats: make(map[string]*DetectedThreat),
		}
		manager.initializeThreatPatterns()
	}

	// Initialize access control
	if config.EnableAccessControl {
		manager.accessControl = &AccessControl{
			enabled:    true,
			rules:      make(map[string]AccessRule),
			blockedIPs: make(map[string]time.Time),
			allowedIPs: make(map[string]bool),
		}
		manager.initializeAccessRules()
	}

	return manager, nil
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableThreatDetection: true,
		EnableAccessControl:   true,
		EnableAuditLogging:    true,
		SessionTimeout:        30 * time.Minute,
		MaxFailedAttempts:     3,
		BlockDuration:         15 * time.Minute,
		RequireAuthentication: true,
		AllowedNetworks:       []string{"0.0.0.0/0"}, // Allow all by default
	}
}

// Start starts the security manager
func (m *SecurityManager) Start() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.isRunning {
		return errors.New("security manager is already running")
	}

	m.logger.Info("Starting security manager...")

	// Start security monitoring routines
	go m.securityMonitoringRoutine()
	go m.contextCleanupRoutine()

	m.isRunning = true
	m.logger.Info("Security manager started successfully")

	return nil
}

// Stop stops the security manager
func (m *SecurityManager) Stop() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isRunning {
		return nil
	}

	m.logger.Info("Stopping security manager...")
	m.cancel()

	// Clear all contexts
	for _, context := range m.contexts {
		context.Close()
	}

	m.isRunning = false
	m.logger.Info("Security manager stopped")

	return nil
}

// CreateSecurityContext creates a new security context
func (m *SecurityManager) CreateSecurityContext(callID int64, userID, peerID int64) (*SecurityContext, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	contextID := m.generateContextID(callID, userID, peerID)

	if _, exists := m.contexts[contextID]; exists {
		return nil, fmt.Errorf("security context with ID %s already exists", contextID)
	}

	// Generate session token
	sessionToken := m.generateSessionToken()

	context := &SecurityContext{
		ID:           contextID,
		CallID:       callID,
		UserID:       userID,
		PeerID:       peerID,
		SessionToken: sessionToken,
		AuthLevel:    AuthLevelBasic,
		Permissions:  []Permission{PermissionJoinCall},
		ThreatLevel:  ThreatLevelNone,
		LastAccess:   time.Now(),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(m.config.SessionTimeout),
		Metadata:     make(map[string]string),
	}

	m.contexts[contextID] = context
	m.logger.Infof("Created security context: %s", contextID)

	return context, nil
}

// GetSecurityContext gets a security context by ID
func (m *SecurityManager) GetSecurityContext(contextID string) (*SecurityContext, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	context, exists := m.contexts[contextID]
	if !exists {
		return nil, fmt.Errorf("security context with ID %s not found", contextID)
	}

	return context, nil
}

// ValidateAccess validates access for a security context
func (m *SecurityManager) ValidateAccess(contextID string, permission Permission) error {
	context, err := m.GetSecurityContext(contextID)
	if err != nil {
		return err
	}

	return context.ValidateAccess(permission)
}

// DetectThreat detects threats for a security context
func (m *SecurityManager) DetectThreat(contextID string, data map[string]interface{}) (*DetectedThreat, error) {
	if m.threatDetector == nil || !m.threatDetector.enabled {
		return nil, nil
	}

	return m.threatDetector.DetectThreat(contextID, data)
}

// Private methods

func (m *SecurityManager) generateContextID(callID int64, userID, peerID int64) string {
	data := fmt.Sprintf("%d:%d:%d:%d", callID, userID, peerID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

func (m *SecurityManager) generateSessionToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (m *SecurityManager) initializeThreatPatterns() {
	if m.threatDetector == nil {
		return
	}

	patterns := map[string]ThreatPattern{
		"brute_force": {
			Name:        "Brute Force Attack",
			Pattern:     "multiple_failed_attempts",
			ThreatLevel: ThreatLevelHigh,
			Action:      "block",
		},
		"suspicious_activity": {
			Name:        "Suspicious Activity",
			Pattern:     "unusual_behavior",
			ThreatLevel: ThreatLevelMedium,
			Action:      "monitor",
		},
	}

	m.threatDetector.patterns = patterns
}

func (m *SecurityManager) initializeAccessRules() {
	if m.accessControl == nil {
		return
	}

	rules := map[string]AccessRule{
		"default_allow": {
			Name:      "Default Allow",
			Condition: "authenticated",
			Action:    "allow",
			Priority:  1,
		},
		"block_suspicious": {
			Name:      "Block Suspicious",
			Condition: "threat_level_high",
			Action:    "block",
			Priority:  10,
		},
	}

	m.accessControl.rules = rules
}

func (m *SecurityManager) securityMonitoringRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performSecurityChecks()
		}
	}
}

func (m *SecurityManager) contextCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredContexts()
		}
	}
}

func (m *SecurityManager) performSecurityChecks() {
	// Implement security monitoring logic
	m.logger.Debug("Performing security checks...")
}

func (m *SecurityManager) cleanupExpiredContexts() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	expiredContexts := make([]string, 0)

	for contextID, context := range m.contexts {
		context.mutex.RLock()
		if now.After(context.ExpiresAt) {
			expiredContexts = append(expiredContexts, contextID)
		}
		context.mutex.RUnlock()
	}

	for _, contextID := range expiredContexts {
		if context, exists := m.contexts[contextID]; exists {
			context.Close()
			delete(m.contexts, contextID)
		}
	}

	if len(expiredContexts) > 0 {
		m.logger.Infof("Cleaned up %d expired security contexts", len(expiredContexts))
	}
}

// SecurityContext methods

// ValidateAccess validates access for a specific permission
func (c *SecurityContext) ValidateAccess(permission Permission) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.IsBlocked {
		if time.Now().Before(c.BlockedUntil) {
			return fmt.Errorf("access blocked until %v", c.BlockedUntil)
		}
		c.IsBlocked = false
	}

	// Check if permission is granted
	for _, p := range c.Permissions {
		if p == permission {
			c.LastAccess = time.Now()
			c.AccessAttempts++
			return nil
		}
	}

	c.FailedAttempts++
	return fmt.Errorf("permission %s not granted", permission)
}

// Close closes the security context
func (c *SecurityContext) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear sensitive data
	c.SessionToken = ""
	c.Metadata = make(map[string]string)
}

// ThreatDetector methods

// DetectThreat detects threats based on provided data
func (td *ThreatDetector) DetectThreat(contextID string, data map[string]interface{}) (*DetectedThreat, error) {
	td.mutex.Lock()
	defer td.mutex.Unlock()

	// Simplified threat detection logic
	if failedAttempts, ok := data["failed_attempts"].(int); ok && failedAttempts > 3 {
		threat := &DetectedThreat{
			ID:          td.generateThreatID(),
			Type:        "brute_force",
			Level:       ThreatLevelHigh,
			Source:      contextID,
			Description: "Multiple failed access attempts detected",
			DetectedAt:  time.Now(),
			Resolved:    false,
		}

		td.detectedThreats[threat.ID] = threat
		return threat, nil
	}

	return nil, nil
}

func (td *ThreatDetector) generateThreatID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
