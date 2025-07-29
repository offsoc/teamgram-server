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
//

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"

	"github.com/teamgram/proto/mtproto/rpc/metadata"
	"github.com/teamgram/teamgram-server/app/bff/messages/internal/svc"
	"github.com/teamgram/teamgram-server/pkg/ai/content"
	"github.com/teamgram/teamgram-server/pkg/enterprise/audit"
	"github.com/teamgram/teamgram-server/pkg/security"
)

// MessagesCore provides secure message processing with enterprise-grade features
type MessagesCore struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
	MD *metadata.RpcMetadata

	// Security and encryption
	pqcManager      *pqcEngine
	securityManager *security.Manager
	contentFilter   *content.Filter
	auditLogger     *audit.Logger

	// PQC enhancement fields
	pqcEnabled bool
	hybridMode bool
	pqcMutex   sync.RWMutex
	pqcMetrics *PQCMessageMetrics

	// Enterprise features
	enterpriseMode bool
	rateLimiter    *MessageRateLimiter
	messageCache   map[string]*CachedMessage
	cacheMutex     sync.RWMutex
	lastCleanup    time.Time

	// Advanced features
	aiTranslation   bool
	smartReply      bool
	contentAnalysis bool
	spamDetection   bool
	nsfwDetection   bool
}

// PQCMessageMetrics tracks PQC message processing metrics
type PQCMessageMetrics struct {
	TotalMessages          int64              `json:"total_messages"`
	PQCEncryptedMessages   int64              `json:"pqc_encrypted_messages"`
	PQCDecryptedMessages   int64              `json:"pqc_decrypted_messages"`
	EncryptionLatency      time.Duration      `json:"encryption_latency"`
	DecryptionLatency      time.Duration      `json:"decryption_latency"`
	IntegrityVerifications int64              `json:"integrity_verifications"`
	IntegrityFailures      int64              `json:"integrity_failures"`
	LastOperationTime      time.Time          `json:"last_operation_time"`
	SecurityEvents         int64              `json:"security_events"`
	PerformanceMetrics     map[string]float64 `json:"performance_metrics"`
}

// MessageRateLimiter provides rate limiting for message operations
type MessageRateLimiter struct {
	userLimits map[int64][]time.Time
	mutex      sync.RWMutex
	limit      int
	window     time.Duration
}

// CachedMessage represents a cached message
type CachedMessage struct {
	MessageID int64                  `json:"message_id"`
	Content   []byte                 `json:"content"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Hash      string                 `json:"hash"`
	Encrypted bool                   `json:"encrypted"`
}

// MessageConfig represents message service configuration
type MessageConfig struct {
	PQCEnabled      bool `json:"pqc_enabled"`
	HybridMode      bool `json:"hybrid_mode"`
	EnterpriseMode  bool `json:"enterprise_mode"`
	AITranslation   bool `json:"ai_translation"`
	SmartReply      bool `json:"smart_reply"`
	ContentAnalysis bool `json:"content_analysis"`
	SpamDetection   bool `json:"spam_detection"`
	NSFWDetection   bool `json:"nsfw_detection"`
}

// New creates a new secure MessagesCore instance with enhanced security features
func New(ctx context.Context, svcCtx *svc.ServiceContext) (*MessagesCore, error) {
	return NewWithConfig(ctx, svcCtx, &MessageConfig{
		PQCEnabled:      true,
		HybridMode:      true,
		EnterpriseMode:  true,
		AITranslation:   true,
		SmartReply:      true,
		ContentAnalysis: true,
		SpamDetection:   true,
		NSFWDetection:   true,
	})
}

// NewWithConfig creates a new MessagesCore with custom configuration
func NewWithConfig(ctx context.Context, svcCtx *svc.ServiceContext, config *MessageConfig) (*MessagesCore, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if svcCtx == nil {
		return nil, errors.New("service context cannot be nil")
	}
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	core := &MessagesCore{
		ctx:             ctx,
		svcCtx:          svcCtx,
		Logger:          logx.WithContext(ctx),
		MD:              metadata.RpcMetadataFromIncoming(ctx),
		pqcEnabled:      config.PQCEnabled,
		hybridMode:      config.HybridMode,
		enterpriseMode:  config.EnterpriseMode,
		aiTranslation:   config.AITranslation,
		smartReply:      config.SmartReply,
		contentAnalysis: config.ContentAnalysis,
		spamDetection:   config.SpamDetection,
		nsfwDetection:   config.NSFWDetection,
		messageCache:    make(map[string]*CachedMessage),
		lastCleanup:     time.Now(),
		pqcMetrics: &PQCMessageMetrics{
			LastOperationTime:  time.Now(),
			PerformanceMetrics: make(map[string]float64),
		},
	}

	var err error

	// Initialize PQC manager
	if config.PQCEnabled {
		core.pqcManager = newPQCEngine()
	}

	// Initialize security manager
	core.securityManager, err = security.NewManager(&security.Config{
		EncryptionEnabled: true,
		AuditEnabled:      true,
		RateLimitEnabled:  true,
		ThreatDetection:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security manager: %w", err)
	}

	// Initialize content filter
	if config.ContentAnalysis {
		core.contentFilter, err = content.NewFilter(&content.Config{
			SpamDetection:     config.SpamDetection,
			NSFWDetection:     config.NSFWDetection,
			LanguageDetection: true,
			SentimentAnalysis: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize content filter: %w", err)
		}
	}

	// Initialize audit logger
	if config.EnterpriseMode {
		core.auditLogger, err = audit.NewLogger(&audit.Config{
			Enabled:           true,
			RealTimeLogging:   true,
			EncryptionEnabled: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
		}
	}

	// Initialize rate limiter
	core.rateLimiter = &MessageRateLimiter{
		userLimits: make(map[int64][]time.Time),
		limit:      1000, // 1000 messages per minute
		window:     time.Minute,
	}

	// Start background cleanup routine
	go core.cleanupRoutine()

	return core, nil
}

// ValidateMessageRequest validates incoming message requests for security
func (c *MessagesCore) ValidateMessageRequest(ctx context.Context, userID int64, peerID int64) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if userID <= 0 {
		return errors.New("invalid user ID")
	}

	// Check rate limiting
	if !c.rateLimiter.Allow(userID) {
		if c.auditLogger != nil {
			c.auditLogger.LogSecurityEvent(ctx, "message_rate_limit_exceeded", userID, map[string]interface{}{
				"peer_id": peerID,
			})
		}
		return errors.New("message rate limit exceeded")
	}

	// Validate metadata
	if c.MD == nil {
		return errors.New("missing RPC metadata")
	}

	// Additional security validations
	if c.securityManager != nil {
		if err := c.securityManager.ValidateRequest(ctx, userID); err != nil {
			if c.auditLogger != nil {
				c.auditLogger.LogSecurityEvent(ctx, "message_request_validation_failed", userID, map[string]interface{}{
					"error":   err.Error(),
					"peer_id": peerID,
				})
			}
			return fmt.Errorf("request validation failed: %w", err)
		}
	}

	return nil
}

// Stub types are defined in messages_military.go

// ProcessMessage processes a message with security and content filtering
func (c *MessagesCore) ProcessMessage(ctx context.Context, userID int64, message []byte, messageType string) (*ProcessedMessage, error) {
	// Validate request
	if err := c.ValidateMessageRequest(ctx, userID, 0); err != nil {
		return nil, err
	}

	// Validate message
	if len(message) == 0 {
		return nil, errors.New("message cannot be empty")
	}
	if len(message) > 4096 { // 4KB limit for text messages
		return nil, errors.New("message too large")
	}

	startTime := time.Now()

	// Generate message hash
	hash := c.generateMessageHash(message)

	// Check cache first
	if cached := c.getCachedMessage(hash); cached != nil {
		if c.auditLogger != nil {
			c.auditLogger.LogEvent(ctx, "message_cache_hit", userID, map[string]interface{}{
				"hash":         hash,
				"message_type": messageType,
			})
		}
		return &ProcessedMessage{
			Content:   cached.Content,
			Metadata:  cached.Metadata,
			Encrypted: cached.Encrypted,
			Hash:      cached.Hash,
		}, nil
	}

	processed := &ProcessedMessage{
		Content:  message,
		Metadata: make(map[string]interface{}),
		Hash:     hash,
	}

	// Content filtering
	if c.contentFilter != nil {
		filterResult, err := c.contentFilter.FilterContent(ctx, &content.FilterRequest{
			Content:     message,
			ContentType: messageType,
			UserID:      userID,
		})
		if err != nil {
			c.Logger.Infow("Content filtering failed", logx.Field("error", err))
		} else {
			processed.Metadata["content_filter"] = filterResult
			if filterResult.Blocked {
				return nil, errors.New("message blocked by content filter")
			}
		}
	}

	// PQC encryption if enabled
	if c.pqcEnabled && c.pqcManager != nil {
		encryptedContent, err := c.pqcManager.Encrypt(message)
		if err != nil {
			c.Logger.Infow("PQC encryption failed", logx.Field("error", err))
		} else {
			processed.Content = encryptedContent
			processed.Encrypted = true
			processed.Metadata["encryption"] = "pqc"

			// Update metrics
			c.updatePQCMetrics("encrypt", time.Since(startTime))
		}
	}

	// Cache processed message
	c.cacheMessage(hash, processed)

	// Log processing
	if c.auditLogger != nil {
		c.auditLogger.LogEvent(ctx, "message_processed", userID, map[string]interface{}{
			"hash":            hash,
			"message_type":    messageType,
			"encrypted":       processed.Encrypted,
			"processing_time": time.Since(startTime),
		})
	}

	return processed, nil
}

// DecryptMessage decrypts a PQC-encrypted message
func (c *MessagesCore) DecryptMessage(ctx context.Context, userID int64, encryptedMessage []byte) ([]byte, error) {
	if !c.pqcEnabled || c.pqcManager == nil {
		return encryptedMessage, nil // Return as-is if PQC not enabled
	}

	startTime := time.Now()

	decryptedMessage, err := c.pqcManager.Decrypt(encryptedMessage)
	if err != nil {
		c.updatePQCMetrics("decrypt_failed", time.Since(startTime))
		return nil, fmt.Errorf("PQC decryption failed: %w", err)
	}

	// Update metrics
	c.updatePQCMetrics("decrypt", time.Since(startTime))

	// Log decryption
	if c.auditLogger != nil {
		c.auditLogger.LogEvent(ctx, "message_decrypted", userID, map[string]interface{}{
			"decryption_time": time.Since(startTime),
		})
	}

	return decryptedMessage, nil
}

// Helper methods

func (c *MessagesCore) generateMessageHash(message []byte) string {
	hash := sha256.Sum256(message)
	return hex.EncodeToString(hash[:])
}

func (c *MessagesCore) getCachedMessage(hash string) *CachedMessage {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	cached, exists := c.messageCache[hash]
	if !exists {
		return nil
	}

	// Check if cache entry is still valid (5 minutes TTL)
	if time.Since(cached.Timestamp) > 5*time.Minute {
		delete(c.messageCache, hash)
		return nil
	}

	return cached
}

func (c *MessagesCore) cacheMessage(hash string, processed *ProcessedMessage) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	c.messageCache[hash] = &CachedMessage{
		Content:   processed.Content,
		Metadata:  processed.Metadata,
		Timestamp: time.Now(),
		Hash:      hash,
		Encrypted: processed.Encrypted,
	}
}

func (c *MessagesCore) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanupCache()
		}
	}
}

func (c *MessagesCore) cleanupCache() {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	now := time.Now()
	for hash, cached := range c.messageCache {
		if now.Sub(cached.Timestamp) > 5*time.Minute {
			delete(c.messageCache, hash)
		}
	}

	c.lastCleanup = now
}

func (c *MessagesCore) updatePQCMetrics(operation string, duration time.Duration) {
	c.pqcMutex.Lock()
	defer c.pqcMutex.Unlock()

	switch operation {
	case "encrypt":
		c.pqcMetrics.PQCEncryptedMessages++
		c.pqcMetrics.EncryptionLatency = duration
	case "decrypt":
		c.pqcMetrics.PQCDecryptedMessages++
		c.pqcMetrics.DecryptionLatency = duration
	case "decrypt_failed":
		c.pqcMetrics.IntegrityFailures++
	}

	c.pqcMetrics.TotalMessages++
	c.pqcMetrics.LastOperationTime = time.Now()
	c.pqcMetrics.PerformanceMetrics[operation] = float64(duration.Nanoseconds()) / 1e6 // Convert to milliseconds
}

// Rate limiter methods

func (rl *MessageRateLimiter) Allow(userID int64) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Clean old requests
	if requests, exists := rl.userLimits[userID]; exists {
		var validRequests []time.Time
		for _, req := range requests {
			if now.Sub(req) < rl.window {
				validRequests = append(validRequests, req)
			}
		}
		rl.userLimits[userID] = validRequests
	}

	// Check if limit exceeded
	if len(rl.userLimits[userID]) >= rl.limit {
		return false
	}

	// Add current request
	rl.userLimits[userID] = append(rl.userLimits[userID], now)
	return true
}

// Legacy compatibility methods

// IsPQCEnabled returns whether PQC is enabled
func (c *MessagesCore) IsPQCEnabled() bool {
	c.pqcMutex.RLock()
	defer c.pqcMutex.RUnlock()
	return c.pqcEnabled
}

// IsHybridMode returns whether hybrid mode is enabled
func (c *MessagesCore) IsHybridMode() bool {
	c.pqcMutex.RLock()
	defer c.pqcMutex.RUnlock()
	return c.hybridMode
}

// GetPQCMetrics returns current PQC metrics
func (c *MessagesCore) GetPQCMetrics() *PQCMessageMetrics {
	c.pqcMutex.RLock()
	defer c.pqcMutex.RUnlock()

	// Return a copy to avoid race conditions
	metrics := *c.pqcMetrics
	return &metrics
}

// ProcessedMessage represents a processed message
type ProcessedMessage struct {
	Content   []byte                 `json:"content"`
	Metadata  map[string]interface{} `json:"metadata"`
	Encrypted bool                   `json:"encrypted"`
	Hash      string                 `json:"hash"`
}
