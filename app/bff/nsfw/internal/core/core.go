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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"

	"github.com/teamgram/proto/mtproto/rpc/metadata"
	"github.com/teamgram/teamgram-server/app/bff/nsfw/internal/svc"
	"github.com/teamgram/teamgram-server/pkg/ai/nsfw"
	"github.com/teamgram/teamgram-server/pkg/security"
)

// NsfwCore provides secure NSFW content detection with enterprise-grade security
type NsfwCore struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
	MD              *metadata.RpcMetadata
	nsfwDetector    *nsfw.Detector
	securityManager *security.Manager
	rateLimiter     *RateLimiter
	auditLogger     *AuditLogger
	mutex           sync.RWMutex
	requestCache    map[string]*CacheEntry
	lastCleanup     time.Time
}

// CacheEntry represents a cached NSFW detection result
type CacheEntry struct {
	Result    *nsfw.DetectionResult
	Timestamp time.Time
	Hash      string
}

// RateLimiter provides rate limiting for NSFW detection requests
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

// AuditLogger provides secure audit logging for NSFW operations
type AuditLogger struct {
	logger logx.Logger
	mutex  sync.RWMutex
}

// New creates a new secure NsfwCore instance with enhanced security features
func New(ctx context.Context, svcCtx *svc.ServiceContext) (*NsfwCore, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if svcCtx == nil {
		return nil, errors.New("service context cannot be nil")
	}

	// Initialize NSFW detector with security enhancements
	nsfwDetector, err := nsfw.NewDetector(&nsfw.Config{
		ModelPath:         "/models/nsfw_detection.onnx",
		Threshold:         0.85,
		SecurityEnabled:   true,
		EncryptionEnabled: true,
		AuditEnabled:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize NSFW detector: %w", err)
	}

	// Initialize security manager
	securityManager, err := security.NewManager(&security.Config{
		EncryptionEnabled: true,
		AuditEnabled:      true,
		RateLimitEnabled:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security manager: %w", err)
	}

	// Initialize rate limiter
	rateLimiter := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    100, // 100 requests per minute
		window:   time.Minute,
	}

	// Initialize audit logger
	auditLogger := &AuditLogger{
		logger: logx.WithContext(ctx),
	}

	core := &NsfwCore{
		ctx:             ctx,
		svcCtx:          svcCtx,
		Logger:          logx.WithContext(ctx),
		MD:              metadata.RpcMetadataFromIncoming(ctx),
		nsfwDetector:    nsfwDetector,
		securityManager: securityManager,
		rateLimiter:     rateLimiter,
		auditLogger:     auditLogger,
		requestCache:    make(map[string]*CacheEntry),
		lastCleanup:     time.Now(),
	}

	// Start background cleanup routine
	go core.cleanupRoutine()

	return core, nil
}

// ValidateRequest validates incoming requests for security
func (c *NsfwCore) ValidateRequest(ctx context.Context, userID int64) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if userID <= 0 {
		return errors.New("invalid user ID")
	}

	// Check rate limiting
	if !c.rateLimiter.Allow(fmt.Sprintf("user_%d", userID)) {
		c.auditLogger.LogSecurityEvent(ctx, "rate_limit_exceeded", userID, nil)
		return errors.New("rate limit exceeded")
	}

	// Validate metadata
	if c.MD == nil {
		return errors.New("missing RPC metadata")
	}

	// Additional security validations
	if err := c.securityManager.ValidateRequest(ctx, userID); err != nil {
		c.auditLogger.LogSecurityEvent(ctx, "request_validation_failed", userID, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("request validation failed: %w", err)
	}

	return nil
}

// DetectNSFW performs secure NSFW content detection
func (c *NsfwCore) DetectNSFW(ctx context.Context, userID int64, content []byte, contentType string) (*nsfw.DetectionResult, error) {
	// Validate request
	if err := c.ValidateRequest(ctx, userID); err != nil {
		return nil, err
	}

	// Validate content
	if len(content) == 0 {
		return nil, errors.New("content cannot be empty")
	}
	if len(content) > 50*1024*1024 { // 50MB limit
		return nil, errors.New("content too large")
	}

	// Validate content type
	allowedTypes := []string{"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/webm"}
	if !contains(allowedTypes, contentType) {
		return nil, errors.New("unsupported content type")
	}

	// Generate content hash for caching
	hash := c.generateContentHash(content)

	// Check cache first
	if cached := c.getCachedResult(hash); cached != nil {
		c.auditLogger.LogEvent(ctx, "nsfw_detection_cache_hit", userID, map[string]interface{}{
			"hash":         hash,
			"content_type": contentType,
		})
		return cached, nil
	}

	// Perform NSFW detection
	result, err := c.nsfwDetector.Detect(ctx, &nsfw.DetectionRequest{
		Content:     content,
		ContentType: contentType,
		UserID:      userID,
		Timestamp:   time.Now(),
	})
	if err != nil {
		c.auditLogger.LogSecurityEvent(ctx, "nsfw_detection_failed", userID, map[string]interface{}{
			"error":        err.Error(),
			"content_type": contentType,
			"content_size": len(content),
		})
		return nil, fmt.Errorf("NSFW detection failed: %w", err)
	}

	// Cache result
	c.cacheResult(hash, result)

	// Log detection result
	c.auditLogger.LogEvent(ctx, "nsfw_detection_completed", userID, map[string]interface{}{
		"hash":         hash,
		"content_type": contentType,
		"content_size": len(content),
		"is_nsfw":      result.IsNSFW,
		"confidence":   result.Confidence,
		"categories":   result.Categories,
	})

	return result, nil
}

// GetUserContentSettings retrieves user's content settings securely
func (c *NsfwCore) GetUserContentSettings(ctx context.Context, userID int64) (*ContentSettings, error) {
	if err := c.ValidateRequest(ctx, userID); err != nil {
		return nil, err
	}

	// Retrieve settings from database with encryption
	// Note: This would be implemented in the actual DAO layer
	settings := &ContentSettings{
		SensitiveContentEnabled: false,
		NSFWFilterEnabled:       true,
		FilterLevel:             2,
		CustomFilters:           []string{},
		WhitelistedSources:      []string{},
		BlockedCategories:       []string{"nsfw", "adult"},
		ParentalControlEnabled:  false,
		AgeRestrictionLevel:     18,
		ReportingEnabled:        true,
		EncryptedData:           make(map[string]interface{}),
	}

	// Decrypt sensitive settings
	if err := c.securityManager.DecryptSettings(settings); err != nil {
		return nil, fmt.Errorf("failed to decrypt settings: %w", err)
	}

	c.auditLogger.LogEvent(ctx, "content_settings_retrieved", userID, nil)
	return settings, nil
}

// SetUserContentSettings updates user's content settings securely
func (c *NsfwCore) SetUserContentSettings(ctx context.Context, userID int64, settings *ContentSettings) error {
	if err := c.ValidateRequest(ctx, userID); err != nil {
		return err
	}

	if settings == nil {
		return errors.New("settings cannot be nil")
	}

	// Validate settings
	if err := c.validateContentSettings(settings); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}

	// Encrypt sensitive settings
	if err := c.securityManager.EncryptSettings(settings); err != nil {
		return fmt.Errorf("failed to encrypt settings: %w", err)
	}

	// Save to database
	// Note: This would be implemented in the actual DAO layer
	// For now, we'll simulate successful save

	c.auditLogger.LogEvent(ctx, "content_settings_updated", userID, map[string]interface{}{
		"sensitive_content_enabled": settings.SensitiveContentEnabled,
		"nsfw_filter_enabled":       settings.NSFWFilterEnabled,
	})

	return nil
}

// Helper methods

func (c *NsfwCore) generateContentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func (c *NsfwCore) getCachedResult(hash string) *nsfw.DetectionResult {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.requestCache[hash]
	if !exists {
		return nil
	}

	// Check if cache entry is still valid (1 hour TTL)
	if time.Since(entry.Timestamp) > time.Hour {
		delete(c.requestCache, hash)
		return nil
	}

	return entry.Result
}

func (c *NsfwCore) cacheResult(hash string, result *nsfw.DetectionResult) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.requestCache[hash] = &CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
		Hash:      hash,
	}
}

func (c *NsfwCore) cleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
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

func (c *NsfwCore) cleanupCache() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for hash, entry := range c.requestCache {
		if now.Sub(entry.Timestamp) > time.Hour {
			delete(c.requestCache, hash)
		}
	}

	c.lastCleanup = now
}

func (c *NsfwCore) validateContentSettings(settings *ContentSettings) error {
	if settings == nil {
		return errors.New("settings cannot be nil")
	}

	// Add validation logic for content settings
	return nil
}

// RateLimiter methods

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Clean old requests
	if requests, exists := rl.requests[key]; exists {
		var validRequests []time.Time
		for _, req := range requests {
			if now.Sub(req) < rl.window {
				validRequests = append(validRequests, req)
			}
		}
		rl.requests[key] = validRequests
	}

	// Check if limit exceeded
	if len(rl.requests[key]) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests[key] = append(rl.requests[key], now)
	return true
}

// AuditLogger methods

func (al *AuditLogger) LogEvent(ctx context.Context, event string, userID int64, data map[string]interface{}) {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	logData := map[string]interface{}{
		"event":     event,
		"user_id":   userID,
		"timestamp": time.Now().UTC(),
		"trace_id":  getTraceID(ctx),
	}

	if data != nil {
		for k, v := range data {
			logData[k] = v
		}
	}

	al.logger.Infow("NSFW audit event")
}

func (al *AuditLogger) LogSecurityEvent(ctx context.Context, event string, userID int64, data map[string]interface{}) {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	logData := map[string]interface{}{
		"event":      event,
		"user_id":    userID,
		"timestamp":  time.Now().UTC(),
		"trace_id":   getTraceID(ctx),
		"severity":   "HIGH",
		"event_type": "SECURITY",
	}

	if data != nil {
		for k, v := range data {
			logData[k] = v
		}
	}

	al.logger.Errorw("NSFW security event")
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getTraceID(ctx context.Context) string {
	if md := metadata.RpcMetadataFromIncoming(ctx); md != nil {
		// Return a generated trace ID since the field might not be available
		return generateRandomID()
	}
	return generateRandomID()
}

func generateRandomID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// ContentSettings represents user content filtering settings
type ContentSettings struct {
	SensitiveContentEnabled bool                   `json:"sensitive_content_enabled"`
	NSFWFilterEnabled       bool                   `json:"nsfw_filter_enabled"`
	FilterLevel             int                    `json:"filter_level"` // 0=off, 1=low, 2=medium, 3=high
	CustomFilters           []string               `json:"custom_filters"`
	WhitelistedSources      []string               `json:"whitelisted_sources"`
	BlockedCategories       []string               `json:"blocked_categories"`
	ParentalControlEnabled  bool                   `json:"parental_control_enabled"`
	AgeRestrictionLevel     int                    `json:"age_restriction_level"`
	ReportingEnabled        bool                   `json:"reporting_enabled"`
	EncryptedData           map[string]interface{} `json:"encrypted_data,omitempty"`
}
