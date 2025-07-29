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

package moderation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// ModerationManager manages AI content moderation
type ModerationManager struct {
	mutex      sync.RWMutex
	config     *ModerationConfig
	moderators map[string]ContentModerator
	policies   map[string]*ModerationPolicy
	metrics    *ModerationMetrics
	logger     logx.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	isRunning  bool
}

// ModerationConfig configuration for content moderation
type ModerationConfig struct {
	// Moderation settings
	EnableTextModeration  bool `json:"enable_text_moderation"`
	EnableImageModeration bool `json:"enable_image_moderation"`
	EnableAudioModeration bool `json:"enable_audio_moderation"`
	EnableVideoModeration bool `json:"enable_video_moderation"`

	// Policies
	DefaultPolicy  string                       `json:"default_policy"`
	CustomPolicies map[string]*ModerationPolicy `json:"custom_policies"`

	// Thresholds
	ToxicityThreshold   float64 `json:"toxicity_threshold"`
	NSFWThreshold       float64 `json:"nsfw_threshold"`
	SpamThreshold       float64 `json:"spam_threshold"`
	HateSpeechThreshold float64 `json:"hate_speech_threshold"`

	// Actions
	AutoBlock     bool `json:"auto_block"`
	AutoWarn      bool `json:"auto_warn"`
	RequireReview bool `json:"require_review"`

	// Performance
	ProcessingTimeout   time.Duration `json:"processing_timeout"`
	MaxConcurrentChecks int           `json:"max_concurrent_checks"`
	EnableCaching       bool          `json:"enable_caching"`
	CacheTTL            time.Duration `json:"cache_ttl"`
}

// ModerationPolicy defines moderation rules and actions
type ModerationPolicy struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Rules       []ModerationRule   `json:"rules"`
	Actions     []ModerationAction `json:"actions"`
	Enabled     bool               `json:"enabled"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// ModerationRule defines a specific moderation rule
type ModerationRule struct {
	Type      RuleType               `json:"type"`
	Category  ViolationCategory      `json:"category"`
	Threshold float64                `json:"threshold"`
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ModerationAction defines actions to take when content violates rules
type ModerationAction struct {
	Type     ActionType             `json:"type"`
	Severity ActionSeverity         `json:"severity"`
	Duration time.Duration          `json:"duration,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ContentModerationRequest represents a content moderation request
type ContentModerationRequest struct {
	ID        string                 `json:"id"`
	Content   *ContentItem           `json:"content"`
	UserID    int64                  `json:"user_id"`
	ChatID    int64                  `json:"chat_id"`
	MessageID int64                  `json:"message_id"`
	Policy    string                 `json:"policy,omitempty"`
	Context   map[string]interface{} `json:"context"`
	CreatedAt time.Time              `json:"created_at"`
}

// ContentModerationResponse represents a content moderation response
type ContentModerationResponse struct {
	ID            string             `json:"id"`
	RequestID     string             `json:"request_id"`
	IsViolation   bool               `json:"is_violation"`
	Violations    []Violation        `json:"violations"`
	OverallScore  float64            `json:"overall_score"`
	Confidence    float64            `json:"confidence"`
	Actions       []ModerationAction `json:"actions"`
	Explanation   string             `json:"explanation"`
	ProcessTime   time.Duration      `json:"process_time"`
	ModeratorUsed string             `json:"moderator_used"`
	CreatedAt     time.Time          `json:"created_at"`
}

// ContentItem represents content to be moderated
type ContentItem struct {
	Type      ContentType            `json:"type"`
	Text      string                 `json:"text,omitempty"`
	ImageData []byte                 `json:"image_data,omitempty"`
	AudioData []byte                 `json:"audio_data,omitempty"`
	VideoData []byte                 `json:"video_data,omitempty"`
	URL       string                 `json:"url,omitempty"`
	MimeType  string                 `json:"mime_type,omitempty"`
	Size      int64                  `json:"size"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Violation represents a content violation
type Violation struct {
	Category    ViolationCategory      `json:"category"`
	Score       float64                `json:"score"`
	Threshold   float64                `json:"threshold"`
	Severity    ViolationSeverity      `json:"severity"`
	Description string                 `json:"description"`
	Evidence    []Evidence             `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Evidence represents evidence of a violation
type Evidence struct {
	Type       string                 `json:"type"`
	Content    string                 `json:"content"`
	Position   map[string]interface{} `json:"position,omitempty"`
	Confidence float64                `json:"confidence"`
}

// Enums
type ContentType string

const (
	ContentTypeText  ContentType = "text"
	ContentTypeImage ContentType = "image"
	ContentTypeAudio ContentType = "audio"
	ContentTypeVideo ContentType = "video"
)

type RuleType string

const (
	RuleTypeToxicity     RuleType = "toxicity"
	RuleTypeNSFW         RuleType = "nsfw"
	RuleTypeSpam         RuleType = "spam"
	RuleTypeHateSpeech   RuleType = "hate_speech"
	RuleTypeViolence     RuleType = "violence"
	RuleTypeProfanity    RuleType = "profanity"
	RuleTypePersonalInfo RuleType = "personal_info"
)

type ViolationCategory string

const (
	ViolationCategoryToxicity     ViolationCategory = "toxicity"
	ViolationCategoryNSFW         ViolationCategory = "nsfw"
	ViolationCategorySpam         ViolationCategory = "spam"
	ViolationCategoryHateSpeech   ViolationCategory = "hate_speech"
	ViolationCategoryViolence     ViolationCategory = "violence"
	ViolationCategoryProfanity    ViolationCategory = "profanity"
	ViolationCategoryPersonalInfo ViolationCategory = "personal_info"
)

type ViolationSeverity string

const (
	ViolationSeverityLow      ViolationSeverity = "low"
	ViolationSeverityMedium   ViolationSeverity = "medium"
	ViolationSeverityHigh     ViolationSeverity = "high"
	ViolationSeverityCritical ViolationSeverity = "critical"
)

type ActionType string

const (
	ActionTypeBlock  ActionType = "block"
	ActionTypeWarn   ActionType = "warn"
	ActionTypeFlag   ActionType = "flag"
	ActionTypeReview ActionType = "review"
	ActionTypeDelete ActionType = "delete"
	ActionTypeMute   ActionType = "mute"
	ActionTypeBan    ActionType = "ban"
)

type ActionSeverity string

const (
	ActionSeverityLow      ActionSeverity = "low"
	ActionSeverityMedium   ActionSeverity = "medium"
	ActionSeverityHigh     ActionSeverity = "high"
	ActionSeverityCritical ActionSeverity = "critical"
)

// ContentModerator interface for different moderation providers
type ContentModerator interface {
	Name() string
	SupportedTypes() []ContentType
	ModerateContent(ctx context.Context, content *ContentItem, policy *ModerationPolicy) (*ContentModerationResponse, error)
	IsAvailable() bool
	GetMetrics() *ModeratorMetrics
	Start() error
	Stop() error
}

// ModeratorMetrics tracks moderator performance
type ModeratorMetrics struct {
	Name            string        `json:"name"`
	ChecksPerformed int64         `json:"checks_performed"`
	ViolationsFound int64         `json:"violations_found"`
	FalsePositives  int64         `json:"false_positives"`
	FalseNegatives  int64         `json:"false_negatives"`
	AverageLatency  time.Duration `json:"average_latency"`
	Accuracy        float64       `json:"accuracy"`
	LastUsed        time.Time     `json:"last_used"`
	IsAvailable     bool          `json:"is_available"`
}

// ModerationMetrics tracks overall moderation performance
type ModerationMetrics struct {
	TotalChecks        int64                        `json:"total_checks"`
	ViolationsDetected int64                        `json:"violations_detected"`
	ActionsPerformed   int64                        `json:"actions_performed"`
	AverageLatency     time.Duration                `json:"average_latency"`
	ModeratorMetrics   map[string]*ModeratorMetrics `json:"moderator_metrics"`
	CategoryStats      map[ViolationCategory]int64  `json:"category_stats"`
	ActionStats        map[ActionType]int64         `json:"action_stats"`
	LastUpdated        time.Time                    `json:"last_updated"`
}

// NewModerationManager creates a new moderation manager
func NewModerationManager(config *ModerationConfig) (*ModerationManager, error) {
	if config == nil {
		config = DefaultModerationConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &ModerationManager{
		config:     config,
		moderators: make(map[string]ContentModerator),
		policies:   make(map[string]*ModerationPolicy),
		metrics: &ModerationMetrics{
			ModeratorMetrics: make(map[string]*ModeratorMetrics),
			CategoryStats:    make(map[ViolationCategory]int64),
			ActionStats:      make(map[ActionType]int64),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize moderators
	if err := manager.initializeModerators(); err != nil {
		return nil, fmt.Errorf("failed to initialize moderators: %w", err)
	}

	// Initialize policies
	manager.initializePolicies()

	return manager, nil
}

// Start starts the moderation manager
func (mm *ModerationManager) Start() error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if mm.isRunning {
		return fmt.Errorf("moderation manager is already running")
	}

	mm.logger.Info("Starting moderation manager...")

	// Start all moderators
	for name, moderator := range mm.moderators {
		if err := moderator.Start(); err != nil {
			mm.logger.Errorf("Failed to start moderator %s: %v", name, err)
			continue
		}
		mm.logger.Infof("Started content moderator: %s", name)
	}

	// Start metrics collection
	go mm.metricsLoop()

	mm.isRunning = true
	mm.logger.Info("Moderation manager started successfully")

	return nil
}

// ModerateContent moderates content according to policies
func (mm *ModerationManager) ModerateContent(ctx context.Context, request *ContentModerationRequest) (*ContentModerationResponse, error) {
	start := time.Now()

	mm.logger.Infof("Moderating content: id=%s", request.ID)

	// Create a simple response for now
	response := &ContentModerationResponse{
		ID:            request.ID,
		RequestID:     request.ID,
		IsViolation:   false,
		Violations:    []Violation{},
		OverallScore:  0.0,
		Confidence:    1.0,
		Actions:       []ModerationAction{},
		Explanation:   "Content passed moderation",
		ProcessTime:   time.Since(start),
		ModeratorUsed: "default",
		CreatedAt:     time.Now(),
	}

	mm.logger.Infof("Content moderated: id=%s, violations=%d, time=%v",
		request.ID, len(response.Violations), response.ProcessTime)

	return response, nil
}

// GetAvailableModels returns available moderation models
func (mm *ModerationManager) GetAvailableModels() []string {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	var models []string
	for name, moderator := range mm.moderators {
		if moderator.IsAvailable() {
			models = append(models, name)
		}
	}

	return models
}

// GetMetrics returns moderation metrics
func (mm *ModerationManager) GetMetrics() *ModerationMetrics {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// Update moderator metrics
	for name, moderator := range mm.moderators {
		mm.metrics.ModeratorMetrics[name] = moderator.GetMetrics()
	}

	mm.metrics.LastUpdated = time.Now()

	// Return a copy
	metrics := *mm.metrics
	return &metrics
}

// Helper methods

func (mm *ModerationManager) initializeModerators() error {
	// For now, just log that moderators would be initialized
	mm.logger.Infof("Moderators initialization skipped for now")
	return nil
}

func (mm *ModerationManager) initializePolicies() {
	// Create default policy
	defaultPolicy := &ModerationPolicy{
		Name:        "default",
		Description: "Default moderation policy",
		Rules: []ModerationRule{
			{
				Type:      RuleTypeToxicity,
				Category:  ViolationCategoryToxicity,
				Threshold: mm.config.ToxicityThreshold,
				Enabled:   true,
			},
			{
				Type:      RuleTypeNSFW,
				Category:  ViolationCategoryNSFW,
				Threshold: mm.config.NSFWThreshold,
				Enabled:   true,
			},
			{
				Type:      RuleTypeSpam,
				Category:  ViolationCategorySpam,
				Threshold: mm.config.SpamThreshold,
				Enabled:   true,
			},
		},
		Actions: []ModerationAction{
			{
				Type:     ActionTypeFlag,
				Severity: ActionSeverityMedium,
				Message:  "Content flagged for review",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mm.policies["default"] = defaultPolicy

	// Add custom policies from config
	for name, policy := range mm.config.CustomPolicies {
		mm.policies[name] = policy
	}
}

func (mm *ModerationManager) getPolicy(policyName string) *ModerationPolicy {
	if policyName == "" {
		policyName = mm.config.DefaultPolicy
	}
	if policyName == "" {
		policyName = "default"
	}

	return mm.policies[policyName]
}

func (mm *ModerationManager) selectModerator(contentType ContentType) ContentModerator {
	for _, moderator := range mm.moderators {
		if !moderator.IsAvailable() {
			continue
		}

		for _, supportedType := range moderator.SupportedTypes() {
			if supportedType == contentType {
				return moderator
			}
		}
	}

	return nil
}

func (mm *ModerationManager) applyModerationActions(request *ContentModerationRequest, response *ContentModerationResponse) {
	// Apply actions based on violations
	for _, action := range response.Actions {
		mm.logger.Infof("Applying moderation action %s for user %d: %s",
			action.Type, request.UserID, action.Message)

		// Update action statistics
		mm.mutex.Lock()
		mm.metrics.ActionStats[action.Type]++
		mm.metrics.ActionsPerformed++
		mm.mutex.Unlock()

		// Here you would integrate with the actual action system
		// For example, blocking users, deleting messages, etc.
	}
}

func (mm *ModerationManager) updateMetrics(request *ContentModerationRequest, success bool, latency time.Duration) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	mm.metrics.TotalChecks++
	mm.metrics.AverageLatency = (mm.metrics.AverageLatency + latency) / 2
}

func (mm *ModerationManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.collectMetrics()
		case <-mm.ctx.Done():
			return
		}
	}
}

func (mm *ModerationManager) collectMetrics() {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	for name, moderator := range mm.moderators {
		mm.metrics.ModeratorMetrics[name] = moderator.GetMetrics()
	}

	mm.metrics.LastUpdated = time.Now()
}

// DefaultModerationConfig returns default moderation configuration
func DefaultModerationConfig() *ModerationConfig {
	return &ModerationConfig{
		EnableTextModeration:  true,
		EnableImageModeration: true,
		EnableAudioModeration: false,
		EnableVideoModeration: false,
		DefaultPolicy:         "default",
		ToxicityThreshold:     0.7,
		NSFWThreshold:         0.8,
		SpamThreshold:         0.6,
		HateSpeechThreshold:   0.8,
		AutoBlock:             false,
		AutoWarn:              true,
		RequireReview:         true,
		ProcessingTimeout:     10 * time.Second,
		MaxConcurrentChecks:   20,
		EnableCaching:         true,
		CacheTTL:              1 * time.Hour,
	}
}
