package text

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// TextModerator handles text content moderation
type TextModerator struct {
	config     *Config
	rules      map[string]*Rule
	patterns   map[string]*regexp.Regexp
	whitelist  map[string]bool
	blacklist  map[string]bool
	mutex      sync.RWMutex
	logger     logx.Logger
}

// Config for text moderation
type Config struct {
	EnableProfanityFilter bool     `json:"enable_profanity_filter"`
	EnableSpamDetection   bool     `json:"enable_spam_detection"`
	EnableToxicityCheck   bool     `json:"enable_toxicity_check"`
	MaxMessageLength      int      `json:"max_message_length"`
	BannedWords          []string `json:"banned_words"`
	AllowedDomains       []string `json:"allowed_domains"`
	StrictMode           bool     `json:"strict_mode"`
}

// Rule represents a moderation rule
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	Action      Action    `json:"action"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Action types for moderation
type Action string

const (
	ActionWarn   Action = "warn"
	ActionBlock  Action = "block"
	ActionDelete Action = "delete"
	ActionFlag   Action = "flag"
)

// Severity levels
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ModerationResult contains the result of text moderation
type ModerationResult struct {
	IsAllowed    bool                   `json:"is_allowed"`
	Confidence   float64                `json:"confidence"`
	Violations   []Violation            `json:"violations"`
	Suggestions  []string               `json:"suggestions"`
	ProcessedAt  time.Time              `json:"processed_at"`
	ProcessingMs int64                  `json:"processing_ms"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Violation represents a moderation violation
type Violation struct {
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Action      Action    `json:"action"`
	Severity    Severity  `json:"severity"`
	Message     string    `json:"message"`
	Position    int       `json:"position"`
	Length      int       `json:"length"`
	Confidence  float64   `json:"confidence"`
	DetectedAt  time.Time `json:"detected_at"`
}

// NewTextModerator creates a new text moderator
func NewTextModerator(config *Config) *TextModerator {
	if config == nil {
		config = DefaultConfig()
	}

	moderator := &TextModerator{
		config:    config,
		rules:     make(map[string]*Rule),
		patterns:  make(map[string]*regexp.Regexp),
		whitelist: make(map[string]bool),
		blacklist: make(map[string]bool),
		logger:    logx.WithContext(context.Background()),
	}

	// Initialize default rules
	moderator.initializeDefaultRules()
	
	// Load banned words
	for _, word := range config.BannedWords {
		moderator.blacklist[strings.ToLower(word)] = true
	}

	return moderator
}

// DefaultConfig returns default text moderation configuration
func DefaultConfig() *Config {
	return &Config{
		EnableProfanityFilter: true,
		EnableSpamDetection:   true,
		EnableToxicityCheck:   true,
		MaxMessageLength:      4096,
		BannedWords:          []string{},
		AllowedDomains:       []string{},
		StrictMode:           false,
	}
}

// ModerateText performs text moderation
func (tm *TextModerator) ModerateText(ctx context.Context, text string) (*ModerationResult, error) {
	start := time.Now()
	
	result := &ModerationResult{
		IsAllowed:    true,
		Confidence:   1.0,
		Violations:   []Violation{},
		Suggestions:  []string{},
		ProcessedAt:  start,
		Metadata:     make(map[string]interface{}),
	}

	// Check message length
	if len(text) > tm.config.MaxMessageLength {
		violation := Violation{
			RuleID:     "length_limit",
			RuleName:   "Message Length Limit",
			Action:     ActionBlock,
			Severity:   SeverityMedium,
			Message:    fmt.Sprintf("Message exceeds maximum length of %d characters", tm.config.MaxMessageLength),
			Position:   tm.config.MaxMessageLength,
			Length:     len(text) - tm.config.MaxMessageLength,
			Confidence: 1.0,
			DetectedAt: time.Now(),
		}
		result.Violations = append(result.Violations, violation)
		result.IsAllowed = false
	}

	// Check profanity filter
	if tm.config.EnableProfanityFilter {
		violations := tm.checkProfanity(text)
		result.Violations = append(result.Violations, violations...)
		if len(violations) > 0 {
			result.IsAllowed = false
		}
	}

	// Check spam detection
	if tm.config.EnableSpamDetection {
		violations := tm.checkSpam(text)
		result.Violations = append(result.Violations, violations...)
		if len(violations) > 0 {
			result.IsAllowed = false
		}
	}

	// Check toxicity
	if tm.config.EnableToxicityCheck {
		violations := tm.checkToxicity(text)
		result.Violations = append(result.Violations, violations...)
		if len(violations) > 0 {
			result.IsAllowed = false
		}
	}

	// Apply custom rules
	violations := tm.applyCustomRules(text)
	result.Violations = append(result.Violations, violations...)
	if len(violations) > 0 {
		result.IsAllowed = false
	}

	// Calculate overall confidence
	if len(result.Violations) > 0 {
		totalConfidence := 0.0
		for _, v := range result.Violations {
			totalConfidence += v.Confidence
		}
		result.Confidence = totalConfidence / float64(len(result.Violations))
	}

	result.ProcessingMs = time.Since(start).Milliseconds()
	return result, nil
}

// initializeDefaultRules sets up default moderation rules
func (tm *TextModerator) initializeDefaultRules() {
	// Add default rules here
	rules := []*Rule{
		{
			ID:          "profanity_basic",
			Name:        "Basic Profanity Filter",
			Pattern:     `(?i)\b(fuck|shit|damn|hell|bitch|asshole)\b`,
			Action:      ActionWarn,
			Severity:    SeverityLow,
			Description: "Detects basic profanity",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "spam_repetition",
			Name:        "Spam Repetition",
			Pattern:     `(.)\1{10,}`,
			Action:      ActionBlock,
			Severity:    SeverityMedium,
			Description: "Detects excessive character repetition",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, rule := range rules {
		tm.AddRule(rule)
	}
}

// AddRule adds a new moderation rule
func (tm *TextModerator) AddRule(rule *Rule) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Compile regex pattern
	pattern, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	tm.rules[rule.ID] = rule
	tm.patterns[rule.ID] = pattern
	return nil
}

// checkProfanity checks for profanity in text
func (tm *TextModerator) checkProfanity(text string) []Violation {
	var violations []Violation
	
	words := strings.Fields(strings.ToLower(text))
	for i, word := range words {
		if tm.blacklist[word] {
			violation := Violation{
				RuleID:     "profanity_blacklist",
				RuleName:   "Profanity Blacklist",
				Action:     ActionWarn,
				Severity:   SeverityMedium,
				Message:    "Profanity detected",
				Position:   i,
				Length:     len(word),
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}
	
	return violations
}

// checkSpam checks for spam patterns
func (tm *TextModerator) checkSpam(text string) []Violation {
	var violations []Violation
	
	// Check for excessive repetition
	if strings.Count(text, strings.Repeat("a", 5)) > 0 {
		violation := Violation{
			RuleID:     "spam_repetition",
			RuleName:   "Spam Repetition",
			Action:     ActionBlock,
			Severity:   SeverityMedium,
			Message:    "Excessive repetition detected",
			Position:   0,
			Length:     len(text),
			Confidence: 0.8,
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
	}
	
	return violations
}

// checkToxicity checks for toxic content
func (tm *TextModerator) checkToxicity(text string) []Violation {
	var violations []Violation
	
	// Simple toxicity check - in production, this would use ML models
	toxicPatterns := []string{"hate", "kill", "die", "stupid"}
	
	for _, pattern := range toxicPatterns {
		if strings.Contains(strings.ToLower(text), pattern) {
			violation := Violation{
				RuleID:     "toxicity_basic",
				RuleName:   "Basic Toxicity",
				Action:     ActionFlag,
				Severity:   SeverityHigh,
				Message:    "Potentially toxic content detected",
				Position:   strings.Index(strings.ToLower(text), pattern),
				Length:     len(pattern),
				Confidence: 0.7,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}
	
	return violations
}

// applyCustomRules applies custom moderation rules
func (tm *TextModerator) applyCustomRules(text string) []Violation {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	var violations []Violation
	
	for ruleID, pattern := range tm.patterns {
		rule := tm.rules[ruleID]
		matches := pattern.FindAllStringIndex(text, -1)
		
		for _, match := range matches {
			violation := Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Action:     rule.Action,
				Severity:   rule.Severity,
				Message:    rule.Description,
				Position:   match[0],
				Length:     match[1] - match[0],
				Confidence: 0.85,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}
	
	return violations
}
