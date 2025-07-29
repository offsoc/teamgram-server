package rules

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// RulesEngine manages moderation rules and policies
type RulesEngine struct {
	rules    map[string]*Rule
	policies map[string]*Policy
	rulesets map[string]*RuleSet
	mutex    sync.RWMutex
	logger   logx.Logger
	config   *Config
}

// Config for rules engine
type Config struct {
	EnableDynamicRules bool   `json:"enable_dynamic_rules"`
	MaxRulesPerSet     int    `json:"max_rules_per_set"`
	CacheTimeout       int    `json:"cache_timeout"` // seconds
	DefaultAction      string `json:"default_action"`
}

// Rule represents a moderation rule
type Rule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        RuleType          `json:"type"`
	Pattern     string            `json:"pattern"`
	Conditions  []Condition       `json:"conditions"`
	Actions     []Action          `json:"actions"`
	Severity    Severity          `json:"severity"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
}

// Policy represents a moderation policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	RuleSetIDs  []string          `json:"ruleset_ids"`
	Scope       PolicyScope       `json:"scope"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RuleSet represents a collection of rules
type RuleSet struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	RuleIDs     []string          `json:"rule_ids"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RuleType represents the type of rule
type RuleType string

const (
	RuleTypeText    RuleType = "text"
	RuleTypeImage   RuleType = "image"
	RuleTypeAudio   RuleType = "audio"
	RuleTypeVideo   RuleType = "video"
	RuleTypeUser    RuleType = "user"
	RuleTypeChannel RuleType = "channel"
)

// Severity levels
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// PolicyScope defines where a policy applies
type PolicyScope string

const (
	ScopeGlobal  PolicyScope = "global"
	ScopeChannel PolicyScope = "channel"
	ScopeUser    PolicyScope = "user"
	ScopeGroup   PolicyScope = "group"
)

// Condition represents a rule condition
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// Action represents a rule action
type Action struct {
	Type       ActionType        `json:"type"`
	Parameters map[string]string `json:"parameters"`
}

// ActionType represents the type of action
type ActionType string

const (
	ActionWarn   ActionType = "warn"
	ActionBlock  ActionType = "block"
	ActionDelete ActionType = "delete"
	ActionFlag   ActionType = "flag"
	ActionMute   ActionType = "mute"
	ActionBan    ActionType = "ban"
	ActionNotify ActionType = "notify"
	ActionLog    ActionType = "log"
)

// EvaluationContext contains context for rule evaluation
type EvaluationContext struct {
	ContentType string                 `json:"content_type"`
	UserID      int64                  `json:"user_id"`
	ChannelID   int64                  `json:"channel_id"`
	Content     string                 `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

// EvaluationResult contains the result of rule evaluation
type EvaluationResult struct {
	Matched      bool                   `json:"matched"`
	MatchedRules []string               `json:"matched_rules"`
	Actions      []Action               `json:"actions"`
	Severity     Severity               `json:"severity"`
	Confidence   float64                `json:"confidence"`
	Metadata     map[string]interface{} `json:"metadata"`
	ProcessedAt  time.Time              `json:"processed_at"`
	ProcessingMs int64                  `json:"processing_ms"`
}

// NewRulesEngine creates a new rules engine
func NewRulesEngine(config *Config) *RulesEngine {
	if config == nil {
		config = DefaultConfig()
	}

	engine := &RulesEngine{
		rules:    make(map[string]*Rule),
		policies: make(map[string]*Policy),
		rulesets: make(map[string]*RuleSet),
		logger:   logx.WithContext(context.Background()),
		config:   config,
	}

	// Initialize default rules
	engine.initializeDefaultRules()

	return engine
}

// DefaultConfig returns default rules engine configuration
func DefaultConfig() *Config {
	return &Config{
		EnableDynamicRules: true,
		MaxRulesPerSet:     100,
		CacheTimeout:       300,
		DefaultAction:      "warn",
	}
}

// EvaluateContent evaluates content against rules
func (re *RulesEngine) EvaluateContent(ctx context.Context, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	start := time.Now()

	result := &EvaluationResult{
		Matched:      false,
		MatchedRules: []string{},
		Actions:      []Action{},
		Severity:     SeverityLow,
		Confidence:   0.0,
		Metadata:     make(map[string]interface{}),
		ProcessedAt:  start,
	}

	re.mutex.RLock()
	defer re.mutex.RUnlock()

	// Evaluate all applicable rules
	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this content type
		if rule.Type != RuleType(evalCtx.ContentType) && rule.Type != "global" {
			continue
		}

		matched, confidence := re.evaluateRule(rule, evalCtx)
		if matched {
			result.Matched = true
			result.MatchedRules = append(result.MatchedRules, rule.ID)
			result.Actions = append(result.Actions, rule.Actions...)

			// Update severity to highest matched rule
			if rule.Severity == SeverityCritical ||
				(rule.Severity == SeverityHigh && result.Severity != SeverityCritical) ||
				(rule.Severity == SeverityMedium && result.Severity == SeverityLow) {
				result.Severity = rule.Severity
			}

			// Update confidence (take maximum)
			if confidence > result.Confidence {
				result.Confidence = confidence
			}
		}
	}

	result.ProcessingMs = time.Since(start).Milliseconds()
	return result, nil
}

// evaluateRule evaluates a single rule against content
func (re *RulesEngine) evaluateRule(rule *Rule, evalCtx *EvaluationContext) (bool, float64) {
	// Pattern matching
	if rule.Pattern != "" {
		matched, err := regexp.MatchString(rule.Pattern, evalCtx.Content)
		if err != nil {
			re.logger.Errorf("Invalid regex pattern in rule %s: %v", rule.ID, err)
			return false, 0.0
		}
		if matched {
			return true, 0.9
		}
	}

	// Condition evaluation
	for _, condition := range rule.Conditions {
		if !re.evaluateCondition(condition, evalCtx) {
			return false, 0.0
		}
	}

	// If we have conditions and they all passed, return true
	if len(rule.Conditions) > 0 {
		return true, 0.8
	}

	return false, 0.0
}

// evaluateCondition evaluates a single condition
func (re *RulesEngine) evaluateCondition(condition Condition, evalCtx *EvaluationContext) bool {
	var fieldValue interface{}

	// Get field value from context
	switch condition.Field {
	case "user_id":
		fieldValue = evalCtx.UserID
	case "channel_id":
		fieldValue = evalCtx.ChannelID
	case "content":
		fieldValue = evalCtx.Content
	case "content_length":
		fieldValue = len(evalCtx.Content)
	default:
		// Check metadata
		if val, exists := evalCtx.Metadata[condition.Field]; exists {
			fieldValue = val
		} else {
			return false
		}
	}

	// Evaluate based on operator
	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "not_equals":
		return fieldValue != condition.Value
	case "contains":
		if str, ok := fieldValue.(string); ok {
			if substr, ok := condition.Value.(string); ok {
				return contains(str, substr)
			}
		}
		return false
	case "greater_than":
		return compareNumbers(fieldValue, condition.Value, ">")
	case "less_than":
		return compareNumbers(fieldValue, condition.Value, "<")
	case "greater_equal":
		return compareNumbers(fieldValue, condition.Value, ">=")
	case "less_equal":
		return compareNumbers(fieldValue, condition.Value, "<=")
	default:
		return false
	}
}

// AddRule adds a new rule
func (re *RulesEngine) AddRule(rule *Rule) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	// Validate rule
	if err := re.validateRule(rule); err != nil {
		return err
	}

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	re.rules[rule.ID] = rule

	re.logger.Infof("Added rule: %s", rule.ID)
	return nil
}

// UpdateRule updates an existing rule
func (re *RulesEngine) UpdateRule(rule *Rule) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	if _, exists := re.rules[rule.ID]; !exists {
		return fmt.Errorf("rule %s not found", rule.ID)
	}

	// Validate rule
	if err := re.validateRule(rule); err != nil {
		return err
	}

	rule.UpdatedAt = time.Now()
	re.rules[rule.ID] = rule

	re.logger.Infof("Updated rule: %s", rule.ID)
	return nil
}

// DeleteRule deletes a rule
func (re *RulesEngine) DeleteRule(ruleID string) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	if _, exists := re.rules[ruleID]; !exists {
		return fmt.Errorf("rule %s not found", ruleID)
	}

	delete(re.rules, ruleID)
	re.logger.Infof("Deleted rule: %s", ruleID)
	return nil
}

// GetRule gets a rule by ID
func (re *RulesEngine) GetRule(ruleID string) (*Rule, error) {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	rule, exists := re.rules[ruleID]
	if !exists {
		return nil, fmt.Errorf("rule %s not found", ruleID)
	}

	return rule, nil
}

// ListRules lists all rules
func (re *RulesEngine) ListRules() []*Rule {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	rules := make([]*Rule, 0, len(re.rules))
	for _, rule := range re.rules {
		rules = append(rules, rule)
	}

	return rules
}

// validateRule validates a rule
func (re *RulesEngine) validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	if rule.Pattern != "" {
		_, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}
	return nil
}

// initializeDefaultRules sets up default moderation rules
func (re *RulesEngine) initializeDefaultRules() {
	defaultRules := []*Rule{
		{
			ID:          "profanity_filter",
			Name:        "Profanity Filter",
			Description: "Detects and blocks profanity",
			Type:        RuleTypeText,
			Pattern:     `(?i)\b(fuck|shit|damn|bitch)\b`,
			Actions: []Action{
				{Type: ActionWarn, Parameters: map[string]string{"reason": "profanity"}},
			},
			Severity:  SeverityMedium,
			Priority:  100,
			Enabled:   true,
			Metadata:  map[string]string{"category": "language"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
		},
		{
			ID:          "spam_detection",
			Name:        "Spam Detection",
			Description: "Detects spam content",
			Type:        RuleTypeText,
			Conditions: []Condition{
				{Field: "content_length", Operator: "greater_than", Value: 1000},
			},
			Actions: []Action{
				{Type: ActionFlag, Parameters: map[string]string{"reason": "potential_spam"}},
			},
			Severity:  SeverityLow,
			Priority:  50,
			Enabled:   true,
			Metadata:  map[string]string{"category": "spam"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
		},
	}

	for _, rule := range defaultRules {
		re.rules[rule.ID] = rule
	}
}

// Helper functions
func contains(text, substr string) bool {
	return len(text) >= len(substr) && findInString(text, substr)
}

func findInString(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func compareNumbers(a, b interface{}, op string) bool {
	// Simple number comparison - in production, this would be more robust
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)

	if !aOk || !bOk {
		return false
	}

	switch op {
	case ">":
		return aFloat > bFloat
	case "<":
		return aFloat < bFloat
	case ">=":
		return aFloat >= bFloat
	case "<=":
		return aFloat <= bFloat
	default:
		return false
	}
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	case float32:
		return float64(val), true
	default:
		return 0, false
	}
}
