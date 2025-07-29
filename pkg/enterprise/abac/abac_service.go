package abac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// ABACService provides attribute-based access control
type ABACService struct {
	config     *Config
	policies   map[string]*Policy
	attributes map[string]*AttributeDefinition
	mutex      sync.RWMutex
	logger     logx.Logger
}

// Config for ABAC service
type Config struct {
	EnableDynamicPolicies   bool `json:"enable_dynamic_policies"`
	EnableAttributeInheritance bool `json:"enable_attribute_inheritance"`
	EnablePolicyConflictResolution bool `json:"enable_policy_conflict_resolution"`
	CacheTimeout            int  `json:"cache_timeout"` // seconds
	MaxPolicyEvaluations    int  `json:"max_policy_evaluations"`
	DefaultDecision         Decision `json:"default_decision"`
}

// Policy represents an ABAC policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Target      Target            `json:"target"`
	Rules       []Rule            `json:"rules"`
	Effect      Decision          `json:"effect"`
	Priority    int               `json:"priority"`
	Conditions  []Condition       `json:"conditions"`
	Obligations []Obligation      `json:"obligations"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
	IsActive    bool              `json:"is_active"`
}

// Target defines what the policy applies to
type Target struct {
	Subjects  []AttributeMatch `json:"subjects"`
	Resources []AttributeMatch `json:"resources"`
	Actions   []AttributeMatch `json:"actions"`
	Environment []AttributeMatch `json:"environment"`
}

// Rule represents a rule within a policy
type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Condition   Condition   `json:"condition"`
	Effect      Decision    `json:"effect"`
	Priority    int         `json:"priority"`
}

// Condition represents a condition for evaluation
type Condition struct {
	Type       ConditionType `json:"type"`
	Expression string        `json:"expression"`
	Attributes []AttributeReference `json:"attributes"`
	Operator   Operator      `json:"operator"`
	Value      interface{}   `json:"value"`
	Children   []Condition   `json:"children,omitempty"`
}

// AttributeMatch represents an attribute matching criteria
type AttributeMatch struct {
	AttributeID string      `json:"attribute_id"`
	Operator    Operator    `json:"operator"`
	Value       interface{} `json:"value"`
}

// AttributeReference references an attribute in conditions
type AttributeReference struct {
	Category    AttributeCategory `json:"category"`
	AttributeID string           `json:"attribute_id"`
	DataType    DataType         `json:"data_type"`
}

// AttributeDefinition defines an attribute
type AttributeDefinition struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    AttributeCategory `json:"category"`
	DataType    DataType          `json:"data_type"`
	IsMultiValue bool             `json:"is_multi_value"`
	DefaultValue interface{}      `json:"default_value"`
	Constraints []Constraint      `json:"constraints"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	IsActive    bool              `json:"is_active"`
}

// Constraint represents a constraint on attribute values
type Constraint struct {
	Type        ConstraintType `json:"type"`
	Value       interface{}    `json:"value"`
	Description string         `json:"description"`
}

// Obligation represents an obligation that must be fulfilled
type Obligation struct {
	ID          string                 `json:"id"`
	Type        ObligationType         `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Fulfillment FulfillmentType        `json:"fulfillment"`
}

// AccessRequest represents an access request for ABAC evaluation
type AccessRequest struct {
	Subject     Subject                `json:"subject"`
	Resource    Resource               `json:"resource"`
	Action      Action                 `json:"action"`
	Environment Environment            `json:"environment"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Subject represents the subject requesting access
type Subject struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Resource represents the resource being accessed
type Resource struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Action represents the action being performed
type Action struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Environment represents the environment context
type Environment struct {
	Attributes map[string]interface{} `json:"attributes"`
}

// AccessResult represents the result of access evaluation
type AccessResult struct {
	Decision     Decision               `json:"decision"`
	Reason       string                 `json:"reason"`
	MatchedPolicies []string            `json:"matched_policies"`
	Obligations  []Obligation           `json:"obligations"`
	Advice       []string               `json:"advice"`
	Confidence   float64                `json:"confidence"`
	ProcessedAt  time.Time              `json:"processed_at"`
	ProcessingMs int64                  `json:"processing_ms"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Enums and types
type Decision string
const (
	DecisionPermit Decision = "permit"
	DecisionDeny   Decision = "deny"
	DecisionNotApplicable Decision = "not_applicable"
	DecisionIndeterminate Decision = "indeterminate"
)

type ConditionType string
const (
	ConditionTypeSimple    ConditionType = "simple"
	ConditionTypeComplex   ConditionType = "complex"
	ConditionTypeLogical   ConditionType = "logical"
)

type Operator string
const (
	OperatorEquals         Operator = "equals"
	OperatorNotEquals      Operator = "not_equals"
	OperatorGreaterThan    Operator = "greater_than"
	OperatorLessThan       Operator = "less_than"
	OperatorGreaterEqual   Operator = "greater_equal"
	OperatorLessEqual      Operator = "less_equal"
	OperatorContains       Operator = "contains"
	OperatorNotContains    Operator = "not_contains"
	OperatorIn             Operator = "in"
	OperatorNotIn          Operator = "not_in"
	OperatorMatches        Operator = "matches"
	OperatorAnd            Operator = "and"
	OperatorOr             Operator = "or"
	OperatorNot            Operator = "not"
)

type AttributeCategory string
const (
	AttributeCategorySubject     AttributeCategory = "subject"
	AttributeCategoryResource    AttributeCategory = "resource"
	AttributeCategoryAction      AttributeCategory = "action"
	AttributeCategoryEnvironment AttributeCategory = "environment"
)

type DataType string
const (
	DataTypeString   DataType = "string"
	DataTypeInteger  DataType = "integer"
	DataTypeFloat    DataType = "float"
	DataTypeBoolean  DataType = "boolean"
	DataTypeDateTime DataType = "datetime"
	DataTypeArray    DataType = "array"
	DataTypeObject   DataType = "object"
)

type ConstraintType string
const (
	ConstraintTypeRange      ConstraintType = "range"
	ConstraintTypeEnum       ConstraintType = "enum"
	ConstraintTypePattern    ConstraintType = "pattern"
	ConstraintTypeLength     ConstraintType = "length"
	ConstraintTypeRequired   ConstraintType = "required"
)

type ObligationType string
const (
	ObligationTypeLog        ObligationType = "log"
	ObligationTypeNotify     ObligationType = "notify"
	ObligationTypeEncrypt    ObligationType = "encrypt"
	ObligationTypeAudit      ObligationType = "audit"
	ObligationTypeTransform  ObligationType = "transform"
)

type FulfillmentType string
const (
	FulfillmentTypeBefore FulfillmentType = "before"
	FulfillmentTypeAfter  FulfillmentType = "after"
	FulfillmentTypeDuring FulfillmentType = "during"
)

// NewABACService creates a new ABAC service
func NewABACService(config *Config) *ABACService {
	if config == nil {
		config = DefaultConfig()
	}

	service := &ABACService{
		config:     config,
		policies:   make(map[string]*Policy),
		attributes: make(map[string]*AttributeDefinition),
		logger:     logx.WithContext(context.Background()),
	}

	// Initialize default attributes and policies
	service.initializeDefaults()

	return service
}

// DefaultConfig returns default ABAC configuration
func DefaultConfig() *Config {
	return &Config{
		EnableDynamicPolicies:          true,
		EnableAttributeInheritance:     true,
		EnablePolicyConflictResolution: true,
		CacheTimeout:                   300,
		MaxPolicyEvaluations:           100,
		DefaultDecision:                DecisionDeny,
	}
}

// EvaluateAccess evaluates an access request against ABAC policies
func (abs *ABACService) EvaluateAccess(ctx context.Context, request *AccessRequest) (*AccessResult, error) {
	start := time.Now()
	
	result := &AccessResult{
		Decision:        abs.config.DefaultDecision,
		Reason:          "No applicable policies",
		MatchedPolicies: []string{},
		Obligations:     []Obligation{},
		Advice:          []string{},
		Confidence:      0.0,
		ProcessedAt:     start,
		Metadata:        make(map[string]interface{}),
	}

	// Get applicable policies
	applicablePolicies := abs.getApplicablePolicies(request)
	if len(applicablePolicies) == 0 {
		result.Decision = DecisionNotApplicable
		result.Reason = "No applicable policies found"
		result.ProcessingMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Evaluate policies
	decisions := make([]PolicyDecision, 0)
	for _, policy := range applicablePolicies {
		decision, err := abs.evaluatePolicy(policy, request)
		if err != nil {
			abs.logger.Errorf("Error evaluating policy %s: %v", policy.ID, err)
			continue
		}
		decisions = append(decisions, decision)
		result.MatchedPolicies = append(result.MatchedPolicies, policy.ID)
	}

	// Combine decisions
	finalDecision := abs.combineDecisions(decisions)
	result.Decision = finalDecision.Decision
	result.Reason = finalDecision.Reason
	result.Obligations = finalDecision.Obligations
	result.Confidence = finalDecision.Confidence

	// Add advice based on decision
	if result.Decision == DecisionDeny {
		result.Advice = append(result.Advice, "Access denied by policy")
	} else if result.Decision == DecisionPermit {
		result.Advice = append(result.Advice, "Access granted")
	}

	result.ProcessingMs = time.Since(start).Milliseconds()
	return result, nil
}

// PolicyDecision represents a policy evaluation decision
type PolicyDecision struct {
	PolicyID    string       `json:"policy_id"`
	Decision    Decision     `json:"decision"`
	Reason      string       `json:"reason"`
	Obligations []Obligation `json:"obligations"`
	Confidence  float64      `json:"confidence"`
	Priority    int          `json:"priority"`
}

// getApplicablePolicies finds policies applicable to the request
func (abs *ABACService) getApplicablePolicies(request *AccessRequest) []*Policy {
	abs.mutex.RLock()
	defer abs.mutex.RUnlock()

	var applicable []*Policy
	for _, policy := range abs.policies {
		if !policy.IsActive {
			continue
		}

		if abs.isPolicyApplicable(policy, request) {
			applicable = append(applicable, policy)
		}
	}

	return applicable
}

// isPolicyApplicable checks if a policy is applicable to the request
func (abs *ABACService) isPolicyApplicable(policy *Policy, request *AccessRequest) bool {
	// Check target matches
	target := policy.Target

	// Check subject matches
	if len(target.Subjects) > 0 {
		if !abs.matchesAttributes(target.Subjects, request.Subject.Attributes) {
			return false
		}
	}

	// Check resource matches
	if len(target.Resources) > 0 {
		if !abs.matchesAttributes(target.Resources, request.Resource.Attributes) {
			return false
		}
	}

	// Check action matches
	if len(target.Actions) > 0 {
		if !abs.matchesAttributes(target.Actions, request.Action.Attributes) {
			return false
		}
	}

	// Check environment matches
	if len(target.Environment) > 0 {
		if !abs.matchesAttributes(target.Environment, request.Environment.Attributes) {
			return false
		}
	}

	return true
}

// matchesAttributes checks if attributes match the criteria
func (abs *ABACService) matchesAttributes(matches []AttributeMatch, attributes map[string]interface{}) bool {
	for _, match := range matches {
		value, exists := attributes[match.AttributeID]
		if !exists {
			return false
		}

		if !abs.evaluateOperator(match.Operator, value, match.Value) {
			return false
		}
	}
	return true
}

// evaluatePolicy evaluates a single policy
func (abs *ABACService) evaluatePolicy(policy *Policy, request *AccessRequest) (PolicyDecision, error) {
	decision := PolicyDecision{
		PolicyID:    policy.ID,
		Decision:    policy.Effect,
		Reason:      fmt.Sprintf("Policy %s evaluated", policy.Name),
		Obligations: policy.Obligations,
		Confidence:  0.8,
		Priority:    policy.Priority,
	}

	// Evaluate policy conditions
	if len(policy.Conditions) > 0 {
		conditionMet := abs.evaluateConditions(policy.Conditions, request)
		if !conditionMet {
			decision.Decision = DecisionNotApplicable
			decision.Reason = "Policy conditions not met"
			return decision, nil
		}
	}

	// Evaluate rules
	if len(policy.Rules) > 0 {
		ruleDecision := abs.evaluateRules(policy.Rules, request)
		decision.Decision = ruleDecision
	}

	return decision, nil
}

// evaluateConditions evaluates policy conditions
func (abs *ABACService) evaluateConditions(conditions []Condition, request *AccessRequest) bool {
	for _, condition := range conditions {
		if !abs.evaluateCondition(condition, request) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (abs *ABACService) evaluateCondition(condition Condition, request *AccessRequest) bool {
	switch condition.Type {
	case ConditionTypeSimple:
		return abs.evaluateSimpleCondition(condition, request)
	case ConditionTypeLogical:
		return abs.evaluateLogicalCondition(condition, request)
	default:
		return false
	}
}

// evaluateSimpleCondition evaluates a simple condition
func (abs *ABACService) evaluateSimpleCondition(condition Condition, request *AccessRequest) bool {
	// Get attribute value based on category
	var value interface{}
	for _, attr := range condition.Attributes {
		switch attr.Category {
		case AttributeCategorySubject:
			value = request.Subject.Attributes[attr.AttributeID]
		case AttributeCategoryResource:
			value = request.Resource.Attributes[attr.AttributeID]
		case AttributeCategoryAction:
			value = request.Action.Attributes[attr.AttributeID]
		case AttributeCategoryEnvironment:
			value = request.Environment.Attributes[attr.AttributeID]
		}
		break // Use first attribute for simple conditions
	}

	return abs.evaluateOperator(condition.Operator, value, condition.Value)
}

// evaluateLogicalCondition evaluates a logical condition
func (abs *ABACService) evaluateLogicalCondition(condition Condition, request *AccessRequest) bool {
	switch condition.Operator {
	case OperatorAnd:
		for _, child := range condition.Children {
			if !abs.evaluateCondition(child, request) {
				return false
			}
		}
		return true
	case OperatorOr:
		for _, child := range condition.Children {
			if abs.evaluateCondition(child, request) {
				return true
			}
		}
		return false
	case OperatorNot:
		if len(condition.Children) > 0 {
			return !abs.evaluateCondition(condition.Children[0], request)
		}
		return false
	default:
		return false
	}
}

// evaluateRules evaluates policy rules
func (abs *ABACService) evaluateRules(rules []Rule, request *AccessRequest) Decision {
	for _, rule := range rules {
		if abs.evaluateCondition(rule.Condition, request) {
			return rule.Effect
		}
	}
	return DecisionNotApplicable
}

// evaluateOperator evaluates an operator
func (abs *ABACService) evaluateOperator(operator Operator, left, right interface{}) bool {
	switch operator {
	case OperatorEquals:
		return left == right
	case OperatorNotEquals:
		return left != right
	case OperatorGreaterThan:
		return compareValues(left, right) > 0
	case OperatorLessThan:
		return compareValues(left, right) < 0
	case OperatorGreaterEqual:
		return compareValues(left, right) >= 0
	case OperatorLessEqual:
		return compareValues(left, right) <= 0
	case OperatorContains:
		return containsValue(left, right)
	default:
		return false
	}
}

// combineDecisions combines multiple policy decisions
func (abs *ABACService) combineDecisions(decisions []PolicyDecision) PolicyDecision {
	if len(decisions) == 0 {
		return PolicyDecision{
			Decision:   abs.config.DefaultDecision,
			Reason:     "No decisions to combine",
			Confidence: 0.0,
		}
	}

	// Simple combining algorithm: deny overrides
	for _, decision := range decisions {
		if decision.Decision == DecisionDeny {
			return decision
		}
	}

	// If no deny, return first permit
	for _, decision := range decisions {
		if decision.Decision == DecisionPermit {
			return decision
		}
	}

	// Default to first decision
	return decisions[0]
}

// Helper functions
func compareValues(left, right interface{}) int {
	// Simple comparison - in production, this would handle different types
	if leftStr, ok := left.(string); ok {
		if rightStr, ok := right.(string); ok {
			if leftStr > rightStr {
				return 1
			} else if leftStr < rightStr {
				return -1
			}
			return 0
		}
	}
	return 0
}

func containsValue(container, value interface{}) bool {
	// Simple contains check - in production, this would handle different types
	if containerStr, ok := container.(string); ok {
		if valueStr, ok := value.(string); ok {
			return len(containerStr) >= len(valueStr) && 
				   findInString(containerStr, valueStr)
		}
	}
	return false
}

func findInString(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// initializeDefaults initializes default attributes and policies
func (abs *ABACService) initializeDefaults() {
	// Default attribute definitions
	defaultAttributes := []*AttributeDefinition{
		{
			ID:          "user.role",
			Name:        "User Role",
			Description: "Role of the user",
			Category:    AttributeCategorySubject,
			DataType:    DataTypeString,
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          "resource.type",
			Name:        "Resource Type",
			Description: "Type of the resource",
			Category:    AttributeCategoryResource,
			DataType:    DataTypeString,
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, attr := range defaultAttributes {
		abs.attributes[attr.ID] = attr
	}

	// Default policies
	defaultPolicies := []*Policy{
		{
			ID:          "admin_access",
			Name:        "Admin Access Policy",
			Description: "Allows admin users full access",
			Version:     "1.0",
			Target: Target{
				Subjects: []AttributeMatch{
					{AttributeID: "user.role", Operator: OperatorEquals, Value: "admin"},
				},
			},
			Effect:    DecisionPermit,
			Priority:  100,
			CreatedAt: time.Now(),
			IsActive:  true,
		},
	}

	for _, policy := range defaultPolicies {
		abs.policies[policy.ID] = policy
	}
}

// CreatePolicy creates a new ABAC policy
func (abs *ABACService) CreatePolicy(ctx context.Context, policy *Policy) error {
	abs.mutex.Lock()
	defer abs.mutex.Unlock()

	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	if _, exists := abs.policies[policy.ID]; exists {
		return fmt.Errorf("policy %s already exists", policy.ID)
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.IsActive = true

	abs.policies[policy.ID] = policy
	abs.logger.Infof("Created ABAC policy: %s", policy.ID)

	return nil
}

// GetPolicy gets a policy by ID
func (abs *ABACService) GetPolicy(policyID string) (*Policy, error) {
	abs.mutex.RLock()
	defer abs.mutex.RUnlock()

	policy, exists := abs.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	return policy, nil
}

// ListPolicies lists all policies
func (abs *ABACService) ListPolicies() []*Policy {
	abs.mutex.RLock()
	defer abs.mutex.RUnlock()

	policies := make([]*Policy, 0, len(abs.policies))
	for _, policy := range abs.policies {
		policies = append(policies, policy)
	}

	return policies
}
