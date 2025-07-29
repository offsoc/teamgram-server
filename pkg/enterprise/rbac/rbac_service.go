package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// RBACService provides role-based access control
type RBACService struct {
	config      *Config
	roles       map[string]*Role
	permissions map[string]*Permission
	policies    map[string]*Policy
	mutex       sync.RWMutex
	logger      logx.Logger
}

// Config for RBAC service
type Config struct {
	EnableHierarchicalRoles bool `json:"enable_hierarchical_roles"`
	EnableDynamicPermissions bool `json:"enable_dynamic_permissions"`
	EnableAuditLogging      bool `json:"enable_audit_logging"`
	CacheTimeout            int  `json:"cache_timeout"` // seconds
	MaxRolesPerUser         int  `json:"max_roles_per_user"`
}

// Role represents a role in the system
type Role struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Permissions []string          `json:"permissions"`
	ParentRoles []string          `json:"parent_roles"`
	ChildRoles  []string          `json:"child_roles"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
	IsActive    bool              `json:"is_active"`
}

// Permission represents a permission in the system
type Permission struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Scope       string            `json:"scope"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	IsActive    bool              `json:"is_active"`
}

// Policy represents an access policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Rules       []PolicyRule      `json:"rules"`
	Effect      PolicyEffect      `json:"effect"`
	Conditions  []Condition       `json:"conditions"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	IsActive    bool              `json:"is_active"`
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	Resource    string   `json:"resource"`
	Actions     []string `json:"actions"`
	Conditions  []string `json:"conditions"`
	Effect      PolicyEffect `json:"effect"`
}

// PolicyEffect represents the effect of a policy
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// Condition represents a condition for policy evaluation
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// UserRole represents a user's role assignment
type UserRole struct {
	UserID    int64     `json:"user_id"`
	RoleID    string    `json:"role_id"`
	Scope     string    `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	IsActive  bool      `json:"is_active"`
}

// AccessRequest represents an access request
type AccessRequest struct {
	UserID    int64                  `json:"user_id"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

// AccessResult represents the result of an access check
type AccessResult struct {
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason"`
	MatchedRole string                 `json:"matched_role"`
	MatchedPolicy string               `json:"matched_policy"`
	Permissions []string               `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
	ProcessedAt time.Time              `json:"processed_at"`
}

// NewRBACService creates a new RBAC service
func NewRBACService(config *Config) *RBACService {
	if config == nil {
		config = DefaultConfig()
	}

	service := &RBACService{
		config:      config,
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
		policies:    make(map[string]*Policy),
		logger:      logx.WithContext(context.Background()),
	}

	// Initialize default roles and permissions
	service.initializeDefaults()

	return service
}

// DefaultConfig returns default RBAC configuration
func DefaultConfig() *Config {
	return &Config{
		EnableHierarchicalRoles:  true,
		EnableDynamicPermissions: true,
		EnableAuditLogging:       true,
		CacheTimeout:             300,
		MaxRolesPerUser:          10,
	}
}

// CheckAccess checks if a user has access to a resource
func (rs *RBACService) CheckAccess(ctx context.Context, request *AccessRequest) (*AccessResult, error) {
	start := time.Now()
	
	result := &AccessResult{
		Allowed:     false,
		Reason:      "",
		Permissions: []string{},
		Metadata:    make(map[string]interface{}),
		ProcessedAt: start,
	}

	// Get user roles
	userRoles, err := rs.getUserRoles(request.UserID)
	if err != nil {
		result.Reason = fmt.Sprintf("Failed to get user roles: %v", err)
		return result, nil
	}

	if len(userRoles) == 0 {
		result.Reason = "User has no roles assigned"
		return result, nil
	}

	// Check each role for access
	for _, userRole := range userRoles {
		role, exists := rs.roles[userRole.RoleID]
		if !exists || !role.IsActive {
			continue
		}

		// Check if role has required permission
		hasAccess, matchedPermission := rs.checkRolePermission(role, request.Resource, request.Action)
		if hasAccess {
			result.Allowed = true
			result.MatchedRole = role.ID
			result.Reason = fmt.Sprintf("Access granted via role: %s", role.Name)
			result.Permissions = append(result.Permissions, matchedPermission)
			break
		}
	}

	// Check policies if no direct role access
	if !result.Allowed {
		policyResult := rs.checkPolicies(request, userRoles)
		if policyResult.Allowed {
			result.Allowed = true
			result.MatchedPolicy = policyResult.MatchedPolicy
			result.Reason = policyResult.Reason
		}
	}

	if !result.Allowed {
		result.Reason = "Access denied: insufficient permissions"
	}

	// Audit logging
	if rs.config.EnableAuditLogging {
		rs.logAccess(request, result)
	}

	return result, nil
}

// CreateRole creates a new role
func (rs *RBACService) CreateRole(ctx context.Context, role *Role) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if role.ID == "" {
		return fmt.Errorf("role ID cannot be empty")
	}

	if _, exists := rs.roles[role.ID]; exists {
		return fmt.Errorf("role %s already exists", role.ID)
	}

	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	role.IsActive = true

	rs.roles[role.ID] = role
	rs.logger.Infof("Created role: %s", role.ID)

	return nil
}

// UpdateRole updates an existing role
func (rs *RBACService) UpdateRole(ctx context.Context, role *Role) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if _, exists := rs.roles[role.ID]; !exists {
		return fmt.Errorf("role %s not found", role.ID)
	}

	role.UpdatedAt = time.Now()
	rs.roles[role.ID] = role
	rs.logger.Infof("Updated role: %s", role.ID)

	return nil
}

// DeleteRole deletes a role
func (rs *RBACService) DeleteRole(ctx context.Context, roleID string) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if _, exists := rs.roles[roleID]; !exists {
		return fmt.Errorf("role %s not found", roleID)
	}

	delete(rs.roles, roleID)
	rs.logger.Infof("Deleted role: %s", roleID)

	return nil
}

// CreatePermission creates a new permission
func (rs *RBACService) CreatePermission(ctx context.Context, permission *Permission) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if permission.ID == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	if _, exists := rs.permissions[permission.ID]; exists {
		return fmt.Errorf("permission %s already exists", permission.ID)
	}

	permission.CreatedAt = time.Now()
	permission.UpdatedAt = time.Now()
	permission.IsActive = true

	rs.permissions[permission.ID] = permission
	rs.logger.Infof("Created permission: %s", permission.ID)

	return nil
}

// AssignRoleToUser assigns a role to a user
func (rs *RBACService) AssignRoleToUser(ctx context.Context, userRole *UserRole) error {
	// Validate role exists
	rs.mutex.RLock()
	_, exists := rs.roles[userRole.RoleID]
	rs.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("role %s not found", userRole.RoleID)
	}

	userRole.CreatedAt = time.Now()
	userRole.IsActive = true

	// In a real implementation, this would be stored in database
	rs.logger.Infof("Assigned role %s to user %d", userRole.RoleID, userRole.UserID)

	return nil
}

// getUserRoles gets roles for a user (mock implementation)
func (rs *RBACService) getUserRoles(userID int64) ([]UserRole, error) {
	// Mock implementation - in production, this would query database
	return []UserRole{
		{
			UserID:    userID,
			RoleID:    "user",
			Scope:     "global",
			CreatedAt: time.Now(),
			IsActive:  true,
		},
	}, nil
}

// checkRolePermission checks if a role has permission for resource/action
func (rs *RBACService) checkRolePermission(role *Role, resource, action string) (bool, string) {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	for _, permissionID := range role.Permissions {
		permission, exists := rs.permissions[permissionID]
		if !exists || !permission.IsActive {
			continue
		}

		if rs.matchesPermission(permission, resource, action) {
			return true, permissionID
		}
	}

	// Check parent roles if hierarchical roles are enabled
	if rs.config.EnableHierarchicalRoles {
		for _, parentRoleID := range role.ParentRoles {
			parentRole, exists := rs.roles[parentRoleID]
			if exists && parentRole.IsActive {
				if hasAccess, permissionID := rs.checkRolePermission(parentRole, resource, action); hasAccess {
					return true, permissionID
				}
			}
		}
	}

	return false, ""
}

// matchesPermission checks if a permission matches resource/action
func (rs *RBACService) matchesPermission(permission *Permission, resource, action string) bool {
	// Simple matching - in production, this would support wildcards and patterns
	return (permission.Resource == "*" || permission.Resource == resource) &&
		   (permission.Action == "*" || permission.Action == action)
}

// checkPolicies checks policies for access
func (rs *RBACService) checkPolicies(request *AccessRequest, userRoles []UserRole) *AccessResult {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	result := &AccessResult{
		Allowed: false,
		Reason:  "No matching policy",
	}

	for _, policy := range rs.policies {
		if !policy.IsActive {
			continue
		}

		if rs.evaluatePolicy(policy, request, userRoles) {
			result.Allowed = (policy.Effect == PolicyEffectAllow)
			result.MatchedPolicy = policy.ID
			result.Reason = fmt.Sprintf("Policy %s: %s", policy.Name, policy.Effect)
			
			// If deny policy matches, immediately return
			if policy.Effect == PolicyEffectDeny {
				result.Allowed = false
				return result
			}
		}
	}

	return result
}

// evaluatePolicy evaluates a policy against a request
func (rs *RBACService) evaluatePolicy(policy *Policy, request *AccessRequest, userRoles []UserRole) bool {
	// Simple policy evaluation - in production, this would be more sophisticated
	for _, rule := range policy.Rules {
		if (rule.Resource == "*" || rule.Resource == request.Resource) {
			for _, action := range rule.Actions {
				if action == "*" || action == request.Action {
					return true
				}
			}
		}
	}
	return false
}

// logAccess logs access attempts for audit
func (rs *RBACService) logAccess(request *AccessRequest, result *AccessResult) {
	rs.logger.Infof("Access attempt: user=%d, resource=%s, action=%s, allowed=%t, reason=%s",
		request.UserID, request.Resource, request.Action, result.Allowed, result.Reason)
}

// initializeDefaults initializes default roles and permissions
func (rs *RBACService) initializeDefaults() {
	// Default permissions
	defaultPermissions := []*Permission{
		{
			ID:          "read_messages",
			Name:        "Read Messages",
			Description: "Permission to read messages",
			Resource:    "messages",
			Action:      "read",
			Scope:       "global",
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          "write_messages",
			Name:        "Write Messages",
			Description: "Permission to write messages",
			Resource:    "messages",
			Action:      "write",
			Scope:       "global",
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          "admin_all",
			Name:        "Admin All",
			Description: "Full administrative access",
			Resource:    "*",
			Action:      "*",
			Scope:       "global",
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, permission := range defaultPermissions {
		rs.permissions[permission.ID] = permission
	}

	// Default roles
	defaultRoles := []*Role{
		{
			ID:          "user",
			Name:        "User",
			Description: "Basic user role",
			Permissions: []string{"read_messages", "write_messages"},
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          "admin",
			Name:        "Administrator",
			Description: "Administrator role",
			Permissions: []string{"admin_all"},
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, role := range defaultRoles {
		rs.roles[role.ID] = role
	}
}

// GetRole gets a role by ID
func (rs *RBACService) GetRole(roleID string) (*Role, error) {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	role, exists := rs.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}

	return role, nil
}

// ListRoles lists all roles
func (rs *RBACService) ListRoles() []*Role {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	roles := make([]*Role, 0, len(rs.roles))
	for _, role := range rs.roles {
		roles = append(roles, role)
	}

	return roles
}

// GetPermission gets a permission by ID
func (rs *RBACService) GetPermission(permissionID string) (*Permission, error) {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	permission, exists := rs.permissions[permissionID]
	if !exists {
		return nil, fmt.Errorf("permission %s not found", permissionID)
	}

	return permission, nil
}

// ListPermissions lists all permissions
func (rs *RBACService) ListPermissions() []*Permission {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	permissions := make([]*Permission, 0, len(rs.permissions))
	for _, permission := range rs.permissions {
		permissions = append(permissions, permission)
	}

	return permissions
}
