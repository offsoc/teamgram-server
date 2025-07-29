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

package supergroup

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Manager handles supergroup operations for up to 2 million members
type Manager struct {
	config             *Config
	memberManager      *MemberManager
	permissionManager  *PermissionManager
	shardManager       *ShardManager
	roleManager        *RoleManager
	inviteManager      *InviteManager
	performanceMonitor *PerformanceMonitor
	metrics            *SupergroupMetrics
	mutex              sync.RWMutex
	logger             logx.Logger
}

// Config represents supergroup configuration
type Config struct {
	// Scale settings
	MaxMembers         int `json:"max_members"`
	ShardCount         int `json:"shard_count"`
	MemberQueryTimeout int `json:"member_query_timeout_ms"`
	CreationTimeout    int `json:"creation_timeout_ms"`

	// Performance settings
	MaxConcurrentOps int           `json:"max_concurrent_ops"`
	CacheSize        int64         `json:"cache_size"`
	CacheExpiry      time.Duration `json:"cache_expiry"`

	// Sharding settings
	HashFunction      string `json:"hash_function"`
	ReplicationFactor int    `json:"replication_factor"`
	ConsistencyLevel  string `json:"consistency_level"`

	// Permission settings
	DefaultRoles        []string `json:"default_roles"`
	CustomRoleLimit     int      `json:"custom_role_limit"`
	PermissionCacheSize int      `json:"permission_cache_size"`
}

// MemberManager handles distributed member management
type MemberManager struct {
	memberShards   map[int]*MemberShard `json:"member_shards"`
	consistentHash *ConsistentHash      `json:"-"`
	memberCache    *MemberCache         `json:"-"`
	memberIndex    *MemberIndex         `json:"-"`
	memberMetrics  *MemberMetrics       `json:"member_metrics"`
	mutex          sync.RWMutex
}

// PermissionManager handles role-based permissions
type PermissionManager struct {
	roleDefinitions   map[string]*Role               `json:"role_definitions"`
	userRoles         map[int64]map[string]*UserRole `json:"user_roles"`
	permissionCache   *PermissionCache               `json:"-"`
	roleHierarchy     *RoleHierarchy                 `json:"-"`
	permissionMetrics *PermissionMetrics             `json:"permission_metrics"`
	mutex             sync.RWMutex
}

// ShardManager handles consistent hashing and sharding
type ShardManager struct {
	shards             map[int]*Shard      `json:"shards"`
	hashRing           *HashRing           `json:"-"`
	replicationManager *ReplicationManager `json:"-"`
	shardMetrics       *ShardMetrics       `json:"shard_metrics"`
	mutex              sync.RWMutex
}

// Supporting types
type Supergroup struct {
	ID           int64              `json:"id"`
	Title        string             `json:"title"`
	About        string             `json:"about"`
	Photo        *GroupPhoto        `json:"photo"`
	MemberCount  int                `json:"member_count"`
	MaxMembers   int                `json:"max_members"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
	CreatorID    int64              `json:"creator_id"`
	AdminCount   int                `json:"admin_count"`
	IsPublic     bool               `json:"is_public"`
	Username     string             `json:"username"`
	InviteLink   string             `json:"invite_link"`
	Settings     *GroupSettings     `json:"settings"`
	Restrictions *GroupRestrictions `json:"restrictions"`
}

type Member struct {
	UserID      int64     `json:"user_id"`
	GroupID     int64     `json:"group_id"`
	JoinedAt    time.Time `json:"joined_at"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
	InvitedBy   int64     `json:"invited_by"`
	IsActive    bool      `json:"is_active"`
	LastSeen    time.Time `json:"last_seen"`
	ShardID     int       `json:"shard_id"`
}

type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Priority    int          `json:"priority"`
	IsCustom    bool         `json:"is_custom"`
	CreatedBy   int64        `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	Color       string       `json:"color"`
	Badge       string       `json:"badge"`
}

type Permission string

const (
	PermissionSendMessages     Permission = "send_messages"
	PermissionSendMedia        Permission = "send_media"
	PermissionSendStickers     Permission = "send_stickers"
	PermissionSendPolls        Permission = "send_polls"
	PermissionAddUsers         Permission = "add_users"
	PermissionPinMessages      Permission = "pin_messages"
	PermissionDeleteMessages   Permission = "delete_messages"
	PermissionBanUsers         Permission = "ban_users"
	PermissionChangeInfo       Permission = "change_info"
	PermissionManageRoles      Permission = "manage_roles"
	PermissionManageInvites    Permission = "manage_invites"
	PermissionViewMembers      Permission = "view_members"
	PermissionManageVoiceChats Permission = "manage_voice_chats"
)

type UserRole struct {
	UserID     int64      `json:"user_id"`
	GroupID    int64      `json:"group_id"`
	RoleID     string     `json:"role_id"`
	AssignedBy int64      `json:"assigned_by"`
	AssignedAt time.Time  `json:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	IsActive   bool       `json:"is_active"`
}

type MemberShard struct {
	ID          int               `json:"id"`
	Members     map[int64]*Member `json:"members"`
	MemberCount int               `json:"member_count"`
	LastUpdate  time.Time         `json:"last_update"`
	IsHealthy   bool              `json:"is_healthy"`
}

type GroupPhoto struct {
	PhotoID     int64     `json:"photo_id"`
	SmallFileID string    `json:"small_file_id"`
	BigFileID   string    `json:"big_file_id"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

type GroupSettings struct {
	AllowInvites    bool `json:"allow_invites"`
	AllowPinning    bool `json:"allow_pinning"`
	AllowPolls      bool `json:"allow_polls"`
	AllowForwarding bool `json:"allow_forwarding"`
	SlowModeDelay   int  `json:"slow_mode_delay"`
	MessageTTL      int  `json:"message_ttl"`
	RequireApproval bool `json:"require_approval"`
}

type GroupRestrictions struct {
	RestrictedUntil       time.Time `json:"restricted_until"`
	CanSendMessages       bool      `json:"can_send_messages"`
	CanSendMedia          bool      `json:"can_send_media"`
	CanSendOther          bool      `json:"can_send_other"`
	CanAddWebPagePreviews bool      `json:"can_add_web_page_previews"`
}

type SupergroupMetrics struct {
	TotalGroups         int64         `json:"total_groups"`
	TotalMembers        int64         `json:"total_members"`
	AverageGroupSize    float64       `json:"average_group_size"`
	LargestGroupSize    int           `json:"largest_group_size"`
	AverageCreationTime time.Duration `json:"average_creation_time"`
	AverageQueryTime    time.Duration `json:"average_query_time"`
	SuccessRate         float64       `json:"success_rate"`
	StartTime           time.Time     `json:"start_time"`
	LastUpdate          time.Time     `json:"last_update"`
}

// Request and Response types
type CreateSupergroupRequest struct {
	Title     string         `json:"title"`
	About     string         `json:"about"`
	Photo     *GroupPhoto    `json:"photo"`
	CreatorID int64          `json:"creator_id"`
	IsPublic  bool           `json:"is_public"`
	Username  string         `json:"username"`
	Settings  *GroupSettings `json:"settings"`
}

type QueryMembersRequest struct {
	GroupID   int64  `json:"group_id"`
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
	Filter    string `json:"filter"`
	SortBy    string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

type QueryMembersResponse struct {
	Members    []*Member     `json:"members"`
	TotalCount int           `json:"total_count"`
	HasMore    bool          `json:"has_more"`
	QueryTime  time.Duration `json:"query_time"`
}

type InviteMembersRequest struct {
	GroupID   int64   `json:"group_id"`
	UserIDs   []int64 `json:"user_ids"`
	InviterID int64   `json:"inviter_id"`
	Message   string  `json:"message"`
}

type InviteMembersResponse struct {
	SuccessfulInvites []int64       `json:"successful_invites"`
	FailedInvites     []int64       `json:"failed_invites"`
	InviteTime        time.Duration `json:"invite_time"`
}

type BatchInviteResult struct {
	SuccessfulInvites []int64 `json:"successful_invites"`
	FailedInvites     []int64 `json:"failed_invites"`
}

// Stub types for complex components
type RoleManager struct{}
type InviteManager struct{}
type PerformanceMonitor struct{}
type ConsistentHash struct{}
type MemberCache struct{}
type MemberIndex struct{}
type MemberMetrics struct{}
type PermissionCache struct{}
type RoleHierarchy struct{}
type PermissionMetrics struct{}
type Shard struct{}
type HashRing struct{}
type ReplicationManager struct{}
type ShardMetrics struct{}

// NewManager creates a new supergroup manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	manager := &Manager{
		config: config,
		metrics: &SupergroupMetrics{
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize member manager
	manager.memberManager = &MemberManager{
		memberShards:   make(map[int]*MemberShard),
		consistentHash: &ConsistentHash{},
		memberCache:    &MemberCache{},
		memberIndex:    &MemberIndex{},
		memberMetrics:  &MemberMetrics{},
	}
	manager.initializeMemberShards()

	// Initialize permission manager
	manager.permissionManager = &PermissionManager{
		roleDefinitions:   make(map[string]*Role),
		userRoles:         make(map[int64]map[string]*UserRole),
		permissionCache:   &PermissionCache{},
		roleHierarchy:     &RoleHierarchy{},
		permissionMetrics: &PermissionMetrics{},
	}
	manager.initializeDefaultRoles()

	// Initialize shard manager
	manager.shardManager = &ShardManager{
		shards:             make(map[int]*Shard),
		hashRing:           &HashRing{},
		replicationManager: &ReplicationManager{},
		shardMetrics:       &ShardMetrics{},
	}
	manager.initializeShards()

	// Initialize role manager
	manager.roleManager = &RoleManager{}

	// Initialize invite manager
	manager.inviteManager = &InviteManager{}

	// Initialize performance monitor
	manager.performanceMonitor = &PerformanceMonitor{}

	return manager, nil
}

// CreateSupergroup creates a new supergroup with up to 2 million members
func (m *Manager) CreateSupergroup(ctx context.Context, req *CreateSupergroupRequest) (*Supergroup, error) {
	startTime := time.Now()

	m.logger.Infof("Creating supergroup: title=%s, creator=%d", req.Title, req.CreatorID)

	// Validate request
	if err := m.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid create request: %w", err)
	}

	// Generate group ID
	groupID := m.generateGroupID()

	// Create supergroup
	supergroup := &Supergroup{
		ID:           groupID,
		Title:        req.Title,
		About:        req.About,
		Photo:        req.Photo,
		MemberCount:  1, // Creator is first member
		MaxMembers:   m.config.MaxMembers,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		CreatorID:    req.CreatorID,
		AdminCount:   1,
		IsPublic:     req.IsPublic,
		Username:     req.Username,
		Settings:     req.Settings,
		Restrictions: &GroupRestrictions{},
	}

	// Generate invite link
	supergroup.InviteLink = m.generateInviteLink(groupID)

	// Add creator as first member with admin role
	// Convert permissions to strings
	permissions := m.getAllPermissions()
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = string(perm)
	}

	creatorMember := &Member{
		UserID:      req.CreatorID,
		GroupID:     groupID,
		JoinedAt:    time.Now(),
		Role:        "creator",
		Permissions: permissionStrings,
		InvitedBy:   req.CreatorID,
		IsActive:    true,
		LastSeen:    time.Now(),
		ShardID:     m.calculateShardID(req.CreatorID),
	}

	// Add member to shard
	err := m.memberManager.AddMember(ctx, creatorMember)
	if err != nil {
		return nil, fmt.Errorf("failed to add creator member: %w", err)
	}

	// Store supergroup
	err = m.storeSupergroup(ctx, supergroup)
	if err != nil {
		return nil, fmt.Errorf("failed to store supergroup: %w", err)
	}

	// Update metrics
	creationTime := time.Since(startTime)
	m.updateCreationMetrics(creationTime, true)

	// Verify creation time requirement (<10 seconds)
	if creationTime > 10*time.Second {
		m.logger.Errorf("Supergroup creation exceeded 10 seconds: %v", creationTime)
	}

	m.logger.Infof("Supergroup created successfully: ID=%d, creation_time=%v", groupID, creationTime)

	return supergroup, nil
}

// QueryMembers queries members with pagination and filtering
func (m *Manager) QueryMembers(ctx context.Context, req *QueryMembersRequest) (*QueryMembersResponse, error) {
	startTime := time.Now()

	m.logger.Infof("Querying members: group=%d, limit=%d, offset=%d", req.GroupID, req.Limit, req.Offset)

	// Validate request
	if err := m.validateQueryRequest(req); err != nil {
		return nil, fmt.Errorf("invalid query request: %w", err)
	}

	// Query members from shards
	members, totalCount, err := m.memberManager.QueryMembers(ctx, req)
	if err != nil {
		m.updateQueryMetrics(time.Since(startTime), false)
		return nil, fmt.Errorf("failed to query members: %w", err)
	}

	// Update metrics
	queryTime := time.Since(startTime)
	m.updateQueryMetrics(queryTime, true)

	// Verify query time requirement (<500ms)
	if queryTime > 500*time.Millisecond {
		m.logger.Errorf("Member query exceeded 500ms: %v", queryTime)
	}

	response := &QueryMembersResponse{
		Members:    members,
		TotalCount: totalCount,
		HasMore:    req.Offset+len(members) < totalCount,
		QueryTime:  queryTime,
	}

	m.logger.Infof("Member query completed: found=%d, total=%d, time=%v", len(members), totalCount, queryTime)

	return response, nil
}

// InviteMembers invites multiple members to the supergroup
func (m *Manager) InviteMembers(ctx context.Context, req *InviteMembersRequest) (*InviteMembersResponse, error) {
	startTime := time.Now()

	m.logger.Infof("Inviting members: group=%d, count=%d", req.GroupID, len(req.UserIDs))

	// Validate request
	if err := m.validateInviteRequest(req); err != nil {
		return nil, fmt.Errorf("invalid invite request: %w", err)
	}

	// Check group capacity
	currentCount, err := m.memberManager.GetMemberCount(ctx, req.GroupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get member count: %w", err)
	}

	if currentCount+len(req.UserIDs) > m.config.MaxMembers {
		return nil, fmt.Errorf("group capacity exceeded: current=%d, adding=%d, max=%d",
			currentCount, len(req.UserIDs), m.config.MaxMembers)
	}

	// Batch invite members
	results, err := m.memberManager.BatchInviteMembers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("batch invite failed: %w", err)
	}

	// Update metrics
	inviteTime := time.Since(startTime)
	m.updateInviteMetrics(inviteTime, len(results.SuccessfulInvites))

	response := &InviteMembersResponse{
		SuccessfulInvites: results.SuccessfulInvites,
		FailedInvites:     results.FailedInvites,
		InviteTime:        inviteTime,
	}

	m.logger.Infof("Member invitation completed: successful=%d, failed=%d, time=%v",
		len(results.SuccessfulInvites), len(results.FailedInvites), inviteTime)

	return response, nil
}

// Helper methods
func (m *Manager) initializeMemberShards() {
	for i := 0; i < m.config.ShardCount; i++ {
		m.memberManager.memberShards[i] = &MemberShard{
			ID:          i,
			Members:     make(map[int64]*Member),
			MemberCount: 0,
			LastUpdate:  time.Now(),
			IsHealthy:   true,
		}
	}
}

func (m *Manager) initializeDefaultRoles() {
	// Creator role
	m.permissionManager.roleDefinitions["creator"] = &Role{
		ID:          "creator",
		Name:        "Creator",
		Description: "Group creator with all permissions",
		Permissions: m.getAllPermissions(),
		Priority:    1000,
		IsCustom:    false,
		Color:       "#FF6B6B",
		Badge:       "👑",
	}

	// Admin role
	m.permissionManager.roleDefinitions["admin"] = &Role{
		ID:          "admin",
		Name:        "Administrator",
		Description: "Group administrator with management permissions",
		Permissions: []Permission{
			PermissionSendMessages, PermissionSendMedia, PermissionSendStickers,
			PermissionAddUsers, PermissionPinMessages, PermissionDeleteMessages,
			PermissionBanUsers, PermissionChangeInfo, PermissionManageInvites,
			PermissionViewMembers, PermissionManageVoiceChats,
		},
		Priority: 900,
		IsCustom: false,
		Color:    "#4ECDC4",
		Badge:    "⭐",
	}

	// Member role
	m.permissionManager.roleDefinitions["member"] = &Role{
		ID:          "member",
		Name:        "Member",
		Description: "Regular group member",
		Permissions: []Permission{
			PermissionSendMessages, PermissionSendMedia, PermissionSendStickers,
			PermissionSendPolls,
		},
		Priority: 100,
		IsCustom: false,
		Color:    "#95E1D3",
		Badge:    "",
	}
}

func (m *Manager) initializeShards() {
	// Initialize shards for consistent hashing
	for i := 0; i < m.config.ShardCount; i++ {
		m.shardManager.shards[i] = &Shard{}
	}
}

func (m *Manager) getAllPermissions() []Permission {
	return []Permission{
		PermissionSendMessages, PermissionSendMedia, PermissionSendStickers,
		PermissionSendPolls, PermissionAddUsers, PermissionPinMessages,
		PermissionDeleteMessages, PermissionBanUsers, PermissionChangeInfo,
		PermissionManageRoles, PermissionManageInvites, PermissionViewMembers,
		PermissionManageVoiceChats,
	}
}

func (m *Manager) calculateShardID(userID int64) int {
	// Simple hash function for demonstration
	return int(userID % int64(m.config.ShardCount))
}

func (m *Manager) generateGroupID() int64 {
	// Generate unique group ID
	return time.Now().UnixNano()
}

func (m *Manager) generateInviteLink(groupID int64) string {
	return fmt.Sprintf("https://t.me/joinchat/%d", groupID)
}

func (m *Manager) validateCreateRequest(req *CreateSupergroupRequest) error {
	if req.Title == "" {
		return fmt.Errorf("title is required")
	}
	if req.CreatorID <= 0 {
		return fmt.Errorf("invalid creator ID")
	}
	return nil
}

func (m *Manager) validateQueryRequest(req *QueryMembersRequest) error {
	if req.GroupID <= 0 {
		return fmt.Errorf("invalid group ID")
	}
	if req.Limit <= 0 || req.Limit > 1000 {
		return fmt.Errorf("invalid limit: must be between 1 and 1000")
	}
	return nil
}

func (m *Manager) validateInviteRequest(req *InviteMembersRequest) error {
	if req.GroupID <= 0 {
		return fmt.Errorf("invalid group ID")
	}
	if len(req.UserIDs) == 0 {
		return fmt.Errorf("no users to invite")
	}
	if len(req.UserIDs) > 1000 {
		return fmt.Errorf("too many users to invite at once: max 1000")
	}
	return nil
}

func (m *Manager) storeSupergroup(ctx context.Context, supergroup *Supergroup) error {
	// Store supergroup implementation would go here
	return nil
}

func (m *Manager) updateCreationMetrics(duration time.Duration, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.metrics.TotalGroups++
	m.metrics.AverageCreationTime = (m.metrics.AverageCreationTime + duration) / 2
	m.metrics.LastUpdate = time.Now()
}

func (m *Manager) updateQueryMetrics(duration time.Duration, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.metrics.AverageQueryTime = (m.metrics.AverageQueryTime + duration) / 2
	if success {
		m.metrics.SuccessRate = (m.metrics.SuccessRate + 1.0) / 2.0
	} else {
		m.metrics.SuccessRate = (m.metrics.SuccessRate + 0.0) / 2.0
	}
	m.metrics.LastUpdate = time.Now()
}

func (m *Manager) updateInviteMetrics(duration time.Duration, successCount int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.metrics.TotalMembers += int64(successCount)
	m.metrics.LastUpdate = time.Now()
}

// DefaultConfig returns default supergroup configuration
func DefaultConfig() *Config {
	return &Config{
		MaxMembers:          2000000,            // 2 million members
		ShardCount:          1000,               // 1000 shards
		MemberQueryTimeout:  500,                // 500ms
		CreationTimeout:     10000,              // 10 seconds
		MaxConcurrentOps:    10000,              // 10k concurrent operations
		CacheSize:           1024 * 1024 * 1024, // 1GB cache
		CacheExpiry:         1 * time.Hour,
		HashFunction:        "consistent",
		ReplicationFactor:   3,
		ConsistencyLevel:    "quorum",
		DefaultRoles:        []string{"creator", "admin", "member"},
		CustomRoleLimit:     50,
		PermissionCacheSize: 100000,
	}
}

// AddMember adds a member to the appropriate shard
func (mm *MemberManager) AddMember(ctx context.Context, member *Member) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	shard, exists := mm.memberShards[member.ShardID]
	if !exists {
		return fmt.Errorf("shard %d not found", member.ShardID)
	}

	shard.Members[member.UserID] = member
	shard.MemberCount++
	shard.LastUpdate = time.Now()

	return nil
}

// QueryMembers queries members across shards
func (mm *MemberManager) QueryMembers(ctx context.Context, req *QueryMembersRequest) ([]*Member, int, error) {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	var allMembers []*Member
	totalCount := 0

	// Query all shards
	for _, shard := range mm.memberShards {
		for _, member := range shard.Members {
			if member.GroupID == req.GroupID && member.IsActive {
				allMembers = append(allMembers, member)
				totalCount++
			}
		}
	}

	// Apply pagination
	start := req.Offset
	end := req.Offset + req.Limit
	if start > len(allMembers) {
		return []*Member{}, totalCount, nil
	}
	if end > len(allMembers) {
		end = len(allMembers)
	}

	return allMembers[start:end], totalCount, nil
}

// GetMemberCount gets total member count for a group
func (mm *MemberManager) GetMemberCount(ctx context.Context, groupID int64) (int, error) {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	count := 0
	for _, shard := range mm.memberShards {
		for _, member := range shard.Members {
			if member.GroupID == groupID && member.IsActive {
				count++
			}
		}
	}

	return count, nil
}

// BatchInviteMembers invites multiple members in batch
func (mm *MemberManager) BatchInviteMembers(ctx context.Context, req *InviteMembersRequest) (*BatchInviteResult, error) {
	result := &BatchInviteResult{
		SuccessfulInvites: []int64{},
		FailedInvites:     []int64{},
	}

	for _, userID := range req.UserIDs {
		member := &Member{
			UserID:      userID,
			GroupID:     req.GroupID,
			JoinedAt:    time.Now(),
			Role:        "member",
			Permissions: []string{"send_messages", "send_media"},
			InvitedBy:   req.InviterID,
			IsActive:    true,
			LastSeen:    time.Now(),
			ShardID:     int(userID % 1000), // Simple sharding
		}

		err := mm.AddMember(ctx, member)
		if err != nil {
			result.FailedInvites = append(result.FailedInvites, userID)
		} else {
			result.SuccessfulInvites = append(result.SuccessfulInvites, userID)
		}
	}

	return result, nil
}
