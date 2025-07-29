package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// SSOService provides single sign-on capabilities
type SSOService struct {
	config    *Config
	providers map[string]Provider
	sessions  map[string]*Session
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for SSO service
type Config struct {
	EnableSAML       bool   `json:"enable_saml"`
	EnableOAuth2     bool   `json:"enable_oauth2"`
	EnableOIDC       bool   `json:"enable_oidc"`
	EnableLDAP       bool   `json:"enable_ldap"`
	SessionTimeout   int    `json:"session_timeout"`   // seconds
	TokenExpiry      int    `json:"token_expiry"`      // seconds
	RefreshTokenTTL  int    `json:"refresh_token_ttl"` // seconds
	DefaultProvider  string `json:"default_provider"`
	RequireMFA       bool   `json:"require_mfa"`
}

// Provider represents an SSO provider
type Provider interface {
	GetID() string
	GetName() string
	GetType() ProviderType
	Authenticate(ctx context.Context, request *AuthRequest) (*AuthResult, error)
	ValidateToken(ctx context.Context, token string) (*TokenValidation, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
	Logout(ctx context.Context, token string) error
}

// ProviderType represents the type of SSO provider
type ProviderType string

const (
	ProviderTypeSAML   ProviderType = "saml"
	ProviderTypeOAuth2 ProviderType = "oauth2"
	ProviderTypeOIDC   ProviderType = "oidc"
	ProviderTypeLDAP   ProviderType = "ldap"
)

// AuthRequest represents an authentication request
type AuthRequest struct {
	ProviderID   string                 `json:"provider_id"`
	Username     string                 `json:"username"`
	Password     string                 `json:"password"`
	Token        string                 `json:"token"`
	RedirectURI  string                 `json:"redirect_uri"`
	State        string                 `json:"state"`
	Scopes       []string               `json:"scopes"`
	Metadata     map[string]interface{} `json:"metadata"`
	ClientIP     string                 `json:"client_ip"`
	UserAgent    string                 `json:"user_agent"`
}

// AuthResult represents the result of authentication
type AuthResult struct {
	Success      bool                   `json:"success"`
	UserID       int64                  `json:"user_id"`
	Username     string                 `json:"username"`
	Email        string                 `json:"email"`
	DisplayName  string                 `json:"display_name"`
	Groups       []string               `json:"groups"`
	Roles        []string               `json:"roles"`
	Attributes   map[string]interface{} `json:"attributes"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	TokenType    string                 `json:"token_type"`
	ExpiresIn    int                    `json:"expires_in"`
	Scope        string                 `json:"scope"`
	SessionID    string                 `json:"session_id"`
	ProviderID   string                 `json:"provider_id"`
	Timestamp    time.Time              `json:"timestamp"`
}

// TokenValidation represents token validation result
type TokenValidation struct {
	Valid       bool                   `json:"valid"`
	UserID      int64                  `json:"user_id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	Scopes      []string               `json:"scopes"`
	ExpiresAt   time.Time              `json:"expires_at"`
	IssuedAt    time.Time              `json:"issued_at"`
	Issuer      string                 `json:"issuer"`
	Audience    string                 `json:"audience"`
	Attributes  map[string]interface{} `json:"attributes"`
	ProviderID  string                 `json:"provider_id"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// Session represents an SSO session
type Session struct {
	ID           string                 `json:"id"`
	UserID       int64                  `json:"user_id"`
	Username     string                 `json:"username"`
	ProviderID   string                 `json:"provider_id"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	LastActivity time.Time              `json:"last_activity"`
	ClientIP     string                 `json:"client_ip"`
	UserAgent    string                 `json:"user_agent"`
	Attributes   map[string]interface{} `json:"attributes"`
	IsActive     bool                   `json:"is_active"`
}

// SAMLProvider implements SAML SSO provider
type SAMLProvider struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	EntityID     string `json:"entity_id"`
	SSOURL       string `json:"sso_url"`
	Certificate  string `json:"certificate"`
	PrivateKey   string `json:"private_key"`
	AttributeMap map[string]string `json:"attribute_map"`
}

// OAuth2Provider implements OAuth2 SSO provider
type OAuth2Provider struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
	Scopes       []string `json:"scopes"`
	RedirectURI  string   `json:"redirect_uri"`
}

// LDAPProvider implements LDAP SSO provider
type LDAPProvider struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	BaseDN         string `json:"base_dn"`
	BindDN         string `json:"bind_dn"`
	BindPassword   string `json:"bind_password"`
	UserFilter     string `json:"user_filter"`
	GroupFilter    string `json:"group_filter"`
	AttributeMap   map[string]string `json:"attribute_map"`
	UseSSL         bool   `json:"use_ssl"`
	SkipTLSVerify  bool   `json:"skip_tls_verify"`
}

// NewSSOService creates a new SSO service
func NewSSOService(config *Config) *SSOService {
	if config == nil {
		config = DefaultConfig()
	}

	service := &SSOService{
		config:    config,
		providers: make(map[string]Provider),
		sessions:  make(map[string]*Session),
		logger:    logx.WithContext(context.Background()),
	}

	// Initialize default providers
	service.initializeDefaultProviders()

	return service
}

// DefaultConfig returns default SSO configuration
func DefaultConfig() *Config {
	return &Config{
		EnableSAML:      true,
		EnableOAuth2:    true,
		EnableOIDC:      true,
		EnableLDAP:      true,
		SessionTimeout:  3600,  // 1 hour
		TokenExpiry:     1800,  // 30 minutes
		RefreshTokenTTL: 86400, // 24 hours
		DefaultProvider: "oauth2",
		RequireMFA:      false,
	}
}

// Authenticate authenticates a user via SSO
func (sso *SSOService) Authenticate(ctx context.Context, request *AuthRequest) (*AuthResult, error) {
	if request.ProviderID == "" {
		request.ProviderID = sso.config.DefaultProvider
	}

	provider, exists := sso.providers[request.ProviderID]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", request.ProviderID)
	}

	// Authenticate with provider
	result, err := provider.Authenticate(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !result.Success {
		return result, nil
	}

	// Create session
	session, err := sso.createSession(result, request)
	if err != nil {
		sso.logger.Errorf("Failed to create session: %v", err)
	} else {
		result.SessionID = session.ID
	}

	sso.logger.Infof("User %s authenticated via %s", result.Username, request.ProviderID)
	return result, nil
}

// ValidateToken validates an access token
func (sso *SSOService) ValidateToken(ctx context.Context, token string) (*TokenValidation, error) {
	// Check if token exists in active sessions
	sso.mutex.RLock()
	var session *Session
	for _, s := range sso.sessions {
		if s.AccessToken == token && s.IsActive && s.ExpiresAt.After(time.Now()) {
			session = s
			break
		}
	}
	sso.mutex.RUnlock()

	if session == nil {
		return &TokenValidation{Valid: false}, nil
	}

	// Update last activity
	sso.mutex.Lock()
	session.LastActivity = time.Now()
	sso.mutex.Unlock()

	// Get provider for additional validation
	provider, exists := sso.providers[session.ProviderID]
	if exists {
		validation, err := provider.ValidateToken(ctx, token)
		if err == nil && validation.Valid {
			return validation, nil
		}
	}

	// Return basic validation based on session
	validation := &TokenValidation{
		Valid:      true,
		UserID:     session.UserID,
		Username:   session.Username,
		ExpiresAt:  session.ExpiresAt,
		IssuedAt:   session.CreatedAt,
		ProviderID: session.ProviderID,
		Attributes: session.Attributes,
	}

	return validation, nil
}

// RefreshToken refreshes an access token
func (sso *SSOService) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// Find session by refresh token
	sso.mutex.RLock()
	var session *Session
	for _, s := range sso.sessions {
		if s.RefreshToken == refreshToken && s.IsActive {
			session = s
			break
		}
	}
	sso.mutex.RUnlock()

	if session == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	provider, exists := sso.providers[session.ProviderID]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", session.ProviderID)
	}

	// Refresh token with provider
	tokenResponse, err := provider.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Update session
	sso.mutex.Lock()
	session.AccessToken = tokenResponse.AccessToken
	session.RefreshToken = tokenResponse.RefreshToken
	session.ExpiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	session.LastActivity = time.Now()
	sso.mutex.Unlock()

	return tokenResponse, nil
}

// Logout logs out a user
func (sso *SSOService) Logout(ctx context.Context, token string) error {
	// Find and invalidate session
	sso.mutex.Lock()
	defer sso.mutex.Unlock()

	for _, session := range sso.sessions {
		if session.AccessToken == token {
			session.IsActive = false
			
			// Logout from provider
			if provider, exists := sso.providers[session.ProviderID]; exists {
				provider.Logout(ctx, token)
			}
			
			sso.logger.Infof("User %s logged out", session.Username)
			return nil
		}
	}

	return fmt.Errorf("session not found")
}

// RegisterProvider registers an SSO provider
func (sso *SSOService) RegisterProvider(provider Provider) error {
	sso.mutex.Lock()
	defer sso.mutex.Unlock()

	sso.providers[provider.GetID()] = provider
	sso.logger.Infof("Registered SSO provider: %s (%s)", provider.GetName(), provider.GetType())
	return nil
}

// GetProviders returns all registered providers
func (sso *SSOService) GetProviders() map[string]Provider {
	sso.mutex.RLock()
	defer sso.mutex.RUnlock()

	providers := make(map[string]Provider)
	for id, provider := range sso.providers {
		providers[id] = provider
	}
	return providers
}

// createSession creates a new SSO session
func (sso *SSOService) createSession(result *AuthResult, request *AuthRequest) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:           sessionID,
		UserID:       result.UserID,
		Username:     result.Username,
		ProviderID:   result.ProviderID,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(sso.config.SessionTimeout) * time.Second),
		LastActivity: time.Now(),
		ClientIP:     request.ClientIP,
		UserAgent:    request.UserAgent,
		Attributes:   result.Attributes,
		IsActive:     true,
	}

	sso.mutex.Lock()
	sso.sessions[sessionID] = session
	sso.mutex.Unlock()

	return session, nil
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// initializeDefaultProviders initializes default SSO providers
func (sso *SSOService) initializeDefaultProviders() {
	// Register mock providers for demonstration
	if sso.config.EnableOAuth2 {
		oauth2Provider := &MockOAuth2Provider{
			ID:   "oauth2",
			Name: "OAuth2 Provider",
		}
		sso.providers["oauth2"] = oauth2Provider
	}

	if sso.config.EnableSAML {
		samlProvider := &MockSAMLProvider{
			ID:   "saml",
			Name: "SAML Provider",
		}
		sso.providers["saml"] = samlProvider
	}
}

// Mock implementations for demonstration

// MockOAuth2Provider is a mock OAuth2 provider
type MockOAuth2Provider struct {
	ID   string
	Name string
}

func (p *MockOAuth2Provider) GetID() string { return p.ID }
func (p *MockOAuth2Provider) GetName() string { return p.Name }
func (p *MockOAuth2Provider) GetType() ProviderType { return ProviderTypeOAuth2 }

func (p *MockOAuth2Provider) Authenticate(ctx context.Context, request *AuthRequest) (*AuthResult, error) {
	// Mock authentication
	return &AuthResult{
		Success:      true,
		UserID:       12345,
		Username:     "testuser",
		Email:        "test@example.com",
		DisplayName:  "Test User",
		Groups:       []string{"users"},
		Roles:        []string{"user"},
		AccessToken:  "mock_access_token",
		RefreshToken: "mock_refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ProviderID:   p.ID,
		Timestamp:    time.Now(),
	}, nil
}

func (p *MockOAuth2Provider) ValidateToken(ctx context.Context, token string) (*TokenValidation, error) {
	return &TokenValidation{
		Valid:      true,
		UserID:     12345,
		Username:   "testuser",
		Email:      "test@example.com",
		ExpiresAt:  time.Now().Add(time.Hour),
		IssuedAt:   time.Now(),
		ProviderID: p.ID,
	}, nil
}

func (p *MockOAuth2Provider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return &TokenResponse{
		AccessToken:  "new_mock_access_token",
		RefreshToken: "new_mock_refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (p *MockOAuth2Provider) Logout(ctx context.Context, token string) error {
	return nil
}

// MockSAMLProvider is a mock SAML provider
type MockSAMLProvider struct {
	ID   string
	Name string
}

func (p *MockSAMLProvider) GetID() string { return p.ID }
func (p *MockSAMLProvider) GetName() string { return p.Name }
func (p *MockSAMLProvider) GetType() ProviderType { return ProviderTypeSAML }

func (p *MockSAMLProvider) Authenticate(ctx context.Context, request *AuthRequest) (*AuthResult, error) {
	// Mock SAML authentication
	return &AuthResult{
		Success:     true,
		UserID:      67890,
		Username:    "samluser",
		Email:       "saml@example.com",
		DisplayName: "SAML User",
		Groups:      []string{"saml_users"},
		Roles:       []string{"user"},
		ProviderID:  p.ID,
		Timestamp:   time.Now(),
	}, nil
}

func (p *MockSAMLProvider) ValidateToken(ctx context.Context, token string) (*TokenValidation, error) {
	return &TokenValidation{
		Valid:      true,
		UserID:     67890,
		Username:   "samluser",
		Email:      "saml@example.com",
		ProviderID: p.ID,
	}, nil
}

func (p *MockSAMLProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return nil, fmt.Errorf("SAML does not support token refresh")
}

func (p *MockSAMLProvider) Logout(ctx context.Context, token string) error {
	return nil
}
