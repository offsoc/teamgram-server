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

package llm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// LLMManager manages multiple LLM providers and models
type LLMManager struct {
	mutex        sync.RWMutex
	config       *LLMConfig
	providers    map[string]LLMProvider
	loadBalancer *LoadBalancer
	cache        *ResponseCache
	metrics      *LLMMetrics
	logger       logx.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	isRunning    bool
}

// LLMConfig configuration for LLM services
type LLMConfig struct {
	// Provider configurations
	OpenAIConfig    *OpenAIConfig    `json:"openai_config"`
	AnthropicConfig *AnthropicConfig `json:"anthropic_config"`
	GoogleConfig    *GoogleConfig    `json:"google_config"`

	// Default settings
	DefaultModel     string  `json:"default_model"`
	DefaultMaxTokens int     `json:"default_max_tokens"`
	DefaultTemp      float64 `json:"default_temperature"`

	// Performance settings
	RequestTimeout time.Duration `json:"request_timeout"`
	MaxRetries     int           `json:"max_retries"`
	RetryDelay     time.Duration `json:"retry_delay"`

	// Load balancing
	LoadBalanceStrategy string `json:"load_balance_strategy"`
	FailoverEnabled     bool   `json:"failover_enabled"`

	// Caching
	EnableCaching bool          `json:"enable_caching"`
	CacheSize     int           `json:"cache_size"`
	CacheTTL      time.Duration `json:"cache_ttl"`
}

// Provider configurations
type OpenAIConfig struct {
	APIKey      string   `json:"api_key"`
	BaseURL     string   `json:"base_url"`
	Models      []string `json:"models"`
	MaxTokens   int      `json:"max_tokens"`
	Temperature float64  `json:"temperature"`
	Enabled     bool     `json:"enabled"`
}

type AnthropicConfig struct {
	APIKey      string   `json:"api_key"`
	BaseURL     string   `json:"base_url"`
	Models      []string `json:"models"`
	MaxTokens   int      `json:"max_tokens"`
	Temperature float64  `json:"temperature"`
	Enabled     bool     `json:"enabled"`
}

type GoogleConfig struct {
	APIKey      string   `json:"api_key"`
	BaseURL     string   `json:"base_url"`
	Models      []string `json:"models"`
	MaxTokens   int      `json:"max_tokens"`
	Temperature float64  `json:"temperature"`
	Enabled     bool     `json:"enabled"`
}

// TextRequest represents a text processing request
type TextRequest struct {
	ID           string                 `json:"id"`
	Text         string                 `json:"text"`
	Model        string                 `json:"model,omitempty"`
	MaxTokens    int                    `json:"max_tokens,omitempty"`
	Temperature  float64                `json:"temperature,omitempty"`
	SystemPrompt string                 `json:"system_prompt,omitempty"`
	Context      []Message              `json:"context,omitempty"`
	Options      map[string]interface{} `json:"options,omitempty"`
	UserID       int64                  `json:"user_id"`
	ChatID       int64                  `json:"chat_id"`
	CreatedAt    time.Time              `json:"created_at"`
}

// TextResponse represents a text processing response
type TextResponse struct {
	ID          string                 `json:"id"`
	RequestID   string                 `json:"request_id"`
	Text        string                 `json:"text"`
	Model       string                 `json:"model"`
	TokensUsed  int64                  `json:"tokens_used"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	ProcessTime time.Duration          `json:"process_time"`
	Provider    string                 `json:"provider"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Message represents a conversation message
type Message struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

// LLMMetrics tracks LLM performance
type LLMMetrics struct {
	TotalRequests      int64                       `json:"total_requests"`
	SuccessfulRequests int64                       `json:"successful_requests"`
	FailedRequests     int64                       `json:"failed_requests"`
	AverageLatency     time.Duration               `json:"average_latency"`
	MaxLatency         time.Duration               `json:"max_latency"`
	MinLatency         time.Duration               `json:"min_latency"`
	TotalTokensUsed    int64                       `json:"total_tokens_used"`
	ProviderMetrics    map[string]*ProviderMetrics `json:"provider_metrics"`
	LastUpdated        time.Time                   `json:"last_updated"`
}

// ProviderMetrics tracks individual provider performance
type ProviderMetrics struct {
	Name           string        `json:"name"`
	Requests       int64         `json:"requests"`
	Successes      int64         `json:"successes"`
	Failures       int64         `json:"failures"`
	AverageLatency time.Duration `json:"average_latency"`
	TokensUsed     int64         `json:"tokens_used"`
	LastUsed       time.Time     `json:"last_used"`
	IsAvailable    bool          `json:"is_available"`
}

// LLMProvider interface for different LLM providers
type LLMProvider interface {
	Name() string
	ProcessText(ctx context.Context, request *TextRequest) (*TextResponse, error)
	GetAvailableModels() []string
	IsAvailable() bool
	GetMetrics() *ProviderMetrics
	Start() error
	Stop() error
}

// LoadBalancer handles load balancing across providers
type LoadBalancer struct {
	strategy  string
	providers []LLMProvider
	current   int
	mutex     sync.RWMutex
}

// ResponseCache caches LLM responses
type ResponseCache struct {
	cache map[string]*CacheEntry
	mutex sync.RWMutex
	size  int
	ttl   time.Duration
}

// CacheEntry represents a cached response
type CacheEntry struct {
	Response  *TextResponse
	CreatedAt time.Time
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(strategy string, providers []LLMProvider) *LoadBalancer {
	return &LoadBalancer{
		strategy:  strategy,
		providers: providers,
		current:   0,
	}
}

// SelectProvider selects a provider based on strategy
func (lb *LoadBalancer) SelectProvider() LLMProvider {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.providers) == 0 {
		return nil
	}

	// Simple round-robin for now
	provider := lb.providers[lb.current]
	lb.current = (lb.current + 1) % len(lb.providers)
	return provider
}

// SelectFallback selects a fallback provider
func (lb *LoadBalancer) SelectFallback(failedProvider LLMProvider) LLMProvider {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	for _, provider := range lb.providers {
		if provider.Name() != failedProvider.Name() {
			return provider
		}
	}
	return nil
}

// NewResponseCache creates a new response cache
func NewResponseCache(size int, ttl time.Duration) *ResponseCache {
	return &ResponseCache{
		cache: make(map[string]*CacheEntry),
		size:  size,
		ttl:   ttl,
	}
}

// Get retrieves a cached response
func (rc *ResponseCache) Get(request *TextRequest) *TextResponse {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	key := rc.generateKey(request)
	if entry, exists := rc.cache[key]; exists {
		if time.Since(entry.CreatedAt) < rc.ttl {
			return entry.Response
		}
		delete(rc.cache, key)
	}
	return nil
}

// Set stores a response in cache
func (rc *ResponseCache) Set(request *TextRequest, response *TextResponse) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	key := rc.generateKey(request)
	rc.cache[key] = &CacheEntry{
		Response:  response,
		CreatedAt: time.Now(),
	}

	// Simple eviction if cache is full
	if len(rc.cache) > rc.size {
		rc.evictOldest()
	}
}

// cleanupLoop runs cache cleanup
func (rc *ResponseCache) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(rc.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

// cleanup removes expired entries
func (rc *ResponseCache) cleanup() {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	now := time.Now()
	for key, entry := range rc.cache {
		if now.Sub(entry.CreatedAt) > rc.ttl {
			delete(rc.cache, key)
		}
	}
}

// generateKey generates a cache key for a request
func (rc *ResponseCache) generateKey(request *TextRequest) string {
	return fmt.Sprintf("%s:%s:%d", request.Text, request.Model, request.MaxTokens)
}

// evictOldest removes the oldest entry
func (rc *ResponseCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range rc.cache {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(rc.cache, oldestKey)
	}
}

// NewLLMManager creates a new LLM manager
func NewLLMManager(config *LLMConfig) (*LLMManager, error) {
	if config == nil {
		config = DefaultLLMConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &LLMManager{
		config:    config,
		providers: make(map[string]LLMProvider),
		metrics: &LLMMetrics{
			MinLatency:      time.Hour,
			ProviderMetrics: make(map[string]*ProviderMetrics),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize providers
	if err := manager.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	// Initialize load balancer
	manager.loadBalancer = NewLoadBalancer(config.LoadBalanceStrategy, manager.getProviderList())

	// Initialize cache
	if config.EnableCaching {
		manager.cache = NewResponseCache(config.CacheSize, config.CacheTTL)
	}

	return manager, nil
}

// Start starts the LLM manager
func (lm *LLMManager) Start() error {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	if lm.isRunning {
		return fmt.Errorf("LLM manager is already running")
	}

	lm.logger.Info("Starting LLM manager...")

	// Start all providers
	for name, provider := range lm.providers {
		if err := provider.Start(); err != nil {
			lm.logger.Errorf("Failed to start provider %s: %v", name, err)
			continue
		}
		lm.logger.Infof("Started LLM provider: %s", name)
	}

	// Start metrics collection
	go lm.metricsLoop()

	// Start cache cleanup
	if lm.cache != nil {
		go lm.cache.cleanupLoop(lm.ctx)
	}

	lm.isRunning = true
	lm.logger.Info("LLM manager started successfully")

	return nil
}

// ProcessText processes a text request
func (lm *LLMManager) ProcessText(ctx context.Context, request *TextRequest) (*TextResponse, error) {
	start := time.Now()

	lm.mutex.RLock()
	if !lm.isRunning {
		lm.mutex.RUnlock()
		return nil, fmt.Errorf("LLM manager is not running")
	}
	lm.mutex.RUnlock()

	// Check cache first
	if lm.cache != nil {
		if cached := lm.cache.Get(request); cached != nil {
			lm.logger.Debugf("Cache hit for request %s", request.ID)
			return cached, nil
		}
	}

	// Select provider
	provider := lm.loadBalancer.SelectProvider()
	if provider == nil {
		return nil, fmt.Errorf("no available providers")
	}

	// Process request
	response, err := provider.ProcessText(ctx, request)
	if err != nil {
		// Try failover if enabled
		if lm.config.FailoverEnabled {
			if fallbackProvider := lm.loadBalancer.SelectFallback(provider); fallbackProvider != nil {
				lm.logger.Errorf("Failing over from %s to %s", provider.Name(), fallbackProvider.Name())
				response, err = fallbackProvider.ProcessText(ctx, request)
			}
		}

		if err != nil {
			lm.updateMetrics(provider.Name(), false, time.Since(start), 0)
			return nil, fmt.Errorf("LLM processing failed: %w", err)
		}
	}

	// Cache response
	if lm.cache != nil && response != nil {
		lm.cache.Set(request, response)
	}

	// Update metrics
	tokensUsed := int64(0)
	if response != nil {
		tokensUsed = response.TokensUsed
		response.ProcessTime = time.Since(start)
	}
	lm.updateMetrics(provider.Name(), true, time.Since(start), tokensUsed)

	return response, nil
}

// GetAvailableModels returns all available models
func (lm *LLMManager) GetAvailableModels() []string {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	var models []string
	for _, provider := range lm.providers {
		if provider.IsAvailable() {
			models = append(models, provider.GetAvailableModels()...)
		}
	}

	return models
}

// GetMetrics returns LLM metrics
func (lm *LLMManager) GetMetrics() *LLMMetrics {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	// Update provider metrics
	for name, provider := range lm.providers {
		lm.metrics.ProviderMetrics[name] = provider.GetMetrics()
	}

	lm.metrics.LastUpdated = time.Now()

	// Return a copy
	metrics := *lm.metrics
	return &metrics
}

// initializeProviders initializes all configured providers
func (lm *LLMManager) initializeProviders() error {
	// Initialize OpenAI provider
	if lm.config.OpenAIConfig != nil && lm.config.OpenAIConfig.Enabled {
		provider, err := NewOpenAIProvider(lm.config.OpenAIConfig)
		if err != nil {
			lm.logger.Errorf("Failed to initialize OpenAI provider: %v", err)
		} else {
			lm.providers["openai"] = provider
		}
	}

	// Initialize Anthropic provider
	if lm.config.AnthropicConfig != nil && lm.config.AnthropicConfig.Enabled {
		provider, err := NewAnthropicProvider(lm.config.AnthropicConfig)
		if err != nil {
			lm.logger.Errorf("Failed to initialize Anthropic provider: %v", err)
		} else {
			lm.providers["anthropic"] = provider
		}
	}

	// Initialize Google provider
	if lm.config.GoogleConfig != nil && lm.config.GoogleConfig.Enabled {
		provider, err := NewGoogleProvider(lm.config.GoogleConfig)
		if err != nil {
			lm.logger.Errorf("Failed to initialize Google provider: %v", err)
		} else {
			lm.providers["google"] = provider
		}
	}

	if len(lm.providers) == 0 {
		return fmt.Errorf("no LLM providers configured")
	}

	lm.logger.Infof("Initialized %d LLM providers", len(lm.providers))
	return nil
}

// getProviderList returns a list of providers for load balancing
func (lm *LLMManager) getProviderList() []LLMProvider {
	var providers []LLMProvider
	for _, provider := range lm.providers {
		providers = append(providers, provider)
	}
	return providers
}

// updateMetrics updates LLM metrics
func (lm *LLMManager) updateMetrics(providerName string, success bool, latency time.Duration, tokensUsed int64) {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	lm.metrics.TotalRequests++
	lm.metrics.TotalTokensUsed += tokensUsed

	if success {
		lm.metrics.SuccessfulRequests++

		// Update latency metrics
		if latency > lm.metrics.MaxLatency {
			lm.metrics.MaxLatency = latency
		}
		if latency < lm.metrics.MinLatency {
			lm.metrics.MinLatency = latency
		}
		lm.metrics.AverageLatency = (lm.metrics.AverageLatency + latency) / 2
	} else {
		lm.metrics.FailedRequests++
	}
}

// metricsLoop collects metrics periodically
func (lm *LLMManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lm.collectMetrics()
		case <-lm.ctx.Done():
			return
		}
	}
}

// collectMetrics collects current metrics
func (lm *LLMManager) collectMetrics() {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	for name, provider := range lm.providers {
		lm.metrics.ProviderMetrics[name] = provider.GetMetrics()
	}

	lm.metrics.LastUpdated = time.Now()
}

// DefaultLLMConfig returns default LLM configuration
func DefaultLLMConfig() *LLMConfig {
	return &LLMConfig{
		DefaultModel:        "gpt-4",
		DefaultMaxTokens:    2048,
		DefaultTemp:         0.7,
		RequestTimeout:      30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		LoadBalanceStrategy: "round_robin",
		FailoverEnabled:     true,
		EnableCaching:       true,
		CacheSize:           1000,
		CacheTTL:            1 * time.Hour,
	}
}
