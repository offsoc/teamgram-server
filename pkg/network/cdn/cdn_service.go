package cdn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// CDNService provides Content Delivery Network capabilities
type CDNService struct {
	config    *Config
	nodes     map[string]*CDNNode
	cache     map[string]*CacheEntry
	origins   map[string]*OriginServer
	policies  map[string]*CachePolicy
	metrics   *CDNMetrics
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for CDN service
type Config struct {
	EnableGeoRouting       bool    `json:"enable_geo_routing"`
	EnableLoadBalancing    bool    `json:"enable_load_balancing"`
	EnableCompression      bool    `json:"enable_compression"`
	EnableImageOptimization bool   `json:"enable_image_optimization"`
	DefaultTTL             int     `json:"default_ttl"`             // seconds
	MaxCacheSize           int64   `json:"max_cache_size"`          // bytes
	PurgeOnUpdate          bool    `json:"purge_on_update"`
	HealthCheckInterval    int     `json:"health_check_interval"`   // seconds
	CompressionThreshold   int64   `json:"compression_threshold"`   // bytes
	CacheHitRatioThreshold float64 `json:"cache_hit_ratio_threshold"`
}

// CDNNode represents a CDN edge node
type CDNNode struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Location    Location          `json:"location"`
	Status      NodeStatus        `json:"status"`
	Capacity    int64             `json:"capacity"`    // bytes
	Used        int64             `json:"used"`        // bytes
	Available   int64             `json:"available"`   // bytes
	Load        float64           `json:"load"`        // 0.0 to 1.0
	Latency     time.Duration     `json:"latency"`
	Bandwidth   int64             `json:"bandwidth"`   // bps
	CacheHitRatio float64         `json:"cache_hit_ratio"`
	RequestCount  int64           `json:"request_count"`
	BytesServed   int64           `json:"bytes_served"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	LastSeen    time.Time         `json:"last_seen"`
}

// Location represents a geographical location
type Location struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
}

// CacheEntry represents a cached content entry
type CacheEntry struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	URL         string            `json:"url"`
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Compressed  bool              `json:"compressed"`
	Optimized   bool              `json:"optimized"`
	TTL         int               `json:"ttl"`         // seconds
	HitCount    int64             `json:"hit_count"`
	LastHit     time.Time         `json:"last_hit"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Metadata    map[string]string `json:"metadata"`
}

// OriginServer represents an origin server
type OriginServer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Status      ServerStatus      `json:"status"`
	Priority    int               `json:"priority"`
	Weight      int               `json:"weight"`
	HealthCheck HealthCheck       `json:"health_check"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	LastChecked time.Time         `json:"last_checked"`
}

// HealthCheck represents health check configuration
type HealthCheck struct {
	Enabled     bool          `json:"enabled"`
	URL         string        `json:"url"`
	Method      string        `json:"method"`
	Interval    time.Duration `json:"interval"`
	Timeout     time.Duration `json:"timeout"`
	HealthyCode int           `json:"healthy_code"`
}

// CachePolicy represents a cache policy
type CachePolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Pattern     string            `json:"pattern"`
	TTL         int               `json:"ttl"`         // seconds
	MaxSize     int64             `json:"max_size"`    // bytes
	Compress    bool              `json:"compress"`
	Optimize    bool              `json:"optimize"`
	Headers     map[string]string `json:"headers"`
	Conditions  []PolicyCondition `json:"conditions"`
	CreatedAt   time.Time         `json:"created_at"`
	IsActive    bool              `json:"is_active"`
}

// PolicyCondition represents a policy condition
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// CDNMetrics represents CDN metrics
type CDNMetrics struct {
	TotalNodes        int                `json:"total_nodes"`
	ActiveNodes       int                `json:"active_nodes"`
	TotalRequests     int64              `json:"total_requests"`
	CacheHits         int64              `json:"cache_hits"`
	CacheMisses       int64              `json:"cache_misses"`
	CacheHitRatio     float64            `json:"cache_hit_ratio"`
	TotalBandwidth    int64              `json:"total_bandwidth"`
	UsedBandwidth     int64              `json:"used_bandwidth"`
	AverageLatency    time.Duration      `json:"average_latency"`
	BytesServed       int64              `json:"bytes_served"`
	RequestHistory    []RequestSample    `json:"request_history"`
	BandwidthHistory  []BandwidthSample  `json:"bandwidth_history"`
	LatencyHistory    []LatencySample    `json:"latency_history"`
	LastUpdated       time.Time          `json:"last_updated"`
}

// RequestSample represents a request sample
type RequestSample struct {
	Timestamp time.Time `json:"timestamp"`
	Requests  int64     `json:"requests"`
	CacheHits int64     `json:"cache_hits"`
}

// BandwidthSample represents a bandwidth sample
type BandwidthSample struct {
	Timestamp time.Time `json:"timestamp"`
	Bandwidth int64     `json:"bandwidth"` // bps
}

// LatencySample represents a latency sample
type LatencySample struct {
	Timestamp time.Time     `json:"timestamp"`
	Latency   time.Duration `json:"latency"`
}

// ContentRequest represents a content request
type ContentRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	ClientIP    string            `json:"client_ip"`
	UserAgent   string            `json:"user_agent"`
	Referer     string            `json:"referer"`
	Metadata    map[string]string `json:"metadata"`
}

// ContentResponse represents a content response
type ContentResponse struct {
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	CacheHit    bool              `json:"cache_hit"`
	NodeID      string            `json:"node_id"`
	Latency     time.Duration     `json:"latency"`
	Headers     map[string]string `json:"headers"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums
type NodeStatus string
const (
	NodeStatusOnline     NodeStatus = "online"
	NodeStatusOffline    NodeStatus = "offline"
	NodeStatusMaintenance NodeStatus = "maintenance"
	NodeStatusDegraded   NodeStatus = "degraded"
)

type ServerStatus string
const (
	ServerStatusHealthy   ServerStatus = "healthy"
	ServerStatusUnhealthy ServerStatus = "unhealthy"
	ServerStatusUnknown   ServerStatus = "unknown"
)

// NewCDNService creates a new CDN service
func NewCDNService(config *Config) *CDNService {
	if config == nil {
		config = DefaultConfig()
	}

	service := &CDNService{
		config:   config,
		nodes:    make(map[string]*CDNNode),
		cache:    make(map[string]*CacheEntry),
		origins:  make(map[string]*OriginServer),
		policies: make(map[string]*CachePolicy),
		metrics:  &CDNMetrics{},
		logger:   logx.WithContext(context.Background()),
	}

	// Initialize default nodes and policies
	service.initializeDefaults()

	return service
}

// DefaultConfig returns default CDN configuration
func DefaultConfig() *Config {
	return &Config{
		EnableGeoRouting:        true,
		EnableLoadBalancing:     true,
		EnableCompression:       true,
		EnableImageOptimization: true,
		DefaultTTL:              3600,  // 1 hour
		MaxCacheSize:            1024 * 1024 * 1024 * 10, // 10GB
		PurgeOnUpdate:           true,
		HealthCheckInterval:     30,    // 30 seconds
		CompressionThreshold:    1024,  // 1KB
		CacheHitRatioThreshold:  0.8,   // 80%
	}
}

// ServeContent serves content through the CDN
func (cdn *CDNService) ServeContent(ctx context.Context, request *ContentRequest) (*ContentResponse, error) {
	start := time.Now()

	// Generate cache key
	cacheKey := cdn.generateCacheKey(request.URL, request.Headers)

	// Check cache first
	if entry := cdn.getCacheEntry(cacheKey); entry != nil {
		// Cache hit
		cdn.updateCacheHit(entry)
		
		response := &ContentResponse{
			Content:     entry.Content,
			ContentType: entry.ContentType,
			Size:        entry.Size,
			CacheHit:    true,
			Latency:     time.Since(start),
			Headers:     make(map[string]string),
			Metadata:    make(map[string]interface{}),
		}

		// Add cache headers
		response.Headers["X-Cache"] = "HIT"
		response.Headers["X-Cache-Node"] = "edge"

		return response, nil
	}

	// Cache miss - fetch from origin
	content, contentType, err := cdn.fetchFromOrigin(request.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from origin: %w", err)
	}

	// Process content (compression, optimization)
	processedContent := cdn.processContent(content, contentType)

	// Cache the content
	entry := &CacheEntry{
		ID:          cdn.generateEntryID(),
		Key:         cacheKey,
		URL:         request.URL,
		Content:     processedContent,
		ContentType: contentType,
		Size:        int64(len(processedContent)),
		Compressed:  cdn.shouldCompress(content, contentType),
		Optimized:   cdn.shouldOptimize(contentType),
		TTL:         cdn.getTTL(request.URL),
		HitCount:    1,
		LastHit:     time.Now(),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(cdn.getTTL(request.URL)) * time.Second),
	}

	cdn.setCacheEntry(entry)

	response := &ContentResponse{
		Content:     processedContent,
		ContentType: contentType,
		Size:        entry.Size,
		CacheHit:    false,
		Latency:     time.Since(start),
		Headers:     make(map[string]string),
		Metadata:    make(map[string]interface{}),
	}

	// Add cache headers
	response.Headers["X-Cache"] = "MISS"
	response.Headers["X-Cache-Node"] = "origin"

	cdn.logger.Infof("Served content: %s (cache_hit=%t, size=%d)", request.URL, response.CacheHit, response.Size)
	return response, nil
}

// PurgeContent purges content from cache
func (cdn *CDNService) PurgeContent(ctx context.Context, pattern string) error {
	cdn.mutex.Lock()
	defer cdn.mutex.Unlock()

	purgedCount := 0
	for key, entry := range cdn.cache {
		if cdn.matchesPattern(entry.URL, pattern) {
			delete(cdn.cache, key)
			purgedCount++
		}
	}

	cdn.logger.Infof("Purged %d cache entries matching pattern: %s", purgedCount, pattern)
	return nil
}

// GetCacheStats gets cache statistics
func (cdn *CDNService) GetCacheStats() map[string]interface{} {
	cdn.mutex.RLock()
	defer cdn.mutex.RUnlock()

	stats := make(map[string]interface{})
	
	totalEntries := len(cdn.cache)
	totalSize := int64(0)
	totalHits := int64(0)
	
	for _, entry := range cdn.cache {
		totalSize += entry.Size
		totalHits += entry.HitCount
	}

	stats["total_entries"] = totalEntries
	stats["total_size"] = totalSize
	stats["total_hits"] = totalHits
	stats["cache_utilization"] = float64(totalSize) / float64(cdn.config.MaxCacheSize)

	return stats
}

// Helper methods

func (cdn *CDNService) generateCacheKey(url string, headers map[string]string) string {
	// Simple cache key generation
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

func (cdn *CDNService) generateEntryID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("entry_%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:8])
}

func (cdn *CDNService) getCacheEntry(key string) *CacheEntry {
	cdn.mutex.RLock()
	defer cdn.mutex.RUnlock()

	entry, exists := cdn.cache[key]
	if !exists {
		return nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Remove expired entry
		go func() {
			cdn.mutex.Lock()
			delete(cdn.cache, key)
			cdn.mutex.Unlock()
		}()
		return nil
	}

	return entry
}

func (cdn *CDNService) setCacheEntry(entry *CacheEntry) {
	cdn.mutex.Lock()
	defer cdn.mutex.Unlock()

	// Check cache size limit
	if cdn.getCurrentCacheSize()+entry.Size > cdn.config.MaxCacheSize {
		cdn.evictLRU()
	}

	cdn.cache[entry.Key] = entry
}

func (cdn *CDNService) updateCacheHit(entry *CacheEntry) {
	cdn.mutex.Lock()
	defer cdn.mutex.Unlock()

	entry.HitCount++
	entry.LastHit = time.Now()
}

func (cdn *CDNService) getCurrentCacheSize() int64 {
	size := int64(0)
	for _, entry := range cdn.cache {
		size += entry.Size
	}
	return size
}

func (cdn *CDNService) evictLRU() {
	// Simple LRU eviction
	var oldestEntry *CacheEntry
	var oldestKey string

	for key, entry := range cdn.cache {
		if oldestEntry == nil || entry.LastHit.Before(oldestEntry.LastHit) {
			oldestEntry = entry
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(cdn.cache, oldestKey)
	}
}

func (cdn *CDNService) fetchFromOrigin(url string) ([]byte, string, error) {
	// Mock origin fetch
	content := []byte(fmt.Sprintf("Content for %s at %s", url, time.Now().Format(time.RFC3339)))
	contentType := "text/plain"
	
	// Simulate network delay
	time.Sleep(50 * time.Millisecond)
	
	return content, contentType, nil
}

func (cdn *CDNService) processContent(content []byte, contentType string) []byte {
	result := content

	// Apply compression if enabled and appropriate
	if cdn.config.EnableCompression && cdn.shouldCompress(content, contentType) {
		result = cdn.compressContent(result)
	}

	// Apply optimization if enabled and appropriate
	if cdn.config.EnableImageOptimization && cdn.shouldOptimize(contentType) {
		result = cdn.optimizeContent(result, contentType)
	}

	return result
}

func (cdn *CDNService) shouldCompress(content []byte, contentType string) bool {
	if !cdn.config.EnableCompression {
		return false
	}

	// Check size threshold
	if int64(len(content)) < cdn.config.CompressionThreshold {
		return false
	}

	// Check content type
	compressibleTypes := []string{
		"text/html",
		"text/css",
		"text/javascript",
		"application/javascript",
		"application/json",
		"text/xml",
		"application/xml",
	}

	for _, cType := range compressibleTypes {
		if contentType == cType {
			return true
		}
	}

	return false
}

func (cdn *CDNService) shouldOptimize(contentType string) bool {
	if !cdn.config.EnableImageOptimization {
		return false
	}

	optimizableTypes := []string{
		"image/jpeg",
		"image/png",
		"image/webp",
		"image/gif",
	}

	for _, cType := range optimizableTypes {
		if contentType == cType {
			return true
		}
	}

	return false
}

func (cdn *CDNService) compressContent(content []byte) []byte {
	// Mock compression - in production, use actual compression
	return content
}

func (cdn *CDNService) optimizeContent(content []byte, contentType string) []byte {
	// Mock optimization - in production, use actual image optimization
	return content
}

func (cdn *CDNService) getTTL(url string) int {
	// Check cache policies for specific TTL
	for _, policy := range cdn.policies {
		if policy.IsActive && cdn.matchesPattern(url, policy.Pattern) {
			return policy.TTL
		}
	}

	return cdn.config.DefaultTTL
}

func (cdn *CDNService) matchesPattern(url, pattern string) bool {
	// Simple pattern matching - in production, use regex or glob
	return len(url) >= len(pattern) && url[:len(pattern)] == pattern
}

func (cdn *CDNService) initializeDefaults() {
	// Initialize default CDN nodes
	nodes := []*CDNNode{
		{
			ID:   "edge_us_east",
			Name: "US East Edge Node",
			Location: Location{
				Country:   "US",
				Region:    "East",
				City:      "New York",
				Latitude:  40.7128,
				Longitude: -74.0060,
				Timezone:  "America/New_York",
			},
			Status:        NodeStatusOnline,
			Capacity:      1024 * 1024 * 1024 * 100, // 100GB
			Available:     1024 * 1024 * 1024 * 100,
			Bandwidth:     1000000000, // 1 Gbps
			CacheHitRatio: 0.85,
			CreatedAt:     time.Now(),
			LastSeen:      time.Now(),
		},
		{
			ID:   "edge_us_west",
			Name: "US West Edge Node",
			Location: Location{
				Country:   "US",
				Region:    "West",
				City:      "Los Angeles",
				Latitude:  34.0522,
				Longitude: -118.2437,
				Timezone:  "America/Los_Angeles",
			},
			Status:        NodeStatusOnline,
			Capacity:      1024 * 1024 * 1024 * 100, // 100GB
			Available:     1024 * 1024 * 1024 * 100,
			Bandwidth:     1000000000, // 1 Gbps
			CacheHitRatio: 0.82,
			CreatedAt:     time.Now(),
			LastSeen:      time.Now(),
		},
	}

	for _, node := range nodes {
		cdn.nodes[node.ID] = node
	}

	// Initialize default cache policies
	policies := []*CachePolicy{
		{
			ID:          "static_assets",
			Name:        "Static Assets Policy",
			Description: "Cache policy for static assets",
			Pattern:     "/static/",
			TTL:         86400, // 24 hours
			MaxSize:     1024 * 1024 * 10, // 10MB
			Compress:    true,
			Optimize:    true,
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          "api_responses",
			Name:        "API Responses Policy",
			Description: "Cache policy for API responses",
			Pattern:     "/api/",
			TTL:         300, // 5 minutes
			MaxSize:     1024 * 1024, // 1MB
			Compress:    true,
			Optimize:    false,
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, policy := range policies {
		cdn.policies[policy.ID] = policy
	}

	// Initialize default origin server
	origin := &OriginServer{
		ID:       "main_origin",
		Name:     "Main Origin Server",
		URL:      "https://origin.example.com",
		Status:   ServerStatusHealthy,
		Priority: 1,
		Weight:   100,
		HealthCheck: HealthCheck{
			Enabled:     true,
			URL:         "https://origin.example.com/health",
			Method:      "GET",
			Interval:    30 * time.Second,
			Timeout:     5 * time.Second,
			HealthyCode: 200,
		},
		CreatedAt:   time.Now(),
		LastChecked: time.Now(),
	}

	cdn.origins[origin.ID] = origin
}

// GetCDNMetrics gets CDN metrics
func (cdn *CDNService) GetCDNMetrics() *CDNMetrics {
	cdn.mutex.RLock()
	defer cdn.mutex.RUnlock()

	return cdn.metrics
}

// ListNodes lists all CDN nodes
func (cdn *CDNService) ListNodes() []*CDNNode {
	cdn.mutex.RLock()
	defer cdn.mutex.RUnlock()

	nodes := make([]*CDNNode, 0, len(cdn.nodes))
	for _, node := range cdn.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}
