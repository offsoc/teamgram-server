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

package nsfw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Detector provides AI-powered NSFW content detection
type Detector struct {
	config        *Config
	imageDetector *ImageDetector
	videoDetector *VideoDetector
	textDetector  *TextDetector
	audioDetector *AudioDetector
	cache         map[string]*CachedResult
	cacheMutex    sync.RWMutex
	metrics       *DetectorMetrics
	logger        logx.Logger
}

// Config represents NSFW detector configuration
type Config struct {
	ModelPath         string        `json:"model_path"`
	Threshold         float64       `json:"threshold"`
	SecurityEnabled   bool          `json:"security_enabled"`
	EncryptionEnabled bool          `json:"encryption_enabled"`
	AuditEnabled      bool          `json:"audit_enabled"`
	CacheEnabled      bool          `json:"cache_enabled"`
	CacheTTL          time.Duration `json:"cache_ttl"`
}

// DetectionRequest represents a content detection request
type DetectionRequest struct {
	Content     []byte    `json:"content"`
	ContentType string    `json:"content_type"`
	UserID      int64     `json:"user_id"`
	Timestamp   time.Time `json:"timestamp"`
}

// DetectionResult represents the result of NSFW detection
type DetectionResult struct {
	IsNSFW         bool               `json:"is_nsfw"`
	Confidence     float64            `json:"confidence"`
	Categories     []string           `json:"categories"`
	Scores         map[string]float64 `json:"scores"`
	ProcessingTime time.Duration      `json:"processing_time"`
	ModelVersion   string             `json:"model_version"`
	Metadata       map[string]any     `json:"metadata"`
}

// CachedResult represents a cached detection result
type CachedResult struct {
	Result    *DetectionResult `json:"result"`
	Timestamp time.Time        `json:"timestamp"`
	Hash      string           `json:"hash"`
}

// DetectorMetrics tracks NSFW detection metrics
type DetectorMetrics struct {
	TotalDetections    int64         `json:"total_detections"`
	NSFWDetections     int64         `json:"nsfw_detections"`
	SafeDetections     int64         `json:"safe_detections"`
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	LastDetection      time.Time     `json:"last_detection"`
}

// ImageDetector handles image NSFW detection
type ImageDetector struct {
	enabled   bool
	threshold float64
	modelPath string
}

// VideoDetector handles video NSFW detection
type VideoDetector struct {
	enabled   bool
	threshold float64
	modelPath string
}

// TextDetector handles text NSFW detection
type TextDetector struct {
	enabled   bool
	threshold float64
	keywords  []string
}

// AudioDetector handles audio NSFW detection
type AudioDetector struct {
	enabled   bool
	threshold float64
	modelPath string
}

// NewDetector creates a new NSFW detector
func NewDetector(config *Config) (*Detector, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	if config.Threshold <= 0 {
		config.Threshold = 0.85
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 1 * time.Hour
	}

	detector := &Detector{
		config: config,
		cache:  make(map[string]*CachedResult),
		metrics: &DetectorMetrics{
			LastDetection: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize image detector
	detector.imageDetector = &ImageDetector{
		enabled:   true,
		threshold: config.Threshold,
		modelPath: config.ModelPath,
	}

	// Initialize video detector
	detector.videoDetector = &VideoDetector{
		enabled:   true,
		threshold: config.Threshold,
		modelPath: config.ModelPath,
	}

	// Initialize text detector
	detector.textDetector = &TextDetector{
		enabled:   true,
		threshold: config.Threshold,
		keywords:  []string{"nsfw", "adult", "explicit", "sexual", "nude", "porn", "xxx"},
	}

	// Initialize audio detector
	detector.audioDetector = &AudioDetector{
		enabled:   true,
		threshold: config.Threshold,
		modelPath: config.ModelPath,
	}

	// Start cache cleanup routine
	if config.CacheEnabled {
		go detector.cacheCleanupRoutine()
	}

	return detector, nil
}

// Detect performs NSFW detection on content
func (d *Detector) Detect(ctx context.Context, req *DetectionRequest) (*DetectionResult, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if len(req.Content) == 0 {
		return nil, errors.New("content cannot be empty")
	}

	startTime := time.Now()

	// Generate content hash for caching
	hash := d.generateContentHash(req.Content)

	// Check cache first
	if d.config.CacheEnabled {
		if cached := d.getCachedResult(hash); cached != nil {
			d.updateMetrics("cache_hit", time.Since(startTime))
			return cached, nil
		}
		d.updateMetrics("cache_miss", 0)
	}

	// Perform detection based on content type
	var result *DetectionResult
	var err error

	switch req.ContentType {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		result, err = d.detectImageNSFW(ctx, req)
	case "video/mp4", "video/webm", "video/avi", "video/mov":
		result, err = d.detectVideoNSFW(ctx, req)
	case "text/plain", "application/json":
		result, err = d.detectTextNSFW(ctx, req)
	case "audio/mp3", "audio/wav", "audio/ogg":
		result, err = d.detectAudioNSFW(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported content type: %s", req.ContentType)
	}

	if err != nil {
		return nil, fmt.Errorf("NSFW detection failed: %w", err)
	}

	// Set processing time
	result.ProcessingTime = time.Since(startTime)
	result.ModelVersion = "v1.0.0"

	// Cache result
	if d.config.CacheEnabled {
		d.cacheResult(hash, result)
	}

	// Update metrics
	d.updateMetrics("detection_completed", result.ProcessingTime)
	if result.IsNSFW {
		d.updateMetrics("nsfw_detected", 0)
	} else {
		d.updateMetrics("safe_detected", 0)
	}

	return result, nil
}

// GetMetrics returns current detector metrics
func (d *Detector) GetMetrics() *DetectorMetrics {
	d.cacheMutex.RLock()
	defer d.cacheMutex.RUnlock()

	metrics := *d.metrics
	return &metrics
}

// Private methods

func (d *Detector) detectImageNSFW(ctx context.Context, req *DetectionRequest) (*DetectionResult, error) {
	if !d.imageDetector.enabled {
		return &DetectionResult{
			IsNSFW:     false,
			Confidence: 0.0,
			Categories: []string{},
			Scores:     make(map[string]float64),
			Metadata:   map[string]any{"detector": "image", "enabled": false},
		}, nil
	}

	// Simulate AI model inference
	// In a real implementation, this would use actual ML models like ONNX, TensorFlow, etc.

	// Simple heuristic based on content size and type
	confidence := 0.0
	categories := []string{}
	scores := make(map[string]float64)

	// Simulate model processing
	contentSize := len(req.Content)
	if contentSize > 1024*1024 { // Large images might be more likely to be NSFW
		confidence += 0.1
	}

	// Simulate various category scores
	scores["nudity"] = 0.05
	scores["sexual_activity"] = 0.03
	scores["suggestive"] = 0.02
	scores["violence"] = 0.01

	// Determine if NSFW based on threshold
	isNSFW := confidence > d.imageDetector.threshold

	if isNSFW {
		categories = append(categories, "potentially_nsfw")
	}

	return &DetectionResult{
		IsNSFW:     isNSFW,
		Confidence: confidence,
		Categories: categories,
		Scores:     scores,
		Metadata: map[string]any{
			"detector":     "image",
			"content_size": contentSize,
			"threshold":    d.imageDetector.threshold,
		},
	}, nil
}

func (d *Detector) detectVideoNSFW(ctx context.Context, req *DetectionRequest) (*DetectionResult, error) {
	if !d.videoDetector.enabled {
		return &DetectionResult{
			IsNSFW:     false,
			Confidence: 0.0,
			Categories: []string{},
			Scores:     make(map[string]float64),
			Metadata:   map[string]any{"detector": "video", "enabled": false},
		}, nil
	}

	// Simulate video analysis
	confidence := 0.0
	categories := []string{}
	scores := make(map[string]float64)

	// Simulate frame-by-frame analysis
	contentSize := len(req.Content)
	if contentSize > 10*1024*1024 { // Large videos
		confidence += 0.05
	}

	scores["nudity"] = 0.03
	scores["sexual_activity"] = 0.02
	scores["suggestive"] = 0.01

	isNSFW := confidence > d.videoDetector.threshold

	if isNSFW {
		categories = append(categories, "potentially_nsfw")
	}

	return &DetectionResult{
		IsNSFW:     isNSFW,
		Confidence: confidence,
		Categories: categories,
		Scores:     scores,
		Metadata: map[string]any{
			"detector":     "video",
			"content_size": contentSize,
			"threshold":    d.videoDetector.threshold,
		},
	}, nil
}

func (d *Detector) detectTextNSFW(ctx context.Context, req *DetectionRequest) (*DetectionResult, error) {
	if !d.textDetector.enabled {
		return &DetectionResult{
			IsNSFW:     false,
			Confidence: 0.0,
			Categories: []string{},
			Scores:     make(map[string]float64),
			Metadata:   map[string]any{"detector": "text", "enabled": false},
		}, nil
	}

	content := string(req.Content)
	confidence := 0.0
	categories := []string{}
	scores := make(map[string]float64)

	// Check for NSFW keywords
	keywordMatches := 0
	for _, keyword := range d.textDetector.keywords {
		if contains(content, keyword) {
			keywordMatches++
			confidence += 0.2
		}
	}

	scores["explicit_language"] = float64(keywordMatches) * 0.1
	scores["sexual_content"] = confidence * 0.5

	isNSFW := confidence > d.textDetector.threshold

	if isNSFW {
		categories = append(categories, "explicit_text")
	}

	return &DetectionResult{
		IsNSFW:     isNSFW,
		Confidence: confidence,
		Categories: categories,
		Scores:     scores,
		Metadata: map[string]any{
			"detector":        "text",
			"content_length":  len(content),
			"keyword_matches": keywordMatches,
			"threshold":       d.textDetector.threshold,
		},
	}, nil
}

func (d *Detector) detectAudioNSFW(ctx context.Context, req *DetectionRequest) (*DetectionResult, error) {
	if !d.audioDetector.enabled {
		return &DetectionResult{
			IsNSFW:     false,
			Confidence: 0.0,
			Categories: []string{},
			Scores:     make(map[string]float64),
			Metadata:   map[string]any{"detector": "audio", "enabled": false},
		}, nil
	}

	// Simulate audio analysis
	confidence := 0.0
	categories := []string{}
	scores := make(map[string]float64)

	// Simulate audio processing
	contentSize := len(req.Content)

	scores["explicit_audio"] = 0.01
	scores["sexual_sounds"] = 0.005

	isNSFW := confidence > d.audioDetector.threshold

	if isNSFW {
		categories = append(categories, "potentially_nsfw_audio")
	}

	return &DetectionResult{
		IsNSFW:     isNSFW,
		Confidence: confidence,
		Categories: categories,
		Scores:     scores,
		Metadata: map[string]any{
			"detector":     "audio",
			"content_size": contentSize,
			"threshold":    d.audioDetector.threshold,
		},
	}, nil
}

func (d *Detector) generateContentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func (d *Detector) getCachedResult(hash string) *DetectionResult {
	d.cacheMutex.RLock()
	defer d.cacheMutex.RUnlock()

	cached, exists := d.cache[hash]
	if !exists {
		return nil
	}

	// Check if cache entry is still valid
	if time.Since(cached.Timestamp) > d.config.CacheTTL {
		delete(d.cache, hash)
		return nil
	}

	return cached.Result
}

func (d *Detector) cacheResult(hash string, result *DetectionResult) {
	d.cacheMutex.Lock()
	defer d.cacheMutex.Unlock()

	d.cache[hash] = &CachedResult{
		Result:    result,
		Timestamp: time.Now(),
		Hash:      hash,
	}
}

func (d *Detector) cacheCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.cleanupCache()
	}
}

func (d *Detector) cleanupCache() {
	d.cacheMutex.Lock()
	defer d.cacheMutex.Unlock()

	now := time.Now()
	for hash, cached := range d.cache {
		if now.Sub(cached.Timestamp) > d.config.CacheTTL {
			delete(d.cache, hash)
		}
	}
}

func (d *Detector) updateMetrics(operation string, duration time.Duration) {
	d.cacheMutex.Lock()
	defer d.cacheMutex.Unlock()

	switch operation {
	case "detection_completed":
		d.metrics.TotalDetections++
		if d.metrics.TotalDetections == 1 {
			d.metrics.AverageProcessTime = duration
		} else {
			d.metrics.AverageProcessTime = (d.metrics.AverageProcessTime + duration) / 2
		}
		d.metrics.LastDetection = time.Now()
	case "nsfw_detected":
		d.metrics.NSFWDetections++
	case "safe_detected":
		d.metrics.SafeDetections++
	case "cache_hit":
		d.metrics.CacheHits++
	case "cache_miss":
		d.metrics.CacheMisses++
	}
}

// Utility functions

func contains(text, substring string) bool {
	return len(text) >= len(substring) &&
		(text == substring ||
			(len(text) > len(substring) &&
				(text[:len(substring)] == substring ||
					text[len(text)-len(substring):] == substring ||
					containsSubstring(text, substring))))
}

func containsSubstring(text, substring string) bool {
	for i := 0; i <= len(text)-len(substring); i++ {
		if text[i:i+len(substring)] == substring {
			return true
		}
	}
	return false
}
