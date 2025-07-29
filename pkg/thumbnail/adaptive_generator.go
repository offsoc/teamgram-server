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

package thumbnail

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// AdaptiveGenerator handles adaptive thumbnail generation
type AdaptiveGenerator struct {
	config              *Config
	resizingEngine      *ResizingEngine
	qualityOptimizer    *QualityOptimizer
	formatConverter     *FormatConverter
	aspectRatioManager  *AspectRatioManager
	performanceMonitor  *PerformanceMonitor
	thumbnailCache      *ThumbnailCache
	metrics             *GenerationMetrics
	mutex               sync.RWMutex
	logger              logx.Logger
}

// Config represents thumbnail generator configuration
type Config struct {
	// Size settings
	DefaultSizes        []ThumbnailSize                `json:"default_sizes"`
	MaxSize             ThumbnailSize                  `json:"max_size"`
	MinSize             ThumbnailSize                  `json:"min_size"`
	EnableAdaptiveSizing bool                          `json:"enable_adaptive_sizing"`
	
	// Quality settings
	DefaultQuality      int                            `json:"default_quality"`
	QualityRange        [2]int                         `json:"quality_range"`
	EnableQualityAdaptation bool                       `json:"enable_quality_adaptation"`
	
	// Format settings
	SupportedFormats    []string                       `json:"supported_formats"`
	DefaultFormat       string                         `json:"default_format"`
	EnableFormatOptimization bool                      `json:"enable_format_optimization"`
	
	// Resizing settings
	ResizingAlgorithm   ResizingAlgorithm              `json:"resizing_algorithm"`
	EnableSharpening    bool                           `json:"enable_sharpening"`
	PreserveAspectRatio bool                           `json:"preserve_aspect_ratio"`
	
	// Performance settings
	MaxConcurrency      int                            `json:"max_concurrency"`
	GenerationTimeout   time.Duration                  `json:"generation_timeout"`
	CacheSize           int64                          `json:"cache_size"`
	CacheExpiry         time.Duration                  `json:"cache_expiry"`
	
	// Progressive settings
	EnableProgressive   bool                           `json:"enable_progressive"`
	ProgressiveSizes    []ThumbnailSize                `json:"progressive_sizes"`
}

// ThumbnailSize represents thumbnail dimensions
type ThumbnailSize struct {
	Width               int                            `json:"width"`
	Height              int                            `json:"height"`
	Name                string                         `json:"name"`
	AspectRatio         float64                        `json:"aspect_ratio"`
	Quality             int                            `json:"quality"`
	Format              string                         `json:"format"`
}

// Thumbnail represents a generated thumbnail
type Thumbnail struct {
	Width               int                            `json:"width"`
	Height              int                            `json:"height"`
	Data                []byte                         `json:"data"`
	Format              string                         `json:"format"`
	Quality             int                            `json:"quality"`
	Size                int64                          `json:"size"`
	AspectRatio         float64                        `json:"aspect_ratio"`
	GenerationTime      time.Duration                  `json:"generation_time"`
	CompressionRatio    float64                        `json:"compression_ratio"`
}

// ResizingEngine handles image resizing
type ResizingEngine struct {
	algorithms          map[ResizingAlgorithm]*ResizingAlgorithmInfo `json:"algorithms"`
	currentAlgorithm    ResizingAlgorithm              `json:"current_algorithm"`
	sharpeningFilter    *SharpeningFilter              `json:"-"`
	qualityPreserver    *QualityPreserver              `json:"-"`
	performanceMetrics  *ResizingMetrics               `json:"performance_metrics"`
	mutex               sync.RWMutex
}

// QualityOptimizer optimizes thumbnail quality
type QualityOptimizer struct {
	qualityPresets      map[string]*QualityPreset      `json:"quality_presets"`
	adaptiveQuality     *AdaptiveQualityEngine         `json:"-"`
	qualityAnalyzer     *QualityAnalyzer               `json:"-"`
	optimizationHistory []*OptimizationEvent           `json:"optimization_history"`
	mutex               sync.RWMutex
}

// AspectRatioManager manages aspect ratio preservation
type AspectRatioManager struct {
	commonRatios        []AspectRatio                  `json:"common_ratios"`
	croppingStrategies  map[string]*CroppingStrategy   `json:"cropping_strategies"`
	paddingStrategies   map[string]*PaddingStrategy    `json:"padding_strategies"`
	adaptiveStrategy    *AdaptiveAspectStrategy        `json:"-"`
	mutex               sync.RWMutex
}

// Supporting types
type ResizingAlgorithm string
const (
	ResizingNearestNeighbor ResizingAlgorithm = "nearest_neighbor"
	ResizingBilinear        ResizingAlgorithm = "bilinear"
	ResizingBicubic         ResizingAlgorithm = "bicubic"
	ResizingLanczos         ResizingAlgorithm = "lanczos"
	ResizingMitchell        ResizingAlgorithm = "mitchell"
	ResizingCatmullRom      ResizingAlgorithm = "catmull_rom"
)

type ResizingAlgorithmInfo struct {
	Algorithm           ResizingAlgorithm              `json:"algorithm"`
	Name                string                         `json:"name"`
	QualityScore        float64                        `json:"quality_score"`
	PerformanceScore    float64                        `json:"performance_score"`
	MemoryUsage         int64                          `json:"memory_usage"`
	BestForSizes        []string                       `json:"best_for_sizes"`
	SupportsSharpening  bool                           `json:"supports_sharpening"`
}

type QualityPreset struct {
	Name                string                         `json:"name"`
	Quality             int                            `json:"quality"`
	Sharpening          float64                        `json:"sharpening"`
	NoiseReduction      float64                        `json:"noise_reduction"`
	ColorOptimization   bool                           `json:"color_optimization"`
	TargetFileSize      int64                          `json:"target_file_size"`
	MaxQualityLoss      float64                        `json:"max_quality_loss"`
}

type OptimizationEvent struct {
	Timestamp           time.Time                      `json:"timestamp"`
	OriginalSize        ThumbnailSize                  `json:"original_size"`
	TargetSize          ThumbnailSize                  `json:"target_size"`
	QualityLoss         float64                        `json:"quality_loss"`
	CompressionRatio    float64                        `json:"compression_ratio"`
	GenerationTime      time.Duration                  `json:"generation_time"`
	Algorithm           ResizingAlgorithm              `json:"algorithm"`
}

type AspectRatio struct {
	Ratio               float64                        `json:"ratio"`
	Name                string                         `json:"name"`
	CommonSizes         []ThumbnailSize                `json:"common_sizes"`
	IsStandard          bool                           `json:"is_standard"`
}

type CroppingStrategy struct {
	Name                string                         `json:"name"`
	Description         string                         `json:"description"`
	FocusPoint          [2]float64                     `json:"focus_point"`
	PreserveFaces       bool                           `json:"preserve_faces"`
	PreserveCenter      bool                           `json:"preserve_center"`
	SmartCropping       bool                           `json:"smart_cropping"`
}

type PaddingStrategy struct {
	Name                string                         `json:"name"`
	Description         string                         `json:"description"`
	PaddingColor        [3]int                         `json:"padding_color"`
	BlurBackground      bool                           `json:"blur_background"`
	GradientPadding     bool                           `json:"gradient_padding"`
}

type GenerationMetrics struct {
	TotalGenerated      int64                          `json:"total_generated"`
	TotalBytes          int64                          `json:"total_bytes"`
	AverageGenerationTime time.Duration                `json:"average_generation_time"`
	AverageQualityLoss  float64                        `json:"average_quality_loss"`
	AverageCompressionRatio float64                    `json:"average_compression_ratio"`
	SuccessRate         float64                        `json:"success_rate"`
	CacheHitRate        float64                        `json:"cache_hit_rate"`
	StartTime           time.Time                      `json:"start_time"`
	LastUpdate          time.Time                      `json:"last_update"`
}

type ResizingMetrics struct {
	AlgorithmUsage      map[ResizingAlgorithm]int64    `json:"algorithm_usage"`
	AverageProcessingTime map[ResizingAlgorithm]time.Duration `json:"average_processing_time"`
	QualityScores       map[ResizingAlgorithm]float64  `json:"quality_scores"`
	LastUpdate          time.Time                      `json:"last_update"`
}

// Stub types for complex components
type SharpeningFilter struct{}
type QualityPreserver struct{}
type AdaptiveQualityEngine struct{}
type QualityAnalyzer struct{}
type AdaptiveAspectStrategy struct{}
type PerformanceMonitor struct{}
type ThumbnailCache struct{}
type FormatConverter struct{}

// NewAdaptiveGenerator creates a new adaptive thumbnail generator
func NewAdaptiveGenerator(config *Config) (*AdaptiveGenerator, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	generator := &AdaptiveGenerator{
		config: config,
		metrics: &GenerationMetrics{
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}
	
	// Initialize resizing engine
	generator.resizingEngine = &ResizingEngine{
		algorithms:         make(map[ResizingAlgorithm]*ResizingAlgorithmInfo),
		currentAlgorithm:   config.ResizingAlgorithm,
		sharpeningFilter:   &SharpeningFilter{},
		qualityPreserver:   &QualityPreserver{},
		performanceMetrics: &ResizingMetrics{
			AlgorithmUsage:        make(map[ResizingAlgorithm]int64),
			AverageProcessingTime: make(map[ResizingAlgorithm]time.Duration),
			QualityScores:         make(map[ResizingAlgorithm]float64),
		},
	}
	generator.initializeResizingAlgorithms()
	
	// Initialize quality optimizer
	generator.qualityOptimizer = &QualityOptimizer{
		qualityPresets:      make(map[string]*QualityPreset),
		adaptiveQuality:     &AdaptiveQualityEngine{},
		qualityAnalyzer:     &QualityAnalyzer{},
		optimizationHistory: make([]*OptimizationEvent, 0),
	}
	generator.initializeQualityPresets()
	
	// Initialize aspect ratio manager
	generator.aspectRatioManager = &AspectRatioManager{
		commonRatios:       make([]AspectRatio, 0),
		croppingStrategies: make(map[string]*CroppingStrategy),
		paddingStrategies:  make(map[string]*PaddingStrategy),
		adaptiveStrategy:   &AdaptiveAspectStrategy{},
	}
	generator.initializeAspectRatios()
	
	// Initialize format converter
	generator.formatConverter = &FormatConverter{}
	
	// Initialize performance monitor
	generator.performanceMonitor = &PerformanceMonitor{}
	
	// Initialize thumbnail cache
	if config.CacheSize > 0 {
		generator.thumbnailCache = &ThumbnailCache{}
	}
	
	return generator, nil
}

// GenerateAdaptiveThumbnails generates adaptive thumbnails for multiple sizes
func (g *AdaptiveGenerator) GenerateAdaptiveThumbnails(ctx context.Context, imageData []byte, sizes []ThumbnailSize) ([]*Thumbnail, error) {
	startTime := time.Now()
	
	g.logger.Infof("Generating adaptive thumbnails: sizes=%d, source_size=%d", len(sizes), len(imageData))
	
	thumbnails := make([]*Thumbnail, 0, len(sizes))
	
	// Generate thumbnails for each size
	for _, size := range sizes {
		thumbnail, err := g.generateSingleThumbnail(ctx, imageData, size)
		if err != nil {
			g.logger.Errorf("Failed to generate thumbnail for size %dx%d: %v", size.Width, size.Height, err)
			continue
		}
		
		thumbnails = append(thumbnails, thumbnail)
	}
	
	// Update metrics
	totalTime := time.Since(startTime)
	g.updateGenerationMetrics(len(thumbnails), totalTime, len(thumbnails) == len(sizes))
	
	// Log performance
	g.logGenerationMetrics(sizes, thumbnails, totalTime)
	
	return thumbnails, nil
}

// generateSingleThumbnail generates a single thumbnail
func (g *AdaptiveGenerator) generateSingleThumbnail(ctx context.Context, imageData []byte, size ThumbnailSize) (*Thumbnail, error) {
	startTime := time.Now()
	
	// Check cache first
	cacheKey := g.generateCacheKey(imageData, size)
	if g.thumbnailCache != nil {
		if cached := g.checkCache(cacheKey); cached != nil {
			g.updateCacheMetrics(true)
			return cached, nil
		}
		g.updateCacheMetrics(false)
	}
	
	// Optimize thumbnail parameters
	optimizedSize := g.optimizeThumbnailSize(size, imageData)
	
	// Select optimal resizing algorithm
	algorithm := g.selectOptimalResizingAlgorithm(optimizedSize)
	
	// Generate thumbnail
	thumbnailData, err := g.resizeImage(imageData, optimizedSize, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to resize image: %w", err)
	}
	
	// Apply post-processing
	if g.config.EnableSharpening {
		thumbnailData, err = g.applySharpeningFilter(thumbnailData)
		if err != nil {
			g.logger.Errorf("Sharpening failed: %v", err)
		}
	}
	
	// Optimize quality
	if g.config.EnableQualityAdaptation {
		thumbnailData, err = g.optimizeQuality(thumbnailData, optimizedSize)
		if err != nil {
			g.logger.Errorf("Quality optimization failed: %v", err)
		}
	}
	
	// Create thumbnail object
	thumbnail := &Thumbnail{
		Width:            optimizedSize.Width,
		Height:           optimizedSize.Height,
		Data:             thumbnailData,
		Format:           optimizedSize.Format,
		Quality:          optimizedSize.Quality,
		Size:             int64(len(thumbnailData)),
		AspectRatio:      optimizedSize.AspectRatio,
		GenerationTime:   time.Since(startTime),
		CompressionRatio: float64(len(thumbnailData)) / float64(len(imageData)),
	}
	
	// Cache result
	if g.thumbnailCache != nil {
		g.cacheResult(cacheKey, thumbnail)
	}
	
	// Update algorithm metrics
	g.updateAlgorithmMetrics(algorithm, time.Since(startTime), true)
	
	return thumbnail, nil
}

// initializeResizingAlgorithms initializes resizing algorithms
func (g *AdaptiveGenerator) initializeResizingAlgorithms() {
	g.resizingEngine.algorithms[ResizingNearestNeighbor] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingNearestNeighbor,
		Name:               "Nearest Neighbor",
		QualityScore:       0.3,
		PerformanceScore:   1.0,
		MemoryUsage:        10 * 1024 * 1024, // 10MB
		BestForSizes:       []string{"small"},
		SupportsSharpening: false,
	}
	
	g.resizingEngine.algorithms[ResizingBilinear] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingBilinear,
		Name:               "Bilinear",
		QualityScore:       0.6,
		PerformanceScore:   0.8,
		MemoryUsage:        20 * 1024 * 1024, // 20MB
		BestForSizes:       []string{"small", "medium"},
		SupportsSharpening: true,
	}
	
	g.resizingEngine.algorithms[ResizingBicubic] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingBicubic,
		Name:               "Bicubic",
		QualityScore:       0.8,
		PerformanceScore:   0.6,
		MemoryUsage:        40 * 1024 * 1024, // 40MB
		BestForSizes:       []string{"medium", "large"},
		SupportsSharpening: true,
	}
	
	g.resizingEngine.algorithms[ResizingLanczos] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingLanczos,
		Name:               "Lanczos",
		QualityScore:       0.95,
		PerformanceScore:   0.4,
		MemoryUsage:        60 * 1024 * 1024, // 60MB
		BestForSizes:       []string{"large", "extra_large"},
		SupportsSharpening: true,
	}
	
	g.resizingEngine.algorithms[ResizingMitchell] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingMitchell,
		Name:               "Mitchell",
		QualityScore:       0.9,
		PerformanceScore:   0.5,
		MemoryUsage:        50 * 1024 * 1024, // 50MB
		BestForSizes:       []string{"medium", "large"},
		SupportsSharpening: true,
	}
	
	g.resizingEngine.algorithms[ResizingCatmullRom] = &ResizingAlgorithmInfo{
		Algorithm:          ResizingCatmullRom,
		Name:               "Catmull-Rom",
		QualityScore:       0.85,
		PerformanceScore:   0.7,
		MemoryUsage:        30 * 1024 * 1024, // 30MB
		BestForSizes:       []string{"small", "medium", "large"},
		SupportsSharpening: true,
	}
}

// initializeQualityPresets initializes quality presets
func (g *AdaptiveGenerator) initializeQualityPresets() {
	g.qualityOptimizer.qualityPresets["ultra"] = &QualityPreset{
		Name:               "ultra",
		Quality:            95,
		Sharpening:         0.3,
		NoiseReduction:     0.1,
		ColorOptimization:  true,
		TargetFileSize:     0, // No size limit
		MaxQualityLoss:     0.01, // 1%
	}
	
	g.qualityOptimizer.qualityPresets["high"] = &QualityPreset{
		Name:               "high",
		Quality:            85,
		Sharpening:         0.2,
		NoiseReduction:     0.2,
		ColorOptimization:  true,
		TargetFileSize:     500 * 1024, // 500KB
		MaxQualityLoss:     0.03, // 3%
	}
	
	g.qualityOptimizer.qualityPresets["medium"] = &QualityPreset{
		Name:               "medium",
		Quality:            75,
		Sharpening:         0.1,
		NoiseReduction:     0.3,
		ColorOptimization:  false,
		TargetFileSize:     200 * 1024, // 200KB
		MaxQualityLoss:     0.05, // 5%
	}
	
	g.qualityOptimizer.qualityPresets["low"] = &QualityPreset{
		Name:               "low",
		Quality:            60,
		Sharpening:         0.0,
		NoiseReduction:     0.4,
		ColorOptimization:  false,
		TargetFileSize:     100 * 1024, // 100KB
		MaxQualityLoss:     0.1, // 10%
	}
}

// initializeAspectRatios initializes common aspect ratios
func (g *AdaptiveGenerator) initializeAspectRatios() {
	g.aspectRatioManager.commonRatios = []AspectRatio{
		{Ratio: 1.0, Name: "1:1 (Square)", IsStandard: true},
		{Ratio: 4.0/3.0, Name: "4:3 (Standard)", IsStandard: true},
		{Ratio: 16.0/9.0, Name: "16:9 (Widescreen)", IsStandard: true},
		{Ratio: 3.0/2.0, Name: "3:2 (Photo)", IsStandard: true},
		{Ratio: 21.0/9.0, Name: "21:9 (Ultrawide)", IsStandard: false},
	}
	
	// Initialize cropping strategies
	g.aspectRatioManager.croppingStrategies["center"] = &CroppingStrategy{
		Name:           "Center Crop",
		Description:    "Crop from the center of the image",
		FocusPoint:     [2]float64{0.5, 0.5},
		PreserveFaces:  false,
		PreserveCenter: true,
		SmartCropping:  false,
	}
	
	g.aspectRatioManager.croppingStrategies["smart"] = &CroppingStrategy{
		Name:           "Smart Crop",
		Description:    "Intelligently crop based on content analysis",
		FocusPoint:     [2]float64{0.5, 0.5},
		PreserveFaces:  true,
		PreserveCenter: false,
		SmartCropping:  true,
	}
	
	// Initialize padding strategies
	g.aspectRatioManager.paddingStrategies["solid"] = &PaddingStrategy{
		Name:            "Solid Color",
		Description:     "Pad with solid color",
		PaddingColor:    [3]int{255, 255, 255}, // White
		BlurBackground:  false,
		GradientPadding: false,
	}
	
	g.aspectRatioManager.paddingStrategies["blur"] = &PaddingStrategy{
		Name:            "Blurred Background",
		Description:     "Pad with blurred version of the image",
		PaddingColor:    [3]int{0, 0, 0},
		BlurBackground:  true,
		GradientPadding: false,
	}
}

// Helper methods
func (g *AdaptiveGenerator) optimizeThumbnailSize(size ThumbnailSize, imageData []byte) ThumbnailSize {
	optimized := size
	
	// Set default quality if not specified
	if optimized.Quality == 0 {
		optimized.Quality = g.config.DefaultQuality
	}
	
	// Set default format if not specified
	if optimized.Format == "" {
		optimized.Format = g.config.DefaultFormat
	}
	
	// Calculate aspect ratio if not set
	if optimized.AspectRatio == 0 {
		optimized.AspectRatio = float64(optimized.Width) / float64(optimized.Height)
	}
	
	// Adaptive sizing based on source image characteristics
	if g.config.EnableAdaptiveSizing {
		// Analyze source image and adjust size accordingly
		// This would involve actual image analysis
	}
	
	return optimized
}

func (g *AdaptiveGenerator) selectOptimalResizingAlgorithm(size ThumbnailSize) ResizingAlgorithm {
	// Select algorithm based on size and quality requirements
	if size.Width <= 64 || size.Height <= 64 {
		return ResizingBilinear // Fast for small thumbnails
	} else if size.Width <= 256 || size.Height <= 256 {
		return ResizingBicubic // Balanced for medium thumbnails
	} else {
		return ResizingLanczos // High quality for large thumbnails
	}
}

func (g *AdaptiveGenerator) resizeImage(imageData []byte, size ThumbnailSize, algorithm ResizingAlgorithm) ([]byte, error) {
	// Image resizing implementation would go here
	g.logger.Infof("Resizing image: algorithm=%s, target=%dx%d", algorithm, size.Width, size.Height)
	
	// For now, return a simplified result
	resizedData := make([]byte, len(imageData)/4) // Simulate 4x compression
	copy(resizedData, imageData[:len(resizedData)])
	
	return resizedData, nil
}

func (g *AdaptiveGenerator) applySharpeningFilter(imageData []byte) ([]byte, error) {
	// Sharpening filter implementation would go here
	g.logger.Infof("Applying sharpening filter")
	
	// For now, return the image unchanged
	return imageData, nil
}

func (g *AdaptiveGenerator) optimizeQuality(imageData []byte, size ThumbnailSize) ([]byte, error) {
	// Quality optimization implementation would go here
	g.logger.Infof("Optimizing quality: target_quality=%d", size.Quality)
	
	// For now, return the image unchanged
	return imageData, nil
}

func (g *AdaptiveGenerator) generateCacheKey(imageData []byte, size ThumbnailSize) string {
	return fmt.Sprintf("%dx%d_%d_%s_%x", size.Width, size.Height, size.Quality, size.Format, imageData[:min(len(imageData), 32)])
}

func (g *AdaptiveGenerator) checkCache(key string) *Thumbnail {
	// Cache checking implementation would go here
	return nil
}

func (g *AdaptiveGenerator) cacheResult(key string, thumbnail *Thumbnail) {
	// Cache storing implementation would go here
}

func (g *AdaptiveGenerator) updateCacheMetrics(hit bool) {
	// Cache metrics update implementation would go here
}

func (g *AdaptiveGenerator) updateAlgorithmMetrics(algorithm ResizingAlgorithm, duration time.Duration, success bool) {
	g.resizingEngine.mutex.Lock()
	defer g.resizingEngine.mutex.Unlock()
	
	g.resizingEngine.performanceMetrics.AlgorithmUsage[algorithm]++
	g.resizingEngine.performanceMetrics.AverageProcessingTime[algorithm] = 
		(g.resizingEngine.performanceMetrics.AverageProcessingTime[algorithm] + duration) / 2
	g.resizingEngine.performanceMetrics.LastUpdate = time.Now()
}

func (g *AdaptiveGenerator) updateGenerationMetrics(generated int, duration time.Duration, success bool) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	
	g.metrics.TotalGenerated += int64(generated)
	g.metrics.AverageGenerationTime = (g.metrics.AverageGenerationTime + duration) / 2
	
	if success {
		g.metrics.SuccessRate = (g.metrics.SuccessRate + 1.0) / 2.0
	} else {
		g.metrics.SuccessRate = (g.metrics.SuccessRate + 0.0) / 2.0
	}
	
	g.metrics.LastUpdate = time.Now()
}

func (g *AdaptiveGenerator) logGenerationMetrics(sizes []ThumbnailSize, thumbnails []*Thumbnail, duration time.Duration) {
	totalSize := int64(0)
	for _, thumbnail := range thumbnails {
		totalSize += thumbnail.Size
	}
	
	g.logger.Infof("Thumbnail generation metrics: sizes=%d, generated=%d, total_size=%d, time=%v", 
		len(sizes), len(thumbnails), totalSize, duration)
}

// DefaultConfig returns default thumbnail generator configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultSizes: []ThumbnailSize{
			{Width: 64, Height: 64, Name: "small", Quality: 75, Format: "jpeg"},
			{Width: 128, Height: 128, Name: "medium", Quality: 80, Format: "jpeg"},
			{Width: 256, Height: 256, Name: "large", Quality: 85, Format: "jpeg"},
			{Width: 512, Height: 512, Name: "extra_large", Quality: 90, Format: "jpeg"},
		},
		MaxSize:                 ThumbnailSize{Width: 1024, Height: 1024},
		MinSize:                 ThumbnailSize{Width: 16, Height: 16},
		EnableAdaptiveSizing:    true,
		DefaultQuality:          80,
		QualityRange:            [2]int{50, 95},
		EnableQualityAdaptation: true,
		SupportedFormats:        []string{"jpeg", "png", "webp"},
		DefaultFormat:           "jpeg",
		EnableFormatOptimization: true,
		ResizingAlgorithm:       ResizingBicubic,
		EnableSharpening:        true,
		PreserveAspectRatio:     true,
		MaxConcurrency:          8,
		GenerationTimeout:       30 * time.Second,
		CacheSize:               100 * 1024 * 1024, // 100MB
		CacheExpiry:             1 * time.Hour,
		EnableProgressive:       true,
		ProgressiveSizes: []ThumbnailSize{
			{Width: 32, Height: 32, Name: "micro", Quality: 70, Format: "jpeg"},
			{Width: 64, Height: 64, Name: "tiny", Quality: 75, Format: "jpeg"},
			{Width: 128, Height: 128, Name: "small", Quality: 80, Format: "jpeg"},
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
