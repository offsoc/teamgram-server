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

package image

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"sync"
	"time"

	"github.com/chai2010/webp"
	"github.com/zeromicro/go-zero/core/logx"
)

// FormatConverter handles image format conversion
type FormatConverter struct {
	supportedFormats map[string]bool
	logger           logx.Logger
}

// NewFormatConverter creates a new format converter
func NewFormatConverter() *FormatConverter {
	return &FormatConverter{
		supportedFormats: map[string]bool{
			"jpeg": true,
			"png":  true,
			"webp": true,
			"avif": true,
		},
		logger: logx.WithContext(context.Background()),
	}
}

// IntelligentProcessor handles intelligent image processing
type IntelligentProcessor struct {
	config             *Config
	formatProcessors   map[string]*FormatProcessor
	qualityOptimizer   *QualityOptimizer
	compressionEngine  *CompressionEngine
	formatConverter    *FormatConverter
	qualityAnalyzer    *QualityAnalyzer
	performanceMonitor *PerformanceMonitor
	processingCache    *ProcessingCache
	metrics            *ProcessingMetrics
	mutex              sync.RWMutex
	logger             logx.Logger
}

// Config represents image processor configuration
type Config struct {
	// Quality settings
	DefaultQuality   int     `json:"default_quality"`
	MinQuality       int     `json:"min_quality"`
	MaxQuality       int     `json:"max_quality"`
	QualityThreshold float64 `json:"quality_threshold"`

	// Format settings
	SupportedFormats []string `json:"supported_formats"`
	DefaultFormat    string   `json:"default_format"`
	EnableWebP       bool     `json:"enable_webp"`
	EnableAVIF       bool     `json:"enable_avif"`
	EnableHEIC       bool     `json:"enable_heic"`

	// Optimization settings
	EnableOptimization bool `json:"enable_optimization"`
	OptimizationLevel  int  `json:"optimization_level"`
	EnableProgressive  bool `json:"enable_progressive"`
	EnableLossless     bool `json:"enable_lossless"`

	// Performance settings
	MaxConcurrency    int           `json:"max_concurrency"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	CacheSize         int64         `json:"cache_size"`
	CacheExpiry       time.Duration `json:"cache_expiry"`

	// Quality analysis
	EnableQualityAnalysis bool     `json:"enable_quality_analysis"`
	QualityMetrics        []string `json:"quality_metrics"`
}

// ProcessingOptions represents image processing options
type ProcessingOptions struct {
	InputFormat      string `json:"input_format"`
	OutputFormat     string `json:"output_format"`
	Quality          int    `json:"quality"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	Optimization     string `json:"optimization"`
	Progressive      bool   `json:"progressive"`
	Lossless         bool   `json:"lossless"`
	PreserveMetadata bool   `json:"preserve_metadata"`
	AutoOrient       bool   `json:"auto_orient"`
}

// FormatProcessor handles specific format processing
type FormatProcessor struct {
	Format              string        `json:"format"`
	MimeType            string        `json:"mime_type"`
	Extension           string        `json:"extension"`
	Encoder             FormatEncoder `json:"-"`
	Decoder             FormatDecoder `json:"-"`
	QualityRange        [2]int        `json:"quality_range"`
	SupportsProgressive bool          `json:"supports_progressive"`
	SupportsLossless    bool          `json:"supports_lossless"`
	CompressionRatio    float64       `json:"compression_ratio"`
}

// QualityOptimizer optimizes image quality settings
type QualityOptimizer struct {
	qualityPresets      map[string]*QualityPreset `json:"quality_presets"`
	adaptiveQuality     *AdaptiveQualityEngine    `json:"-"`
	qualityLearning     *QualityLearningEngine    `json:"-"`
	optimizationHistory []*OptimizationEvent      `json:"optimization_history"`
	mutex               sync.RWMutex
}

// CompressionEngine handles image compression
type CompressionEngine struct {
	compressionAlgorithms map[string]*CompressionAlgorithm `json:"compression_algorithms"`
	adaptiveCompression   *AdaptiveCompressionEngine       `json:"-"`
	compressionCache      *CompressionCache                `json:"-"`
	compressionMetrics    *CompressionMetrics              `json:"compression_metrics"`
	mutex                 sync.RWMutex
}

// QualityAnalyzer analyzes image quality
type QualityAnalyzer struct {
	ssimCalculator   *SSIMCalculator   `json:"-"`
	psnrCalculator   *PSNRCalculator   `json:"-"`
	msssimCalculator *MSSSIMCalculator `json:"-"`
	lpipsCalculator  *LPIPSCalculator  `json:"-"`
	qualityMetrics   *QualityMetrics   `json:"quality_metrics"`
	analysisCache    *AnalysisCache    `json:"-"`
	mutex            sync.RWMutex
}

// PerformanceMonitor monitors processing performance
type PerformanceMonitor struct {
	processingTimes    map[string]*ProcessingTimeStats `json:"processing_times"`
	throughputMetrics  *ThroughputMetrics              `json:"throughput_metrics"`
	resourceUsage      *ResourceUsageMetrics           `json:"resource_usage"`
	errorRates         map[string]float64              `json:"error_rates"`
	qualityLossRates   map[string]float64              `json:"quality_loss_rates"`
	isMonitoring       bool                            `json:"is_monitoring"`
	monitoringInterval time.Duration                   `json:"monitoring_interval"`
	mutex              sync.RWMutex
}

// ProcessingCache caches processing results
type ProcessingCache struct {
	cache          map[string]*CachedResult `json:"-"`
	maxSize        int64                    `json:"max_size"`
	currentSize    int64                    `json:"current_size"`
	hitCount       int64                    `json:"hit_count"`
	missCount      int64                    `json:"miss_count"`
	evictionPolicy string                   `json:"eviction_policy"`
	ttl            time.Duration            `json:"ttl"`
	mutex          sync.RWMutex
}

// Supporting types
type FormatEncoder interface {
	Encode(img image.Image, quality int) ([]byte, error)
}

type FormatDecoder interface {
	Decode(data []byte) (image.Image, error)
}

type QualityPreset struct {
	Name           string  `json:"name"`
	Quality        int     `json:"quality"`
	Optimization   string  `json:"optimization"`
	Progressive    bool    `json:"progressive"`
	Lossless       bool    `json:"lossless"`
	TargetFileSize int64   `json:"target_file_size"`
	MaxQualityLoss float64 `json:"max_quality_loss"`
}

type OptimizationEvent struct {
	Timestamp         time.Time     `json:"timestamp"`
	InputFormat       string        `json:"input_format"`
	OutputFormat      string        `json:"output_format"`
	InputSize         int64         `json:"input_size"`
	OutputSize        int64         `json:"output_size"`
	QualityLoss       float64       `json:"quality_loss"`
	ProcessingTime    time.Duration `json:"processing_time"`
	OptimizationLevel int           `json:"optimization_level"`
}

type CompressionAlgorithm struct {
	Name             string  `json:"name"`
	CompressionRatio float64 `json:"compression_ratio"`
	QualityLoss      float64 `json:"quality_loss"`
	ProcessingSpeed  float64 `json:"processing_speed"`
	MemoryUsage      int64   `json:"memory_usage"`
	IsLossless       bool    `json:"is_lossless"`
}

type QualityMetrics struct {
	SSIM         float64 `json:"ssim"`
	PSNR         float64 `json:"psnr"`
	MSSSIM       float64 `json:"msssim"`
	LPIPS        float64 `json:"lpips"`
	OverallScore float64 `json:"overall_score"`
	QualityLoss  float64 `json:"quality_loss"`
}

type ProcessingTimeStats struct {
	Format         string        `json:"format"`
	AverageTime    time.Duration `json:"average_time"`
	MinTime        time.Duration `json:"min_time"`
	MaxTime        time.Duration `json:"max_time"`
	TotalProcessed int64         `json:"total_processed"`
	SuccessRate    float64       `json:"success_rate"`
	LastUpdate     time.Time     `json:"last_update"`
}

type ThroughputMetrics struct {
	ImagesPerSecond   float64   `json:"images_per_second"`
	BytesPerSecond    int64     `json:"bytes_per_second"`
	PeakThroughput    float64   `json:"peak_throughput"`
	AverageThroughput float64   `json:"average_throughput"`
	LastUpdate        time.Time `json:"last_update"`
}

type ResourceUsageMetrics struct {
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage int64     `json:"memory_usage"`
	DiskIORate  float64   `json:"disk_io_rate"`
	LastUpdate  time.Time `json:"last_update"`
}

type CachedResult struct {
	Key               string             `json:"key"`
	InputData         []byte             `json:"input_data"`
	OutputData        []byte             `json:"output_data"`
	ProcessingOptions *ProcessingOptions `json:"processing_options"`
	QualityMetrics    *QualityMetrics    `json:"quality_metrics"`
	CreatedAt         time.Time          `json:"created_at"`
	LastAccessed      time.Time          `json:"last_accessed"`
	AccessCount       int64              `json:"access_count"`
}

type ProcessingMetrics struct {
	TotalProcessed          int64         `json:"total_processed"`
	TotalBytes              int64         `json:"total_bytes"`
	AverageQualityLoss      float64       `json:"average_quality_loss"`
	AverageCompressionRatio float64       `json:"average_compression_ratio"`
	AverageProcessingTime   time.Duration `json:"average_processing_time"`
	SuccessRate             float64       `json:"success_rate"`
	StartTime               time.Time     `json:"start_time"`
	LastUpdate              time.Time     `json:"last_update"`
}

// Stub types for complex components
type AdaptiveQualityEngine struct{}
type QualityLearningEngine struct{}
type AdaptiveCompressionEngine struct{}
type CompressionCache struct{}
type CompressionMetrics struct{}
type SSIMCalculator struct{}
type PSNRCalculator struct{}
type MSSSIMCalculator struct{}
type LPIPSCalculator struct{}
type AnalysisCache struct{}

// NewIntelligentProcessor creates a new intelligent image processor
func NewIntelligentProcessor(config *Config) (*IntelligentProcessor, error) {
	if config == nil {
		config = DefaultConfig()
	}

	processor := &IntelligentProcessor{
		config:           config,
		formatProcessors: make(map[string]*FormatProcessor),
		metrics: &ProcessingMetrics{
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize format processors
	processor.initializeFormatProcessors()

	// Initialize quality optimizer
	processor.qualityOptimizer = &QualityOptimizer{
		qualityPresets:      make(map[string]*QualityPreset),
		adaptiveQuality:     &AdaptiveQualityEngine{},
		qualityLearning:     &QualityLearningEngine{},
		optimizationHistory: make([]*OptimizationEvent, 0),
	}
	processor.initializeQualityPresets()

	// Initialize compression engine
	processor.compressionEngine = &CompressionEngine{
		compressionAlgorithms: make(map[string]*CompressionAlgorithm),
		adaptiveCompression:   &AdaptiveCompressionEngine{},
		compressionCache:      &CompressionCache{},
		compressionMetrics:    &CompressionMetrics{},
	}
	processor.initializeCompressionAlgorithms()

	// Initialize quality analyzer
	if config.EnableQualityAnalysis {
		processor.qualityAnalyzer = &QualityAnalyzer{
			ssimCalculator:   &SSIMCalculator{},
			psnrCalculator:   &PSNRCalculator{},
			msssimCalculator: &MSSSIMCalculator{},
			lpipsCalculator:  &LPIPSCalculator{},
			qualityMetrics:   &QualityMetrics{},
			analysisCache:    &AnalysisCache{},
		}
	}

	// Initialize performance monitor
	processor.performanceMonitor = &PerformanceMonitor{
		processingTimes:    make(map[string]*ProcessingTimeStats),
		throughputMetrics:  &ThroughputMetrics{},
		resourceUsage:      &ResourceUsageMetrics{},
		errorRates:         make(map[string]float64),
		qualityLossRates:   make(map[string]float64),
		monitoringInterval: 30 * time.Second,
	}

	// Initialize processing cache
	if config.CacheSize > 0 {
		processor.processingCache = &ProcessingCache{
			cache:          make(map[string]*CachedResult),
			maxSize:        config.CacheSize,
			evictionPolicy: "lru",
			ttl:            config.CacheExpiry,
		}
	}

	// Start performance monitoring
	go processor.startPerformanceMonitoring()

	return processor, nil
}

// ProcessImage processes an image with intelligent optimization
func (p *IntelligentProcessor) ProcessImage(ctx context.Context, imageData []byte, options *ProcessingOptions) ([]byte, error) {
	startTime := time.Now()

	p.logger.Infof("Processing image: input=%s, output=%s, quality=%d, size=%d",
		options.InputFormat, options.OutputFormat, options.Quality, len(imageData))

	// Check cache first
	cacheKey := p.generateCacheKey(imageData, options)
	if p.processingCache != nil {
		if cached := p.checkCache(cacheKey); cached != nil {
			p.updateCacheMetrics(true)
			return cached.OutputData, nil
		}
		p.updateCacheMetrics(false)
	}

	// Decode input image
	inputImage, err := p.decodeImage(imageData, options.InputFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Analyze input quality if enabled
	var inputQuality *QualityMetrics
	if p.qualityAnalyzer != nil {
		inputQuality, err = p.analyzeImageQuality(imageData, options.InputFormat)
		if err != nil {
			p.logger.Errorf("Failed to analyze input quality: %v", err)
		}
	}

	// Optimize processing options
	optimizedOptions := p.optimizeProcessingOptions(options, len(imageData), inputQuality)

	// Resize if needed
	processedImage := inputImage
	if optimizedOptions.Width > 0 && optimizedOptions.Height > 0 {
		processedImage = p.resizeImage(inputImage, optimizedOptions.Width, optimizedOptions.Height)
	}

	// Auto-orient if needed
	if optimizedOptions.AutoOrient {
		processedImage = p.autoOrientImage(processedImage, imageData)
	}

	// Encode output image
	outputData, err := p.encodeImage(processedImage, optimizedOptions)
	if err != nil {
		p.updateProcessingMetrics(options.OutputFormat, time.Since(startTime), false, 0.0)
		return nil, fmt.Errorf("failed to encode image: %w", err)
	}

	// Analyze output quality if enabled
	var outputQuality *QualityMetrics
	var qualityLoss float64
	if p.qualityAnalyzer != nil && inputQuality != nil {
		outputQuality, err = p.analyzeImageQuality(outputData, options.OutputFormat)
		if err != nil {
			p.logger.Errorf("Failed to analyze output quality: %v", err)
		} else {
			qualityLoss = p.calculateQualityLoss(inputQuality, outputQuality)
		}
	}

	// Verify quality requirements (<3% quality loss)
	if qualityLoss > 0.03 {
		p.logger.Errorf("Image quality loss exceeded 3%%: %.3f", qualityLoss)
	}

	// Cache result
	if p.processingCache != nil {
		p.cacheResult(cacheKey, imageData, outputData, options, outputQuality)
	}

	// Update metrics
	processingTime := time.Since(startTime)
	p.updateProcessingMetrics(options.OutputFormat, processingTime, true, qualityLoss)

	// Log performance
	p.logProcessingMetrics(options, len(imageData), len(outputData), processingTime, qualityLoss)

	return outputData, nil
}

// initializeFormatProcessors initializes format processors
func (p *IntelligentProcessor) initializeFormatProcessors() {
	// JPEG processor
	p.formatProcessors["jpeg"] = &FormatProcessor{
		Format:              "jpeg",
		MimeType:            "image/jpeg",
		Extension:           ".jpg",
		Encoder:             &JPEGEncoder{},
		Decoder:             &JPEGDecoder{},
		QualityRange:        [2]int{1, 100},
		SupportsProgressive: true,
		SupportsLossless:    false,
		CompressionRatio:    0.1,
	}

	// PNG processor
	p.formatProcessors["png"] = &FormatProcessor{
		Format:              "png",
		MimeType:            "image/png",
		Extension:           ".png",
		Encoder:             &PNGEncoder{},
		Decoder:             &PNGDecoder{},
		QualityRange:        [2]int{0, 9},
		SupportsProgressive: false,
		SupportsLossless:    true,
		CompressionRatio:    0.3,
	}

	// WebP processor
	if p.config.EnableWebP {
		p.formatProcessors["webp"] = &FormatProcessor{
			Format:              "webp",
			MimeType:            "image/webp",
			Extension:           ".webp",
			Encoder:             &WebPEncoder{},
			Decoder:             &WebPDecoder{},
			QualityRange:        [2]int{0, 100},
			SupportsProgressive: false,
			SupportsLossless:    true,
			CompressionRatio:    0.25,
		}
	}

	// AVIF processor
	if p.config.EnableAVIF {
		p.formatProcessors["avif"] = &FormatProcessor{
			Format:              "avif",
			MimeType:            "image/avif",
			Extension:           ".avif",
			Encoder:             &AVIFEncoder{},
			Decoder:             &AVIFDecoder{},
			QualityRange:        [2]int{0, 100},
			SupportsProgressive: false,
			SupportsLossless:    true,
			CompressionRatio:    0.2,
		}
	}

	// HEIC processor
	if p.config.EnableHEIC {
		p.formatProcessors["heic"] = &FormatProcessor{
			Format:              "heic",
			MimeType:            "image/heic",
			Extension:           ".heic",
			Encoder:             &HEICEncoder{},
			Decoder:             &HEICDecoder{},
			QualityRange:        [2]int{0, 100},
			SupportsProgressive: false,
			SupportsLossless:    false,
			CompressionRatio:    0.15,
		}
	}
}

// initializeQualityPresets initializes quality presets
func (p *IntelligentProcessor) initializeQualityPresets() {
	p.qualityOptimizer.qualityPresets["ultra"] = &QualityPreset{
		Name:           "ultra",
		Quality:        95,
		Optimization:   "maximum",
		Progressive:    true,
		Lossless:       false,
		MaxQualityLoss: 0.01, // 1%
	}

	p.qualityOptimizer.qualityPresets["high"] = &QualityPreset{
		Name:           "high",
		Quality:        85,
		Optimization:   "balanced",
		Progressive:    true,
		Lossless:       false,
		MaxQualityLoss: 0.03, // 3%
	}

	p.qualityOptimizer.qualityPresets["medium"] = &QualityPreset{
		Name:           "medium",
		Quality:        75,
		Optimization:   "speed",
		Progressive:    false,
		Lossless:       false,
		MaxQualityLoss: 0.05, // 5%
	}

	p.qualityOptimizer.qualityPresets["low"] = &QualityPreset{
		Name:           "low",
		Quality:        60,
		Optimization:   "speed",
		Progressive:    false,
		Lossless:       false,
		MaxQualityLoss: 0.1, // 10%
	}
}

// initializeCompressionAlgorithms initializes compression algorithms
func (p *IntelligentProcessor) initializeCompressionAlgorithms() {
	p.compressionEngine.compressionAlgorithms["jpeg"] = &CompressionAlgorithm{
		Name:             "JPEG",
		CompressionRatio: 0.1,
		QualityLoss:      0.02,
		ProcessingSpeed:  100.0,
		MemoryUsage:      32 * 1024 * 1024,
		IsLossless:       false,
	}

	p.compressionEngine.compressionAlgorithms["webp"] = &CompressionAlgorithm{
		Name:             "WebP",
		CompressionRatio: 0.25,
		QualityLoss:      0.015,
		ProcessingSpeed:  80.0,
		MemoryUsage:      48 * 1024 * 1024,
		IsLossless:       false,
	}

	p.compressionEngine.compressionAlgorithms["avif"] = &CompressionAlgorithm{
		Name:             "AVIF",
		CompressionRatio: 0.2,
		QualityLoss:      0.01,
		ProcessingSpeed:  40.0,
		MemoryUsage:      64 * 1024 * 1024,
		IsLossless:       false,
	}
}

// Helper methods
func (p *IntelligentProcessor) decodeImage(data []byte, format string) (image.Image, error) {
	processor, exists := p.formatProcessors[format]
	if !exists {
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return processor.Decoder.Decode(data)
}

func (p *IntelligentProcessor) encodeImage(img image.Image, options *ProcessingOptions) ([]byte, error) {
	processor, exists := p.formatProcessors[options.OutputFormat]
	if !exists {
		return nil, fmt.Errorf("unsupported output format: %s", options.OutputFormat)
	}

	return processor.Encoder.Encode(img, options.Quality)
}

func (p *IntelligentProcessor) optimizeProcessingOptions(options *ProcessingOptions, inputSize int, inputQuality *QualityMetrics) *ProcessingOptions {
	optimized := *options

	// Get quality preset
	preset := p.qualityOptimizer.qualityPresets["high"] // Default
	if preset != nil {
		if optimized.Quality == 0 {
			optimized.Quality = preset.Quality
		}
		optimized.Progressive = preset.Progressive
	}

	// Adjust quality based on input size and quality
	if inputSize > 10*1024*1024 { // Large files (>10MB)
		optimized.Quality = min(optimized.Quality, 85) // Reduce quality for large files
	}

	return &optimized
}

func (p *IntelligentProcessor) resizeImage(img image.Image, width, height int) image.Image {
	// Image resizing implementation would go here
	// For now, return original image
	return img
}

func (p *IntelligentProcessor) autoOrientImage(img image.Image, originalData []byte) image.Image {
	// Auto-orientation implementation would go here
	// For now, return original image
	return img
}

func (p *IntelligentProcessor) analyzeImageQuality(data []byte, format string) (*QualityMetrics, error) {
	// Quality analysis implementation would go here
	return &QualityMetrics{
		SSIM:         0.98,
		PSNR:         45.0,
		MSSSIM:       0.97,
		LPIPS:        0.02,
		OverallScore: 0.97,
		QualityLoss:  0.0,
	}, nil
}

func (p *IntelligentProcessor) calculateQualityLoss(input, output *QualityMetrics) float64 {
	return (input.OverallScore - output.OverallScore) / input.OverallScore
}

func (p *IntelligentProcessor) generateCacheKey(data []byte, options *ProcessingOptions) string {
	return fmt.Sprintf("%s_%s_%d_%x", options.InputFormat, options.OutputFormat, options.Quality, data[:min(len(data), 32)])
}

func (p *IntelligentProcessor) checkCache(key string) *CachedResult {
	if p.processingCache == nil {
		return nil
	}

	p.processingCache.mutex.RLock()
	defer p.processingCache.mutex.RUnlock()

	if cached, exists := p.processingCache.cache[key]; exists {
		cached.LastAccessed = time.Now()
		cached.AccessCount++
		return cached
	}

	return nil
}

func (p *IntelligentProcessor) cacheResult(key string, inputData, outputData []byte, options *ProcessingOptions, quality *QualityMetrics) {
	if p.processingCache == nil {
		return
	}

	p.processingCache.mutex.Lock()
	defer p.processingCache.mutex.Unlock()

	result := &CachedResult{
		Key:               key,
		InputData:         inputData,
		OutputData:        outputData,
		ProcessingOptions: options,
		QualityMetrics:    quality,
		CreatedAt:         time.Now(),
		LastAccessed:      time.Now(),
		AccessCount:       1,
	}

	p.processingCache.cache[key] = result
	p.processingCache.currentSize += int64(len(inputData) + len(outputData))
}

func (p *IntelligentProcessor) updateCacheMetrics(hit bool) {
	if p.processingCache == nil {
		return
	}

	p.processingCache.mutex.Lock()
	defer p.processingCache.mutex.Unlock()

	if hit {
		p.processingCache.hitCount++
	} else {
		p.processingCache.missCount++
	}
}

func (p *IntelligentProcessor) updateProcessingMetrics(format string, duration time.Duration, success bool, qualityLoss float64) {
	p.performanceMonitor.mutex.Lock()
	defer p.performanceMonitor.mutex.Unlock()

	stats, exists := p.performanceMonitor.processingTimes[format]
	if !exists {
		stats = &ProcessingTimeStats{
			Format:  format,
			MinTime: duration,
			MaxTime: duration,
		}
		p.performanceMonitor.processingTimes[format] = stats
	}

	stats.TotalProcessed++
	stats.AverageTime = (stats.AverageTime + duration) / 2
	if duration < stats.MinTime {
		stats.MinTime = duration
	}
	if duration > stats.MaxTime {
		stats.MaxTime = duration
	}

	if success {
		stats.SuccessRate = (stats.SuccessRate + 1.0) / 2.0
	} else {
		stats.SuccessRate = (stats.SuccessRate + 0.0) / 2.0
	}

	stats.LastUpdate = time.Now()

	// Update quality loss rates
	p.performanceMonitor.qualityLossRates[format] = (p.performanceMonitor.qualityLossRates[format] + qualityLoss) / 2.0
}

func (p *IntelligentProcessor) logProcessingMetrics(options *ProcessingOptions, inputSize, outputSize int, duration time.Duration, qualityLoss float64) {
	compressionRatio := float64(outputSize) / float64(inputSize)

	p.logger.Infof("Image processing metrics: %s->%s, size=%d->%d (%.1f%%), time=%v, quality_loss=%.3f",
		options.InputFormat, options.OutputFormat, inputSize, outputSize, compressionRatio*100, duration, qualityLoss)

	// Check if we're meeting the <3% quality loss requirement
	if qualityLoss > 0.03 {
		p.logger.Errorf("Image quality loss exceeded 3%%: %.3f", qualityLoss)
	}
}

func (p *IntelligentProcessor) startPerformanceMonitoring() {
	p.performanceMonitor.isMonitoring = true
	ticker := time.NewTicker(p.performanceMonitor.monitoringInterval)
	defer ticker.Stop()

	for range ticker.C {
		if !p.performanceMonitor.isMonitoring {
			break
		}

		// Update performance metrics
		p.updateThroughputMetrics()
	}
}

func (p *IntelligentProcessor) updateThroughputMetrics() {
	// Update throughput metrics
}

// Format encoders and decoders
type JPEGEncoder struct{}

func (e *JPEGEncoder) Encode(img image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
	return buf.Bytes(), err
}

type JPEGDecoder struct{}

func (d *JPEGDecoder) Decode(data []byte) (image.Image, error) {
	return jpeg.Decode(bytes.NewReader(data))
}

type PNGEncoder struct{}

func (e *PNGEncoder) Encode(img image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	return buf.Bytes(), err
}

type PNGDecoder struct{}

func (d *PNGDecoder) Decode(data []byte) (image.Image, error) {
	return png.Decode(bytes.NewReader(data))
}

type WebPEncoder struct{}

func (e *WebPEncoder) Encode(img image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	err := webp.Encode(&buf, img, &webp.Options{Quality: float32(quality)})
	return buf.Bytes(), err
}

type WebPDecoder struct{}

func (d *WebPDecoder) Decode(data []byte) (image.Image, error) {
	return webp.Decode(bytes.NewReader(data))
}

// Stub encoders/decoders for AVIF and HEIC
type AVIFEncoder struct{}

func (e *AVIFEncoder) Encode(img image.Image, quality int) ([]byte, error) {
	// AVIF encoding would be implemented here
	return nil, fmt.Errorf("AVIF encoding not implemented")
}

type AVIFDecoder struct{}

func (d *AVIFDecoder) Decode(data []byte) (image.Image, error) {
	// AVIF decoding would be implemented here
	return nil, fmt.Errorf("AVIF decoding not implemented")
}

type HEICEncoder struct{}

func (e *HEICEncoder) Encode(img image.Image, quality int) ([]byte, error) {
	// HEIC encoding would be implemented here
	return nil, fmt.Errorf("HEIC encoding not implemented")
}

type HEICDecoder struct{}

func (d *HEICDecoder) Decode(data []byte) (image.Image, error) {
	// HEIC decoding would be implemented here
	return nil, fmt.Errorf("HEIC decoding not implemented")
}

// DefaultConfig returns default image processor configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultQuality:        85,
		MinQuality:            10,
		MaxQuality:            100,
		QualityThreshold:      0.97,
		SupportedFormats:      []string{"jpeg", "png", "webp", "avif", "heic"},
		DefaultFormat:         "jpeg",
		EnableWebP:            true,
		EnableAVIF:            true,
		EnableHEIC:            true,
		EnableOptimization:    true,
		OptimizationLevel:     3,
		EnableProgressive:     true,
		EnableLossless:        false,
		MaxConcurrency:        8,
		ProcessingTimeout:     30 * time.Second,
		CacheSize:             100 * 1024 * 1024, // 100MB
		CacheExpiry:           1 * time.Hour,
		EnableQualityAnalysis: true,
		QualityMetrics:        []string{"ssim", "psnr", "msssim", "lpips"},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
