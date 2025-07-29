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

package compression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"sync"
	"time"

	"context"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/zeromicro/go-zero/core/logx"
)

// Manager manages intelligent compression with multiple algorithms
type Manager struct {
	config              *Config
	algorithms          map[Algorithm]*AlgorithmInfo
	fileTypeDetector    *FileTypeDetector
	compressionAnalyzer *CompressionAnalyzer
	performanceMonitor  *PerformanceMonitor
	adaptiveSelector    *AdaptiveSelector
	compressionCache    *CompressionCache
	mutex               sync.RWMutex
	logger              logx.Logger
}

// Config represents compression manager configuration
type Config struct {
	// Algorithm settings
	EnableLZ4     bool `json:"enable_lz4"`
	EnableZstd    bool `json:"enable_zstd"`
	EnableBrotli  bool `json:"enable_brotli"`
	EnableGzip    bool `json:"enable_gzip"`
	EnableDeflate bool `json:"enable_deflate"`

	// Adaptive compression settings
	EnableAdaptive      bool          `json:"enable_adaptive"`
	MinCompressionRatio float64       `json:"min_compression_ratio"`
	MaxCompressionTime  time.Duration `json:"max_compression_time"`

	// Performance settings
	CompressionLevel map[Algorithm]int `json:"compression_level"`
	ThreadCount      int               `json:"thread_count"`
	BufferSize       int               `json:"buffer_size"`

	// Cache settings
	EnableCache bool          `json:"enable_cache"`
	CacheSize   int64         `json:"cache_size"`
	CacheExpiry time.Duration `json:"cache_expiry"`

	// File type specific settings
	FileTypeSettings map[FileType]*FileTypeConfig `json:"file_type_settings"`
}

// AlgorithmInfo contains information about a compression algorithm
type AlgorithmInfo struct {
	Algorithm          Algorithm  `json:"algorithm"`
	Name               string     `json:"name"`
	CompressionRatio   float64    `json:"compression_ratio"`
	CompressionSpeed   float64    `json:"compression_speed"`
	DecompressionSpeed float64    `json:"decompression_speed"`
	MemoryUsage        int64      `json:"memory_usage"`
	CPUUsage           float64    `json:"cpu_usage"`
	BestForFileTypes   []FileType `json:"best_for_file_types"`
	IsEnabled          bool       `json:"is_enabled"`
	LastUpdate         time.Time  `json:"last_update"`
}

// FileTypeDetector detects file types for optimal compression selection
type FileTypeDetector struct {
	fileSignatures   map[string]FileType `json:"file_signatures"`
	mimeTypeMapping  map[string]FileType `json:"mime_type_mapping"`
	extensionMapping map[string]FileType `json:"extension_mapping"`
	detectionCache   map[string]FileType `json:"detection_cache"`
	cacheExpiry      time.Duration       `json:"cache_expiry"`
	mutex            sync.RWMutex
}

// CompressionAnalyzer analyzes compression effectiveness
type CompressionAnalyzer struct {
	compressionStats  map[Algorithm]*CompressionStats `json:"compression_stats"`
	fileTypeStats     map[FileType]*FileTypeStats     `json:"file_type_stats"`
	totalCompressions int64                           `json:"total_compressions"`
	totalSavings      int64                           `json:"total_savings"`
	averageRatio      float64                         `json:"average_ratio"`
	lastAnalysis      time.Time                       `json:"last_analysis"`
	mutex             sync.RWMutex
}

// PerformanceMonitor monitors compression performance
type PerformanceMonitor struct {
	performanceMetrics map[Algorithm]*PerformanceMetrics `json:"performance_metrics"`
	systemMetrics      *SystemMetrics                    `json:"system_metrics"`
	benchmarkResults   map[Algorithm]*BenchmarkResult    `json:"benchmark_results"`
	isMonitoring       bool                              `json:"is_monitoring"`
	monitoringInterval time.Duration                     `json:"monitoring_interval"`
	lastUpdate         time.Time                         `json:"last_update"`
	mutex              sync.RWMutex
}

// AdaptiveSelector selects optimal compression algorithm
type AdaptiveSelector struct {
	selectionStrategy   SelectionStrategy      `json:"selection_strategy"`
	learningEnabled     bool                   `json:"learning_enabled"`
	selectionHistory    []*SelectionEvent      `json:"selection_history"`
	algorithmWeights    map[Algorithm]float64  `json:"algorithm_weights"`
	fileTypePreferences map[FileType]Algorithm `json:"file_type_preferences"`
	adaptationRate      float64                `json:"adaptation_rate"`
	lastAdaptation      time.Time              `json:"last_adaptation"`
	mutex               sync.RWMutex
}

// CompressionCache caches compression results
type CompressionCache struct {
	cache          map[string]*CacheEntry `json:"-"`
	maxSize        int64                  `json:"max_size"`
	currentSize    int64                  `json:"current_size"`
	hitCount       int64                  `json:"hit_count"`
	missCount      int64                  `json:"miss_count"`
	evictionPolicy EvictionPolicy         `json:"eviction_policy"`
	ttl            time.Duration          `json:"ttl"`
	mutex          sync.RWMutex
}

// Supporting types
type Algorithm string

const (
	AlgorithmNone    Algorithm = "none"
	AlgorithmLZ4     Algorithm = "lz4"
	AlgorithmZstd    Algorithm = "zstd"
	AlgorithmBrotli  Algorithm = "brotli"
	AlgorithmGzip    Algorithm = "gzip"
	AlgorithmDeflate Algorithm = "deflate"
)

type FileType string

const (
	FileTypeText     FileType = "text"
	FileTypeImage    FileType = "image"
	FileTypeVideo    FileType = "video"
	FileTypeAudio    FileType = "audio"
	FileTypeDocument FileType = "document"
	FileTypeArchive  FileType = "archive"
	FileTypeBinary   FileType = "binary"
	FileTypeUnknown  FileType = "unknown"
)

type SelectionStrategy string

const (
	StrategyRatio    SelectionStrategy = "ratio"
	StrategySpeed    SelectionStrategy = "speed"
	StrategyBalanced SelectionStrategy = "balanced"
	StrategyAdaptive SelectionStrategy = "adaptive"
)

type EvictionPolicy string

const (
	EvictionLRU EvictionPolicy = "lru"
	EvictionLFU EvictionPolicy = "lfu"
	EvictionTTL EvictionPolicy = "ttl"
)

type FileTypeConfig struct {
	PreferredAlgorithm Algorithm `json:"preferred_algorithm"`
	CompressionLevel   int       `json:"compression_level"`
	MinSizeThreshold   int64     `json:"min_size_threshold"`
	MaxSizeThreshold   int64     `json:"max_size_threshold"`
	SkipCompression    bool      `json:"skip_compression"`
}

type CompressionStats struct {
	Algorithm           Algorithm     `json:"algorithm"`
	TotalCompressions   int64         `json:"total_compressions"`
	TotalOriginalSize   int64         `json:"total_original_size"`
	TotalCompressedSize int64         `json:"total_compressed_size"`
	AverageRatio        float64       `json:"average_ratio"`
	AverageTime         time.Duration `json:"average_time"`
	SuccessRate         float64       `json:"success_rate"`
	ErrorCount          int64         `json:"error_count"`
}

type FileTypeStats struct {
	FileType            FileType  `json:"file_type"`
	TotalFiles          int64     `json:"total_files"`
	TotalOriginalSize   int64     `json:"total_original_size"`
	TotalCompressedSize int64     `json:"total_compressed_size"`
	BestAlgorithm       Algorithm `json:"best_algorithm"`
	AverageRatio        float64   `json:"average_ratio"`
}

type PerformanceMetrics struct {
	Algorithm          Algorithm `json:"algorithm"`
	CompressionSpeed   float64   `json:"compression_speed"`   // MB/s
	DecompressionSpeed float64   `json:"decompression_speed"` // MB/s
	CPUUsage           float64   `json:"cpu_usage"`           // percentage
	MemoryUsage        int64     `json:"memory_usage"`        // bytes
	LastMeasurement    time.Time `json:"last_measurement"`
}

type SystemMetrics struct {
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     int64     `json:"memory_usage"`
	AvailableMemory int64     `json:"available_memory"`
	DiskIORate      float64   `json:"disk_io_rate"`
	NetworkIORate   float64   `json:"network_io_rate"`
	LastUpdate      time.Time `json:"last_update"`
}

type BenchmarkResult struct {
	Algorithm         Algorithm     `json:"algorithm"`
	TestDataSize      int64         `json:"test_data_size"`
	CompressionTime   time.Duration `json:"compression_time"`
	DecompressionTime time.Duration `json:"decompression_time"`
	CompressionRatio  float64       `json:"compression_ratio"`
	Score             float64       `json:"score"`
	Timestamp         time.Time     `json:"timestamp"`
}

type SelectionEvent struct {
	Timestamp         time.Time     `json:"timestamp"`
	FileType          FileType      `json:"file_type"`
	FileSize          int64         `json:"file_size"`
	SelectedAlgorithm Algorithm     `json:"selected_algorithm"`
	CompressionRatio  float64       `json:"compression_ratio"`
	CompressionTime   time.Duration `json:"compression_time"`
	Effectiveness     float64       `json:"effectiveness"`
}

type CacheEntry struct {
	Key              string    `json:"key"`
	OriginalData     []byte    `json:"original_data"`
	CompressedData   []byte    `json:"compressed_data"`
	Algorithm        Algorithm `json:"algorithm"`
	CompressionRatio float64   `json:"compression_ratio"`
	CreatedAt        time.Time `json:"created_at"`
	LastAccessed     time.Time `json:"last_accessed"`
	AccessCount      int64     `json:"access_count"`
}

// NewManager creates a new compression manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	manager := &Manager{
		config:     config,
		algorithms: make(map[Algorithm]*AlgorithmInfo),
		logger:     logx.WithContext(context.Background()),
	}

	// Initialize algorithms
	manager.initializeAlgorithms()

	// Initialize file type detector
	manager.fileTypeDetector = &FileTypeDetector{
		fileSignatures:   make(map[string]FileType),
		mimeTypeMapping:  make(map[string]FileType),
		extensionMapping: make(map[string]FileType),
		detectionCache:   make(map[string]FileType),
		cacheExpiry:      1 * time.Hour,
	}
	manager.initializeFileTypeDetector()

	// Initialize compression analyzer
	manager.compressionAnalyzer = &CompressionAnalyzer{
		compressionStats: make(map[Algorithm]*CompressionStats),
		fileTypeStats:    make(map[FileType]*FileTypeStats),
	}

	// Initialize performance monitor
	manager.performanceMonitor = &PerformanceMonitor{
		performanceMetrics: make(map[Algorithm]*PerformanceMetrics),
		systemMetrics:      &SystemMetrics{},
		benchmarkResults:   make(map[Algorithm]*BenchmarkResult),
		monitoringInterval: 30 * time.Second,
	}

	// Initialize adaptive selector
	manager.adaptiveSelector = &AdaptiveSelector{
		selectionStrategy:   StrategyAdaptive,
		learningEnabled:     true,
		algorithmWeights:    make(map[Algorithm]float64),
		fileTypePreferences: make(map[FileType]Algorithm),
		adaptationRate:      0.1,
	}
	manager.initializeAdaptiveSelector()

	// Initialize compression cache
	if config.EnableCache {
		manager.compressionCache = &CompressionCache{
			cache:          make(map[string]*CacheEntry),
			maxSize:        config.CacheSize,
			evictionPolicy: EvictionLRU,
			ttl:            config.CacheExpiry,
		}
	}

	// Start performance monitoring
	if manager.performanceMonitor != nil {
		go manager.startPerformanceMonitoring()
	}

	return manager, nil
}

// Compress compresses data using the specified algorithm
func (m *Manager) Compress(data []byte, algorithm Algorithm) ([]byte, error) {
	startTime := time.Now()

	// Check cache first
	if m.compressionCache != nil {
		if cached := m.checkCache(data, algorithm); cached != nil {
			m.updateCacheStats(true)
			return cached.CompressedData, nil
		}
		m.updateCacheStats(false)
	}

	// Validate algorithm
	if !m.isAlgorithmEnabled(algorithm) {
		return nil, fmt.Errorf("algorithm %s is not enabled", algorithm)
	}

	// Compress data
	var compressedData []byte
	var err error

	switch algorithm {
	case AlgorithmLZ4:
		compressedData, err = m.compressLZ4(data)
	case AlgorithmZstd:
		compressedData, err = m.compressZstd(data)
	case AlgorithmBrotli:
		compressedData, err = m.compressBrotli(data)
	case AlgorithmGzip:
		compressedData, err = m.compressGzip(data)
	case AlgorithmDeflate:
		compressedData, err = m.compressDeflate(data)
	case AlgorithmNone:
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		m.updateCompressionStats(algorithm, len(data), 0, time.Since(startTime), false)
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Check compression effectiveness
	compressionRatio := float64(len(compressedData)) / float64(len(data))
	if compressionRatio > m.config.MinCompressionRatio {
		// Compression not effective enough, return original data
		m.logger.Infof("Compression not effective: ratio=%.3f, returning original data", compressionRatio)
		return data, nil
	}

	// Update statistics
	compressionTime := time.Since(startTime)
	m.updateCompressionStats(algorithm, len(data), len(compressedData), compressionTime, true)

	// Cache result
	if m.compressionCache != nil {
		m.cacheResult(data, compressedData, algorithm, compressionRatio)
	}

	return compressedData, nil
}

// Decompress decompresses data using the specified algorithm
func (m *Manager) Decompress(data []byte, algorithm Algorithm) ([]byte, error) {
	if algorithm == AlgorithmNone {
		return data, nil
	}

	var decompressedData []byte
	var err error

	switch algorithm {
	case AlgorithmLZ4:
		decompressedData, err = m.decompressLZ4(data)
	case AlgorithmZstd:
		decompressedData, err = m.decompressZstd(data)
	case AlgorithmBrotli:
		decompressedData, err = m.decompressBrotli(data)
	case AlgorithmGzip:
		decompressedData, err = m.decompressGzip(data)
	case AlgorithmDeflate:
		decompressedData, err = m.decompressDeflate(data)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	return decompressedData, nil
}

// SelectOptimalAlgorithm selects the optimal compression algorithm for the given data
func (m *Manager) SelectOptimalAlgorithm(data []byte) Algorithm {
	// Detect file type
	fileType := m.fileTypeDetector.DetectFileType(data)

	// Use adaptive selector
	return m.adaptiveSelector.SelectAlgorithm(data, fileType)
}

// Algorithm implementations
func (m *Manager) compressLZ4(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := lz4.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m *Manager) decompressLZ4(data []byte) ([]byte, error) {
	reader := lz4.NewReader(bytes.NewReader(data))
	var buf bytes.Buffer

	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m *Manager) compressZstd(data []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()

	return encoder.EncodeAll(data, make([]byte, 0, len(data))), nil
}

func (m *Manager) decompressZstd(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	return decoder.DecodeAll(data, nil)
}

func (m *Manager) compressBrotli(data []byte) ([]byte, error) {
	// Brotli compression implementation would go here
	// For now, return a placeholder
	return data, nil
}

func (m *Manager) decompressBrotli(data []byte) ([]byte, error) {
	// Brotli decompression implementation would go here
	return data, nil
}

func (m *Manager) compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m *Manager) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m *Manager) compressDeflate(data []byte) ([]byte, error) {
	// Deflate compression implementation would go here
	return data, nil
}

func (m *Manager) decompressDeflate(data []byte) ([]byte, error) {
	// Deflate decompression implementation would go here
	return data, nil
}

// Helper methods
func (m *Manager) initializeAlgorithms() {
	algorithms := map[Algorithm]*AlgorithmInfo{
		AlgorithmLZ4: {
			Algorithm:          AlgorithmLZ4,
			Name:               "LZ4",
			CompressionRatio:   0.6,
			CompressionSpeed:   500.0,            // MB/s
			DecompressionSpeed: 2000.0,           // MB/s
			MemoryUsage:        64 * 1024 * 1024, // 64MB
			CPUUsage:           20.0,             // 20%
			BestForFileTypes:   []FileType{FileTypeText, FileTypeDocument},
			IsEnabled:          m.config.EnableLZ4,
		},
		AlgorithmZstd: {
			Algorithm:          AlgorithmZstd,
			Name:               "Zstandard",
			CompressionRatio:   0.4,
			CompressionSpeed:   300.0,             // MB/s
			DecompressionSpeed: 1000.0,            // MB/s
			MemoryUsage:        128 * 1024 * 1024, // 128MB
			CPUUsage:           40.0,              // 40%
			BestForFileTypes:   []FileType{FileTypeText, FileTypeDocument, FileTypeBinary},
			IsEnabled:          m.config.EnableZstd,
		},
		AlgorithmBrotli: {
			Algorithm:          AlgorithmBrotli,
			Name:               "Brotli",
			CompressionRatio:   0.35,
			CompressionSpeed:   50.0,              // MB/s
			DecompressionSpeed: 400.0,             // MB/s
			MemoryUsage:        256 * 1024 * 1024, // 256MB
			CPUUsage:           60.0,              // 60%
			BestForFileTypes:   []FileType{FileTypeText, FileTypeDocument},
			IsEnabled:          m.config.EnableBrotli,
		},
		AlgorithmGzip: {
			Algorithm:          AlgorithmGzip,
			Name:               "Gzip",
			CompressionRatio:   0.5,
			CompressionSpeed:   100.0,            // MB/s
			DecompressionSpeed: 500.0,            // MB/s
			MemoryUsage:        32 * 1024 * 1024, // 32MB
			CPUUsage:           30.0,             // 30%
			BestForFileTypes:   []FileType{FileTypeText, FileTypeDocument},
			IsEnabled:          m.config.EnableGzip,
		},
	}

	m.algorithms = algorithms
}

func (m *Manager) initializeFileTypeDetector() {
	// Initialize file signatures
	m.fileTypeDetector.fileSignatures = map[string]FileType{
		"\xFF\xD8\xFF":            FileTypeImage, // JPEG
		"\x89PNG\r\n\x1A\n":       FileTypeImage, // PNG
		"GIF87a":                  FileTypeImage, // GIF87a
		"GIF89a":                  FileTypeImage, // GIF89a
		"\x00\x00\x00\x20ftypmp4": FileTypeVideo, // MP4
		"ID3":                     FileTypeAudio, // MP3
		"\x1A\x45\xDF\xA3":        FileTypeVideo, // WebM/MKV
	}

	// Initialize extension mapping
	m.fileTypeDetector.extensionMapping = map[string]FileType{
		".txt":  FileTypeText,
		".json": FileTypeText,
		".xml":  FileTypeText,
		".html": FileTypeText,
		".css":  FileTypeText,
		".js":   FileTypeText,
		".jpg":  FileTypeImage,
		".jpeg": FileTypeImage,
		".png":  FileTypeImage,
		".gif":  FileTypeImage,
		".mp4":  FileTypeVideo,
		".avi":  FileTypeVideo,
		".mkv":  FileTypeVideo,
		".mp3":  FileTypeAudio,
		".wav":  FileTypeAudio,
		".pdf":  FileTypeDocument,
		".doc":  FileTypeDocument,
		".docx": FileTypeDocument,
		".zip":  FileTypeArchive,
		".rar":  FileTypeArchive,
		".7z":   FileTypeArchive,
	}
}

func (m *Manager) initializeAdaptiveSelector() {
	// Initialize algorithm weights
	m.adaptiveSelector.algorithmWeights = map[Algorithm]float64{
		AlgorithmLZ4:    0.8, // Fast compression
		AlgorithmZstd:   0.9, // Balanced
		AlgorithmBrotli: 0.7, // High compression
		AlgorithmGzip:   0.6, // Standard
	}

	// Initialize file type preferences
	m.adaptiveSelector.fileTypePreferences = map[FileType]Algorithm{
		FileTypeText:     AlgorithmZstd,
		FileTypeImage:    AlgorithmLZ4,
		FileTypeVideo:    AlgorithmNone, // Videos are already compressed
		FileTypeAudio:    AlgorithmNone, // Audio is already compressed
		FileTypeDocument: AlgorithmZstd,
		FileTypeArchive:  AlgorithmNone, // Archives are already compressed
		FileTypeBinary:   AlgorithmLZ4,
		FileTypeUnknown:  AlgorithmLZ4,
	}
}

func (m *Manager) isAlgorithmEnabled(algorithm Algorithm) bool {
	if info, exists := m.algorithms[algorithm]; exists {
		return info.IsEnabled
	}
	return false
}

func (m *Manager) updateCompressionStats(algorithm Algorithm, originalSize, compressedSize int, duration time.Duration, success bool) {
	m.compressionAnalyzer.mutex.Lock()
	defer m.compressionAnalyzer.mutex.Unlock()

	stats, exists := m.compressionAnalyzer.compressionStats[algorithm]
	if !exists {
		stats = &CompressionStats{Algorithm: algorithm}
		m.compressionAnalyzer.compressionStats[algorithm] = stats
	}

	stats.TotalCompressions++
	stats.TotalOriginalSize += int64(originalSize)

	if success {
		stats.TotalCompressedSize += int64(compressedSize)
		ratio := float64(compressedSize) / float64(originalSize)
		stats.AverageRatio = (stats.AverageRatio + ratio) / 2.0
	} else {
		stats.ErrorCount++
	}

	// Update average time
	stats.AverageTime = (stats.AverageTime + duration) / 2

	// Update success rate
	stats.SuccessRate = float64(stats.TotalCompressions-stats.ErrorCount) / float64(stats.TotalCompressions)
}

func (m *Manager) checkCache(data []byte, algorithm Algorithm) *CacheEntry {
	if m.compressionCache == nil {
		return nil
	}

	key := m.generateCacheKey(data, algorithm)

	m.compressionCache.mutex.RLock()
	defer m.compressionCache.mutex.RUnlock()

	if entry, exists := m.compressionCache.cache[key]; exists {
		// Check TTL
		if time.Since(entry.CreatedAt) < m.compressionCache.ttl {
			entry.LastAccessed = time.Now()
			entry.AccessCount++
			return entry
		}
	}

	return nil
}

func (m *Manager) cacheResult(originalData, compressedData []byte, algorithm Algorithm, ratio float64) {
	if m.compressionCache == nil {
		return
	}

	key := m.generateCacheKey(originalData, algorithm)
	entry := &CacheEntry{
		Key:              key,
		OriginalData:     originalData,
		CompressedData:   compressedData,
		Algorithm:        algorithm,
		CompressionRatio: ratio,
		CreatedAt:        time.Now(),
		LastAccessed:     time.Now(),
		AccessCount:      1,
	}

	m.compressionCache.mutex.Lock()
	defer m.compressionCache.mutex.Unlock()

	// Check if we need to evict entries
	entrySize := int64(len(originalData) + len(compressedData))
	if m.compressionCache.currentSize+entrySize > m.compressionCache.maxSize {
		m.evictCacheEntries(entrySize)
	}

	m.compressionCache.cache[key] = entry
	m.compressionCache.currentSize += entrySize
}

func (m *Manager) generateCacheKey(data []byte, algorithm Algorithm) string {
	// Generate a hash-based key for the cache
	return fmt.Sprintf("%s_%x", algorithm, data[:min(len(data), 32)])
}

func (m *Manager) updateCacheStats(hit bool) {
	if m.compressionCache == nil {
		return
	}

	m.compressionCache.mutex.Lock()
	defer m.compressionCache.mutex.Unlock()

	if hit {
		m.compressionCache.hitCount++
	} else {
		m.compressionCache.missCount++
	}
}

func (m *Manager) evictCacheEntries(requiredSpace int64) {
	// Implement LRU eviction policy
	// This is a simplified implementation
	for key, entry := range m.compressionCache.cache {
		entrySize := int64(len(entry.OriginalData) + len(entry.CompressedData))
		delete(m.compressionCache.cache, key)
		m.compressionCache.currentSize -= entrySize

		if m.compressionCache.currentSize+requiredSpace <= m.compressionCache.maxSize {
			break
		}
	}
}

func (m *Manager) startPerformanceMonitoring() {
	m.performanceMonitor.isMonitoring = true
	ticker := time.NewTicker(m.performanceMonitor.monitoringInterval)
	defer ticker.Stop()

	for range ticker.C {
		if !m.performanceMonitor.isMonitoring {
			break
		}

		// Update performance metrics
		m.updatePerformanceMetrics()
	}
}

func (m *Manager) updatePerformanceMetrics() {
	// Update system metrics and algorithm performance
	// This would involve actual system monitoring
}

// DetectFileType detects the file type of the given data
func (ftd *FileTypeDetector) DetectFileType(data []byte) FileType {
	if len(data) == 0 {
		return FileTypeUnknown
	}

	// Check file signatures first
	for signature, fileType := range ftd.fileSignatures {
		if len(data) >= len(signature) && string(data[:len(signature)]) == signature {
			return fileType
		}
	}

	// Analyze content characteristics
	return ftd.analyzeContent(data)
}

func (ftd *FileTypeDetector) analyzeContent(data []byte) FileType {
	// Simple heuristic analysis
	textChars := 0
	binaryChars := 0

	sampleSize := min(len(data), 1024)
	for i := 0; i < sampleSize; i++ {
		b := data[i]
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			textChars++
		} else {
			binaryChars++
		}
	}

	if float64(textChars)/float64(sampleSize) > 0.8 {
		return FileTypeText
	}

	return FileTypeBinary
}

// SelectAlgorithm selects the optimal algorithm for the given data and file type
func (as *AdaptiveSelector) SelectAlgorithm(data []byte, fileType FileType) Algorithm {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	// Check file type preferences first
	if preferred, exists := as.fileTypePreferences[fileType]; exists {
		return preferred
	}

	// Use adaptive selection based on weights
	var bestAlgorithm Algorithm
	var bestScore float64

	for algorithm, weight := range as.algorithmWeights {
		score := weight

		// Adjust score based on data characteristics
		if len(data) > 10*1024*1024 { // Large files
			if algorithm == AlgorithmLZ4 {
				score += 0.2 // Prefer fast compression for large files
			}
		}

		if score > bestScore {
			bestScore = score
			bestAlgorithm = algorithm
		}
	}

	return bestAlgorithm
}

// DefaultConfig returns default compression configuration
func DefaultConfig() *Config {
	return &Config{
		EnableLZ4:           true,
		EnableZstd:          true,
		EnableBrotli:        true,
		EnableGzip:          true,
		EnableDeflate:       false,
		EnableAdaptive:      true,
		MinCompressionRatio: 0.9, // Only compress if we save at least 10%
		MaxCompressionTime:  5 * time.Second,
		CompressionLevel: map[Algorithm]int{
			AlgorithmLZ4:    1, // Fast
			AlgorithmZstd:   3, // Balanced
			AlgorithmBrotli: 6, // High compression
			AlgorithmGzip:   6, // Standard
		},
		ThreadCount: 4,
		BufferSize:  64 * 1024, // 64KB
		EnableCache: true,
		CacheSize:   100 * 1024 * 1024, // 100MB
		CacheExpiry: 1 * time.Hour,
		FileTypeSettings: map[FileType]*FileTypeConfig{
			FileTypeText: {
				PreferredAlgorithm: AlgorithmZstd,
				CompressionLevel:   6,
				MinSizeThreshold:   1024,              // 1KB
				MaxSizeThreshold:   100 * 1024 * 1024, // 100MB
			},
			FileTypeImage: {
				PreferredAlgorithm: AlgorithmLZ4,
				CompressionLevel:   1,
				MinSizeThreshold:   10 * 1024,        // 10KB
				MaxSizeThreshold:   50 * 1024 * 1024, // 50MB
			},
			FileTypeVideo: {
				SkipCompression: true, // Videos are already compressed
			},
			FileTypeAudio: {
				SkipCompression: true, // Audio is already compressed
			},
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
