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

package multimodal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// MultimodalManager manages multimodal AI processing
type MultimodalManager struct {
	mutex      sync.RWMutex
	config     *MultimodalConfig
	processors map[string]MultimodalProcessor
	metrics    *MultimodalMetrics
	logger     logx.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	isRunning  bool
}

// MultimodalConfig configuration for multimodal processing
type MultimodalConfig struct {
	// Processor configurations
	TextConfig  *TextProcessorConfig  `json:"text_config"`
	ImageConfig *ImageProcessorConfig `json:"image_config"`
	AudioConfig *AudioProcessorConfig `json:"audio_config"`
	VideoConfig *VideoProcessorConfig `json:"video_config"`

	// Processing settings
	MaxFileSize       int64         `json:"max_file_size"`
	SupportedFormats  []string      `json:"supported_formats"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`

	// Quality settings
	ImageMaxWidth    int `json:"image_max_width"`
	ImageMaxHeight   int `json:"image_max_height"`
	AudioSampleRate  int `json:"audio_sample_rate"`
	VideoMaxDuration int `json:"video_max_duration"` // seconds

	// Performance settings
	MaxConcurrentJobs int  `json:"max_concurrent_jobs"`
	EnableGPU         bool `json:"enable_gpu"`
	EnableCaching     bool `json:"enable_caching"`
}

// Processor configurations
type TextProcessorConfig struct {
	MaxLength       int      `json:"max_length"`
	Languages       []string `json:"languages"`
	EnableOCR       bool     `json:"enable_ocr"`
	EnableNER       bool     `json:"enable_ner"` // Named Entity Recognition
	EnableSentiment bool     `json:"enable_sentiment"`
}

type ImageProcessorConfig struct {
	MaxResolution         string   `json:"max_resolution"`
	SupportedFormats      []string `json:"supported_formats"`
	EnableFaceDetection   bool     `json:"enable_face_detection"`
	EnableObjectDetection bool     `json:"enable_object_detection"`
	EnableOCR             bool     `json:"enable_ocr"`
	EnableNSFW            bool     `json:"enable_nsfw"`
}

type AudioProcessorConfig struct {
	MaxDuration         int      `json:"max_duration"` // seconds
	SupportedFormats    []string `json:"supported_formats"`
	EnableSTT           bool     `json:"enable_stt"` // Speech to Text
	EnableTTS           bool     `json:"enable_tts"` // Text to Speech
	EnableMusicAnalysis bool     `json:"enable_music_analysis"`
}

type VideoProcessorConfig struct {
	MaxDuration           int      `json:"max_duration"` // seconds
	MaxResolution         string   `json:"max_resolution"`
	SupportedFormats      []string `json:"supported_formats"`
	EnableFrameExtraction bool     `json:"enable_frame_extraction"`
	EnableSceneDetection  bool     `json:"enable_scene_detection"`
	EnableObjectTracking  bool     `json:"enable_object_tracking"`
}

// MultimodalRequest represents a multimodal processing request
type MultimodalRequest struct {
	ID           string                 `json:"id"`
	Type         MediaType              `json:"type"`
	Content      []MediaContent         `json:"content"`
	Instructions string                 `json:"instructions"`
	Options      map[string]interface{} `json:"options"`
	UserID       int64                  `json:"user_id"`
	ChatID       int64                  `json:"chat_id"`
	CreatedAt    time.Time              `json:"created_at"`
}

// MultimodalResponse represents a multimodal processing response
type MultimodalResponse struct {
	ID          string                 `json:"id"`
	RequestID   string                 `json:"request_id"`
	Results     []ProcessingResult     `json:"results"`
	Summary     string                 `json:"summary"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	ProcessTime time.Duration          `json:"process_time"`
	CreatedAt   time.Time              `json:"created_at"`
}

// MediaContent represents different types of media content
type MediaContent struct {
	Type     MediaType              `json:"type"`
	Data     []byte                 `json:"data,omitempty"`
	URL      string                 `json:"url,omitempty"`
	Text     string                 `json:"text,omitempty"`
	Metadata map[string]interface{} `json:"metadata"`
	MimeType string                 `json:"mime_type"`
	Size     int64                  `json:"size"`
}

// ProcessingResult represents the result of processing a media content
type ProcessingResult struct {
	ContentID   string                 `json:"content_id"`
	Type        MediaType              `json:"type"`
	Analysis    map[string]interface{} `json:"analysis"`
	Extracted   []ExtractedData        `json:"extracted"`
	Confidence  float64                `json:"confidence"`
	ProcessTime time.Duration          `json:"process_time"`
	Error       string                 `json:"error,omitempty"`
}

// ExtractedData represents extracted information from media
type ExtractedData struct {
	Type       string                 `json:"type"`
	Content    string                 `json:"content"`
	Confidence float64                `json:"confidence"`
	Position   map[string]interface{} `json:"position,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MediaType represents different types of media
type MediaType string

const (
	MediaTypeText  MediaType = "text"
	MediaTypeImage MediaType = "image"
	MediaTypeAudio MediaType = "audio"
	MediaTypeVideo MediaType = "video"
	MediaTypeMixed MediaType = "mixed"
)

// MultimodalProcessor interface for different media processors
type MultimodalProcessor interface {
	Name() string
	SupportedTypes() []MediaType
	Process(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error)
	IsAvailable() bool
	GetMetrics() *ProcessorMetrics
	Start() error
	Stop() error
}

// ProcessorMetrics tracks processor performance
type ProcessorMetrics struct {
	Name             string        `json:"name"`
	ProcessedItems   int64         `json:"processed_items"`
	SuccessfulItems  int64         `json:"successful_items"`
	FailedItems      int64         `json:"failed_items"`
	AverageLatency   time.Duration `json:"average_latency"`
	TotalProcessTime time.Duration `json:"total_process_time"`
	LastUsed         time.Time     `json:"last_used"`
	IsAvailable      bool          `json:"is_available"`
}

// MultimodalMetrics tracks overall multimodal performance
type MultimodalMetrics struct {
	TotalRequests      int64                        `json:"total_requests"`
	SuccessfulRequests int64                        `json:"successful_requests"`
	FailedRequests     int64                        `json:"failed_requests"`
	AverageLatency     time.Duration                `json:"average_latency"`
	ProcessorMetrics   map[string]*ProcessorMetrics `json:"processor_metrics"`
	MediaTypeStats     map[MediaType]int64          `json:"media_type_stats"`
	LastUpdated        time.Time                    `json:"last_updated"`
}

// NewMultimodalManager creates a new multimodal manager
func NewMultimodalManager(config *MultimodalConfig) (*MultimodalManager, error) {
	if config == nil {
		config = DefaultMultimodalConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &MultimodalManager{
		config:     config,
		processors: make(map[string]MultimodalProcessor),
		metrics: &MultimodalMetrics{
			ProcessorMetrics: make(map[string]*ProcessorMetrics),
			MediaTypeStats:   make(map[MediaType]int64),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize processors
	if err := manager.initializeProcessors(); err != nil {
		return nil, fmt.Errorf("failed to initialize processors: %w", err)
	}

	return manager, nil
}

// Start starts the multimodal manager
func (mm *MultimodalManager) Start() error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if mm.isRunning {
		return fmt.Errorf("multimodal manager is already running")
	}

	mm.logger.Info("Starting multimodal manager...")

	// Start all processors
	for name, processor := range mm.processors {
		if err := processor.Start(); err != nil {
			mm.logger.Errorf("Failed to start processor %s: %v", name, err)
			continue
		}
		mm.logger.Infof("Started multimodal processor: %s", name)
	}

	// Start metrics collection
	go mm.metricsLoop()

	mm.isRunning = true
	mm.logger.Info("Multimodal manager started successfully")

	return nil
}

// ProcessMultimodal processes a multimodal request
func (mm *MultimodalManager) ProcessMultimodal(ctx context.Context, request *MultimodalRequest) (*MultimodalResponse, error) {
	start := time.Now()

	mm.mutex.RLock()
	if !mm.isRunning {
		mm.mutex.RUnlock()
		return nil, fmt.Errorf("multimodal manager is not running")
	}
	mm.mutex.RUnlock()

	response := &MultimodalResponse{
		ID:        fmt.Sprintf("multimodal_%d", time.Now().UnixNano()),
		RequestID: request.ID,
		Results:   make([]ProcessingResult, 0),
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}

	// Process each content item
	var totalConfidence float64
	successCount := 0

	for i, content := range request.Content {
		contentResult, err := mm.processContent(ctx, &content, request.Options)
		if err != nil {
			mm.logger.Errorf("Failed to process content %d: %v", i, err)
			contentResult = &ProcessingResult{
				ContentID: fmt.Sprintf("content_%d", i),
				Type:      content.Type,
				Error:     err.Error(),
			}
		} else {
			totalConfidence += contentResult.Confidence
			successCount++
		}

		response.Results = append(response.Results, *contentResult)
	}

	// Calculate overall confidence
	if successCount > 0 {
		response.Confidence = totalConfidence / float64(successCount)
	}

	// Generate summary
	response.Summary = mm.generateSummary(response.Results)
	response.ProcessTime = time.Since(start)

	// Update metrics
	mm.updateMetrics(request, len(response.Results) > 0, time.Since(start))

	return response, nil
}

// GetAvailableModels returns available multimodal models
func (mm *MultimodalManager) GetAvailableModels() []string {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	var models []string
	for name, processor := range mm.processors {
		if processor.IsAvailable() {
			models = append(models, name)
		}
	}

	return models
}

// GetMetrics returns multimodal metrics
func (mm *MultimodalManager) GetMetrics() *MultimodalMetrics {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// Update processor metrics
	for name, processor := range mm.processors {
		mm.metrics.ProcessorMetrics[name] = processor.GetMetrics()
	}

	mm.metrics.LastUpdated = time.Now()

	// Return a copy
	metrics := *mm.metrics
	return &metrics
}

// initializeProcessors initializes all processors
func (mm *MultimodalManager) initializeProcessors() error {
	// Initialize text processor
	if mm.config.TextConfig != nil {
		processor, err := NewTextProcessor(mm.config.TextConfig)
		if err != nil {
			mm.logger.Errorf("Failed to initialize text processor: %v", err)
		} else {
			mm.processors["text"] = processor
		}
	}

	// Initialize image processor
	if mm.config.ImageConfig != nil {
		processor, err := NewImageProcessor(mm.config.ImageConfig)
		if err != nil {
			mm.logger.Errorf("Failed to initialize image processor: %v", err)
		} else {
			mm.processors["image"] = processor
		}
	}

	// Initialize audio processor
	if mm.config.AudioConfig != nil {
		processor, err := NewAudioProcessor(mm.config.AudioConfig)
		if err != nil {
			mm.logger.Errorf("Failed to initialize audio processor: %v", err)
		} else {
			mm.processors["audio"] = processor
		}
	}

	// Initialize video processor
	if mm.config.VideoConfig != nil {
		processor, err := NewVideoProcessor(mm.config.VideoConfig)
		if err != nil {
			mm.logger.Errorf("Failed to initialize video processor: %v", err)
		} else {
			mm.processors["video"] = processor
		}
	}

	if len(mm.processors) == 0 {
		return fmt.Errorf("no multimodal processors configured")
	}

	mm.logger.Infof("Initialized %d multimodal processors", len(mm.processors))
	return nil
}

// processContent processes a single content item
func (mm *MultimodalManager) processContent(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error) {
	// Find appropriate processor
	var processor MultimodalProcessor
	for _, p := range mm.processors {
		for _, supportedType := range p.SupportedTypes() {
			if supportedType == content.Type {
				processor = p
				break
			}
		}
		if processor != nil {
			break
		}
	}

	if processor == nil {
		return nil, fmt.Errorf("no processor available for media type: %s", content.Type)
	}

	if !processor.IsAvailable() {
		return nil, fmt.Errorf("processor %s is not available", processor.Name())
	}

	return processor.Process(ctx, content, options)
}

// generateSummary generates a summary from processing results
func (mm *MultimodalManager) generateSummary(results []ProcessingResult) string {
	if len(results) == 0 {
		return "No content processed"
	}

	summary := fmt.Sprintf("Processed %d items: ", len(results))

	typeCount := make(map[MediaType]int)
	for _, result := range results {
		typeCount[result.Type]++
	}

	for mediaType, count := range typeCount {
		summary += fmt.Sprintf("%d %s, ", count, mediaType)
	}

	return summary[:len(summary)-2] // Remove trailing comma
}

// updateMetrics updates multimodal metrics
func (mm *MultimodalManager) updateMetrics(request *MultimodalRequest, success bool, latency time.Duration) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	mm.metrics.TotalRequests++

	if success {
		mm.metrics.SuccessfulRequests++
		mm.metrics.AverageLatency = (mm.metrics.AverageLatency + latency) / 2
	} else {
		mm.metrics.FailedRequests++
	}

	// Update media type statistics
	for _, content := range request.Content {
		mm.metrics.MediaTypeStats[content.Type]++
	}
}

// metricsLoop collects metrics periodically
func (mm *MultimodalManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.collectMetrics()
		case <-mm.ctx.Done():
			return
		}
	}
}

// collectMetrics collects current metrics
func (mm *MultimodalManager) collectMetrics() {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	for name, processor := range mm.processors {
		mm.metrics.ProcessorMetrics[name] = processor.GetMetrics()
	}

	mm.metrics.LastUpdated = time.Now()
}

// DefaultMultimodalConfig returns default multimodal configuration
func DefaultMultimodalConfig() *MultimodalConfig {
	return &MultimodalConfig{
		MaxFileSize:       100 * 1024 * 1024, // 100MB
		SupportedFormats:  []string{"jpg", "png", "gif", "mp4", "mp3", "wav", "txt"},
		ProcessingTimeout: 60 * time.Second,
		ImageMaxWidth:     4096,
		ImageMaxHeight:    4096,
		AudioSampleRate:   44100,
		VideoMaxDuration:  300, // 5 minutes
		MaxConcurrentJobs: 10,
		EnableGPU:         false,
		EnableCaching:     true,
	}
}

// NewTextProcessor creates a new text processor
func NewTextProcessor(config *TextProcessorConfig) (MultimodalProcessor, error) {
	return &stubTextProcessor{
		config: config,
	}, nil
}

// NewImageProcessor creates a new image processor
func NewImageProcessor(config *ImageProcessorConfig) (MultimodalProcessor, error) {
	return &stubImageProcessor{
		config: config,
	}, nil
}

// NewAudioProcessor creates a new audio processor
func NewAudioProcessor(config *AudioProcessorConfig) (MultimodalProcessor, error) {
	return &stubAudioProcessor{
		config: config,
	}, nil
}

// NewVideoProcessor creates a new video processor
func NewVideoProcessor(config *VideoProcessorConfig) (MultimodalProcessor, error) {
	return &stubVideoProcessor{
		config: config,
	}, nil
}

// Stub implementations
type stubTextProcessor struct {
	config *TextProcessorConfig
}

func (s *stubTextProcessor) Name() string                { return "text-processor" }
func (s *stubTextProcessor) SupportedTypes() []MediaType { return []MediaType{MediaTypeText} }
func (s *stubTextProcessor) Process(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error) {
	return &ProcessingResult{
		ContentID:  "text_1",
		Type:       MediaTypeText,
		Analysis:   map[string]interface{}{"length": len(content.Text)},
		Confidence: 0.95,
	}, nil
}
func (s *stubTextProcessor) IsAvailable() bool             { return true }
func (s *stubTextProcessor) GetMetrics() *ProcessorMetrics { return &ProcessorMetrics{} }
func (s *stubTextProcessor) Start() error                  { return nil }
func (s *stubTextProcessor) Stop() error                   { return nil }

type stubImageProcessor struct {
	config *ImageProcessorConfig
}

func (s *stubImageProcessor) Name() string                { return "image-processor" }
func (s *stubImageProcessor) SupportedTypes() []MediaType { return []MediaType{MediaTypeImage} }
func (s *stubImageProcessor) Process(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error) {
	return &ProcessingResult{
		ContentID:  "image_1",
		Type:       MediaTypeImage,
		Analysis:   map[string]interface{}{"size": content.Size},
		Confidence: 0.90,
	}, nil
}
func (s *stubImageProcessor) IsAvailable() bool             { return true }
func (s *stubImageProcessor) GetMetrics() *ProcessorMetrics { return &ProcessorMetrics{} }
func (s *stubImageProcessor) Start() error                  { return nil }
func (s *stubImageProcessor) Stop() error                   { return nil }

type stubAudioProcessor struct {
	config *AudioProcessorConfig
}

func (s *stubAudioProcessor) Name() string                { return "audio-processor" }
func (s *stubAudioProcessor) SupportedTypes() []MediaType { return []MediaType{MediaTypeAudio} }
func (s *stubAudioProcessor) Process(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error) {
	return &ProcessingResult{
		ContentID:  "audio_1",
		Type:       MediaTypeAudio,
		Analysis:   map[string]interface{}{"duration": 30},
		Confidence: 0.85,
	}, nil
}
func (s *stubAudioProcessor) IsAvailable() bool             { return true }
func (s *stubAudioProcessor) GetMetrics() *ProcessorMetrics { return &ProcessorMetrics{} }
func (s *stubAudioProcessor) Start() error                  { return nil }
func (s *stubAudioProcessor) Stop() error                   { return nil }

type stubVideoProcessor struct {
	config *VideoProcessorConfig
}

func (s *stubVideoProcessor) Name() string                { return "video-processor" }
func (s *stubVideoProcessor) SupportedTypes() []MediaType { return []MediaType{MediaTypeVideo} }
func (s *stubVideoProcessor) Process(ctx context.Context, content *MediaContent, options map[string]interface{}) (*ProcessingResult, error) {
	return &ProcessingResult{
		ContentID:  "video_1",
		Type:       MediaTypeVideo,
		Analysis:   map[string]interface{}{"duration": 60},
		Confidence: 0.80,
	}, nil
}
func (s *stubVideoProcessor) IsAvailable() bool             { return true }
func (s *stubVideoProcessor) GetMetrics() *ProcessorMetrics { return &ProcessorMetrics{} }
func (s *stubVideoProcessor) Start() error                  { return nil }
func (s *stubVideoProcessor) Stop() error                   { return nil }
