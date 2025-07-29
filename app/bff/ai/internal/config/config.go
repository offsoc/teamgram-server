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

package config

import (
	"fmt"
	"time"

	"github.com/zeromicro/go-zero/zrpc"
)

// Config configuration for AI BFF service
type Config struct {
	zrpc.RpcServerConf
	AI *AIServiceConfig `json:",optional"`
}

// AIServiceConfig configuration for AI service
type AIServiceConfig struct {
	// Basic configuration
	Enabled             bool          `json:",default=true"`
	MaxConcurrentRequests int         `json:",default=100"`
	RequestTimeout      time.Duration `json:",default=30s"`
	
	// LLM configuration
	LLMConfig           *LLMConfig    `json:",optional"`
	
	// Vision configuration
	VisionConfig        *VisionConfig `json:",optional"`
	
	// Speech configuration
	SpeechConfig        *SpeechConfig `json:",optional"`
	
	// Multimodal configuration
	MultimodalConfig    *MultimodalConfig `json:",optional"`
	
	// Moderation configuration
	ModerationConfig    *ModerationConfig `json:",optional"`
	
	// Performance settings
	EnableCaching       bool          `json:",default=true"`
	CacheSize           int           `json:",default=1000"`
	CacheTTL            time.Duration `json:",default=1h"`
	
	// Rate limiting
	EnableRateLimit     bool          `json:",default=true"`
	RequestsPerSecond   int           `json:",default=10"`
	BurstSize           int           `json:",default=20"`
	
	// Monitoring
	EnableMetrics       bool          `json:",default=true"`
	MetricsPort         int           `json:",default=9053"`
	HealthCheckInterval time.Duration `json:",default=30s"`
}

// LLMConfig configuration for LLM services
type LLMConfig struct {
	// Provider configurations
	OpenAIConfig        *OpenAIConfig    `json:",optional"`
	AnthropicConfig     *AnthropicConfig `json:",optional"`
	GoogleConfig        *GoogleConfig    `json:",optional"`
	
	// Default settings
	DefaultModel        string           `json:",default=gpt-4"`
	DefaultMaxTokens    int              `json:",default=2048"`
	DefaultTemperature  float64          `json:",default=0.7"`
	
	// Performance settings
	RequestTimeout      time.Duration    `json:",default=30s"`
	MaxRetries          int              `json:",default=3"`
	RetryDelay          time.Duration    `json:",default=1s"`
	
	// Load balancing
	LoadBalanceStrategy string           `json:",default=round_robin"`
	FailoverEnabled     bool             `json:",default=true"`
	
	// Caching
	EnableCaching       bool             `json:",default=true"`
	CacheSize           int              `json:",default=1000"`
	CacheTTL            time.Duration    `json:",default=1h"`
}

// Provider configurations
type OpenAIConfig struct {
	APIKey      string   `json:",optional"`
	BaseURL     string   `json:",default=https://api.openai.com/v1"`
	Models      []string `json:",default=[\"gpt-4\",\"gpt-4-turbo\",\"gpt-3.5-turbo\"]"`
	MaxTokens   int      `json:",default=4096"`
	Temperature float64  `json:",default=0.7"`
	Enabled     bool     `json:",default=true"`
}

type AnthropicConfig struct {
	APIKey      string   `json:",optional"`
	BaseURL     string   `json:",default=https://api.anthropic.com/v1"`
	Models      []string `json:",default=[\"claude-3-opus-20240229\",\"claude-3-sonnet-20240229\",\"claude-3-haiku-20240307\"]"`
	MaxTokens   int      `json:",default=4096"`
	Temperature float64  `json:",default=0.7"`
	Enabled     bool     `json:",default=false"`
}

type GoogleConfig struct {
	APIKey      string   `json:",optional"`
	BaseURL     string   `json:",default=https://generativelanguage.googleapis.com/v1beta"`
	Models      []string `json:",default=[\"gemini-1.5-pro\",\"gemini-1.5-flash\",\"gemini-pro\"]"`
	MaxTokens   int      `json:",default=4096"`
	Temperature float64  `json:",default=0.7"`
	Enabled     bool     `json:",default=false"`
}

// VisionConfig configuration for vision services
type VisionConfig struct {
	Enabled             bool          `json:",default=true"`
	MaxImageSize        int64         `json:",default=10485760"` // 10MB
	SupportedFormats    []string      `json:",default=[\"jpg\",\"jpeg\",\"png\",\"gif\",\"webp\"]"`
	MaxResolution       string        `json:",default=4096x4096"`
	EnableFaceDetection bool          `json:",default=true"`
	EnableObjectDetection bool        `json:",default=true"`
	EnableOCR           bool          `json:",default=true"`
	EnableNSFW          bool          `json:",default=true"`
	ProcessingTimeout   time.Duration `json:",default=30s"`
}

// SpeechConfig configuration for speech services
type SpeechConfig struct {
	Enabled             bool          `json:",default=true"`
	MaxAudioSize        int64         `json:",default=52428800"` // 50MB
	MaxDuration         int           `json:",default=600"`      // 10 minutes
	SupportedFormats    []string      `json:",default=[\"mp3\",\"wav\",\"ogg\",\"m4a\"]"`
	EnableSTT           bool          `json:",default=true"`     // Speech to Text
	EnableTTS           bool          `json:",default=true"`     // Text to Speech
	EnableMusicAnalysis bool          `json:",default=false"`
	ProcessingTimeout   time.Duration `json:",default=60s"`
	AudioSampleRate     int           `json:",default=44100"`
}

// MultimodalConfig configuration for multimodal services
type MultimodalConfig struct {
	Enabled             bool          `json:",default=true"`
	MaxFileSize         int64         `json:",default=104857600"` // 100MB
	SupportedFormats    []string      `json:",default=[\"jpg\",\"png\",\"gif\",\"mp4\",\"mp3\",\"wav\",\"txt\"]"`
	ProcessingTimeout   time.Duration `json:",default=60s"`
	ImageMaxWidth       int           `json:",default=4096"`
	ImageMaxHeight      int           `json:",default=4096"`
	AudioSampleRate     int           `json:",default=44100"`
	VideoMaxDuration    int           `json:",default=300"` // 5 minutes
	MaxConcurrentJobs   int           `json:",default=10"`
	EnableGPU           bool          `json:",default=false"`
	EnableCaching       bool          `json:",default=true"`
}

// ModerationConfig configuration for content moderation
type ModerationConfig struct {
	Enabled               bool          `json:",default=true"`
	EnableTextModeration  bool          `json:",default=true"`
	EnableImageModeration bool          `json:",default=true"`
	EnableAudioModeration bool          `json:",default=false"`
	EnableVideoModeration bool          `json:",default=false"`
	
	// Thresholds
	ToxicityThreshold     float64       `json:",default=0.7"`
	NSFWThreshold         float64       `json:",default=0.8"`
	SpamThreshold         float64       `json:",default=0.6"`
	HateSpeechThreshold   float64       `json:",default=0.8"`
	
	// Actions
	AutoBlock             bool          `json:",default=false"`
	AutoWarn              bool          `json:",default=true"`
	RequireReview         bool          `json:",default=true"`
	
	// Performance
	ProcessingTimeout     time.Duration `json:",default=10s"`
	MaxConcurrentChecks   int           `json:",default=20"`
	EnableCaching         bool          `json:",default=true"`
	CacheTTL              time.Duration `json:",default=1h"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.AI == nil {
		return nil // AI is optional
	}
	
	// Validate basic settings
	if c.AI.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("max_concurrent_requests must be positive")
	}
	
	if c.AI.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout must be positive")
	}
	
	// Validate LLM config
	if c.AI.LLMConfig != nil {
		if err := c.validateLLMConfig(); err != nil {
			return fmt.Errorf("invalid LLM config: %w", err)
		}
	}
	
	// Validate vision config
	if c.AI.VisionConfig != nil {
		if err := c.validateVisionConfig(); err != nil {
			return fmt.Errorf("invalid vision config: %w", err)
		}
	}
	
	// Validate speech config
	if c.AI.SpeechConfig != nil {
		if err := c.validateSpeechConfig(); err != nil {
			return fmt.Errorf("invalid speech config: %w", err)
		}
	}
	
	// Validate multimodal config
	if c.AI.MultimodalConfig != nil {
		if err := c.validateMultimodalConfig(); err != nil {
			return fmt.Errorf("invalid multimodal config: %w", err)
		}
	}
	
	// Validate moderation config
	if c.AI.ModerationConfig != nil {
		if err := c.validateModerationConfig(); err != nil {
			return fmt.Errorf("invalid moderation config: %w", err)
		}
	}
	
	return nil
}

func (c *Config) validateLLMConfig() error {
	llm := c.AI.LLMConfig
	
	if llm.DefaultMaxTokens <= 0 {
		return fmt.Errorf("default_max_tokens must be positive")
	}
	
	if llm.DefaultTemperature < 0 || llm.DefaultTemperature > 2 {
		return fmt.Errorf("default_temperature must be between 0 and 2")
	}
	
	if llm.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout must be positive")
	}
	
	return nil
}

func (c *Config) validateVisionConfig() error {
	vision := c.AI.VisionConfig
	
	if vision.MaxImageSize <= 0 {
		return fmt.Errorf("max_image_size must be positive")
	}
	
	if len(vision.SupportedFormats) == 0 {
		return fmt.Errorf("supported_formats cannot be empty")
	}
	
	if vision.ProcessingTimeout <= 0 {
		return fmt.Errorf("processing_timeout must be positive")
	}
	
	return nil
}

func (c *Config) validateSpeechConfig() error {
	speech := c.AI.SpeechConfig
	
	if speech.MaxAudioSize <= 0 {
		return fmt.Errorf("max_audio_size must be positive")
	}
	
	if speech.MaxDuration <= 0 {
		return fmt.Errorf("max_duration must be positive")
	}
	
	if speech.AudioSampleRate <= 0 {
		return fmt.Errorf("audio_sample_rate must be positive")
	}
	
	return nil
}

func (c *Config) validateMultimodalConfig() error {
	mm := c.AI.MultimodalConfig
	
	if mm.MaxFileSize <= 0 {
		return fmt.Errorf("max_file_size must be positive")
	}
	
	if mm.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max_concurrent_jobs must be positive")
	}
	
	if mm.VideoMaxDuration <= 0 {
		return fmt.Errorf("video_max_duration must be positive")
	}
	
	return nil
}

func (c *Config) validateModerationConfig() error {
	mod := c.AI.ModerationConfig
	
	if mod.ToxicityThreshold < 0 || mod.ToxicityThreshold > 1 {
		return fmt.Errorf("toxicity_threshold must be between 0 and 1")
	}
	
	if mod.NSFWThreshold < 0 || mod.NSFWThreshold > 1 {
		return fmt.Errorf("nsfw_threshold must be between 0 and 1")
	}
	
	if mod.MaxConcurrentChecks <= 0 {
		return fmt.Errorf("max_concurrent_checks must be positive")
	}
	
	return nil
}

// GetAIConfig returns AI configuration with defaults
func (c *Config) GetAIConfig() *AIServiceConfig {
	if c.AI == nil {
		return &AIServiceConfig{
			Enabled:               false,
			MaxConcurrentRequests: 100,
			RequestTimeout:        30 * time.Second,
			EnableCaching:         true,
			CacheSize:             1000,
			CacheTTL:              1 * time.Hour,
			EnableRateLimit:       true,
			RequestsPerSecond:     10,
			BurstSize:             20,
			EnableMetrics:         true,
			MetricsPort:           9053,
			HealthCheckInterval:   30 * time.Second,
		}
	}
	
	return c.AI
}

// IsAIEnabled returns whether AI is enabled
func (c *Config) IsAIEnabled() bool {
	return c.AI != nil && c.AI.Enabled
}

// GetMetricsAddress returns the metrics port address
func (c *Config) GetMetricsAddress() string {
	if !c.IsAIEnabled() || !c.AI.EnableMetrics {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.AI.MetricsPort)
}
