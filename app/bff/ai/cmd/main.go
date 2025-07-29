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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/teamgram/teamgram-server/app/bff/ai/internal/config"
	"github.com/teamgram/teamgram-server/app/bff/ai/internal/core"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/logx"
)

var configFile = flag.String("f", "etc/ai.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)

	// Validate configuration
	if err := c.Validate(); err != nil {
		logx.Errorf("Invalid configuration: %v", err)
		os.Exit(1)
	}

	logx.Infof("Starting Teamgram AI Service...")
	logx.Infof("Config file: %s", *configFile)

	// Check if AI is enabled
	if !c.IsAIEnabled() {
		logx.Info("AI service is disabled in configuration")
		os.Exit(0)
	}

	// Create AI service
	aiConfig := convertToAIConfig(c.GetAIConfig())
	aiService, err := core.NewAIService(aiConfig)
	if err != nil {
		logx.Errorf("Failed to create AI service: %v", err)
		os.Exit(1)
	}

	// Start AI service
	if err := aiService.Start(); err != nil {
		logx.Errorf("Failed to start AI service: %v", err)
		os.Exit(1)
	}

	logx.Info("AI service started successfully")

	// Print service information
	printServiceInfo(c, aiService)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start health monitoring
	go monitorHealth(ctx, aiService)

	// Start metrics reporting
	if c.GetAIConfig().EnableMetrics {
		go reportMetrics(ctx, aiService)
	}

	// Start performance monitoring
	go monitorPerformance(ctx, aiService)

	// Wait for shutdown signal
	<-sigChan
	logx.Info("Received shutdown signal, stopping AI service...")

	// Stop AI service
	if err := aiService.Stop(); err != nil {
		logx.Errorf("Error stopping AI service: %v", err)
	}

	logx.Info("AI service stopped gracefully")
}

// printServiceInfo prints service configuration and status
func printServiceInfo(c config.Config, service *core.AIService) {
	aiConfig := c.GetAIConfig()

	fmt.Println("\n=== Teamgram AI Service ===")
	fmt.Printf("Max Concurrent Requests: %d\n", aiConfig.MaxConcurrentRequests)
	fmt.Printf("Request Timeout: %v\n", aiConfig.RequestTimeout)

	if aiConfig.EnableMetrics {
		fmt.Printf("Metrics: %s\n", c.GetMetricsAddress())
	}

	if aiConfig.EnableRateLimit {
		fmt.Printf("Rate Limit: %d req/s (burst: %d)\n", aiConfig.RequestsPerSecond, aiConfig.BurstSize)
	}

	if aiConfig.EnableCaching {
		fmt.Printf("Cache: %d items, TTL: %v\n", aiConfig.CacheSize, aiConfig.CacheTTL)
	}

	// LLM information
	if aiConfig.LLMConfig != nil {
		fmt.Println("\nLLM Configuration:")
		fmt.Printf("  Default Model: %s\n", aiConfig.LLMConfig.DefaultModel)
		fmt.Printf("  Max Tokens: %d\n", aiConfig.LLMConfig.DefaultMaxTokens)
		fmt.Printf("  Temperature: %.2f\n", aiConfig.LLMConfig.DefaultTemperature)
		fmt.Printf("  Load Balance: %s\n", aiConfig.LLMConfig.LoadBalanceStrategy)

		if aiConfig.LLMConfig.OpenAIConfig != nil && aiConfig.LLMConfig.OpenAIConfig.Enabled {
			fmt.Printf("  ✓ OpenAI: %v\n", aiConfig.LLMConfig.OpenAIConfig.Models)
		}
		if aiConfig.LLMConfig.AnthropicConfig != nil && aiConfig.LLMConfig.AnthropicConfig.Enabled {
			fmt.Printf("  ✓ Anthropic: %v\n", aiConfig.LLMConfig.AnthropicConfig.Models)
		}
		if aiConfig.LLMConfig.GoogleConfig != nil && aiConfig.LLMConfig.GoogleConfig.Enabled {
			fmt.Printf("  ✓ Google: %v\n", aiConfig.LLMConfig.GoogleConfig.Models)
		}
	}

	// Vision information
	if aiConfig.VisionConfig != nil && aiConfig.VisionConfig.Enabled {
		fmt.Println("\nVision Configuration:")
		fmt.Printf("  Max Image Size: %d MB\n", aiConfig.VisionConfig.MaxImageSize/(1024*1024))
		fmt.Printf("  Supported Formats: %v\n", aiConfig.VisionConfig.SupportedFormats)
		fmt.Printf("  Max Resolution: %s\n", aiConfig.VisionConfig.MaxResolution)

		features := []string{}
		if aiConfig.VisionConfig.EnableFaceDetection {
			features = append(features, "Face Detection")
		}
		if aiConfig.VisionConfig.EnableObjectDetection {
			features = append(features, "Object Detection")
		}
		if aiConfig.VisionConfig.EnableOCR {
			features = append(features, "OCR")
		}
		if aiConfig.VisionConfig.EnableNSFW {
			features = append(features, "NSFW Detection")
		}
		fmt.Printf("  Features: %v\n", features)
	}

	// Speech information
	if aiConfig.SpeechConfig != nil && aiConfig.SpeechConfig.Enabled {
		fmt.Println("\nSpeech Configuration:")
		fmt.Printf("  Max Audio Size: %d MB\n", aiConfig.SpeechConfig.MaxAudioSize/(1024*1024))
		fmt.Printf("  Max Duration: %d seconds\n", aiConfig.SpeechConfig.MaxDuration)
		fmt.Printf("  Supported Formats: %v\n", aiConfig.SpeechConfig.SupportedFormats)
		fmt.Printf("  Sample Rate: %d Hz\n", aiConfig.SpeechConfig.AudioSampleRate)

		features := []string{}
		if aiConfig.SpeechConfig.EnableSTT {
			features = append(features, "Speech-to-Text")
		}
		if aiConfig.SpeechConfig.EnableTTS {
			features = append(features, "Text-to-Speech")
		}
		if aiConfig.SpeechConfig.EnableMusicAnalysis {
			features = append(features, "Music Analysis")
		}
		fmt.Printf("  Features: %v\n", features)
	}

	// Multimodal information
	if aiConfig.MultimodalConfig != nil && aiConfig.MultimodalConfig.Enabled {
		fmt.Println("\nMultimodal Configuration:")
		fmt.Printf("  Max File Size: %d MB\n", aiConfig.MultimodalConfig.MaxFileSize/(1024*1024))
		fmt.Printf("  Supported Formats: %v\n", aiConfig.MultimodalConfig.SupportedFormats)
		fmt.Printf("  Max Concurrent Jobs: %d\n", aiConfig.MultimodalConfig.MaxConcurrentJobs)
		fmt.Printf("  GPU Enabled: %v\n", aiConfig.MultimodalConfig.EnableGPU)
	}

	// Moderation information
	if aiConfig.ModerationConfig != nil && aiConfig.ModerationConfig.Enabled {
		fmt.Println("\nModeration Configuration:")
		fmt.Printf("  Text Moderation: %v\n", aiConfig.ModerationConfig.EnableTextModeration)
		fmt.Printf("  Image Moderation: %v\n", aiConfig.ModerationConfig.EnableImageModeration)
		fmt.Printf("  Audio Moderation: %v\n", aiConfig.ModerationConfig.EnableAudioModeration)
		fmt.Printf("  Video Moderation: %v\n", aiConfig.ModerationConfig.EnableVideoModeration)

		fmt.Printf("  Thresholds - Toxicity: %.2f, NSFW: %.2f, Spam: %.2f\n",
			aiConfig.ModerationConfig.ToxicityThreshold,
			aiConfig.ModerationConfig.NSFWThreshold,
			aiConfig.ModerationConfig.SpamThreshold)

		actions := []string{}
		if aiConfig.ModerationConfig.AutoBlock {
			actions = append(actions, "Auto Block")
		}
		if aiConfig.ModerationConfig.AutoWarn {
			actions = append(actions, "Auto Warn")
		}
		if aiConfig.ModerationConfig.RequireReview {
			actions = append(actions, "Require Review")
		}
		fmt.Printf("  Actions: %v\n", actions)
	}

	fmt.Println("\n=== Service Status ===")
	fmt.Printf("Running: %v\n", service.IsRunning())

	healthStatus, err := service.GetHealthStatus()
	fmt.Printf("Healthy: %v\n", healthStatus)
	if err != nil {
		fmt.Printf("Health check error: %v\n", err)
	}

	// Available models
	models := service.GetAvailableModels()
	fmt.Println("Available Models:")
	for _, model := range models {
		fmt.Printf("  - %s\n", model)
	}

	fmt.Println("\n=== Ready for AI Requests ===")
	fmt.Println("AI service is ready to process requests")
	fmt.Println("Press Ctrl+C to stop the service")
	fmt.Println()
}

// monitorHealth monitors service health
func monitorHealth(ctx context.Context, service *core.AIService) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			healthStatus, err := service.GetHealthStatus()
			if err != nil {
				logx.Errorf("Health check failed: %v", err)
			} else if healthStatus != "healthy" {
				logx.Errorf("Health check failed: %s", healthStatus)
			} else {
				logx.Debug("Health check passed")
			}
		}
	}
}

// reportMetrics reports service metrics
func reportMetrics(ctx context.Context, service *core.AIService) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()
			logx.Infof("AI Metrics - Total: %d, Success: %d (%.2f%%), Avg Latency: %v",
				metrics.TotalRequests,
				metrics.SuccessfulRequests,
				metrics.OverallAccuracy,
				metrics.AverageResponseTime)

			logx.Infof("Service Breakdown - LLM: %d, Vision: %d, Speech: %d, Multimodal: %d, Moderation: %d",
				metrics.LLMRequests,
				metrics.VisionRequests,
				metrics.SpeechRequests,
				metrics.MultimodalRequests,
				metrics.ModerationRequests)

			if metrics.CacheHits+metrics.CacheMisses > 0 {
				logx.Infof("Cache Performance - Hit Rate: %.2f%%, Hits: %d, Misses: %d",
					metrics.CacheHitRate,
					metrics.CacheHits,
					metrics.CacheMisses)
			}

			if metrics.RateLimitedRequests > 0 {
				logx.Errorf("Rate Limited Requests: %d", metrics.RateLimitedRequests)
			}
		}
	}
}

// monitorPerformance monitors performance and alerts on issues
func monitorPerformance(ctx context.Context, service *core.AIService) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()

			// Check response time
			if metrics.AverageResponseTime > 1*time.Second {
				logx.Errorf("High average response time: %v", metrics.AverageResponseTime)
			}

			// Check accuracy
			if metrics.OverallAccuracy < 95.0 && metrics.TotalRequests > 10 {
				logx.Errorf("Low accuracy: %.2f%%", metrics.OverallAccuracy)
			}

			// Check error rate
			if metrics.TotalRequests > 0 {
				errorRate := float64(metrics.FailedRequests) / float64(metrics.TotalRequests) * 100
				if errorRate > 5.0 {
					logx.Errorf("High error rate: %.2f%%", errorRate)
				}
			}

			// Check rate limiting
			if metrics.RateLimitedRequests > 0 {
				rateLimitRate := float64(metrics.RateLimitedRequests) / float64(metrics.TotalRequests) * 100
				if rateLimitRate > 10.0 {
					logx.Errorf("High rate limit rate: %.2f%%", rateLimitRate)
				}
			}
		}
	}
}

// convertToAIConfig converts AIServiceConfig to AIConfig
func convertToAIConfig(serviceConfig *config.AIServiceConfig) *core.AIConfig {
	if serviceConfig == nil {
		return core.DefaultAIConfig()
	}

	return &core.AIConfig{
		LLMProvider:        "openai",
		LLMModel:           "gpt-4-turbo",
		MaxTokens:          4096,
		Temperature:        0.7,
		TopP:               0.9,
		VisionProvider:     "openai",
		VisionModel:        "gpt-4-vision",
		MaxImageSize:       20 * 1024 * 1024,
		SupportedFormats:   []string{"jpg", "jpeg", "png", "gif", "webp"},
		SpeechProvider:     "openai",
		TTSModel:           "tts-1-hd",
		STTModel:           "whisper-1",
		SupportedLanguages: []string{"en", "zh", "es", "fr", "de", "ja", "ko", "ru", "ar", "hi"},
		ResponseTime:       serviceConfig.RequestTimeout,
		AccuracyTarget:     99.99,
		ConcurrentRequests: serviceConfig.MaxConcurrentRequests,
		ContentFiltering:   true,
		PrivacyMode:        true,
		DataRetention:      24 * time.Hour,
		EncryptionEnabled:  true,
	}
}
