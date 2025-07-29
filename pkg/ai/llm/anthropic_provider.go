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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// AnthropicProvider implements LLM provider for Anthropic Claude models
type AnthropicProvider struct {
	mutex      sync.RWMutex
	config     *AnthropicConfig
	httpClient *http.Client
	metrics    *ProviderMetrics
	logger     logx.Logger
	isRunning  bool
}

// AnthropicRequest represents an Anthropic API request
type AnthropicRequest struct {
	Model       string              `json:"model"`
	MaxTokens   int                 `json:"max_tokens"`
	Messages    []AnthropicMessage  `json:"messages"`
	System      string              `json:"system,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
	StopSequences []string          `json:"stop_sequences,omitempty"`
}

// AnthropicMessage represents a message in Anthropic format
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicResponse represents an Anthropic API response
type AnthropicResponse struct {
	ID           string              `json:"id"`
	Type         string              `json:"type"`
	Role         string              `json:"role"`
	Content      []AnthropicContent  `json:"content"`
	Model        string              `json:"model"`
	StopReason   string              `json:"stop_reason"`
	StopSequence string              `json:"stop_sequence"`
	Usage        AnthropicUsage      `json:"usage"`
	Error        *AnthropicError     `json:"error,omitempty"`
}

// AnthropicContent represents content in Anthropic response
type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AnthropicUsage represents token usage in Anthropic response
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnthropicError represents an error in Anthropic response
type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(config *AnthropicConfig) (*AnthropicProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("Anthropic config is required")
	}
	
	if config.APIKey == "" {
		return nil, fmt.Errorf("Anthropic API key is required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.anthropic.com/v1"
	}
	
	if len(config.Models) == 0 {
		config.Models = []string{"claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"}
	}
	
	provider := &AnthropicProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		metrics: &ProviderMetrics{
			Name:        "anthropic",
			IsAvailable: true,
		},
		logger: logx.WithContext(nil),
	}
	
	return provider, nil
}

// Name returns the provider name
func (ap *AnthropicProvider) Name() string {
	return "anthropic"
}

// Start starts the Anthropic provider
func (ap *AnthropicProvider) Start() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	
	if ap.isRunning {
		return fmt.Errorf("Anthropic provider is already running")
	}
	
	ap.logger.Info("Starting Anthropic provider...")
	
	// Test API connectivity
	if err := ap.testConnectivity(); err != nil {
		ap.logger.Errorf("Anthropic connectivity test failed: %v", err)
		ap.metrics.IsAvailable = false
		return err
	}
	
	ap.isRunning = true
	ap.metrics.IsAvailable = true
	ap.logger.Info("Anthropic provider started successfully")
	
	return nil
}

// Stop stops the Anthropic provider
func (ap *AnthropicProvider) Stop() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	
	if !ap.isRunning {
		return nil
	}
	
	ap.logger.Info("Stopping Anthropic provider...")
	ap.isRunning = false
	ap.metrics.IsAvailable = false
	ap.logger.Info("Anthropic provider stopped")
	
	return nil
}

// ProcessText processes a text request using Anthropic
func (ap *AnthropicProvider) ProcessText(ctx context.Context, request *TextRequest) (*TextResponse, error) {
	start := time.Now()
	
	ap.mutex.RLock()
	if !ap.isRunning {
		ap.mutex.RUnlock()
		return nil, fmt.Errorf("Anthropic provider is not running")
	}
	ap.mutex.RUnlock()
	
	// Prepare Anthropic request
	anthropicReq := ap.prepareRequest(request)
	
	// Make API call
	anthropicResp, err := ap.makeAPICall(ctx, anthropicReq)
	if err != nil {
		ap.updateMetrics(false, time.Since(start), 0)
		return nil, fmt.Errorf("Anthropic API call failed: %w", err)
	}
	
	// Convert response
	response := ap.convertResponse(request, anthropicResp)
	response.ProcessTime = time.Since(start)
	
	ap.updateMetrics(true, time.Since(start), response.TokensUsed)
	
	return response, nil
}

// GetAvailableModels returns available Anthropic models
func (ap *AnthropicProvider) GetAvailableModels() []string {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	
	if !ap.isRunning {
		return []string{}
	}
	
	return ap.config.Models
}

// IsAvailable returns whether the provider is available
func (ap *AnthropicProvider) IsAvailable() bool {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	
	return ap.isRunning && ap.metrics.IsAvailable
}

// GetMetrics returns provider metrics
func (ap *AnthropicProvider) GetMetrics() *ProviderMetrics {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	
	// Return a copy
	metrics := *ap.metrics
	return &metrics
}

// testConnectivity tests API connectivity
func (ap *AnthropicProvider) testConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create a simple test request
	testReq := &AnthropicRequest{
		Model:     ap.config.Models[0],
		MaxTokens: 5,
		Messages: []AnthropicMessage{
			{Role: "user", Content: "Hello"},
		},
	}
	
	_, err := ap.makeAPICall(ctx, testReq)
	return err
}

// prepareRequest prepares an Anthropic request from a text request
func (ap *AnthropicProvider) prepareRequest(request *TextRequest) *AnthropicRequest {
	model := request.Model
	if model == "" {
		model = ap.config.Models[0] // Use first available model
	}
	
	maxTokens := request.MaxTokens
	if maxTokens == 0 {
		maxTokens = ap.config.MaxTokens
	}
	
	temperature := request.Temperature
	if temperature == 0 {
		temperature = ap.config.Temperature
	}
	
	// Build messages (exclude system messages from messages array)
	var messages []AnthropicMessage
	
	// Add context messages
	for _, msg := range request.Context {
		if msg.Role != "system" {
			messages = append(messages, AnthropicMessage{
				Role:    msg.Role,
				Content: msg.Content,
			})
		}
	}
	
	// Add current message
	messages = append(messages, AnthropicMessage{
		Role:    "user",
		Content: request.Text,
	})
	
	req := &AnthropicRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		Messages:    messages,
		Temperature: temperature,
	}
	
	// Set system prompt separately
	if request.SystemPrompt != "" {
		req.System = request.SystemPrompt
	}
	
	return req
}

// makeAPICall makes an API call to Anthropic
func (ap *AnthropicProvider) makeAPICall(ctx context.Context, request *AnthropicRequest) (*AnthropicResponse, error) {
	// Serialize request
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", ap.config.BaseURL+"/messages", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", ap.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("User-Agent", "Teamgram-AI/1.0")
	
	// Make request
	resp, err := ap.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	// Parse response
	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Check for API errors
	if anthropicResp.Error != nil {
		return nil, fmt.Errorf("Anthropic API error: %s", anthropicResp.Error.Message)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	
	return &anthropicResp, nil
}

// convertResponse converts Anthropic response to standard format
func (ap *AnthropicProvider) convertResponse(request *TextRequest, anthropicResp *AnthropicResponse) *TextResponse {
	response := &TextResponse{
		ID:        anthropicResp.ID,
		RequestID: request.ID,
		Model:     anthropicResp.Model,
		Provider:  "anthropic",
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
	
	// Extract text from content
	if len(anthropicResp.Content) > 0 {
		response.Text = anthropicResp.Content[0].Text
		response.Metadata["stop_reason"] = anthropicResp.StopReason
		if anthropicResp.StopSequence != "" {
			response.Metadata["stop_sequence"] = anthropicResp.StopSequence
		}
	}
	
	// Set token usage
	response.TokensUsed = int64(anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens)
	response.Metadata["input_tokens"] = anthropicResp.Usage.InputTokens
	response.Metadata["output_tokens"] = anthropicResp.Usage.OutputTokens
	
	// Set confidence (simplified)
	response.Confidence = 0.93 // Anthropic doesn't provide confidence scores
	
	return response
}

// updateMetrics updates provider metrics
func (ap *AnthropicProvider) updateMetrics(success bool, latency time.Duration, tokensUsed int64) {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	
	ap.metrics.Requests++
	ap.metrics.TokensUsed += tokensUsed
	ap.metrics.LastUsed = time.Now()
	
	if success {
		ap.metrics.Successes++
		ap.metrics.AverageLatency = (ap.metrics.AverageLatency + latency) / 2
	} else {
		ap.metrics.Failures++
		ap.metrics.IsAvailable = false // Mark as unavailable on failure
	}
}
