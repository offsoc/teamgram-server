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

// OpenAIProvider implements LLM provider for OpenAI GPT models
type OpenAIProvider struct {
	mutex      sync.RWMutex
	config     *OpenAIConfig
	httpClient *http.Client
	metrics    *ProviderMetrics
	logger     logx.Logger
	isRunning  bool
}

// OpenAIRequest represents an OpenAI API request
type OpenAIRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIMessage     `json:"messages"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
	Stream      bool                `json:"stream"`
	Stop        []string            `json:"stop,omitempty"`
	User        string              `json:"user,omitempty"`
}

// OpenAIMessage represents a message in OpenAI format
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse represents an OpenAI API response
type OpenAIResponse struct {
	ID      string           `json:"id"`
	Object  string           `json:"object"`
	Created int64            `json:"created"`
	Model   string           `json:"model"`
	Choices []OpenAIChoice   `json:"choices"`
	Usage   OpenAIUsage      `json:"usage"`
	Error   *OpenAIError     `json:"error,omitempty"`
}

// OpenAIChoice represents a choice in OpenAI response
type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

// OpenAIUsage represents token usage in OpenAI response
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIError represents an error in OpenAI response
type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(config *OpenAIConfig) (*OpenAIProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("OpenAI config is required")
	}
	
	if config.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key is required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.openai.com/v1"
	}
	
	if len(config.Models) == 0 {
		config.Models = []string{"gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"}
	}
	
	provider := &OpenAIProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		metrics: &ProviderMetrics{
			Name:        "openai",
			IsAvailable: true,
		},
		logger: logx.WithContext(nil),
	}
	
	return provider, nil
}

// Name returns the provider name
func (op *OpenAIProvider) Name() string {
	return "openai"
}

// Start starts the OpenAI provider
func (op *OpenAIProvider) Start() error {
	op.mutex.Lock()
	defer op.mutex.Unlock()
	
	if op.isRunning {
		return fmt.Errorf("OpenAI provider is already running")
	}
	
	op.logger.Info("Starting OpenAI provider...")
	
	// Test API connectivity
	if err := op.testConnectivity(); err != nil {
		op.logger.Errorf("OpenAI connectivity test failed: %v", err)
		op.metrics.IsAvailable = false
		return err
	}
	
	op.isRunning = true
	op.metrics.IsAvailable = true
	op.logger.Info("OpenAI provider started successfully")
	
	return nil
}

// Stop stops the OpenAI provider
func (op *OpenAIProvider) Stop() error {
	op.mutex.Lock()
	defer op.mutex.Unlock()
	
	if !op.isRunning {
		return nil
	}
	
	op.logger.Info("Stopping OpenAI provider...")
	op.isRunning = false
	op.metrics.IsAvailable = false
	op.logger.Info("OpenAI provider stopped")
	
	return nil
}

// ProcessText processes a text request using OpenAI
func (op *OpenAIProvider) ProcessText(ctx context.Context, request *TextRequest) (*TextResponse, error) {
	start := time.Now()
	
	op.mutex.RLock()
	if !op.isRunning {
		op.mutex.RUnlock()
		return nil, fmt.Errorf("OpenAI provider is not running")
	}
	op.mutex.RUnlock()
	
	// Prepare OpenAI request
	openaiReq := op.prepareRequest(request)
	
	// Make API call
	openaiResp, err := op.makeAPICall(ctx, openaiReq)
	if err != nil {
		op.updateMetrics(false, time.Since(start), 0)
		return nil, fmt.Errorf("OpenAI API call failed: %w", err)
	}
	
	// Convert response
	response := op.convertResponse(request, openaiResp)
	response.ProcessTime = time.Since(start)
	
	op.updateMetrics(true, time.Since(start), response.TokensUsed)
	
	return response, nil
}

// GetAvailableModels returns available OpenAI models
func (op *OpenAIProvider) GetAvailableModels() []string {
	op.mutex.RLock()
	defer op.mutex.RUnlock()
	
	if !op.isRunning {
		return []string{}
	}
	
	return op.config.Models
}

// IsAvailable returns whether the provider is available
func (op *OpenAIProvider) IsAvailable() bool {
	op.mutex.RLock()
	defer op.mutex.RUnlock()
	
	return op.isRunning && op.metrics.IsAvailable
}

// GetMetrics returns provider metrics
func (op *OpenAIProvider) GetMetrics() *ProviderMetrics {
	op.mutex.RLock()
	defer op.mutex.RUnlock()
	
	// Return a copy
	metrics := *op.metrics
	return &metrics
}

// testConnectivity tests API connectivity
func (op *OpenAIProvider) testConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create a simple test request
	testReq := &OpenAIRequest{
		Model: op.config.Models[0],
		Messages: []OpenAIMessage{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 5,
	}
	
	_, err := op.makeAPICall(ctx, testReq)
	return err
}

// prepareRequest prepares an OpenAI request from a text request
func (op *OpenAIProvider) prepareRequest(request *TextRequest) *OpenAIRequest {
	model := request.Model
	if model == "" {
		model = op.config.Models[0] // Use first available model
	}
	
	maxTokens := request.MaxTokens
	if maxTokens == 0 {
		maxTokens = op.config.MaxTokens
	}
	
	temperature := request.Temperature
	if temperature == 0 {
		temperature = op.config.Temperature
	}
	
	// Build messages
	var messages []OpenAIMessage
	
	// Add system prompt if provided
	if request.SystemPrompt != "" {
		messages = append(messages, OpenAIMessage{
			Role:    "system",
			Content: request.SystemPrompt,
		})
	}
	
	// Add context messages
	for _, msg := range request.Context {
		messages = append(messages, OpenAIMessage{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}
	
	// Add current message
	messages = append(messages, OpenAIMessage{
		Role:    "user",
		Content: request.Text,
	})
	
	return &OpenAIRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temperature,
		Stream:      false,
		User:        fmt.Sprintf("user_%d", request.UserID),
	}
}

// makeAPICall makes an API call to OpenAI
func (op *OpenAIProvider) makeAPICall(ctx context.Context, request *OpenAIRequest) (*OpenAIResponse, error) {
	// Serialize request
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", op.config.BaseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+op.config.APIKey)
	httpReq.Header.Set("User-Agent", "Teamgram-AI/1.0")
	
	// Make request
	resp, err := op.httpClient.Do(httpReq)
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
	var openaiResp OpenAIResponse
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Check for API errors
	if openaiResp.Error != nil {
		return nil, fmt.Errorf("OpenAI API error: %s", openaiResp.Error.Message)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	
	return &openaiResp, nil
}

// convertResponse converts OpenAI response to standard format
func (op *OpenAIProvider) convertResponse(request *TextRequest, openaiResp *OpenAIResponse) *TextResponse {
	response := &TextResponse{
		ID:        openaiResp.ID,
		RequestID: request.ID,
		Model:     openaiResp.Model,
		Provider:  "openai",
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
	
	// Extract text from first choice
	if len(openaiResp.Choices) > 0 {
		response.Text = openaiResp.Choices[0].Message.Content
		response.Metadata["finish_reason"] = openaiResp.Choices[0].FinishReason
	}
	
	// Set token usage
	response.TokensUsed = int64(openaiResp.Usage.TotalTokens)
	response.Metadata["prompt_tokens"] = openaiResp.Usage.PromptTokens
	response.Metadata["completion_tokens"] = openaiResp.Usage.CompletionTokens
	
	// Set confidence (simplified)
	response.Confidence = 0.95 // OpenAI doesn't provide confidence scores
	
	return response
}

// updateMetrics updates provider metrics
func (op *OpenAIProvider) updateMetrics(success bool, latency time.Duration, tokensUsed int64) {
	op.mutex.Lock()
	defer op.mutex.Unlock()
	
	op.metrics.Requests++
	op.metrics.TokensUsed += tokensUsed
	op.metrics.LastUsed = time.Now()
	
	if success {
		op.metrics.Successes++
		op.metrics.AverageLatency = (op.metrics.AverageLatency + latency) / 2
	} else {
		op.metrics.Failures++
		op.metrics.IsAvailable = false // Mark as unavailable on failure
	}
}
