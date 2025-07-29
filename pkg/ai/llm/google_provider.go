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

// GoogleProvider implements LLM provider for Google Gemini models
type GoogleProvider struct {
	mutex      sync.RWMutex
	config     *GoogleConfig
	httpClient *http.Client
	metrics    *ProviderMetrics
	logger     logx.Logger
	isRunning  bool
}

// GoogleRequest represents a Google Gemini API request
type GoogleRequest struct {
	Contents         []GoogleContent         `json:"contents"`
	GenerationConfig *GoogleGenerationConfig `json:"generationConfig,omitempty"`
	SafetySettings   []GoogleSafetySetting   `json:"safetySettings,omitempty"`
}

// GoogleContent represents content in Google format
type GoogleContent struct {
	Role  string       `json:"role"`
	Parts []GooglePart `json:"parts"`
}

// GooglePart represents a part of content
type GooglePart struct {
	Text string `json:"text"`
}

// GoogleGenerationConfig represents generation configuration
type GoogleGenerationConfig struct {
	Temperature     float64  `json:"temperature,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	TopK            int      `json:"topK,omitempty"`
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

// GoogleSafetySetting represents safety settings
type GoogleSafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

// GoogleResponse represents a Google Gemini API response
type GoogleResponse struct {
	Candidates     []GoogleCandidate    `json:"candidates"`
	UsageMetadata  GoogleUsageMetadata  `json:"usageMetadata"`
	Error          *GoogleError         `json:"error,omitempty"`
}

// GoogleCandidate represents a candidate response
type GoogleCandidate struct {
	Content       GoogleContent       `json:"content"`
	FinishReason  string              `json:"finishReason"`
	Index         int                 `json:"index"`
	SafetyRatings []GoogleSafetyRating `json:"safetyRatings"`
}

// GoogleSafetyRating represents safety rating
type GoogleSafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

// GoogleUsageMetadata represents usage metadata
type GoogleUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// GoogleError represents an error in Google response
type GoogleError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// NewGoogleProvider creates a new Google provider
func NewGoogleProvider(config *GoogleConfig) (*GoogleProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("Google config is required")
	}
	
	if config.APIKey == "" {
		return nil, fmt.Errorf("Google API key is required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	
	if len(config.Models) == 0 {
		config.Models = []string{"gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"}
	}
	
	provider := &GoogleProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		metrics: &ProviderMetrics{
			Name:        "google",
			IsAvailable: true,
		},
		logger: logx.WithContext(nil),
	}
	
	return provider, nil
}

// Name returns the provider name
func (gp *GoogleProvider) Name() string {
	return "google"
}

// Start starts the Google provider
func (gp *GoogleProvider) Start() error {
	gp.mutex.Lock()
	defer gp.mutex.Unlock()
	
	if gp.isRunning {
		return fmt.Errorf("Google provider is already running")
	}
	
	gp.logger.Info("Starting Google provider...")
	
	// Test API connectivity
	if err := gp.testConnectivity(); err != nil {
		gp.logger.Errorf("Google connectivity test failed: %v", err)
		gp.metrics.IsAvailable = false
		return err
	}
	
	gp.isRunning = true
	gp.metrics.IsAvailable = true
	gp.logger.Info("Google provider started successfully")
	
	return nil
}

// Stop stops the Google provider
func (gp *GoogleProvider) Stop() error {
	gp.mutex.Lock()
	defer gp.mutex.Unlock()
	
	if !gp.isRunning {
		return nil
	}
	
	gp.logger.Info("Stopping Google provider...")
	gp.isRunning = false
	gp.metrics.IsAvailable = false
	gp.logger.Info("Google provider stopped")
	
	return nil
}

// ProcessText processes a text request using Google Gemini
func (gp *GoogleProvider) ProcessText(ctx context.Context, request *TextRequest) (*TextResponse, error) {
	start := time.Now()
	
	gp.mutex.RLock()
	if !gp.isRunning {
		gp.mutex.RUnlock()
		return nil, fmt.Errorf("Google provider is not running")
	}
	gp.mutex.RUnlock()
	
	// Prepare Google request
	googleReq := gp.prepareRequest(request)
	
	// Make API call
	googleResp, err := gp.makeAPICall(ctx, googleReq, request.Model)
	if err != nil {
		gp.updateMetrics(false, time.Since(start), 0)
		return nil, fmt.Errorf("Google API call failed: %w", err)
	}
	
	// Convert response
	response := gp.convertResponse(request, googleResp)
	response.ProcessTime = time.Since(start)
	
	gp.updateMetrics(true, time.Since(start), response.TokensUsed)
	
	return response, nil
}

// GetAvailableModels returns available Google models
func (gp *GoogleProvider) GetAvailableModels() []string {
	gp.mutex.RLock()
	defer gp.mutex.RUnlock()
	
	if !gp.isRunning {
		return []string{}
	}
	
	return gp.config.Models
}

// IsAvailable returns whether the provider is available
func (gp *GoogleProvider) IsAvailable() bool {
	gp.mutex.RLock()
	defer gp.mutex.RUnlock()
	
	return gp.isRunning && gp.metrics.IsAvailable
}

// GetMetrics returns provider metrics
func (gp *GoogleProvider) GetMetrics() *ProviderMetrics {
	gp.mutex.RLock()
	defer gp.mutex.RUnlock()
	
	// Return a copy
	metrics := *gp.metrics
	return &metrics
}

// testConnectivity tests API connectivity
func (gp *GoogleProvider) testConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create a simple test request
	testReq := &GoogleRequest{
		Contents: []GoogleContent{
			{
				Role: "user",
				Parts: []GooglePart{
					{Text: "Hello"},
				},
			},
		},
		GenerationConfig: &GoogleGenerationConfig{
			MaxOutputTokens: 5,
		},
	}
	
	_, err := gp.makeAPICall(ctx, testReq, gp.config.Models[0])
	return err
}

// prepareRequest prepares a Google request from a text request
func (gp *GoogleProvider) prepareRequest(request *TextRequest) *GoogleRequest {
	maxTokens := request.MaxTokens
	if maxTokens == 0 {
		maxTokens = gp.config.MaxTokens
	}
	
	temperature := request.Temperature
	if temperature == 0 {
		temperature = gp.config.Temperature
	}
	
	// Build contents
	var contents []GoogleContent
	
	// Add system prompt as first user message if provided
	if request.SystemPrompt != "" {
		contents = append(contents, GoogleContent{
			Role: "user",
			Parts: []GooglePart{
				{Text: "System: " + request.SystemPrompt},
			},
		})
	}
	
	// Add context messages
	for _, msg := range request.Context {
		role := msg.Role
		if role == "assistant" {
			role = "model" // Google uses "model" instead of "assistant"
		}
		
		contents = append(contents, GoogleContent{
			Role: role,
			Parts: []GooglePart{
				{Text: msg.Content},
			},
		})
	}
	
	// Add current message
	contents = append(contents, GoogleContent{
		Role: "user",
		Parts: []GooglePart{
			{Text: request.Text},
		},
	})
	
	return &GoogleRequest{
		Contents: contents,
		GenerationConfig: &GoogleGenerationConfig{
			Temperature:     temperature,
			MaxOutputTokens: maxTokens,
		},
		SafetySettings: []GoogleSafetySetting{
			{
				Category:  "HARM_CATEGORY_HARASSMENT",
				Threshold: "BLOCK_MEDIUM_AND_ABOVE",
			},
			{
				Category:  "HARM_CATEGORY_HATE_SPEECH",
				Threshold: "BLOCK_MEDIUM_AND_ABOVE",
			},
		},
	}
}

// makeAPICall makes an API call to Google Gemini
func (gp *GoogleProvider) makeAPICall(ctx context.Context, request *GoogleRequest, model string) (*GoogleResponse, error) {
	if model == "" {
		model = gp.config.Models[0]
	}
	
	// Serialize request
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", gp.config.BaseURL, model, gp.config.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Teamgram-AI/1.0")
	
	// Make request
	resp, err := gp.httpClient.Do(httpReq)
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
	var googleResp GoogleResponse
	if err := json.Unmarshal(respBody, &googleResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Check for API errors
	if googleResp.Error != nil {
		return nil, fmt.Errorf("Google API error: %s", googleResp.Error.Message)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	
	return &googleResp, nil
}

// convertResponse converts Google response to standard format
func (gp *GoogleProvider) convertResponse(request *TextRequest, googleResp *GoogleResponse) *TextResponse {
	model := request.Model
	if model == "" {
		model = gp.config.Models[0]
	}
	
	response := &TextResponse{
		ID:        fmt.Sprintf("google_%d", time.Now().UnixNano()),
		RequestID: request.ID,
		Model:     model,
		Provider:  "google",
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
	
	// Extract text from first candidate
	if len(googleResp.Candidates) > 0 {
		candidate := googleResp.Candidates[0]
		if len(candidate.Content.Parts) > 0 {
			response.Text = candidate.Content.Parts[0].Text
		}
		response.Metadata["finish_reason"] = candidate.FinishReason
		response.Metadata["safety_ratings"] = candidate.SafetyRatings
	}
	
	// Set token usage
	response.TokensUsed = int64(googleResp.UsageMetadata.TotalTokenCount)
	response.Metadata["prompt_tokens"] = googleResp.UsageMetadata.PromptTokenCount
	response.Metadata["completion_tokens"] = googleResp.UsageMetadata.CandidatesTokenCount
	
	// Set confidence (simplified)
	response.Confidence = 0.92 // Google doesn't provide confidence scores
	
	return response
}

// updateMetrics updates provider metrics
func (gp *GoogleProvider) updateMetrics(success bool, latency time.Duration, tokensUsed int64) {
	gp.mutex.Lock()
	defer gp.mutex.Unlock()
	
	gp.metrics.Requests++
	gp.metrics.TokensUsed += tokensUsed
	gp.metrics.LastUsed = time.Now()
	
	if success {
		gp.metrics.Successes++
		gp.metrics.AverageLatency = (gp.metrics.AverageLatency + latency) / 2
	} else {
		gp.metrics.Failures++
		gp.metrics.IsAvailable = false // Mark as unavailable on failure
	}
}
