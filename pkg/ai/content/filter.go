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

package content

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Filter provides AI-powered content filtering
type Filter struct {
	config            *Config
	spamDetector      *SpamDetector
	nsfwDetector      *NSFWDetector
	languageDetector  *LanguageDetector
	sentimentAnalyzer *SentimentAnalyzer
	toxicityDetector  *ToxicityDetector
	metrics           *FilterMetrics
	mutex             sync.RWMutex
	logger            logx.Logger
}

// Config represents content filter configuration
type Config struct {
	SpamDetection     bool    `json:"spam_detection"`
	NSFWDetection     bool    `json:"nsfw_detection"`
	LanguageDetection bool    `json:"language_detection"`
	SentimentAnalysis bool    `json:"sentiment_analysis"`
	ToxicityDetection bool    `json:"toxicity_detection"`
	Threshold         float64 `json:"threshold"`
	StrictMode        bool    `json:"strict_mode"`
}

// FilterRequest represents a content filtering request
type FilterRequest struct {
	Content     []byte `json:"content"`
	ContentType string `json:"content_type"`
	UserID      int64  `json:"user_id"`
	Language    string `json:"language,omitempty"`
}

// FilterResult represents the result of content filtering
type FilterResult struct {
	Blocked        bool                   `json:"blocked"`
	Confidence     float64                `json:"confidence"`
	Reasons        []string               `json:"reasons"`
	Categories     []string               `json:"categories"`
	Language       string                 `json:"language"`
	Sentiment      string                 `json:"sentiment"`
	ToxicityScore  float64                `json:"toxicity_score"`
	SpamScore      float64                `json:"spam_score"`
	NSFWScore      float64                `json:"nsfw_score"`
	ProcessingTime time.Duration          `json:"processing_time"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// FilterMetrics tracks content filtering metrics
type FilterMetrics struct {
	TotalRequests      int64         `json:"total_requests"`
	BlockedContent     int64         `json:"blocked_content"`
	AllowedContent     int64         `json:"allowed_content"`
	SpamDetections     int64         `json:"spam_detections"`
	NSFWDetections     int64         `json:"nsfw_detections"`
	ToxicDetections    int64         `json:"toxic_detections"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	LastUpdate         time.Time     `json:"last_update"`
}

// SpamDetector detects spam content
type SpamDetector struct {
	enabled   bool
	patterns  []*regexp.Regexp
	keywords  []string
	threshold float64
}

// NSFWDetector detects NSFW content
type NSFWDetector struct {
	enabled   bool
	patterns  []*regexp.Regexp
	keywords  []string
	threshold float64
}

// LanguageDetector detects content language
type LanguageDetector struct {
	enabled bool
	models  map[string]*LanguageModel
}

// SentimentAnalyzer analyzes content sentiment
type SentimentAnalyzer struct {
	enabled bool
	models  map[string]*SentimentModel
}

// ToxicityDetector detects toxic content
type ToxicityDetector struct {
	enabled   bool
	patterns  []*regexp.Regexp
	keywords  []string
	threshold float64
}

// LanguageModel represents a language detection model
type LanguageModel struct {
	Language   string           `json:"language"`
	Patterns   []*regexp.Regexp `json:"patterns"`
	Keywords   []string         `json:"keywords"`
	Confidence float64          `json:"confidence"`
}

// SentimentModel represents a sentiment analysis model
type SentimentModel struct {
	Language      string   `json:"language"`
	PositiveWords []string `json:"positive_words"`
	NegativeWords []string `json:"negative_words"`
	NeutralWords  []string `json:"neutral_words"`
}

// NewFilter creates a new content filter
func NewFilter(config *Config) (*Filter, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	filter := &Filter{
		config: config,
		metrics: &FilterMetrics{
			LastUpdate: time.Now(),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize spam detector
	if config.SpamDetection {
		filter.spamDetector = &SpamDetector{
			enabled:   true,
			threshold: config.Threshold,
		}
		filter.initializeSpamDetector()
	}

	// Initialize NSFW detector
	if config.NSFWDetection {
		filter.nsfwDetector = &NSFWDetector{
			enabled:   true,
			threshold: config.Threshold,
		}
		filter.initializeNSFWDetector()
	}

	// Initialize language detector
	if config.LanguageDetection {
		filter.languageDetector = &LanguageDetector{
			enabled: true,
			models:  make(map[string]*LanguageModel),
		}
		filter.initializeLanguageDetector()
	}

	// Initialize sentiment analyzer
	if config.SentimentAnalysis {
		filter.sentimentAnalyzer = &SentimentAnalyzer{
			enabled: true,
			models:  make(map[string]*SentimentModel),
		}
		filter.initializeSentimentAnalyzer()
	}

	// Initialize toxicity detector
	if config.ToxicityDetection {
		filter.toxicityDetector = &ToxicityDetector{
			enabled:   true,
			threshold: config.Threshold,
		}
		filter.initializeToxicityDetector()
	}

	return filter, nil
}

// FilterContent filters content and returns analysis results
func (f *Filter) FilterContent(ctx context.Context, req *FilterRequest) (*FilterResult, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if len(req.Content) == 0 {
		return nil, errors.New("content cannot be empty")
	}

	startTime := time.Now()

	result := &FilterResult{
		Blocked:    false,
		Confidence: 0.0,
		Reasons:    make([]string, 0),
		Categories: make([]string, 0),
		Metadata:   make(map[string]interface{}),
	}

	content := string(req.Content)

	// Language detection
	if f.languageDetector != nil && f.languageDetector.enabled {
		language := f.detectLanguage(content)
		result.Language = language
		result.Metadata["detected_language"] = language
	}

	// Spam detection
	if f.spamDetector != nil && f.spamDetector.enabled {
		spamScore := f.detectSpam(content)
		result.SpamScore = spamScore
		if spamScore > f.spamDetector.threshold {
			result.Blocked = true
			result.Reasons = append(result.Reasons, "spam_detected")
			result.Categories = append(result.Categories, "spam")
			f.updateMetrics("spam_detected")
		}
	}

	// NSFW detection
	if f.nsfwDetector != nil && f.nsfwDetector.enabled {
		nsfwScore := f.detectNSFW(content)
		result.NSFWScore = nsfwScore
		if nsfwScore > f.nsfwDetector.threshold {
			result.Blocked = true
			result.Reasons = append(result.Reasons, "nsfw_detected")
			result.Categories = append(result.Categories, "nsfw")
			f.updateMetrics("nsfw_detected")
		}
	}

	// Toxicity detection
	if f.toxicityDetector != nil && f.toxicityDetector.enabled {
		toxicityScore := f.detectToxicity(content)
		result.ToxicityScore = toxicityScore
		if toxicityScore > f.toxicityDetector.threshold {
			result.Blocked = true
			result.Reasons = append(result.Reasons, "toxicity_detected")
			result.Categories = append(result.Categories, "toxic")
			f.updateMetrics("toxic_detected")
		}
	}

	// Sentiment analysis
	if f.sentimentAnalyzer != nil && f.sentimentAnalyzer.enabled {
		sentiment := f.analyzeSentiment(content, result.Language)
		result.Sentiment = sentiment
		result.Metadata["sentiment"] = sentiment
	}

	// Calculate overall confidence
	scores := []float64{result.SpamScore, result.NSFWScore, result.ToxicityScore}
	maxScore := 0.0
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}
	result.Confidence = maxScore

	// Processing time
	result.ProcessingTime = time.Since(startTime)

	// Update metrics
	f.updateMetrics("content_processed")
	if result.Blocked {
		f.updateMetrics("content_blocked")
	} else {
		f.updateMetrics("content_allowed")
	}

	return result, nil
}

// GetMetrics returns current filter metrics
func (f *Filter) GetMetrics() *FilterMetrics {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	metrics := *f.metrics
	return &metrics
}

// Private methods

func (f *Filter) initializeSpamDetector() {
	if f.spamDetector == nil {
		return
	}

	// Common spam patterns
	patterns := []string{
		`(?i)(buy now|click here|limited time|act now|urgent|free money)`,
		`(?i)(viagra|cialis|pharmacy|pills|medication)`,
		`(?i)(lottery|winner|congratulations|prize|million dollars)`,
		`(?i)(work from home|make money|easy money|get rich)`,
		`(?i)(crypto|bitcoin|investment|trading|profit)`,
	}

	f.spamDetector.patterns = make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			f.spamDetector.patterns = append(f.spamDetector.patterns, regex)
		}
	}

	f.spamDetector.keywords = []string{
		"spam", "scam", "fraud", "fake", "phishing",
		"malware", "virus", "trojan", "suspicious",
	}
}

func (f *Filter) initializeNSFWDetector() {
	if f.nsfwDetector == nil {
		return
	}

	// NSFW patterns (simplified for example)
	patterns := []string{
		`(?i)(adult|porn|xxx|sex|nude|naked)`,
		`(?i)(explicit|graphic|mature|18\+)`,
		`(?i)(erotic|sexual|intimate|sensual)`,
	}

	f.nsfwDetector.patterns = make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			f.nsfwDetector.patterns = append(f.nsfwDetector.patterns, regex)
		}
	}

	f.nsfwDetector.keywords = []string{
		"nsfw", "adult", "explicit", "mature", "sexual",
	}
}

func (f *Filter) initializeLanguageDetector() {
	if f.languageDetector == nil {
		return
	}

	// Initialize language models
	f.languageDetector.models["en"] = &LanguageModel{
		Language: "en",
		Keywords: []string{"the", "and", "or", "but", "in", "on", "at", "to", "for", "of"},
	}

	f.languageDetector.models["es"] = &LanguageModel{
		Language: "es",
		Keywords: []string{"el", "la", "y", "o", "pero", "en", "de", "a", "para", "con"},
	}

	f.languageDetector.models["fr"] = &LanguageModel{
		Language: "fr",
		Keywords: []string{"le", "la", "et", "ou", "mais", "dans", "de", "à", "pour", "avec"},
	}

	f.languageDetector.models["de"] = &LanguageModel{
		Language: "de",
		Keywords: []string{"der", "die", "das", "und", "oder", "aber", "in", "von", "zu", "für"},
	}
}

func (f *Filter) initializeSentimentAnalyzer() {
	if f.sentimentAnalyzer == nil {
		return
	}

	// Initialize sentiment models
	f.sentimentAnalyzer.models["en"] = &SentimentModel{
		Language:      "en",
		PositiveWords: []string{"good", "great", "excellent", "amazing", "wonderful", "fantastic", "love", "like", "happy", "joy"},
		NegativeWords: []string{"bad", "terrible", "awful", "horrible", "hate", "dislike", "sad", "angry", "frustrated", "disappointed"},
		NeutralWords:  []string{"okay", "fine", "normal", "average", "standard", "regular", "typical", "usual"},
	}
}

func (f *Filter) initializeToxicityDetector() {
	if f.toxicityDetector == nil {
		return
	}

	// Toxicity patterns
	patterns := []string{
		`(?i)(hate|kill|die|death|murder)`,
		`(?i)(stupid|idiot|moron|dumb|retard)`,
		`(?i)(racist|sexist|homophobic|bigot)`,
		`(?i)(threat|violence|harm|hurt|attack)`,
	}

	f.toxicityDetector.patterns = make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			f.toxicityDetector.patterns = append(f.toxicityDetector.patterns, regex)
		}
	}

	f.toxicityDetector.keywords = []string{
		"toxic", "harassment", "bullying", "abuse", "threat",
	}
}

func (f *Filter) detectSpam(content string) float64 {
	if f.spamDetector == nil || !f.spamDetector.enabled {
		return 0.0
	}

	score := 0.0
	content = strings.ToLower(content)

	// Check patterns
	for _, pattern := range f.spamDetector.patterns {
		if pattern.MatchString(content) {
			score += 0.3
		}
	}

	// Check keywords
	for _, keyword := range f.spamDetector.keywords {
		if strings.Contains(content, keyword) {
			score += 0.2
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (f *Filter) detectNSFW(content string) float64 {
	if f.nsfwDetector == nil || !f.nsfwDetector.enabled {
		return 0.0
	}

	score := 0.0
	content = strings.ToLower(content)

	// Check patterns
	for _, pattern := range f.nsfwDetector.patterns {
		if pattern.MatchString(content) {
			score += 0.4
		}
	}

	// Check keywords
	for _, keyword := range f.nsfwDetector.keywords {
		if strings.Contains(content, keyword) {
			score += 0.3
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (f *Filter) detectToxicity(content string) float64 {
	if f.toxicityDetector == nil || !f.toxicityDetector.enabled {
		return 0.0
	}

	score := 0.0
	content = strings.ToLower(content)

	// Check patterns
	for _, pattern := range f.toxicityDetector.patterns {
		if pattern.MatchString(content) {
			score += 0.5
		}
	}

	// Check keywords
	for _, keyword := range f.toxicityDetector.keywords {
		if strings.Contains(content, keyword) {
			score += 0.3
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (f *Filter) detectLanguage(content string) string {
	if f.languageDetector == nil || !f.languageDetector.enabled {
		return "unknown"
	}

	content = strings.ToLower(content)
	bestLanguage := "en" // Default to English
	bestScore := 0.0

	for lang, model := range f.languageDetector.models {
		score := 0.0
		for _, keyword := range model.Keywords {
			if strings.Contains(content, keyword) {
				score += 1.0
			}
		}

		if score > bestScore {
			bestScore = score
			bestLanguage = lang
		}
	}

	return bestLanguage
}

func (f *Filter) analyzeSentiment(content, language string) string {
	if f.sentimentAnalyzer == nil || !f.sentimentAnalyzer.enabled {
		return "neutral"
	}

	model, exists := f.sentimentAnalyzer.models[language]
	if !exists {
		model = f.sentimentAnalyzer.models["en"] // Fallback to English
	}

	content = strings.ToLower(content)
	positiveScore := 0.0
	negativeScore := 0.0

	for _, word := range model.PositiveWords {
		if strings.Contains(content, word) {
			positiveScore += 1.0
		}
	}

	for _, word := range model.NegativeWords {
		if strings.Contains(content, word) {
			negativeScore += 1.0
		}
	}

	if positiveScore > negativeScore {
		return "positive"
	} else if negativeScore > positiveScore {
		return "negative"
	}

	return "neutral"
}

func (f *Filter) updateMetrics(operation string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	switch operation {
	case "content_processed":
		f.metrics.TotalRequests++
	case "content_blocked":
		f.metrics.BlockedContent++
	case "content_allowed":
		f.metrics.AllowedContent++
	case "spam_detected":
		f.metrics.SpamDetections++
	case "nsfw_detected":
		f.metrics.NSFWDetections++
	case "toxic_detected":
		f.metrics.ToxicDetections++
	}

	f.metrics.LastUpdate = time.Now()
}
