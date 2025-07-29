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

package message

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ExampleRichTextProcessor demonstrates rich text processing
func ExampleRichTextProcessor() {
	processor := NewRichTextProcessor()

	// Parse Markdown
	text := "Hello **world**! Check out this `code` and visit [Telegram](https://telegram.org)"
	result, err := processor.ParseMarkdown(text)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Text: %s\n", result.Text)
	fmt.Printf("Entities: %d\n", len(result.Entities))
	for _, entity := range result.Entities {
		fmt.Printf("- %s at %d-%d\n", entity.Type, entity.Offset, entity.Offset+entity.Length)
	}

	// Output:
	// Text: Hello **world**! Check out this `code` and visit [Telegram](https://telegram.org)
	// Entities: 3
	// - bold at 6-13
	// - code at 32-38
	// - text_link at 54-63
}

// ExampleEmojiProcessor demonstrates emoji processing
func ExampleEmojiProcessor() {
	processor := NewEmojiProcessor()

	// Process text with emojis
	text := "Hello 😀 world! 👍"
	result, err := processor.ProcessText(text)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Text: %s\n", result.Text)
	fmt.Printf("Emoji entities: %d\n", len(result.Entities))

	// Get emoji suggestions
	suggestions, err := processor.GetSuggestions("smile", 3)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Suggestions for 'smile': %d\n", len(suggestions))
	for _, suggestion := range suggestions {
		fmt.Printf("- %s (%s)\n", suggestion.Name, suggestion.Shortcode)
	}

	// Output:
	// Text: Hello 😀 world! 👍
	// Emoji entities: 2
	// Suggestions for 'smile': 1
	// - grinning face (:grinning:)
}

// ExampleLocationProcessor demonstrates location processing
func ExampleLocationProcessor() {
	config := &LocationConfig{
		MaxLiveLocationDuration: 8 * time.Hour,
		UpdateInterval:          30 * time.Second,
		EnableGeocoding:         true,
	}
	processor := NewLocationProcessor(config)

	// Process location
	location := &LocationInfo{
		Latitude:  40.7128,
		Longitude: -74.0060,
		Accuracy:  10.0,
	}

	result, err := processor.ProcessLocation(context.Background(), location)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Location: %.4f, %.4f\n", result.Latitude, result.Longitude)
	fmt.Printf("Accuracy: %.1f meters\n", result.Accuracy)
	if result.Address != nil {
		fmt.Printf("Address: %s\n", result.Address.FormattedAddress)
	}

	// Output:
	// Location: 40.7128, -74.0060
	// Accuracy: 10.0 meters
	// Address: 40.712800, -74.006000
}

// ExamplePollProcessor demonstrates poll processing
func ExamplePollProcessor() {
	// Mock storage for example
	storage := &MockPollStorage{}
	config := &PollConfig{
		MaxOptions:        10,
		MaxQuestionLength: 300,
		MaxOptionLength:   100,
	}
	processor := NewPollProcessor(storage, config)

	// Create poll
	poll := &PollInfo{
		Question: "What's your favorite programming language?",
		Options: []*PollOption{
			{Text: "Go"},
			{Text: "Python"},
			{Text: "JavaScript"},
		},
		IsAnonymous:           true,
		AllowsMultipleAnswers: false,
		CreatedBy:             12345,
	}

	result, err := processor.CreatePoll(context.Background(), poll)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Poll created: %s\n", result.Question)
	fmt.Printf("Options: %d\n", len(result.Options))
	for i, option := range result.Options {
		fmt.Printf("- %d: %s\n", i, option.Text)
	}

	// Output:
	// Poll created: What's your favorite programming language?
	// Options: 3
	// - 0: Go
	// - 1: Python
	// - 2: JavaScript
}

// TestIntegrationExample demonstrates integration testing
func TestIntegrationExample(t *testing.T) {
	// Test rich text processing
	processor := NewRichTextProcessor()

	testCases := []struct {
		name        string
		input       string
		parseMode   string
		minEntities int
	}{
		{
			name:        "Markdown with formatting",
			input:       "**Bold** and __italic__ text",
			parseMode:   "Markdown",
			minEntities: 2,
		},
		{
			name:        "HTML with formatting",
			input:       "<b>Bold</b> and <i>italic</i> text",
			parseMode:   "HTML",
			minEntities: 2,
		},
		{
			name:        "Plain text with entities",
			input:       "Hello @username and visit https://telegram.org",
			parseMode:   "",
			minEntities: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var result *FormattedText
			var err error

			switch tc.parseMode {
			case "Markdown":
				result, err = processor.ParseMarkdown(tc.input)
			case "HTML":
				result, err = processor.ParseHTML(tc.input)
			default:
				entities, extractErr := processor.ExtractEntities(tc.input)
				if extractErr == nil {
					result = &FormattedText{
						Text:     tc.input,
						Entities: entities,
					}
				} else {
					err = extractErr
				}
			}

			if err != nil {
				t.Errorf("Processing failed: %v", err)
				return
			}

			if len(result.Entities) < tc.minEntities {
				t.Errorf("Expected at least %d entities, got %d", tc.minEntities, len(result.Entities))
			}

			// Validate entities
			validator := NewEntityValidator()
			if err := validator.Validate(result.Text, result.Entities); err != nil {
				t.Errorf("Entity validation failed: %v", err)
			}
		})
	}
}

// MockPollStorage implements PollStorage for testing
type MockPollStorage struct {
	polls map[string]*PollInfo
	votes map[string]map[int64]*PollAnswer
}

func (m *MockPollStorage) SavePoll(ctx context.Context, poll *PollInfo) error {
	if m.polls == nil {
		m.polls = make(map[string]*PollInfo)
	}
	m.polls[poll.ID] = poll
	return nil
}

func (m *MockPollStorage) GetPoll(ctx context.Context, pollID string) (*PollInfo, error) {
	if m.polls == nil {
		return nil, fmt.Errorf("poll not found")
	}
	poll, exists := m.polls[pollID]
	if !exists {
		return nil, fmt.Errorf("poll not found")
	}
	return poll, nil
}

func (m *MockPollStorage) SaveVote(ctx context.Context, vote *PollAnswer) error {
	if m.votes == nil {
		m.votes = make(map[string]map[int64]*PollAnswer)
	}
	if m.votes[vote.PollID] == nil {
		m.votes[vote.PollID] = make(map[int64]*PollAnswer)
	}
	m.votes[vote.PollID][vote.UserID] = vote
	return nil
}

func (m *MockPollStorage) GetUserVote(ctx context.Context, pollID string, userID int64) (*PollAnswer, error) {
	if m.votes == nil || m.votes[pollID] == nil {
		return nil, fmt.Errorf("vote not found")
	}
	vote, exists := m.votes[pollID][userID]
	if !exists {
		return nil, fmt.Errorf("vote not found")
	}
	return vote, nil
}

func (m *MockPollStorage) GetPollVotes(ctx context.Context, pollID string) ([]*PollAnswer, error) {
	if m.votes == nil || m.votes[pollID] == nil {
		return []*PollAnswer{}, nil
	}

	var votes []*PollAnswer
	for _, vote := range m.votes[pollID] {
		votes = append(votes, vote)
	}
	return votes, nil
}

// BenchmarkRichTextProcessing benchmarks rich text processing performance
func BenchmarkRichTextProcessing(b *testing.B) {
	processor := NewRichTextProcessor()
	text := strings.Repeat("**Bold** and __italic__ text with `code` and [links](https://example.com). ", 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := processor.ParseMarkdown(text)
		if err != nil {
			b.Fatalf("ParseMarkdown failed: %v", err)
		}
	}
}

// BenchmarkEmojiProcessing benchmarks emoji processing performance
func BenchmarkEmojiProcessing(b *testing.B) {
	processor := NewEmojiProcessor()
	text := strings.Repeat("Hello 😀 world! 👍 🎉 ❤️ 🚀 ", 20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := processor.ProcessText(text)
		if err != nil {
			b.Fatalf("ProcessText failed: %v", err)
		}
	}
}
