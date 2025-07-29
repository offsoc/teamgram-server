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
	"testing"
)

func TestEmojiProcessor_ProcessText(t *testing.T) {
	processor := NewEmojiProcessor()
	
	tests := []struct {
		name     string
		input    string
		expected int // number of emoji entities expected
	}{
		{
			name:     "Single emoji",
			input:    "Hello 😀 world",
			expected: 1,
		},
		{
			name:     "Multiple emojis",
			input:    "😀😂❤️👍",
			expected: 4,
		},
		{
			name:     "Custom emoji",
			input:    "Hello <:custom:123456789> world",
			expected: 1,
		},
		{
			name:     "Mixed emojis",
			input:    "😀 <:custom:123> 👍",
			expected: 3,
		},
		{
			name:     "No emojis",
			input:    "Plain text without emojis",
			expected: 0,
		},
		{
			name:     "Emoji with skin tone",
			input:    "👋🏻 Hello",
			expected: 1,
		},
		{
			name:     "Flag emoji",
			input:    "🇺🇸 United States",
			expected: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.ProcessText(tt.input)
			if err != nil {
				t.Errorf("ProcessText() error = %v", err)
				return
			}
			
			if len(result.Entities) != tt.expected {
				t.Errorf("ProcessText() got %d entities, expected %d", len(result.Entities), tt.expected)
			}
			
			// Verify all entities are emoji types
			for _, entity := range result.Entities {
				if entity.Type != EntityTypeCustomEmoji {
					t.Errorf("Expected emoji entity type, got %s", entity.Type)
				}
			}
		})
	}
}

func TestEmojiProcessor_GetSuggestions(t *testing.T) {
	processor := NewEmojiProcessor()
	
	tests := []struct {
		name     string
		query    string
		limit    int
		minCount int // minimum number of suggestions expected
	}{
		{
			name:     "Smile query",
			query:    "smile",
			limit:    5,
			minCount: 1,
		},
		{
			name:     "Heart query",
			query:    "heart",
			limit:    5,
			minCount: 1,
		},
		{
			name:     "Laugh query",
			query:    "laugh",
			limit:    5,
			minCount: 1,
		},
		{
			name:     "Empty query",
			query:    "",
			limit:    5,
			minCount: 0,
		},
		{
			name:     "Non-existent query",
			query:    "xyznonsense",
			limit:    5,
			minCount: 0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions, err := processor.GetSuggestions(tt.query, tt.limit)
			if err != nil {
				t.Errorf("GetSuggestions() error = %v", err)
				return
			}
			
			if len(suggestions) < tt.minCount {
				t.Errorf("GetSuggestions() got %d suggestions, expected at least %d", len(suggestions), tt.minCount)
			}
			
			if len(suggestions) > tt.limit {
				t.Errorf("GetSuggestions() got %d suggestions, expected at most %d", len(suggestions), tt.limit)
			}
			
			// Verify suggestion structure
			for _, suggestion := range suggestions {
				if suggestion.Type != "unicode" && suggestion.Type != "custom" {
					t.Errorf("Invalid suggestion type: %s", suggestion.Type)
				}
				
				if suggestion.Name == "" {
					t.Errorf("Suggestion name is empty")
				}
				
				if suggestion.Shortcode == "" {
					t.Errorf("Suggestion shortcode is empty")
				}
				
				if suggestion.Relevance < 0 {
					t.Errorf("Suggestion relevance is negative: %f", suggestion.Relevance)
				}
			}
		})
	}
}

func TestEmojiProcessor_AddCustomEmoji(t *testing.T) {
	processor := NewEmojiProcessor()
	
	customEmoji := &CustomEmojiInfo{
		ID:         "test123",
		Name:       "test emoji",
		Keywords:   []string{"test", "custom"},
		FileID:     "file123",
		IsAnimated: true,
		IsPremium:  true,
		Shortcodes: []string{":test:", ":custom_test:"},
	}
	
	err := processor.AddCustomEmoji(customEmoji)
	if err != nil {
		t.Errorf("AddCustomEmoji() error = %v", err)
		return
	}
	
	// Test that the emoji is now available in suggestions
	suggestions, err := processor.GetSuggestions("test", 10)
	if err != nil {
		t.Errorf("GetSuggestions() error = %v", err)
		return
	}
	
	found := false
	for _, suggestion := range suggestions {
		if suggestion.CustomID == "test123" {
			found = true
			break
		}
	}
	
	if !found {
		t.Errorf("Custom emoji not found in suggestions")
	}
}

func TestEmojiProcessor_AddCustomEmoji_EmptyID(t *testing.T) {
	processor := NewEmojiProcessor()
	
	customEmoji := &CustomEmojiInfo{
		ID:         "", // Empty ID should cause error
		Name:       "test emoji",
		Keywords:   []string{"test"},
		Shortcodes: []string{":test:"},
	}
	
	err := processor.AddCustomEmoji(customEmoji)
	if err == nil {
		t.Errorf("AddCustomEmoji() expected error for empty ID, got nil")
	}
}

func TestEmojiTrie_InsertAndSearch(t *testing.T) {
	trie := NewEmojiTrie()
	
	// Insert test suggestions
	suggestions := []*EmojiSuggestion{
		{Type: "unicode", Unicode: "😀", Name: "grinning face", Shortcode: ":grinning:"},
		{Type: "unicode", Unicode: "😂", Name: "face with tears of joy", Shortcode: ":joy:"},
		{Type: "unicode", Unicode: "❤️", Name: "red heart", Shortcode: ":heart:"},
	}
	
	for _, suggestion := range suggestions {
		trie.Insert(suggestion.Shortcode, suggestion)
	}
	
	// Test exact match
	results := trie.Search(":grinning:", 5)
	if len(results) == 0 {
		t.Errorf("Search() found no results for exact match")
	}
	
	// Test partial match
	results = trie.Search(":gr", 5)
	if len(results) == 0 {
		t.Errorf("Search() found no results for partial match")
	}
	
	// Test non-existent
	results = trie.Search(":nonexistent:", 5)
	if len(results) != 0 {
		t.Errorf("Search() found results for non-existent query")
	}
}

func TestEmojiProcessor_isEmojiRune(t *testing.T) {
	processor := NewEmojiProcessor()
	
	tests := []struct {
		name     string
		rune     rune
		expected bool
	}{
		{
			name:     "Grinning face emoji",
			rune:     '😀',
			expected: true,
		},
		{
			name:     "Heart emoji",
			rune:     '❤',
			expected: true,
		},
		{
			name:     "Regular letter",
			rune:     'A',
			expected: false,
		},
		{
			name:     "Number",
			rune:     '1',
			expected: false,
		},
		{
			name:     "Space",
			rune:     ' ',
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.isEmojiRune(tt.rune)
			if result != tt.expected {
				t.Errorf("isEmojiRune() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestEmojiProcessor_calculateRelevance(t *testing.T) {
	processor := NewEmojiProcessor()
	
	tests := []struct {
		name       string
		query      string
		suggestion *EmojiSuggestion
		minScore   float64
	}{
		{
			name:  "Exact shortcode match",
			query: ":smile:",
			suggestion: &EmojiSuggestion{
				Type:      "unicode",
				Name:      "smiling face",
				Shortcode: ":smile:",
			},
			minScore: 100.0,
		},
		{
			name:  "Exact name match",
			query: "smile",
			suggestion: &EmojiSuggestion{
				Type:      "unicode",
				Name:      "smile",
				Shortcode: ":smile:",
			},
			minScore: 90.0,
		},
		{
			name:  "Prefix match",
			query: "smi",
			suggestion: &EmojiSuggestion{
				Type:      "unicode",
				Name:      "smiling face",
				Shortcode: ":smile:",
			},
			minScore: 70.0,
		},
		{
			name:  "Custom emoji bonus",
			query: "custom",
			suggestion: &EmojiSuggestion{
				Type:      "custom",
				Name:      "custom emoji",
				Shortcode: ":custom:",
			},
			minScore: 5.0, // At least the custom bonus
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := processor.calculateRelevance(tt.query, tt.suggestion)
			if score < tt.minScore {
				t.Errorf("calculateRelevance() = %f, expected at least %f", score, tt.minScore)
			}
		})
	}
}

func TestEmojiProcessor_getEmojiSequenceLength(t *testing.T) {
	processor := NewEmojiProcessor()
	
	tests := []struct {
		name     string
		text     string
		start    int
		expected int
	}{
		{
			name:     "Single emoji",
			text:     "😀",
			start:    0,
			expected: 1,
		},
		{
			name:     "Emoji with skin tone",
			text:     "👋🏻",
			start:    0,
			expected: 2,
		},
		{
			name:     "Flag emoji",
			text:     "🇺🇸",
			start:    0,
			expected: 2,
		},
		{
			name:     "Regular character",
			text:     "A",
			start:    0,
			expected: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runes := []rune(tt.text)
			length := processor.getEmojiSequenceLength(runes, tt.start)
			if length != tt.expected {
				t.Errorf("getEmojiSequenceLength() = %d, expected %d", length, tt.expected)
			}
		})
	}
}
