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
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// EmojiProcessor handles emoji processing and suggestions
type EmojiProcessor struct {
	emojiMap         map[string]*EmojiInfo
	customEmojiMap   map[string]*CustomEmojiInfo
	suggestionTrie   *EmojiTrie
	unicodeRegex     *regexp.Regexp
	customEmojiRegex *regexp.Regexp
}

// EmojiInfo represents standard Unicode emoji information
type EmojiInfo struct {
	Unicode    string   `json:"unicode"`
	Name       string   `json:"name"`
	Keywords   []string `json:"keywords"`
	Category   string   `json:"category"`
	Version    string   `json:"version"`
	Shortcodes []string `json:"shortcodes"`
}

// CustomEmojiInfo represents custom animated emoji information
type CustomEmojiInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Keywords   []string `json:"keywords"`
	FileID     string   `json:"file_id"`
	IsAnimated bool     `json:"is_animated"`
	IsPremium  bool     `json:"is_premium"`
	Shortcodes []string `json:"shortcodes"`
}

// EmojiSuggestion represents an emoji suggestion
type EmojiSuggestion struct {
	Type      string  `json:"type"` // "unicode" or "custom"
	Unicode   string  `json:"unicode,omitempty"`
	CustomID  string  `json:"custom_id,omitempty"`
	Name      string  `json:"name"`
	Shortcode string  `json:"shortcode"`
	Relevance float64 `json:"relevance"`
}

// EmojiTrie for efficient emoji suggestion lookup
type EmojiTrie struct {
	children map[rune]*EmojiTrie
	emojis   []*EmojiSuggestion
	isEnd    bool
}

// NewEmojiProcessor creates a new emoji processor
func NewEmojiProcessor() *EmojiProcessor {
	ep := &EmojiProcessor{
		emojiMap:         make(map[string]*EmojiInfo),
		customEmojiMap:   make(map[string]*CustomEmojiInfo),
		suggestionTrie:   NewEmojiTrie(),
		unicodeRegex:     regexp.MustCompile(`[\x{1F600}-\x{1F64F}]|[\x{1F300}-\x{1F5FF}]|[\x{1F680}-\x{1F6FF}]|[\x{1F1E0}-\x{1F1FF}]|[\x{2600}-\x{26FF}]|[\x{2700}-\x{27BF}]`),
		customEmojiRegex: regexp.MustCompile(`<a?:([^:]+):(\d+)>`),
	}

	// Load default emoji set
	ep.loadDefaultEmojis()

	return ep
}

// NewEmojiTrie creates a new emoji trie
func NewEmojiTrie() *EmojiTrie {
	return &EmojiTrie{
		children: make(map[rune]*EmojiTrie),
		emojis:   make([]*EmojiSuggestion, 0),
	}
}

// ProcessText processes text to find and replace emoji entities
func (ep *EmojiProcessor) ProcessText(text string) (*FormattedText, error) {
	var entities []*MessageEntity

	// Find Unicode emojis
	entities = append(entities, ep.findUnicodeEmojis(text)...)

	// Find custom emojis
	entities = append(entities, ep.findCustomEmojis(text)...)

	// Sort entities by offset
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Offset < entities[j].Offset
	})

	return &FormattedText{
		Text:     text,
		Entities: entities,
	}, nil
}

// GetSuggestions returns emoji suggestions for a given query
func (ep *EmojiProcessor) GetSuggestions(query string, limit int) ([]*EmojiSuggestion, error) {
	if limit <= 0 {
		limit = 10
	}

	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return []*EmojiSuggestion{}, nil
	}

	suggestions := ep.suggestionTrie.Search(query, limit*2) // Get more for filtering

	// Score and sort suggestions
	for _, suggestion := range suggestions {
		suggestion.Relevance = ep.calculateRelevance(query, suggestion)
	}

	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Relevance > suggestions[j].Relevance
	})

	// Limit results
	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}

	return suggestions, nil
}

// AddCustomEmoji adds a custom emoji to the processor
func (ep *EmojiProcessor) AddCustomEmoji(emoji *CustomEmojiInfo) error {
	if emoji.ID == "" {
		return fmt.Errorf("custom emoji ID cannot be empty")
	}

	ep.customEmojiMap[emoji.ID] = emoji

	// Add to suggestion trie
	for _, shortcode := range emoji.Shortcodes {
		suggestion := &EmojiSuggestion{
			Type:      "custom",
			CustomID:  emoji.ID,
			Name:      emoji.Name,
			Shortcode: shortcode,
		}
		ep.suggestionTrie.Insert(shortcode, suggestion)
	}

	// Add keywords to trie
	for _, keyword := range emoji.Keywords {
		suggestion := &EmojiSuggestion{
			Type:      "custom",
			CustomID:  emoji.ID,
			Name:      emoji.Name,
			Shortcode: emoji.Shortcodes[0], // Use first shortcode
		}
		ep.suggestionTrie.Insert(keyword, suggestion)
	}

	return nil
}

// findUnicodeEmojis finds Unicode emoji entities in text
func (ep *EmojiProcessor) findUnicodeEmojis(text string) []*MessageEntity {
	var entities []*MessageEntity

	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		if ep.isEmojiRune(runes[i]) {
			// Check for multi-rune emoji sequences
			length := ep.getEmojiSequenceLength(runes, i)

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeCustomEmoji,
				Offset: i,
				Length: length,
			})

			i += length - 1 // Skip processed runes
		}
	}

	return entities
}

// findCustomEmojis finds custom emoji entities in text
func (ep *EmojiProcessor) findCustomEmojis(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ep.customEmojiRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 6 {
			offset := len([]rune(text[:match[0]]))
			length := len([]rune(text[match[0]:match[1]]))

			// Extract custom emoji ID
			customID := text[match[4]:match[5]]

			entities = append(entities, &MessageEntity{
				Type:          EntityTypeCustomEmoji,
				Offset:        offset,
				Length:        length,
				CustomEmojiID: customID,
			})
		}
	}

	return entities
}

// isEmojiRune checks if a rune is an emoji
func (ep *EmojiProcessor) isEmojiRune(r rune) bool {
	// Check common emoji ranges
	return (r >= 0x1F600 && r <= 0x1F64F) || // Emoticons
		(r >= 0x1F300 && r <= 0x1F5FF) || // Misc Symbols and Pictographs
		(r >= 0x1F680 && r <= 0x1F6FF) || // Transport and Map
		(r >= 0x1F1E0 && r <= 0x1F1FF) || // Regional Indicator Symbols
		(r >= 0x2600 && r <= 0x26FF) || // Misc symbols
		(r >= 0x2700 && r <= 0x27BF) || // Dingbats
		unicode.Is(unicode.So, r) // Other symbols
}

// getEmojiSequenceLength gets the length of an emoji sequence
func (ep *EmojiProcessor) getEmojiSequenceLength(runes []rune, start int) int {
	length := 1

	// Handle multi-rune emoji sequences (skin tones, ZWJ sequences, etc.)
	for i := start + 1; i < len(runes) && i < start+10; i++ { // Max 10 runes for safety
		r := runes[i]

		// Zero Width Joiner (ZWJ) sequences
		if r == 0x200D {
			length++
			continue
		}

		// Variation selectors
		if r >= 0xFE00 && r <= 0xFE0F {
			length++
			continue
		}

		// Skin tone modifiers
		if r >= 0x1F3FB && r <= 0x1F3FF {
			length++
			continue
		}

		// Regional indicator symbols (flags)
		if r >= 0x1F1E0 && r <= 0x1F1FF && i == start+1 {
			length++
			continue
		}

		// If not part of sequence, break
		if !ep.isEmojiRune(r) {
			break
		}

		// Check if this could be part of a sequence
		if i == start+1 && ep.isEmojiRune(r) {
			length++
		} else {
			break
		}
	}

	return length
}

// calculateRelevance calculates relevance score for emoji suggestion
func (ep *EmojiProcessor) calculateRelevance(query string, suggestion *EmojiSuggestion) float64 {
	score := 0.0

	// Exact match gets highest score
	if strings.EqualFold(query, suggestion.Shortcode) {
		score += 100.0
	} else if strings.HasPrefix(strings.ToLower(suggestion.Shortcode), query) {
		score += 80.0
	} else if strings.Contains(strings.ToLower(suggestion.Shortcode), query) {
		score += 60.0
	}

	// Name matching
	if strings.EqualFold(query, suggestion.Name) {
		score += 90.0
	} else if strings.HasPrefix(strings.ToLower(suggestion.Name), query) {
		score += 70.0
	} else if strings.Contains(strings.ToLower(suggestion.Name), query) {
		score += 50.0
	}

	// Custom emojis get slight boost for premium features
	if suggestion.Type == "custom" {
		score += 5.0
	}

	return score
}

// Insert inserts an emoji suggestion into the trie
func (trie *EmojiTrie) Insert(key string, suggestion *EmojiSuggestion) {
	current := trie

	for _, char := range strings.ToLower(key) {
		if current.children[char] == nil {
			current.children[char] = NewEmojiTrie()
		}
		current = current.children[char]
		current.emojis = append(current.emojis, suggestion)
	}

	current.isEnd = true
}

// Search searches for emoji suggestions in the trie
func (trie *EmojiTrie) Search(prefix string, limit int) []*EmojiSuggestion {
	current := trie

	// Navigate to prefix
	for _, char := range strings.ToLower(prefix) {
		if current.children[char] == nil {
			return []*EmojiSuggestion{}
		}
		current = current.children[char]
	}

	// Collect suggestions
	suggestions := make([]*EmojiSuggestion, 0, limit)
	seen := make(map[string]bool)

	for _, emoji := range current.emojis {
		key := emoji.Type + ":" + emoji.Shortcode
		if !seen[key] && len(suggestions) < limit {
			suggestions = append(suggestions, emoji)
			seen[key] = true
		}
	}

	return suggestions
}

// loadDefaultEmojis loads a basic set of default emojis
func (ep *EmojiProcessor) loadDefaultEmojis() {
	// Basic emoji set - in production this would be loaded from a comprehensive database
	defaultEmojis := []*EmojiInfo{
		{Unicode: "😀", Name: "grinning face", Keywords: []string{"happy", "smile"}, Shortcodes: []string{":grinning:", ":smile:"}},
		{Unicode: "😂", Name: "face with tears of joy", Keywords: []string{"laugh", "funny"}, Shortcodes: []string{":joy:", ":laugh:"}},
		{Unicode: "❤️", Name: "red heart", Keywords: []string{"love", "heart"}, Shortcodes: []string{":heart:", ":love:"}},
		{Unicode: "👍", Name: "thumbs up", Keywords: []string{"like", "good"}, Shortcodes: []string{":thumbsup:", ":+1:"}},
		{Unicode: "👎", Name: "thumbs down", Keywords: []string{"dislike", "bad"}, Shortcodes: []string{":thumbsdown:", ":-1:"}},
	}

	for _, emoji := range defaultEmojis {
		ep.emojiMap[emoji.Unicode] = emoji

		// Add to suggestion trie
		for _, shortcode := range emoji.Shortcodes {
			suggestion := &EmojiSuggestion{
				Type:      "unicode",
				Unicode:   emoji.Unicode,
				Name:      emoji.Name,
				Shortcode: shortcode,
			}
			ep.suggestionTrie.Insert(shortcode, suggestion)
		}

		// Add keywords to trie
		for _, keyword := range emoji.Keywords {
			suggestion := &EmojiSuggestion{
				Type:      "unicode",
				Unicode:   emoji.Unicode,
				Name:      emoji.Name,
				Shortcode: emoji.Shortcodes[0], // Use first shortcode
			}
			ep.suggestionTrie.Insert(keyword, suggestion)
		}
	}
}
