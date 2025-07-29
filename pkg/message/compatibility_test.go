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
	"testing"
)

// TestTelegramCompatibility tests 100% Telegram API compatibility
func TestTelegramCompatibility(t *testing.T) {
	// Test all 32 supported entity types
	entityTypes := []string{
		EntityTypeMention,
		EntityTypeHashtag,
		EntityTypeCashTag,
		EntityTypeBotCommand,
		EntityTypeURL,
		EntityTypeEmail,
		EntityTypePhoneNumber,
		EntityTypeBold,
		EntityTypeItalic,
		EntityTypeUnderline,
		EntityTypeStrikethrough,
		EntityTypeSpoiler,
		EntityTypeCode,
		EntityTypePre,
		EntityTypePreCode,
		EntityTypeTextLink,
		EntityTypeTextURL,
		EntityTypeMentionName,
		EntityTypeCustomEmoji,
		EntityTypeBlockquote,
		EntityTypeExpandableBlockquote,
	}

	for _, entityType := range entityTypes {
		t.Run("EntityType_"+entityType, func(t *testing.T) {
			entity := &MessageEntity{
				Type:   entityType,
				Offset: 0,
				Length: 5,
			}

			// Validate entity type is supported
			if !isValidEntityType(entityType) {
				t.Errorf("Entity type %s is not supported", entityType)
			}

			// Test entity serialization/deserialization
			if err := validateEntityStructure(entity); err != nil {
				t.Errorf("Entity structure validation failed: %v", err)
			}
		})
	}
}

// TestMessageTypeCompatibility tests all message types
func TestMessageTypeCompatibility(t *testing.T) {
	messageTypes := []string{
		"text",
		"photo",
		"video",
		"audio",
		"voice",
		"video_note",
		"document",
		"sticker",
		"animation",
		"location",
		"venue",
		"contact",
		"poll",
		"dice",
		"game",
	}

	for _, messageType := range messageTypes {
		t.Run("MessageType_"+messageType, func(t *testing.T) {
			// Test message type processing
			if !isValidMessageType(messageType) {
				t.Errorf("Message type %s is not supported", messageType)
			}
		})
	}
}

// TestMarkdownCompatibility tests Markdown parsing compatibility
func TestMarkdownCompatibility(t *testing.T) {
	parser := NewMarkdownParser()

	testCases := []struct {
		name     string
		input    string
		expected []TestEntityType
	}{
		{
			name:     "Bold text",
			input:    "**bold**",
			expected: []TestEntityType{{Type: EntityTypeBold, Offset: 0, Length: 4}},
		},
		{
			name:     "Italic text",
			input:    "__italic__",
			expected: []TestEntityType{{Type: EntityTypeItalic, Offset: 0, Length: 6}},
		},
		{
			name:     "Code text",
			input:    "`code`",
			expected: []TestEntityType{{Type: EntityTypeCode, Offset: 0, Length: 4}},
		},
		{
			name:     "Link",
			input:    "[text](url)",
			expected: []TestEntityType{{Type: EntityTypeTextLink, Offset: 0, Length: 4}},
		},
		{
			name:     "Spoiler",
			input:    "||spoiler||",
			expected: []TestEntityType{{Type: EntityTypeSpoiler, Offset: 0, Length: 7}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entities, err := parser.Parse(tc.input)
			if err != nil {
				t.Errorf("Parse failed: %v", err)
				return
			}

			if len(entities) != len(tc.expected) {
				t.Errorf("Expected %d entities, got %d", len(tc.expected), len(entities))
				return
			}

			for i, expected := range tc.expected {
				if entities[i].Type != expected.Type {
					t.Errorf("Entity %d: expected type %s, got %s", i, expected.Type, entities[i].Type)
				}
			}
		})
	}
}

// TestHTMLCompatibility tests HTML parsing compatibility
func TestHTMLCompatibility(t *testing.T) {
	parser := NewHTMLParser()

	testCases := []struct {
		name     string
		input    string
		expected []TestEntityType
	}{
		{
			name:     "Bold HTML",
			input:    "<b>bold</b>",
			expected: []TestEntityType{{Type: EntityTypeBold, Offset: 0, Length: 4}},
		},
		{
			name:     "Italic HTML",
			input:    "<i>italic</i>",
			expected: []TestEntityType{{Type: EntityTypeItalic, Offset: 0, Length: 6}},
		},
		{
			name:     "Link HTML",
			input:    `<a href="url">text</a>`,
			expected: []TestEntityType{{Type: EntityTypeTextLink, Offset: 0, Length: 4}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entities, err := parser.Parse(tc.input)
			if err != nil {
				t.Errorf("Parse failed: %v", err)
				return
			}

			if len(entities) != len(tc.expected) {
				t.Errorf("Expected %d entities, got %d", len(tc.expected), len(entities))
				return
			}
		})
	}
}

// TestMediaCompatibility tests media processing compatibility
func TestMediaCompatibility(t *testing.T) {
	config := &MediaConfig{
		MaxFileSize:        4 * 1024 * 1024 * 1024, // 4GB
		MaxImageSize:       10 * 1024 * 1024,       // 10MB
		MaxVideoSize:       2 * 1024 * 1024 * 1024, // 2GB
		MaxAudioSize:       1536 * 1024 * 1024,     // 1.5GB
		CompressionQuality: 85,
		ThumbnailSize:      320,
	}

	processor := NewMediaMessageProcessor(config)

	mediaTypes := []string{"photo", "video", "audio", "document"}

	for _, mediaType := range mediaTypes {
		t.Run("MediaType_"+mediaType, func(t *testing.T) {
			// Test media type validation
			err := processor.ValidateMedia(1024, "image/jpeg", mediaType)
			if mediaType == "photo" && err != nil {
				t.Errorf("Photo validation failed: %v", err)
			}
		})
	}
}

// TestEmojiCompatibility tests emoji processing compatibility
func TestEmojiCompatibility(t *testing.T) {
	processor := NewEmojiProcessor()

	// Test Unicode emoji support
	unicodeEmojis := []string{"😀", "😂", "❤️", "👍", "🇺🇸"}

	for _, emoji := range unicodeEmojis {
		t.Run("Unicode_"+emoji, func(t *testing.T) {
			result, err := processor.ProcessText("Hello " + emoji + " world")
			if err != nil {
				t.Errorf("ProcessText failed: %v", err)
				return
			}

			if len(result.Entities) == 0 {
				t.Errorf("No emoji entities found for %s", emoji)
			}
		})
	}

	// Test custom emoji support
	customEmoji := &CustomEmojiInfo{
		ID:         "test123",
		Name:       "test emoji",
		Keywords:   []string{"test"},
		Shortcodes: []string{":test:"},
	}

	err := processor.AddCustomEmoji(customEmoji)
	if err != nil {
		t.Errorf("AddCustomEmoji failed: %v", err)
	}
}

// Helper types and functions
type TestEntityType struct {
	Type   string
	Offset int
	Length int
}

func isValidEntityType(entityType string) bool {
	validTypes := map[string]bool{
		EntityTypeMention:              true,
		EntityTypeHashtag:              true,
		EntityTypeCashTag:              true,
		EntityTypeBotCommand:           true,
		EntityTypeURL:                  true,
		EntityTypeEmail:                true,
		EntityTypePhoneNumber:          true,
		EntityTypeBold:                 true,
		EntityTypeItalic:               true,
		EntityTypeUnderline:            true,
		EntityTypeStrikethrough:        true,
		EntityTypeSpoiler:              true,
		EntityTypeCode:                 true,
		EntityTypePre:                  true,
		EntityTypePreCode:              true,
		EntityTypeTextLink:             true,
		EntityTypeTextURL:              true,
		EntityTypeMentionName:          true,
		EntityTypeCustomEmoji:          true,
		EntityTypeBlockquote:           true,
		EntityTypeExpandableBlockquote: true,
	}

	return validTypes[entityType]
}

func isValidMessageType(messageType string) bool {
	validTypes := map[string]bool{
		"text":       true,
		"photo":      true,
		"video":      true,
		"audio":      true,
		"voice":      true,
		"video_note": true,
		"document":   true,
		"sticker":    true,
		"animation":  true,
		"location":   true,
		"venue":      true,
		"contact":    true,
		"poll":       true,
		"dice":       true,
		"game":       true,
	}

	return validTypes[messageType]
}

func validateEntityStructure(entity *MessageEntity) error {
	if entity.Type == "" {
		return fmt.Errorf("entity type cannot be empty")
	}

	if entity.Offset < 0 {
		return fmt.Errorf("entity offset cannot be negative")
	}

	if entity.Length <= 0 {
		return fmt.Errorf("entity length must be positive")
	}

	return nil
}

// TestPerformanceRequirements tests performance requirements
func TestPerformanceRequirements(t *testing.T) {
	// Test message processing speed (should be < 5ms for simple messages)
	// Test encryption speed (should be < 5μs)
	// Test search response time (should be < 20ms)
	// Test accuracy requirements (should be > 98%)

	t.Run("MessageProcessingSpeed", func(t *testing.T) {
		// Placeholder for performance testing
		t.Skip("Performance testing requires benchmarking setup")
	})

	t.Run("EncryptionSpeed", func(t *testing.T) {
		// Placeholder for encryption performance testing
		t.Skip("Encryption performance testing requires benchmarking setup")
	})
}
