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

func TestMarkdownParser_Parse(t *testing.T) {
	parser := NewMarkdownParser()
	
	tests := []struct {
		name     string
		input    string
		expected int // number of entities expected
	}{
		{
			name:     "Bold text",
			input:    "This is **bold** text",
			expected: 1,
		},
		{
			name:     "Italic text",
			input:    "This is __italic__ text",
			expected: 1,
		},
		{
			name:     "Code text",
			input:    "This is `code` text",
			expected: 1,
		},
		{
			name:     "Multiple formatting",
			input:    "**Bold** and __italic__ and `code`",
			expected: 3,
		},
		{
			name:     "Link",
			input:    "Check out [Telegram](https://telegram.org)",
			expected: 1,
		},
		{
			name:     "Spoiler",
			input:    "This is ||spoiler|| text",
			expected: 1,
		},
		{
			name:     "Pre-formatted code",
			input:    "```go\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n```",
			expected: 1,
		},
		{
			name:     "No formatting",
			input:    "Plain text without any formatting",
			expected: 0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, err := parser.Parse(tt.input)
			if err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			
			if len(entities) != tt.expected {
				t.Errorf("Parse() got %d entities, expected %d", len(entities), tt.expected)
			}
		})
	}
}

func TestHTMLParser_Parse(t *testing.T) {
	parser := NewHTMLParser()
	
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Bold HTML",
			input:    "This is <b>bold</b> text",
			expected: 1,
		},
		{
			name:     "Italic HTML",
			input:    "This is <i>italic</i> text",
			expected: 1,
		},
		{
			name:     "Link HTML",
			input:    `This is <a href="https://telegram.org">link</a> text`,
			expected: 1,
		},
		{
			name:     "Multiple tags",
			input:    "Text with <b>bold</b> and <i>italic</i>",
			expected: 2,
		},
		{
			name:     "Nested tags",
			input:    "<b>Bold <i>and italic</i></b>",
			expected: 2,
		},
		{
			name:     "Code HTML",
			input:    "This is <code>code</code> text",
			expected: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, err := parser.Parse(tt.input)
			if err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			
			if len(entities) != tt.expected {
				t.Errorf("Parse() got %d entities, expected %d", len(entities), tt.expected)
			}
		})
	}
}

func TestEntityExtractor_Extract(t *testing.T) {
	extractor := NewEntityExtractor()
	
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Mention",
			input:    "Hello @username how are you?",
			expected: 1,
		},
		{
			name:     "Hashtag",
			input:    "This is a #hashtag",
			expected: 1,
		},
		{
			name:     "URL",
			input:    "Visit https://telegram.org for more info",
			expected: 1,
		},
		{
			name:     "Email",
			input:    "Contact us at support@telegram.org",
			expected: 1,
		},
		{
			name:     "Phone number",
			input:    "Call us at +1234567890",
			expected: 1,
		},
		{
			name:     "Bot command",
			input:    "/start the bot",
			expected: 1,
		},
		{
			name:     "Cashtag",
			input:    "Buy $TSLA stock",
			expected: 1,
		},
		{
			name:     "Multiple entities",
			input:    "Hello @user, check https://telegram.org and use /help",
			expected: 3,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, err := extractor.Extract(tt.input)
			if err != nil {
				t.Errorf("Extract() error = %v", err)
				return
			}
			
			if len(entities) != tt.expected {
				t.Errorf("Extract() got %d entities, expected %d", len(entities), tt.expected)
			}
		})
	}
}

func TestEntityValidator_Validate(t *testing.T) {
	validator := NewEntityValidator()
	
	tests := []struct {
		name      string
		text      string
		entities  []*MessageEntity
		expectErr bool
	}{
		{
			name: "Valid entities",
			text: "Hello world",
			entities: []*MessageEntity{
				{Type: EntityTypeBold, Offset: 0, Length: 5},
				{Type: EntityTypeItalic, Offset: 6, Length: 5},
			},
			expectErr: false,
		},
		{
			name: "Negative offset",
			text: "Hello world",
			entities: []*MessageEntity{
				{Type: EntityTypeBold, Offset: -1, Length: 5},
			},
			expectErr: true,
		},
		{
			name: "Zero length",
			text: "Hello world",
			entities: []*MessageEntity{
				{Type: EntityTypeBold, Offset: 0, Length: 0},
			},
			expectErr: true,
		},
		{
			name: "Out of bounds",
			text: "Hello",
			entities: []*MessageEntity{
				{Type: EntityTypeBold, Offset: 0, Length: 10},
			},
			expectErr: true,
		},
		{
			name: "Text URL without URL",
			text: "Hello world",
			entities: []*MessageEntity{
				{Type: EntityTypeTextURL, Offset: 0, Length: 5},
			},
			expectErr: true,
		},
		{
			name: "Valid text URL",
			text: "Hello world",
			entities: []*MessageEntity{
				{Type: EntityTypeTextURL, Offset: 0, Length: 5, URL: "https://example.com"},
			},
			expectErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.text, tt.entities)
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestRichTextProcessor_ParseMarkdown(t *testing.T) {
	processor := NewRichTextProcessor()
	
	text := "This is **bold** and __italic__ text with `code`"
	result, err := processor.ParseMarkdown(text)
	
	if err != nil {
		t.Errorf("ParseMarkdown() error = %v", err)
		return
	}
	
	if result.Text != text {
		t.Errorf("ParseMarkdown() text = %v, expected %v", result.Text, text)
	}
	
	if len(result.Entities) != 3 {
		t.Errorf("ParseMarkdown() got %d entities, expected 3", len(result.Entities))
	}
	
	// Check entity types
	expectedTypes := []string{EntityTypeBold, EntityTypeItalic, EntityTypeCode}
	for i, entity := range result.Entities {
		if entity.Type != expectedTypes[i] {
			t.Errorf("Entity %d type = %v, expected %v", i, entity.Type, expectedTypes[i])
		}
	}
}

func TestRichTextProcessor_ParseHTML(t *testing.T) {
	processor := NewRichTextProcessor()
	
	text := "This is <b>bold</b> and <i>italic</i> text"
	result, err := processor.ParseHTML(text)
	
	if err != nil {
		t.Errorf("ParseHTML() error = %v", err)
		return
	}
	
	if result.Text != text {
		t.Errorf("ParseHTML() text = %v, expected %v", result.Text, text)
	}
	
	if len(result.Entities) != 2 {
		t.Errorf("ParseHTML() got %d entities, expected 2", len(result.Entities))
	}
}

func TestFormatProcessor_ProcessText(t *testing.T) {
	processor := NewFormatProcessor()
	
	tests := []struct {
		name      string
		text      string
		parseMode string
		entities  []*MessageEntity
		expectErr bool
	}{
		{
			name:      "Markdown processing",
			text:      "**Bold** text",
			parseMode: "Markdown",
			entities:  nil,
			expectErr: false,
		},
		{
			name:      "HTML processing",
			text:      "<b>Bold</b> text",
			parseMode: "HTML",
			entities:  nil,
			expectErr: false,
		},
		{
			name:      "Plain text with entities",
			text:      "Plain text",
			parseMode: "",
			entities: []*MessageEntity{
				{Type: EntityTypeBold, Offset: 0, Length: 5},
			},
			expectErr: false,
		},
		{
			name:      "Plain text without entities",
			text:      "Plain text with @mention",
			parseMode: "",
			entities:  nil,
			expectErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.ProcessText(tt.text, tt.parseMode, tt.entities)
			if (err != nil) != tt.expectErr {
				t.Errorf("ProcessText() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			
			if !tt.expectErr && result == nil {
				t.Errorf("ProcessText() returned nil result")
			}
		})
	}
}
