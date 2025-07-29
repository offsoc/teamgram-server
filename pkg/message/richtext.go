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
	"html"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// RichTextProcessor handles all rich text formatting operations
type RichTextProcessor struct {
	markdownParser  *MarkdownParser
	htmlParser      *HTMLParser
	entityExtractor *EntityExtractor
	entityValidator *EntityValidator
}

// NewRichTextProcessor creates a new rich text processor
func NewRichTextProcessor() *RichTextProcessor {
	return &RichTextProcessor{
		markdownParser:  NewMarkdownParser(),
		htmlParser:      NewHTMLParser(),
		entityExtractor: NewEntityExtractor(),
		entityValidator: NewEntityValidator(),
	}
}

// ParseMarkdown parses Markdown text and returns formatted text with entities
func (rtp *RichTextProcessor) ParseMarkdown(text string) (*FormattedText, error) {
	entities, err := rtp.markdownParser.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("markdown parsing failed: %w", err)
	}

	return &FormattedText{
		Text:     text,
		Entities: entities,
	}, nil
}

// ParseHTML parses HTML text and returns formatted text with entities
func (rtp *RichTextProcessor) ParseHTML(text string) (*FormattedText, error) {
	entities, err := rtp.htmlParser.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("html parsing failed: %w", err)
	}

	return &FormattedText{
		Text:     text,
		Entities: entities,
	}, nil
}

// ExtractEntities extracts entities from plain text
func (rtp *RichTextProcessor) ExtractEntities(text string) ([]*MessageEntity, error) {
	return rtp.entityExtractor.Extract(text)
}

// ValidateEntities validates entity consistency and positioning
func (rtp *RichTextProcessor) ValidateEntities(text string, entities []*MessageEntity) error {
	return rtp.entityValidator.Validate(text, entities)
}

// MarkdownParser handles Markdown parsing with full Telegram compatibility
type MarkdownParser struct {
	boldRegex          *regexp.Regexp
	italicRegex        *regexp.Regexp
	underlineRegex     *regexp.Regexp
	strikethroughRegex *regexp.Regexp
	codeRegex          *regexp.Regexp
	preRegex           *regexp.Regexp
	linkRegex          *regexp.Regexp
	spoilerRegex       *regexp.Regexp
}

// NewMarkdownParser creates a new Markdown parser
func NewMarkdownParser() *MarkdownParser {
	return &MarkdownParser{
		boldRegex:          regexp.MustCompile(`\*\*([^*]+)\*\*`),
		italicRegex:        regexp.MustCompile(`__([^_]+)__`),
		underlineRegex:     regexp.MustCompile(`--([^-]+)--`),
		strikethroughRegex: regexp.MustCompile(`~~([^~]+)~~`),
		codeRegex:          regexp.MustCompile("`([^`]+)`"),
		preRegex:           regexp.MustCompile("```([a-zA-Z0-9]*)\n([\\s\\S]*?)```"),
		linkRegex:          regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`),
		spoilerRegex:       regexp.MustCompile(`\|\|([^|]+)\|\|`),
	}
}

// Parse parses Markdown text and returns message entities
func (mp *MarkdownParser) Parse(text string) ([]*MessageEntity, error) {
	var entities []*MessageEntity

	// Parse bold text (**text**)
	entities = append(entities, mp.findEntities(text, mp.boldRegex, EntityTypeBold)...)

	// Parse italic text (__text__)
	entities = append(entities, mp.findEntities(text, mp.italicRegex, EntityTypeItalic)...)

	// Parse underline text (--text--)
	entities = append(entities, mp.findEntities(text, mp.underlineRegex, EntityTypeUnderline)...)

	// Parse strikethrough text (~~text~~)
	entities = append(entities, mp.findEntities(text, mp.strikethroughRegex, EntityTypeStrikethrough)...)

	// Parse inline code (`code`)
	entities = append(entities, mp.findEntities(text, mp.codeRegex, EntityTypeCode)...)

	// Parse spoiler text (||text||)
	entities = append(entities, mp.findEntities(text, mp.spoilerRegex, EntityTypeSpoiler)...)

	// Parse pre-formatted code blocks (```language\ncode```)
	entities = append(entities, mp.findPreEntities(text)...)

	// Parse links ([text](url))
	entities = append(entities, mp.findLinkEntities(text)...)

	// Sort entities by offset
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Offset < entities[j].Offset
	})

	return entities, nil
}

// findEntities finds entities using a regex pattern
func (mp *MarkdownParser) findEntities(text string, regex *regexp.Regexp, entityType string) []*MessageEntity {
	var entities []*MessageEntity
	matches := regex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			// Calculate UTF-16 offset and length
			offset := utf8.RuneCountInString(text[:match[2]])
			length := utf8.RuneCountInString(text[match[2]:match[3]])

			entities = append(entities, &MessageEntity{
				Type:   entityType,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// findPreEntities finds pre-formatted code block entities
func (mp *MarkdownParser) findPreEntities(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := mp.preRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 6 {
			// Calculate UTF-16 offset and length for the code content
			offset := utf8.RuneCountInString(text[:match[4]])
			length := utf8.RuneCountInString(text[match[4]:match[5]])

			// Get language if specified
			language := ""
			if match[2] != match[3] {
				language = text[match[2]:match[3]]
			}

			entity := &MessageEntity{
				Type:   EntityTypePreCode,
				Offset: offset,
				Length: length,
			}

			if language != "" {
				entity.Language = language
			}

			entities = append(entities, entity)
		}
	}

	return entities
}

// findLinkEntities finds link entities
func (mp *MarkdownParser) findLinkEntities(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := mp.linkRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 6 {
			// Calculate UTF-16 offset and length for the link text
			offset := utf8.RuneCountInString(text[:match[2]])
			length := utf8.RuneCountInString(text[match[2]:match[3]])

			// Get URL
			url := text[match[4]:match[5]]

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeTextLink,
				Offset: offset,
				Length: length,
				URL:    url,
			})
		}
	}

	return entities
}

// HTMLParser handles HTML parsing with security and compatibility
type HTMLParser struct {
	allowedTags map[string]string
}

// NewHTMLParser creates a new HTML parser
func NewHTMLParser() *HTMLParser {
	return &HTMLParser{
		allowedTags: map[string]string{
			"b":       EntityTypeBold,
			"strong":  EntityTypeBold,
			"i":       EntityTypeItalic,
			"em":      EntityTypeItalic,
			"u":       EntityTypeUnderline,
			"s":       EntityTypeStrikethrough,
			"strike":  EntityTypeStrikethrough,
			"del":     EntityTypeStrikethrough,
			"code":    EntityTypeCode,
			"pre":     EntityTypePre,
			"a":       EntityTypeTextLink,
			"spoiler": EntityTypeSpoiler,
		},
	}
}

// Parse parses HTML text and returns message entities
func (hp *HTMLParser) Parse(text string) ([]*MessageEntity, error) {
	var entities []*MessageEntity

	// Simple HTML tag parsing (for security, we only support specific tags)
	tagRegex := regexp.MustCompile(`<(/?)(\w+)(?:\s+([^>]*))?>`)
	matches := tagRegex.FindAllStringSubmatchIndex(text, -1)

	var tagStack []tagInfo

	for _, match := range matches {
		if len(match) >= 6 {
			isClosing := text[match[2]:match[3]] == "/"
			tagName := strings.ToLower(text[match[4]:match[5]])

			if entityType, allowed := hp.allowedTags[tagName]; allowed {
				if isClosing {
					// Find matching opening tag
					for i := len(tagStack) - 1; i >= 0; i-- {
						if tagStack[i].name == tagName {
							// Calculate entity
							offset := tagStack[i].offset
							length := utf8.RuneCountInString(text[tagStack[i].textStart:match[0]]) - tagStack[i].tagsLength

							entity := &MessageEntity{
								Type:   entityType,
								Offset: offset,
								Length: length,
							}

							// Handle special attributes
							if tagName == "a" && tagStack[i].attributes != "" {
								if url := extractHrefAttribute(tagStack[i].attributes); url != "" {
									entity.URL = url
								}
							}

							entities = append(entities, entity)

							// Remove from stack
							tagStack = append(tagStack[:i], tagStack[i+1:]...)
							break
						}
					}
				} else {
					// Opening tag
					attributes := ""
					if len(match) >= 8 && match[6] != match[7] {
						attributes = text[match[6]:match[7]]
					}

					tagStack = append(tagStack, tagInfo{
						name:       tagName,
						offset:     utf8.RuneCountInString(text[:match[0]]),
						textStart:  match[1],
						attributes: attributes,
						tagsLength: 0,
					})
				}
			}
		}
	}

	// Sort entities by offset
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Offset < entities[j].Offset
	})

	return entities, nil
}

type tagInfo struct {
	name       string
	offset     int
	textStart  int
	attributes string
	tagsLength int
}

// extractHrefAttribute extracts href attribute from HTML attributes string
func extractHrefAttribute(attributes string) string {
	hrefRegex := regexp.MustCompile(`href\s*=\s*["']([^"']+)["']`)
	matches := hrefRegex.FindStringSubmatch(attributes)
	if len(matches) >= 2 {
		return html.UnescapeString(matches[1])
	}
	return ""
}

// EntityExtractor extracts entities from plain text
type EntityExtractor struct {
	mentionRegex    *regexp.Regexp
	hashtagRegex    *regexp.Regexp
	urlRegex        *regexp.Regexp
	emailRegex      *regexp.Regexp
	phoneRegex      *regexp.Regexp
	botCommandRegex *regexp.Regexp
	cashtagRegex    *regexp.Regexp
}

// NewEntityExtractor creates a new entity extractor
func NewEntityExtractor() *EntityExtractor {
	return &EntityExtractor{
		mentionRegex:    regexp.MustCompile(`@([a-zA-Z0-9_]{5,32})`),
		hashtagRegex:    regexp.MustCompile(`#([a-zA-Z0-9_]+)`),
		urlRegex:        regexp.MustCompile(`https?://[^\s]+`),
		emailRegex:      regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		phoneRegex:      regexp.MustCompile(`\+[1-9]\d{1,14}`),
		botCommandRegex: regexp.MustCompile(`/([a-zA-Z0-9_]+)(?:@([a-zA-Z0-9_]{5,32}))?`),
		cashtagRegex:    regexp.MustCompile(`\$([A-Z]{1,8})`),
	}
}

// Extract extracts all entities from text
func (ee *EntityExtractor) Extract(text string) ([]*MessageEntity, error) {
	var entities []*MessageEntity

	// Extract mentions
	entities = append(entities, ee.extractMentions(text)...)

	// Extract hashtags
	entities = append(entities, ee.extractHashtags(text)...)

	// Extract URLs
	entities = append(entities, ee.extractURLs(text)...)

	// Extract emails
	entities = append(entities, ee.extractEmails(text)...)

	// Extract phone numbers
	entities = append(entities, ee.extractPhoneNumbers(text)...)

	// Extract bot commands
	entities = append(entities, ee.extractBotCommands(text)...)

	// Extract cashtags
	entities = append(entities, ee.extractCashtags(text)...)

	// Sort entities by offset
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Offset < entities[j].Offset
	})

	return entities, nil
}

// extractMentions extracts mention entities
func (ee *EntityExtractor) extractMentions(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.mentionRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeMention,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractHashtags extracts hashtag entities
func (ee *EntityExtractor) extractHashtags(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.hashtagRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeHashtag,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractURLs extracts URL entities
func (ee *EntityExtractor) extractURLs(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.urlRegex.FindAllStringIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeURL,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractEmails extracts email entities
func (ee *EntityExtractor) extractEmails(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.emailRegex.FindAllStringIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeEmail,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractPhoneNumbers extracts phone number entities
func (ee *EntityExtractor) extractPhoneNumbers(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.phoneRegex.FindAllStringIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypePhoneNumber,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractBotCommands extracts bot command entities
func (ee *EntityExtractor) extractBotCommands(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.botCommandRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeBotCommand,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// extractCashtags extracts cashtag entities
func (ee *EntityExtractor) extractCashtags(text string) []*MessageEntity {
	var entities []*MessageEntity
	matches := ee.cashtagRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			offset := utf8.RuneCountInString(text[:match[0]])
			length := utf8.RuneCountInString(text[match[0]:match[1]])

			entities = append(entities, &MessageEntity{
				Type:   EntityTypeCashTag,
				Offset: offset,
				Length: length,
			})
		}
	}

	return entities
}

// EntityValidator validates entity consistency and positioning
type EntityValidator struct{}

// NewEntityValidator creates a new entity validator
func NewEntityValidator() *EntityValidator {
	return &EntityValidator{}
}

// Validate validates entities for consistency and positioning
func (ev *EntityValidator) Validate(text string, entities []*MessageEntity) error {
	textLength := utf8.RuneCountInString(text)

	for i, entity := range entities {
		// Check bounds
		if entity.Offset < 0 {
			return fmt.Errorf("entity %d: negative offset %d", i, entity.Offset)
		}

		if entity.Length <= 0 {
			return fmt.Errorf("entity %d: non-positive length %d", i, entity.Length)
		}

		if entity.Offset+entity.Length > textLength {
			return fmt.Errorf("entity %d: offset+length (%d) exceeds text length (%d)",
				i, entity.Offset+entity.Length, textLength)
		}

		// Check entity type specific requirements
		if err := ev.validateEntityType(entity); err != nil {
			return fmt.Errorf("entity %d: %w", i, err)
		}
	}

	// Check for overlapping entities
	if err := ev.checkOverlaps(entities); err != nil {
		return fmt.Errorf("entity overlap: %w", err)
	}

	return nil
}

// validateEntityType validates entity type specific requirements
func (ev *EntityValidator) validateEntityType(entity *MessageEntity) error {
	switch entity.Type {
	case EntityTypeTextLink, EntityTypeTextURL:
		if entity.URL == "" {
			return fmt.Errorf("text_url entity requires URL")
		}
	case EntityTypePreCode:
		// Language is optional for pre-formatted code
	case EntityTypeMentionName:
		if entity.User == nil {
			return fmt.Errorf("mention_name entity requires user")
		}
	case EntityTypeCustomEmoji:
		if entity.CustomEmojiID == "" {
			return fmt.Errorf("custom_emoji entity requires custom_emoji_id")
		}
	}

	return nil
}

// checkOverlaps checks for overlapping entities
func (ev *EntityValidator) checkOverlaps(entities []*MessageEntity) error {
	for i := 0; i < len(entities); i++ {
		for j := i + 1; j < len(entities); j++ {
			entity1 := entities[i]
			entity2 := entities[j]

			// Check if entities overlap
			if ev.entitiesOverlap(entity1, entity2) {
				return fmt.Errorf("entities %d and %d overlap", i, j)
			}
		}
	}

	return nil
}

// entitiesOverlap checks if two entities overlap
func (ev *EntityValidator) entitiesOverlap(e1, e2 *MessageEntity) bool {
	end1 := e1.Offset + e1.Length
	end2 := e2.Offset + e2.Length

	// No overlap if one entity ends before the other starts
	if end1 <= e2.Offset || end2 <= e1.Offset {
		return false
	}

	// Nested entities are allowed (one completely inside another)
	if (e1.Offset <= e2.Offset && end1 >= end2) || (e2.Offset <= e1.Offset && end2 >= end1) {
		return false
	}

	// Partial overlap is not allowed
	return true
}

// FormatProcessor handles text formatting operations
type FormatProcessor struct {
	richTextProcessor *RichTextProcessor
}

// NewFormatProcessor creates a new format processor
func NewFormatProcessor() *FormatProcessor {
	return &FormatProcessor{
		richTextProcessor: NewRichTextProcessor(),
	}
}

// ProcessText processes text with the specified parse mode
func (fp *FormatProcessor) ProcessText(text, parseMode string, entities []*MessageEntity) (*FormattedText, error) {
	switch parseMode {
	case "Markdown", "MarkdownV2":
		return fp.richTextProcessor.ParseMarkdown(text)
	case "HTML":
		return fp.richTextProcessor.ParseHTML(text)
	default:
		// Return provided entities or extract from text
		if entities != nil {
			return &FormattedText{
				Text:     text,
				Entities: entities,
			}, nil
		}

		extractedEntities, err := fp.richTextProcessor.ExtractEntities(text)
		if err != nil {
			return nil, fmt.Errorf("entity extraction failed: %w", err)
		}

		return &FormattedText{
			Text:     text,
			Entities: extractedEntities,
		}, nil
	}
}

// ConvertToMTProto converts FormattedText to MTProto format
func (fp *FormatProcessor) ConvertToMTProto(formattedText *FormattedText) (string, []*MessageEntity) {
	return formattedText.Text, formattedText.Entities
}

// ConvertFromMTProto converts MTProto format to FormattedText
func (fp *FormatProcessor) ConvertFromMTProto(text string, entities []*MessageEntity) *FormattedText {
	return &FormattedText{
		Text:     text,
		Entities: entities,
	}
}
