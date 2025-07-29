# Teamgram Message Module

## Overview

This module implements comprehensive message processing functionality with 100% Telegram API compatibility. It supports all message types, rich text formatting, media processing, and advanced features like polls, location sharing, and emoji handling.

## Features

### 1. Rich Text Processing

#### Supported Entity Types (32 total)
- **Basic Formatting**: bold, italic, underline, strikethrough, spoiler
- **Code**: inline code, pre-formatted code blocks with language support
- **Links**: URLs, text links, mentions, hashtags, cashtags
- **Special**: bot commands, phone numbers, emails, custom emojis
- **Advanced**: blockquotes, expandable blockquotes, mention names

#### Markdown Support
```markdown
**bold text**
__italic text__
--underlined text--
~~strikethrough text~~
||spoiler text||
`inline code`
```language
code block
```
[link text](https://example.com)
```

#### HTML Support
```html
<b>bold</b> <strong>bold</strong>
<i>italic</i> <em>italic</em>
<u>underlined</u>
<s>strikethrough</s> <strike>strikethrough</strike> <del>strikethrough</del>
<code>inline code</code>
<pre>preformatted</pre>
<a href="https://example.com">link</a>
<spoiler>spoiler text</spoiler>
```

### 2. Media Processing

#### Supported Media Types
- **Images**: JPEG, PNG, GIF, WebP, BMP, TIFF, SVG
- **Videos**: MP4, AVI, MOV, WMV, FLV, WebM, MKV, 3GP
- **Audio**: MP3, WAV, FLAC, AAC, OGG, M4A, WMA
- **Documents**: Any file type (with security restrictions)

#### Features
- **Image Processing**: Compression, thumbnail generation, metadata extraction
- **Video Processing**: Multiple quality variants, thumbnail extraction, duration detection
- **Audio Processing**: Duration extraction, voice message support
- **File Validation**: Size limits, MIME type validation, security checks

#### Size Limits
- Images: 10MB
- Videos: 2GB (4GB for premium)
- Audio: 1.5GB
- Documents: 2GB (4GB for premium)

### 3. Emoji Support

#### Unicode Emoji
- Full Unicode 15.0 support
- Skin tone modifiers
- ZWJ sequences
- Regional indicator symbols (flags)
- Cross-platform compatibility

#### Custom Emoji
- Animated emoji support
- Premium emoji features
- Custom shortcodes
- Keyword-based suggestions

#### Emoji Suggestions
- Real-time suggestions
- Relevance scoring
- Fuzzy matching
- Keyword search

### 4. Location Sharing

#### Features
- **Current Location**: GPS coordinates with accuracy
- **Venue Sharing**: POI search and selection
- **Live Location**: Real-time location updates (up to 8 hours)
- **Geocoding**: Address resolution
- **Proximity Alerts**: Distance-based notifications

#### Supported Data
- Latitude/longitude coordinates
- Accuracy radius
- Altitude and heading
- Speed information
- Address information
- Venue details (name, category, rating)

### 5. Poll System

#### Poll Types
- **Regular Polls**: Multiple choice with anonymous/public options
- **Quiz Polls**: Single correct answer with explanations
- **Multiple Answer**: Allow multiple selections

#### Features
- Up to 10 options per poll
- Anonymous or public voting
- Real-time results
- Automatic closing
- Vote retraction
- Result statistics

### 6. Performance Requirements

#### Response Times
- Message processing: < 5ms
- Search queries: < 20ms
- Media processing: Background with progress
- Encryption: < 5μs

#### Accuracy
- Search accuracy: > 98%
- Entity extraction: > 99%
- Format preservation: 100%

#### Scalability
- Concurrent message processing
- Efficient memory usage
- Database optimization
- Caching strategies

## API Usage

### Basic Message Processing

```go
// Create message manager
config := &MessageConfig{
    MaxMessageLength: 4096,
    EnableEncryption: true,
    SearchResponseTime: 20 * time.Millisecond,
}
manager := NewMessageManager(config)

// Send text message
req := &SendMessageRequest{
    ChatID: 123456,
    Text:   "Hello **world**!",
    ParseMode: "Markdown",
}
message, err := manager.SendMessage(ctx, req)
```

### Rich Text Processing

```go
// Process Markdown
processor := NewRichTextProcessor()
result, err := processor.ParseMarkdown("**Bold** and __italic__ text")

// Process HTML
result, err := processor.ParseHTML("<b>Bold</b> and <i>italic</i> text")

// Extract entities
entities, err := processor.ExtractEntities("Hello @username #hashtag")
```

### Media Processing

```go
// Process media
config := &MediaConfig{
    MaxFileSize: 4 * 1024 * 1024 * 1024, // 4GB
    CompressionQuality: 85,
    ThumbnailSize: 320,
}
processor := NewMediaMessageProcessor(config)

result, err := processor.ProcessMedia(ctx, reader, "image.jpg")
```

### Emoji Processing

```go
// Process emoji
processor := NewEmojiProcessor()
result, err := processor.ProcessText("Hello 😀 world")

// Get suggestions
suggestions, err := processor.GetSuggestions("smile", 10)

// Add custom emoji
customEmoji := &CustomEmojiInfo{
    ID: "custom123",
    Name: "custom emoji",
    Shortcodes: []string{":custom:"},
}
err := processor.AddCustomEmoji(customEmoji)
```

### Location Processing

```go
// Process location
config := &LocationConfig{
    MaxLiveLocationDuration: 8 * time.Hour,
    EnableGeocoding: true,
}
processor := NewLocationProcessor(config)

location := &LocationInfo{
    Latitude:  40.7128,
    Longitude: -74.0060,
}
result, err := processor.ProcessLocation(ctx, location)

// Start live location
err := processor.StartLiveLocation(ctx, userID, chatID, messageID, location, time.Hour)
```

### Poll Processing

```go
// Create poll
config := &PollConfig{
    MaxOptions: 10,
    MaxQuestionLength: 300,
}
processor := NewPollProcessor(storage, config)

poll := &PollInfo{
    Question: "What's your favorite color?",
    Options: []*PollOption{
        {Text: "Red"},
        {Text: "Blue"},
        {Text: "Green"},
    },
    IsAnonymous: true,
}
result, err := processor.CreatePoll(ctx, poll)

// Vote on poll
result, err := processor.VotePoll(ctx, pollID, userID, []int{0})
```

## Testing

Run the test suite:

```bash
go test -v ./pkg/message/...
```

### Test Coverage
- Unit tests for all components
- Integration tests for message flows
- Performance benchmarks
- Compatibility tests with Telegram API
- Security validation tests

## Security

### Encryption
- AES-256-GCM encryption
- End-to-end encryption support
- Key rotation
- Perfect forward secrecy

### Validation
- Input sanitization
- XSS prevention
- File type validation
- Size limit enforcement
- Rate limiting

### Privacy
- Anonymous polls
- Location privacy controls
- Message deletion
- Data retention policies

## Monitoring

### Metrics
- Message processing times
- Error rates
- Memory usage
- Database performance
- Search accuracy

### Logging
- Structured logging
- Error tracking
- Performance monitoring
- Security events

## Configuration

### Environment Variables
- `MESSAGE_MAX_LENGTH`: Maximum message length (default: 4096)
- `MEDIA_MAX_SIZE`: Maximum media file size
- `ENCRYPTION_ENABLED`: Enable message encryption
- `SEARCH_TIMEOUT`: Search query timeout

### Database Configuration
- Message storage optimization
- Index configuration
- Backup strategies
- Archival policies

## Contributing

1. Follow Go coding standards
2. Add comprehensive tests
3. Update documentation
4. Ensure Telegram API compatibility
5. Performance testing required

## License

Licensed under the Apache License, Version 2.0.
