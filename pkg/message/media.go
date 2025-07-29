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
	"io"
	"mime"
	"path/filepath"
	"strings"
	"time"
)

// MediaMessageProcessor handles all media message processing
type MediaMessageProcessor struct {
	imageProcessor *ImageProcessor
	videoProcessor *VideoProcessor
	audioProcessor *AudioProcessor
	fileProcessor  *FileProcessor
	config         *MediaConfig
}

// MediaConfig contains media processing configuration
type MediaConfig struct {
	MaxFileSize        int64         `json:"max_file_size"`       // 4GB for premium
	MaxImageSize       int64         `json:"max_image_size"`      // 10MB
	MaxVideoSize       int64         `json:"max_video_size"`      // 2GB
	MaxAudioSize       int64         `json:"max_audio_size"`      // 1.5GB
	CompressionQuality int           `json:"compression_quality"` // 0-100
	ThumbnailSize      int           `json:"thumbnail_size"`      // 320px
	ProcessingTimeout  time.Duration `json:"processing_timeout"`  // 30s
	EnableEncryption   bool          `json:"enable_encryption"`
}

// MediaInfo represents media file information
type MediaInfo struct {
	Type       string            `json:"type"` // photo, video, audio, document
	MimeType   string            `json:"mime_type"`
	Size       int64             `json:"size"`
	Width      int               `json:"width,omitempty"`
	Height     int               `json:"height,omitempty"`
	Duration   int               `json:"duration,omitempty"`
	Thumbnail  *ThumbnailInfo    `json:"thumbnail,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	FileID     string            `json:"file_id"`
	UniqueID   string            `json:"unique_id"`
}

// ThumbnailInfo represents thumbnail information
type ThumbnailInfo struct {
	FileID   string `json:"file_id"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
}

// ProcessedMedia represents processed media result
type ProcessedMedia struct {
	Original   *MediaInfo      `json:"original"`
	Compressed *MediaInfo      `json:"compressed,omitempty"`
	Thumbnail  *ThumbnailInfo  `json:"thumbnail,omitempty"`
	Variants   []*MediaVariant `json:"variants,omitempty"`
}

// MediaVariant represents different quality variants
type MediaVariant struct {
	Quality    string     `json:"quality"` // low, medium, high, original
	MediaInfo  *MediaInfo `json:"media_info"`
	Bitrate    int        `json:"bitrate,omitempty"`
	Resolution string     `json:"resolution,omitempty"`
}

// NewMediaMessageProcessor creates a new media processor
func NewMediaMessageProcessor(config *MediaConfig) *MediaMessageProcessor {
	return &MediaMessageProcessor{
		imageProcessor: NewImageProcessor(config),
		videoProcessor: NewVideoProcessor(config),
		audioProcessor: NewAudioProcessor(config),
		fileProcessor:  NewFileProcessor(config),
		config:         config,
	}
}

// ProcessMedia processes media based on its type
func (mp *MediaMessageProcessor) ProcessMedia(ctx context.Context, reader io.Reader, filename string) (*ProcessedMedia, error) {
	// Detect media type
	mediaType, mimeType := mp.detectMediaType(filename)

	switch mediaType {
	case "photo":
		return mp.imageProcessor.Process(ctx, reader, filename, mimeType)
	case "video":
		return mp.videoProcessor.Process(ctx, reader, filename, mimeType)
	case "audio":
		return mp.audioProcessor.Process(ctx, reader, filename, mimeType)
	case "voice":
		return mp.audioProcessor.ProcessVoice(ctx, reader, filename, mimeType)
	case "video_note":
		return mp.videoProcessor.ProcessVideoNote(ctx, reader, filename, mimeType)
	default:
		return mp.fileProcessor.Process(ctx, reader, filename, mimeType)
	}
}

// ValidateMedia validates media file before processing
func (mp *MediaMessageProcessor) ValidateMedia(size int64, mimeType, mediaType string) error {
	// Check file size limits
	switch mediaType {
	case "photo":
		if size > mp.config.MaxImageSize {
			return fmt.Errorf("image size %d exceeds limit %d", size, mp.config.MaxImageSize)
		}
	case "video", "video_note":
		if size > mp.config.MaxVideoSize {
			return fmt.Errorf("video size %d exceeds limit %d", size, mp.config.MaxVideoSize)
		}
	case "audio", "voice":
		if size > mp.config.MaxAudioSize {
			return fmt.Errorf("audio size %d exceeds limit %d", size, mp.config.MaxAudioSize)
		}
	default:
		if size > mp.config.MaxFileSize {
			return fmt.Errorf("file size %d exceeds limit %d", size, mp.config.MaxFileSize)
		}
	}

	// Validate MIME type
	if !mp.isAllowedMimeType(mimeType, mediaType) {
		return fmt.Errorf("unsupported MIME type %s for media type %s", mimeType, mediaType)
	}

	return nil
}

// detectMediaType detects media type from filename and content
func (mp *MediaMessageProcessor) detectMediaType(filename string) (string, string) {
	ext := strings.ToLower(filepath.Ext(filename))
	mimeType := mime.TypeByExtension(ext)

	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return "photo", mimeType
	case strings.HasPrefix(mimeType, "video/"):
		return "video", mimeType
	case strings.HasPrefix(mimeType, "audio/"):
		return "audio", mimeType
	case ext == ".ogg" || ext == ".oga":
		return "voice", "audio/ogg"
	default:
		return "document", mimeType
	}
}

// isAllowedMimeType checks if MIME type is allowed for media type
func (mp *MediaMessageProcessor) isAllowedMimeType(mimeType, mediaType string) bool {
	allowedTypes := map[string][]string{
		"photo": {
			"image/jpeg", "image/png", "image/gif", "image/webp",
			"image/bmp", "image/tiff", "image/svg+xml",
		},
		"video": {
			"video/mp4", "video/avi", "video/mov", "video/wmv",
			"video/flv", "video/webm", "video/mkv", "video/3gp",
		},
		"audio": {
			"audio/mp3", "audio/wav", "audio/flac", "audio/aac",
			"audio/ogg", "audio/m4a", "audio/wma",
		},
		"voice": {
			"audio/ogg", "audio/wav", "audio/mp3", "audio/m4a",
		},
	}

	if allowed, exists := allowedTypes[mediaType]; exists {
		for _, allowed_type := range allowed {
			if mimeType == allowed_type {
				return true
			}
		}
		return false
	}

	// For documents, allow most types except dangerous ones
	dangerousTypes := []string{
		"application/x-executable",
		"application/x-msdownload",
		"application/x-msdos-program",
	}

	for _, dangerous := range dangerousTypes {
		if mimeType == dangerous {
			return false
		}
	}

	return true
}

// ImageProcessor handles image processing
type ImageProcessor struct {
	config *MediaConfig
}

// NewImageProcessor creates a new image processor
func NewImageProcessor(config *MediaConfig) *ImageProcessor {
	return &ImageProcessor{config: config}
}

// Process processes an image
func (ip *ImageProcessor) Process(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Read image data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read image data: %w", err)
	}

	// Get image dimensions and create media info
	width, height, err := ip.getImageDimensions(data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to get image dimensions: %w", err)
	}

	original := &MediaInfo{
		Type:     "photo",
		MimeType: mimeType,
		Size:     int64(len(data)),
		Width:    width,
		Height:   height,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
	}

	result := &ProcessedMedia{
		Original: original,
	}

	// Generate thumbnail if needed
	if width > ip.config.ThumbnailSize || height > ip.config.ThumbnailSize {
		thumbnail, err := ip.generateThumbnail(data, mimeType)
		if err == nil {
			result.Thumbnail = thumbnail
		}
	}

	// Generate compressed version if image is large
	if original.Size > 1024*1024 { // 1MB threshold
		compressed, err := ip.compressImage(data, mimeType)
		if err == nil {
			result.Compressed = compressed
		}
	}

	return result, nil
}

// getImageDimensions gets image dimensions from data
func (ip *ImageProcessor) getImageDimensions(data []byte, mimeType string) (int, int, error) {
	// This is a simplified implementation
	// In production, use proper image libraries like imaging or go-image
	switch mimeType {
	case "image/jpeg", "image/jpg":
		return ip.getJPEGDimensions(data)
	case "image/png":
		return ip.getPNGDimensions(data)
	case "image/gif":
		return ip.getGIFDimensions(data)
	case "image/webp":
		return ip.getWebPDimensions(data)
	default:
		return 0, 0, fmt.Errorf("unsupported image format: %s", mimeType)
	}
}

// getJPEGDimensions gets JPEG image dimensions
func (ip *ImageProcessor) getJPEGDimensions(data []byte) (int, int, error) {
	// Simplified JPEG dimension reading
	// In production, use proper JPEG parsing library
	if len(data) < 10 {
		return 0, 0, fmt.Errorf("invalid JPEG data")
	}

	// This is a placeholder - implement proper JPEG parsing
	return 1920, 1080, nil
}

// getPNGDimensions gets PNG image dimensions
func (ip *ImageProcessor) getPNGDimensions(data []byte) (int, int, error) {
	// Simplified PNG dimension reading
	if len(data) < 24 {
		return 0, 0, fmt.Errorf("invalid PNG data")
	}

	// PNG width and height are at bytes 16-23 (big-endian)
	width := int(data[16])<<24 | int(data[17])<<16 | int(data[18])<<8 | int(data[19])
	height := int(data[20])<<24 | int(data[21])<<16 | int(data[22])<<8 | int(data[23])

	return width, height, nil
}

// getGIFDimensions gets GIF image dimensions
func (ip *ImageProcessor) getGIFDimensions(data []byte) (int, int, error) {
	if len(data) < 10 {
		return 0, 0, fmt.Errorf("invalid GIF data")
	}

	// GIF width and height are at bytes 6-9 (little-endian)
	width := int(data[6]) | int(data[7])<<8
	height := int(data[8]) | int(data[9])<<8

	return width, height, nil
}

// getWebPDimensions gets WebP image dimensions
func (ip *ImageProcessor) getWebPDimensions(data []byte) (int, int, error) {
	// Simplified WebP dimension reading
	// In production, implement proper WebP parsing
	return 1920, 1080, nil
}

// generateThumbnail generates a thumbnail for the image
func (ip *ImageProcessor) generateThumbnail(data []byte, mimeType string) (*ThumbnailInfo, error) {
	// This is a placeholder implementation
	// In production, use proper image resizing library
	return &ThumbnailInfo{
		FileID:   generateFileID(),
		Width:    ip.config.ThumbnailSize,
		Height:   ip.config.ThumbnailSize,
		Size:     int64(len(data) / 10), // Rough estimate
		MimeType: "image/jpeg",
	}, nil
}

// compressImage compresses an image
func (ip *ImageProcessor) compressImage(data []byte, mimeType string) (*MediaInfo, error) {
	// This is a placeholder implementation
	// In production, implement proper image compression
	compressedSize := int64(float64(len(data)) * 0.7) // 30% compression

	return &MediaInfo{
		Type:     "photo",
		MimeType: mimeType,
		Size:     compressedSize,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
	}, nil
}

// generateFileID generates a unique file ID
func generateFileID() string {
	return fmt.Sprintf("file_%d", time.Now().UnixNano())
}

// generateUniqueID generates a unique ID
func generateUniqueID() string {
	return fmt.Sprintf("unique_%d", time.Now().UnixNano())
}

// VideoProcessor handles video processing
type VideoProcessor struct {
	config *MediaConfig
}

// NewVideoProcessor creates a new video processor
func NewVideoProcessor(config *MediaConfig) *VideoProcessor {
	return &VideoProcessor{config: config}
}

// Process processes a video
func (vp *VideoProcessor) Process(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Read video data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read video data: %w", err)
	}

	// Get video metadata
	width, height, duration, err := vp.getVideoMetadata(data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to get video metadata: %w", err)
	}

	original := &MediaInfo{
		Type:     "video",
		MimeType: mimeType,
		Size:     int64(len(data)),
		Width:    width,
		Height:   height,
		Duration: duration,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
	}

	result := &ProcessedMedia{
		Original: original,
	}

	// Generate thumbnail
	thumbnail, err := vp.generateVideoThumbnail(data, mimeType)
	if err == nil {
		result.Thumbnail = thumbnail
	}

	// Generate quality variants
	variants, err := vp.generateQualityVariants(data, mimeType, width, height, duration)
	if err == nil {
		result.Variants = variants
	}

	return result, nil
}

// ProcessVideoNote processes a video note (round video message)
func (vp *VideoProcessor) ProcessVideoNote(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Video notes are always square and short duration
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read video note data: %w", err)
	}

	// Video notes should be max 1 minute and square aspect ratio
	width, height, duration, err := vp.getVideoMetadata(data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to get video note metadata: %w", err)
	}

	if duration > 60 {
		return nil, fmt.Errorf("video note duration %d exceeds 60 seconds", duration)
	}

	// Ensure square aspect ratio (crop if needed)
	size := min(width, height)

	original := &MediaInfo{
		Type:     "video_note",
		MimeType: mimeType,
		Size:     int64(len(data)),
		Width:    size,
		Height:   size,
		Duration: duration,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
		Attributes: map[string]string{
			"is_round": "true",
		},
	}

	result := &ProcessedMedia{
		Original: original,
	}

	// Generate thumbnail
	thumbnail, err := vp.generateVideoThumbnail(data, mimeType)
	if err == nil {
		result.Thumbnail = thumbnail
	}

	return result, nil
}

// getVideoMetadata gets video metadata
func (vp *VideoProcessor) getVideoMetadata(data []byte, mimeType string) (int, int, int, error) {
	// This is a placeholder implementation
	// In production, use FFmpeg or similar library to extract metadata
	switch mimeType {
	case "video/mp4":
		return vp.getMP4Metadata(data)
	case "video/webm":
		return vp.getWebMMetadata(data)
	default:
		// Default values for unsupported formats
		return 1920, 1080, 60, nil
	}
}

// getMP4Metadata gets MP4 video metadata
func (vp *VideoProcessor) getMP4Metadata(data []byte) (int, int, int, error) {
	// Simplified MP4 metadata extraction
	// In production, implement proper MP4 parsing or use FFmpeg
	return 1920, 1080, 60, nil
}

// getWebMMetadata gets WebM video metadata
func (vp *VideoProcessor) getWebMMetadata(data []byte) (int, int, int, error) {
	// Simplified WebM metadata extraction
	// In production, implement proper WebM parsing or use FFmpeg
	return 1920, 1080, 60, nil
}

// generateVideoThumbnail generates a thumbnail from video
func (vp *VideoProcessor) generateVideoThumbnail(data []byte, mimeType string) (*ThumbnailInfo, error) {
	// This is a placeholder implementation
	// In production, use FFmpeg to extract frame at specific timestamp
	return &ThumbnailInfo{
		FileID:   generateFileID(),
		Width:    vp.config.ThumbnailSize,
		Height:   vp.config.ThumbnailSize,
		Size:     10240, // 10KB estimate
		MimeType: "image/jpeg",
	}, nil
}

// generateQualityVariants generates different quality variants
func (vp *VideoProcessor) generateQualityVariants(data []byte, mimeType string, width, height, duration int) ([]*MediaVariant, error) {
	variants := []*MediaVariant{}

	// Generate different quality levels
	qualities := []struct {
		name      string
		maxWidth  int
		maxHeight int
		bitrate   int
	}{
		{"low", 480, 360, 500},
		{"medium", 720, 480, 1000},
		{"high", 1280, 720, 2000},
	}

	for _, quality := range qualities {
		if width <= quality.maxWidth && height <= quality.maxHeight {
			continue // Skip if original is smaller
		}

		// Calculate scaled dimensions
		scaledWidth, scaledHeight := vp.calculateScaledDimensions(width, height, quality.maxWidth, quality.maxHeight)

		variant := &MediaVariant{
			Quality:    quality.name,
			Bitrate:    quality.bitrate,
			Resolution: fmt.Sprintf("%dx%d", scaledWidth, scaledHeight),
			MediaInfo: &MediaInfo{
				Type:     "video",
				MimeType: mimeType,
				Size:     int64(len(data) * quality.bitrate / 2000), // Rough estimate
				Width:    scaledWidth,
				Height:   scaledHeight,
				Duration: duration,
				FileID:   generateFileID(),
				UniqueID: generateUniqueID(),
			},
		}

		variants = append(variants, variant)
	}

	return variants, nil
}

// calculateScaledDimensions calculates scaled dimensions maintaining aspect ratio
func (vp *VideoProcessor) calculateScaledDimensions(originalWidth, originalHeight, maxWidth, maxHeight int) (int, int) {
	aspectRatio := float64(originalWidth) / float64(originalHeight)

	var newWidth, newHeight int

	if float64(maxWidth)/aspectRatio <= float64(maxHeight) {
		newWidth = maxWidth
		newHeight = int(float64(maxWidth) / aspectRatio)
	} else {
		newHeight = maxHeight
		newWidth = int(float64(maxHeight) * aspectRatio)
	}

	return newWidth, newHeight
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AudioProcessor handles audio processing
type AudioProcessor struct {
	config *MediaConfig
}

// NewAudioProcessor creates a new audio processor
func NewAudioProcessor(config *MediaConfig) *AudioProcessor {
	return &AudioProcessor{config: config}
}

// Process processes an audio file
func (ap *AudioProcessor) Process(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Read audio data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read audio data: %w", err)
	}

	// Get audio metadata
	duration, err := ap.getAudioDuration(data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to get audio duration: %w", err)
	}

	original := &MediaInfo{
		Type:     "audio",
		MimeType: mimeType,
		Size:     int64(len(data)),
		Duration: duration,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
	}

	result := &ProcessedMedia{
		Original: original,
	}

	return result, nil
}

// ProcessVoice processes a voice message
func (ap *AudioProcessor) ProcessVoice(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Read voice data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read voice data: %w", err)
	}

	// Get audio duration
	duration, err := ap.getAudioDuration(data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to get voice duration: %w", err)
	}

	original := &MediaInfo{
		Type:     "voice",
		MimeType: mimeType,
		Size:     int64(len(data)),
		Duration: duration,
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
		Attributes: map[string]string{
			"is_voice": "true",
		},
	}

	result := &ProcessedMedia{
		Original: original,
	}

	return result, nil
}

// getAudioDuration gets audio duration from data
func (ap *AudioProcessor) getAudioDuration(data []byte, mimeType string) (int, error) {
	// This is a placeholder implementation
	// In production, use FFmpeg or audio libraries to extract duration
	switch mimeType {
	case "audio/mp3":
		return ap.getMP3Duration(data)
	case "audio/ogg":
		return ap.getOGGDuration(data)
	default:
		return 60, nil // Default 60 seconds
	}
}

// getMP3Duration gets MP3 audio duration
func (ap *AudioProcessor) getMP3Duration(data []byte) (int, error) {
	// Simplified MP3 duration extraction
	// In production, implement proper MP3 parsing
	return 60, nil
}

// getOGGDuration gets OGG audio duration
func (ap *AudioProcessor) getOGGDuration(data []byte) (int, error) {
	// Simplified OGG duration extraction
	// In production, implement proper OGG parsing
	return 60, nil
}

// FileProcessor handles file processing
type FileProcessor struct {
	config *MediaConfig
}

// NewFileProcessor creates a new file processor
func NewFileProcessor(config *MediaConfig) *FileProcessor {
	return &FileProcessor{config: config}
}

// Process processes a document file
func (fp *FileProcessor) Process(ctx context.Context, reader io.Reader, filename, mimeType string) (*ProcessedMedia, error) {
	// Read file data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	original := &MediaInfo{
		Type:     "document",
		MimeType: mimeType,
		Size:     int64(len(data)),
		FileID:   generateFileID(),
		UniqueID: generateUniqueID(),
		Attributes: map[string]string{
			"filename": filename,
		},
	}

	result := &ProcessedMedia{
		Original: original,
	}

	// Generate thumbnail for supported file types
	if fp.canGenerateThumbnail(mimeType) {
		thumbnail, err := fp.generateFileThumbnail(data, mimeType)
		if err == nil {
			result.Thumbnail = thumbnail
		}
	}

	return result, nil
}

// canGenerateThumbnail checks if thumbnail can be generated for file type
func (fp *FileProcessor) canGenerateThumbnail(mimeType string) bool {
	thumbnailTypes := []string{
		"application/pdf",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	}

	for _, thumbnailType := range thumbnailTypes {
		if mimeType == thumbnailType {
			return true
		}
	}

	return false
}

// generateFileThumbnail generates a thumbnail for supported file types
func (fp *FileProcessor) generateFileThumbnail(data []byte, mimeType string) (*ThumbnailInfo, error) {
	// This is a placeholder implementation
	// In production, use appropriate libraries to generate thumbnails
	return &ThumbnailInfo{
		FileID:   generateFileID(),
		Width:    fp.config.ThumbnailSize,
		Height:   fp.config.ThumbnailSize,
		Size:     5120, // 5KB estimate
		MimeType: "image/jpeg",
	}, nil
}
