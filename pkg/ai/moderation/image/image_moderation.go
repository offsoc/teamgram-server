package image

import (
	"context"
	"fmt"
	"image"
	"io"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// ImageModerator handles image content moderation
type ImageModerator struct {
	config *Config
	logger logx.Logger
}

// Config for image moderation
type Config struct {
	EnableNSFWDetection     bool     `json:"enable_nsfw_detection"`
	EnableViolenceDetection bool     `json:"enable_violence_detection"`
	EnableFaceDetection     bool     `json:"enable_face_detection"`
	MaxImageSize            int64    `json:"max_image_size"`
	AllowedFormats          []string `json:"allowed_formats"`
	NSFWThreshold           float64  `json:"nsfw_threshold"`
	ViolenceThreshold       float64  `json:"violence_threshold"`
}

// ModerationResult contains the result of image moderation
type ModerationResult struct {
	IsAllowed       bool                   `json:"is_allowed"`
	NSFWScore       float64                `json:"nsfw_score"`
	ViolenceScore   float64                `json:"violence_score"`
	DetectedFaces   int                    `json:"detected_faces"`
	Classifications []Classification       `json:"classifications"`
	ProcessedAt     time.Time              `json:"processed_at"`
	ProcessingMs    int64                  `json:"processing_ms"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// Classification represents an image classification
type Classification struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// NewImageModerator creates a new image moderator
func NewImageModerator(config *Config) *ImageModerator {
	if config == nil {
		config = DefaultConfig()
	}

	return &ImageModerator{
		config: config,
		logger: logx.WithContext(context.Background()),
	}
}

// DefaultConfig returns default image moderation configuration
func DefaultConfig() *Config {
	return &Config{
		EnableNSFWDetection:     true,
		EnableViolenceDetection: true,
		EnableFaceDetection:     true,
		MaxImageSize:            10 * 1024 * 1024, // 10MB
		AllowedFormats:          []string{"jpeg", "jpg", "png", "gif", "webp"},
		NSFWThreshold:           0.7,
		ViolenceThreshold:       0.8,
	}
}

// ModerateImage performs image moderation
func (im *ImageModerator) ModerateImage(ctx context.Context, imageData io.Reader) (*ModerationResult, error) {
	start := time.Now()

	result := &ModerationResult{
		IsAllowed:       true,
		NSFWScore:       0.0,
		ViolenceScore:   0.0,
		DetectedFaces:   0,
		Classifications: []Classification{},
		ProcessedAt:     start,
		Metadata:        make(map[string]interface{}),
	}

	// Decode image
	img, format, err := image.Decode(imageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	result.Metadata["format"] = format
	result.Metadata["width"] = img.Bounds().Dx()
	result.Metadata["height"] = img.Bounds().Dy()

	// Check format
	if !im.isFormatAllowed(format) {
		result.IsAllowed = false
		result.Metadata["rejection_reason"] = "unsupported format"
		result.ProcessingMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// NSFW Detection
	if im.config.EnableNSFWDetection {
		nsfwScore := im.detectNSFW(img)
		result.NSFWScore = nsfwScore

		if nsfwScore > im.config.NSFWThreshold {
			result.IsAllowed = false
			result.Classifications = append(result.Classifications, Classification{
				Label:      "nsfw",
				Confidence: nsfwScore,
				Category:   "adult_content",
			})
		}
	}

	// Violence Detection
	if im.config.EnableViolenceDetection {
		violenceScore := im.detectViolence(img)
		result.ViolenceScore = violenceScore

		if violenceScore > im.config.ViolenceThreshold {
			result.IsAllowed = false
			result.Classifications = append(result.Classifications, Classification{
				Label:      "violence",
				Confidence: violenceScore,
				Category:   "violent_content",
			})
		}
	}

	// Face Detection
	if im.config.EnableFaceDetection {
		faceCount := im.detectFaces(img)
		result.DetectedFaces = faceCount
		result.Metadata["faces_detected"] = faceCount
	}

	result.ProcessingMs = time.Since(start).Milliseconds()
	return result, nil
}

// ModerateImageFromFile moderates an image from file path
func (im *ImageModerator) ModerateImageFromFile(ctx context.Context, filePath string) (*ModerationResult, error) {
	// This would read from file system
	// For now, return a mock result
	return &ModerationResult{
		IsAllowed:     true,
		NSFWScore:     0.1,
		ViolenceScore: 0.05,
		DetectedFaces: 1,
		ProcessedAt:   time.Now(),
		ProcessingMs:  50,
		Metadata:      map[string]interface{}{"source": "file"},
	}, nil
}

// isFormatAllowed checks if image format is allowed
func (im *ImageModerator) isFormatAllowed(format string) bool {
	for _, allowed := range im.config.AllowedFormats {
		if format == allowed {
			return true
		}
	}
	return false
}

// detectNSFW performs NSFW detection (mock implementation)
func (im *ImageModerator) detectNSFW(img image.Image) float64 {
	// In a real implementation, this would use ML models
	// For now, return a mock score based on image properties
	bounds := img.Bounds()
	area := bounds.Dx() * bounds.Dy()

	// Mock logic: larger images have slightly higher NSFW scores
	score := float64(area) / 10000000.0
	if score > 1.0 {
		score = 0.9
	}

	return score
}

// detectViolence performs violence detection (mock implementation)
func (im *ImageModerator) detectViolence(img image.Image) float64 {
	// In a real implementation, this would use ML models
	// For now, return a low mock score
	return 0.05
}

// detectFaces performs face detection (mock implementation)
func (im *ImageModerator) detectFaces(img image.Image) int {
	// In a real implementation, this would use face detection algorithms
	// For now, return a mock count
	bounds := img.Bounds()
	area := bounds.Dx() * bounds.Dy()

	// Mock logic: assume 1 face per 100k pixels
	faceCount := area / 100000
	if faceCount > 10 {
		faceCount = 10
	}

	return faceCount
}

// AnalyzeImageContent provides detailed image analysis
func (im *ImageModerator) AnalyzeImageContent(ctx context.Context, img image.Image) (map[string]interface{}, error) {
	analysis := make(map[string]interface{})

	bounds := img.Bounds()
	analysis["width"] = bounds.Dx()
	analysis["height"] = bounds.Dy()
	analysis["area"] = bounds.Dx() * bounds.Dy()
	analysis["aspect_ratio"] = float64(bounds.Dx()) / float64(bounds.Dy())

	// Color analysis (simplified)
	analysis["dominant_colors"] = im.analyzeDominantColors(img)

	// Brightness analysis
	analysis["brightness"] = im.analyzeBrightness(img)

	return analysis, nil
}

// analyzeDominantColors analyzes dominant colors in image
func (im *ImageModerator) analyzeDominantColors(img image.Image) []string {
	// Simplified color analysis
	return []string{"#FF0000", "#00FF00", "#0000FF"}
}

// analyzeBrightness analyzes image brightness
func (im *ImageModerator) analyzeBrightness(img image.Image) float64 {
	// Simplified brightness calculation
	return 0.5
}

// ValidateImageSize checks if image size is within limits
func (im *ImageModerator) ValidateImageSize(size int64) bool {
	return size <= im.config.MaxImageSize
}

// GetSupportedFormats returns list of supported image formats
func (im *ImageModerator) GetSupportedFormats() []string {
	return im.config.AllowedFormats
}
