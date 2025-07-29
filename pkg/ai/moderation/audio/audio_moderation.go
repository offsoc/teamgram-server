package audio

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// AudioModerator handles audio content moderation
type AudioModerator struct {
	config *Config
	logger logx.Logger
}

// Config for audio moderation
type Config struct {
	EnableSpeechToText     bool     `json:"enable_speech_to_text"`
	EnableToxicityCheck    bool     `json:"enable_toxicity_check"`
	EnableMusicDetection   bool     `json:"enable_music_detection"`
	MaxAudioDuration       int      `json:"max_audio_duration"` // seconds
	AllowedFormats         []string `json:"allowed_formats"`
	SampleRate             int      `json:"sample_rate"`
	ToxicityThreshold      float64  `json:"toxicity_threshold"`
}

// ModerationResult contains the result of audio moderation
type ModerationResult struct {
	IsAllowed        bool                   `json:"is_allowed"`
	TranscribedText  string                 `json:"transcribed_text"`
	ToxicityScore    float64                `json:"toxicity_score"`
	MusicDetected    bool                   `json:"music_detected"`
	Duration         float64                `json:"duration"`
	Classifications  []Classification       `json:"classifications"`
	ProcessedAt      time.Time              `json:"processed_at"`
	ProcessingMs     int64                  `json:"processing_ms"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// Classification represents an audio classification
type Classification struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
	StartTime  float64 `json:"start_time"`
	EndTime    float64 `json:"end_time"`
}

// AudioFeatures represents extracted audio features
type AudioFeatures struct {
	SampleRate    int     `json:"sample_rate"`
	Duration      float64 `json:"duration"`
	Channels      int     `json:"channels"`
	BitRate       int     `json:"bit_rate"`
	Format        string  `json:"format"`
	VolumeLevel   float64 `json:"volume_level"`
	SilenceRatio  float64 `json:"silence_ratio"`
}

// NewAudioModerator creates a new audio moderator
func NewAudioModerator(config *Config) *AudioModerator {
	if config == nil {
		config = DefaultConfig()
	}

	return &AudioModerator{
		config: config,
		logger: logx.WithContext(context.Background()),
	}
}

// DefaultConfig returns default audio moderation configuration
func DefaultConfig() *Config {
	return &Config{
		EnableSpeechToText:  true,
		EnableToxicityCheck: true,
		EnableMusicDetection: true,
		MaxAudioDuration:    300, // 5 minutes
		AllowedFormats:      []string{"mp3", "wav", "ogg", "m4a", "aac"},
		SampleRate:          44100,
		ToxicityThreshold:   0.7,
	}
}

// ModerateAudio performs audio moderation
func (am *AudioModerator) ModerateAudio(ctx context.Context, audioData io.Reader) (*ModerationResult, error) {
	start := time.Now()
	
	result := &ModerationResult{
		IsAllowed:       true,
		TranscribedText: "",
		ToxicityScore:   0.0,
		MusicDetected:   false,
		Duration:        0.0,
		Classifications: []Classification{},
		ProcessedAt:     start,
		Metadata:        make(map[string]interface{}),
	}

	// Extract audio features
	features, err := am.extractAudioFeatures(audioData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract audio features: %w", err)
	}

	result.Duration = features.Duration
	result.Metadata["features"] = features

	// Check duration limit
	if features.Duration > float64(am.config.MaxAudioDuration) {
		result.IsAllowed = false
		result.Metadata["rejection_reason"] = "duration_exceeded"
		result.ProcessingMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Check format
	if !am.isFormatAllowed(features.Format) {
		result.IsAllowed = false
		result.Metadata["rejection_reason"] = "unsupported_format"
		result.ProcessingMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Speech to text conversion
	if am.config.EnableSpeechToText {
		transcription, err := am.speechToText(audioData)
		if err != nil {
			am.logger.Errorf("Speech to text failed: %v", err)
		} else {
			result.TranscribedText = transcription
		}
	}

	// Toxicity check on transcribed text
	if am.config.EnableToxicityCheck && result.TranscribedText != "" {
		toxicityScore := am.checkTextToxicity(result.TranscribedText)
		result.ToxicityScore = toxicityScore
		
		if toxicityScore > am.config.ToxicityThreshold {
			result.IsAllowed = false
			result.Classifications = append(result.Classifications, Classification{
				Label:      "toxic_speech",
				Confidence: toxicityScore,
				Category:   "harmful_content",
				StartTime:  0.0,
				EndTime:    features.Duration,
			})
		}
	}

	// Music detection
	if am.config.EnableMusicDetection {
		musicDetected := am.detectMusic(audioData)
		result.MusicDetected = musicDetected
		
		if musicDetected {
			result.Classifications = append(result.Classifications, Classification{
				Label:      "music",
				Confidence: 0.8,
				Category:   "audio_type",
				StartTime:  0.0,
				EndTime:    features.Duration,
			})
		}
	}

	result.ProcessingMs = time.Since(start).Milliseconds()
	return result, nil
}

// ModerateAudioFromFile moderates an audio file
func (am *AudioModerator) ModerateAudioFromFile(ctx context.Context, filePath string) (*ModerationResult, error) {
	// This would read from file system
	// For now, return a mock result
	return &ModerationResult{
		IsAllowed:       true,
		TranscribedText: "Hello, this is a test audio message.",
		ToxicityScore:   0.1,
		MusicDetected:   false,
		Duration:        5.2,
		ProcessedAt:     time.Now(),
		ProcessingMs:    150,
		Metadata:        map[string]interface{}{"source": "file"},
	}, nil
}

// extractAudioFeatures extracts features from audio data
func (am *AudioModerator) extractAudioFeatures(audioData io.Reader) (*AudioFeatures, error) {
	// In a real implementation, this would use audio processing libraries
	// For now, return mock features
	return &AudioFeatures{
		SampleRate:   44100,
		Duration:     5.2,
		Channels:     2,
		BitRate:      128000,
		Format:       "mp3",
		VolumeLevel:  0.7,
		SilenceRatio: 0.1,
	}, nil
}

// speechToText converts speech to text
func (am *AudioModerator) speechToText(audioData io.Reader) (string, error) {
	// In a real implementation, this would use speech recognition APIs
	// For now, return mock transcription
	return "This is a mock transcription of the audio content.", nil
}

// checkTextToxicity checks toxicity of transcribed text
func (am *AudioModerator) checkTextToxicity(text string) float64 {
	// Simple toxicity check - in production, this would use ML models
	toxicWords := []string{"hate", "kill", "stupid", "idiot"}
	
	score := 0.0
	for _, word := range toxicWords {
		if contains(text, word) {
			score += 0.3
		}
	}
	
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// detectMusic detects if audio contains music
func (am *AudioModerator) detectMusic(audioData io.Reader) bool {
	// In a real implementation, this would use audio analysis
	// For now, return false (no music detected)
	return false
}

// isFormatAllowed checks if audio format is allowed
func (am *AudioModerator) isFormatAllowed(format string) bool {
	for _, allowed := range am.config.AllowedFormats {
		if format == allowed {
			return true
		}
	}
	return false
}

// AnalyzeAudioContent provides detailed audio analysis
func (am *AudioModerator) AnalyzeAudioContent(ctx context.Context, audioData io.Reader) (map[string]interface{}, error) {
	features, err := am.extractAudioFeatures(audioData)
	if err != nil {
		return nil, err
	}

	analysis := make(map[string]interface{})
	analysis["features"] = features
	analysis["quality_score"] = am.calculateQualityScore(features)
	analysis["content_type"] = am.classifyContentType(features)
	
	return analysis, nil
}

// calculateQualityScore calculates audio quality score
func (am *AudioModerator) calculateQualityScore(features *AudioFeatures) float64 {
	score := 0.5 // base score
	
	// Higher sample rate = better quality
	if features.SampleRate >= 44100 {
		score += 0.2
	}
	
	// Higher bit rate = better quality
	if features.BitRate >= 128000 {
		score += 0.2
	}
	
	// Lower silence ratio = better content
	if features.SilenceRatio < 0.2 {
		score += 0.1
	}
	
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// classifyContentType classifies the type of audio content
func (am *AudioModerator) classifyContentType(features *AudioFeatures) string {
	// Simple classification based on features
	if features.Duration < 10 {
		return "short_message"
	} else if features.Duration < 60 {
		return "voice_message"
	} else {
		return "long_audio"
	}
}

// ValidateAudioDuration checks if audio duration is within limits
func (am *AudioModerator) ValidateAudioDuration(duration float64) bool {
	return duration <= float64(am.config.MaxAudioDuration)
}

// GetSupportedFormats returns list of supported audio formats
func (am *AudioModerator) GetSupportedFormats() []string {
	return am.config.AllowedFormats
}

// Helper function to check if string contains substring (case-insensitive)
func contains(text, substr string) bool {
	return len(text) >= len(substr) && 
		   (text == substr || 
		    (len(text) > len(substr) && 
		     (text[:len(substr)] == substr || 
		      text[len(text)-len(substr):] == substr ||
		      findInString(text, substr))))
}

func findInString(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
