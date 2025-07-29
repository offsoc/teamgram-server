package hardware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// HardwareEncoder provides hardware-accelerated video encoding
type HardwareEncoder struct {
	config   *Config
	encoders map[string]*Encoder
	mutex    sync.RWMutex
	logger   logx.Logger
}

// Config for hardware encoder
type Config struct {
	EnableNVENC        bool `json:"enable_nvenc"`
	EnableQSV          bool `json:"enable_qsv"`
	EnableVAAPI        bool `json:"enable_vaapi"`
	EnableVideoToolbox bool `json:"enable_videotoolbox"`
	MaxConcurrency     int  `json:"max_concurrency"`
}

// Encoder represents a hardware encoder
type Encoder struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Device      string    `json:"device"`
	Codec       string    `json:"codec"`
	Status      string    `json:"status"`
	Performance int       `json:"performance"`
	CreatedAt   time.Time `json:"created_at"`
}

// EncodingRequest represents an encoding request
type EncodingRequest struct {
	InputPath  string            `json:"input_path"`
	OutputPath string            `json:"output_path"`
	Codec      string            `json:"codec"`
	Bitrate    int               `json:"bitrate"`
	Resolution string            `json:"resolution"`
	Parameters map[string]string `json:"parameters"`
}

// EncodingResult represents encoding results
type EncodingResult struct {
	Success    bool          `json:"success"`
	OutputPath string        `json:"output_path"`
	Duration   time.Duration `json:"duration"`
	FileSize   int64         `json:"file_size"`
	Quality    float64       `json:"quality"`
	Error      error         `json:"error"`
}

// NewHardwareEncoder creates a new hardware encoder
func NewHardwareEncoder(config *Config) *HardwareEncoder {
	if config == nil {
		config = &Config{
			EnableNVENC:        true,
			EnableQSV:          true,
			EnableVAAPI:        true,
			EnableVideoToolbox: true,
			MaxConcurrency:     4,
		}
	}

	encoder := &HardwareEncoder{
		config:   config,
		encoders: make(map[string]*Encoder),
		logger:   logx.WithContext(context.Background()),
	}

	// Initialize available encoders
	encoder.initializeEncoders()

	return encoder
}

// Encode encodes video using hardware acceleration
func (he *HardwareEncoder) Encode(ctx context.Context, request *EncodingRequest) (*EncodingResult, error) {
	start := time.Now()

	// Select best encoder for the codec
	encoder := he.selectEncoder(request.Codec)
	if encoder == nil {
		return &EncodingResult{
			Success: false,
			Error:   fmt.Errorf("no suitable hardware encoder found for codec %s", request.Codec),
		}, nil
	}

	// Mock encoding process
	he.logger.Infof("Encoding video with %s encoder: %s -> %s", encoder.Type, request.InputPath, request.OutputPath)

	// Simulate encoding time
	time.Sleep(time.Millisecond * 100)

	result := &EncodingResult{
		Success:    true,
		OutputPath: request.OutputPath,
		Duration:   time.Since(start),
		FileSize:   1024 * 1024, // 1MB mock size
		Quality:    0.95,        // 95% quality
	}

	he.logger.Infof("Video encoding completed in %v", result.Duration)
	return result, nil
}

// GetAvailableEncoders gets list of available encoders
func (he *HardwareEncoder) GetAvailableEncoders() []*Encoder {
	he.mutex.RLock()
	defer he.mutex.RUnlock()

	encoders := make([]*Encoder, 0, len(he.encoders))
	for _, encoder := range he.encoders {
		encoders = append(encoders, encoder)
	}

	return encoders
}

// Helper methods

func (he *HardwareEncoder) initializeEncoders() {
	// Mock encoder initialization
	encoders := []*Encoder{
		{
			ID:          "nvenc_h264",
			Type:        "NVENC",
			Device:      "GPU0",
			Codec:       "h264",
			Status:      "available",
			Performance: 95,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "qsv_h264",
			Type:        "QSV",
			Device:      "iGPU",
			Codec:       "h264",
			Status:      "available",
			Performance: 85,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "vaapi_h264",
			Type:        "VAAPI",
			Device:      "GPU0",
			Codec:       "h264",
			Status:      "available",
			Performance: 80,
			CreatedAt:   time.Now(),
		},
	}

	for _, encoder := range encoders {
		he.encoders[encoder.ID] = encoder
	}
}

func (he *HardwareEncoder) selectEncoder(codec string) *Encoder {
	he.mutex.RLock()
	defer he.mutex.RUnlock()

	var bestEncoder *Encoder
	bestPerformance := 0

	for _, encoder := range he.encoders {
		if encoder.Codec == codec && encoder.Status == "available" {
			if encoder.Performance > bestPerformance {
				bestPerformance = encoder.Performance
				bestEncoder = encoder
			}
		}
	}

	return bestEncoder
}
