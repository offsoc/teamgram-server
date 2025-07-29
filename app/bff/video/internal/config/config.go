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

package config

import (
	"fmt"
	"time"

	"github.com/zeromicro/go-zero/zrpc"
)

// Config configuration for Video BFF service
type Config struct {
	zrpc.RpcServerConf
	Video *VideoServiceConfig `json:",optional"`
}

// VideoServiceConfig configuration for video service
type VideoServiceConfig struct {
	// Basic settings
	Enabled             bool          `json:",default=true"`
	MaxConcurrentCalls  int           `json:",default=10000"`
	MaxParticipants     int           `json:",default=200000"`
	CallTimeout         time.Duration `json:",default=24h"`
	
	// Video quality settings
	MaxResolution       string        `json:",default=8K"`
	MaxFrameRate        int           `json:",default=60"`
	MaxBitrate          int           `json:",default=100000000"` // 100 Mbps
	AdaptiveBitrate     bool          `json:",default=true"`
	
	// Codec settings
	CodecConfig         *CodecConfig  `json:",optional"`
	
	// SFU settings
	SFUConfig           *SFUConfig    `json:",optional"`
	
	// AI Enhancement settings
	AIEnhanceConfig     *AIEnhanceConfig `json:",optional"`
	
	// WebRTC settings
	WebRTCConfig        *WebRTCConfig `json:",optional"`
	
	// Performance settings
	EnableGPU           bool          `json:",default=true"`
	EnableHardwareCodec bool          `json:",default=true"`
	MaxCPUUsage         float64       `json:",default=80.0"`
	MaxMemoryUsage      int64         `json:",default=8589934592"` // 8GB
	
	// Network settings
	EnableP2P           bool          `json:",default=true"`
	EnableRelay         bool          `json:",default=true"`
	STUNServers         []string      `json:",optional"`
	TURNServers         []string      `json:",optional"`
	
	// Quality settings
	TargetLatency       time.Duration `json:",default=30ms"`
	MaxLatency          time.Duration `json:",default=50ms"`
	EnableJitterBuffer  bool          `json:",default=true"`
	EnableFEC           bool          `json:",default=true"`
	
	// Security settings
	EnableDTLS          bool          `json:",default=true"`
	EnableSRTP          bool          `json:",default=true"`
	EnableAuth          bool          `json:",default=true"`
	
	// Monitoring
	EnableMetrics       bool          `json:",default=true"`
	MetricsPort         int           `json:",default=9055"`
	MetricsInterval     time.Duration `json:",default=30s"`
	HealthCheckInterval time.Duration `json:",default=30s"`
}

// CodecConfig configuration for video codecs
type CodecConfig struct {
	// AV1 settings
	EnableAV1           bool          `json:",default=true"`
	AV1Profile          string        `json:",default=main"`
	AV1Level            string        `json:",default=6.3"`
	AV1Preset           string        `json:",default=fast"`
	AV1CRF              int           `json:",default=23"`
	
	// H.266/VVC settings
	EnableH266          bool          `json:",default=true"`
	H266Profile         string        `json:",default=main10"`
	H266Level           string        `json:",default=6.3"`
	H266Tier            string        `json:",default=high"`
	H266Preset          string        `json:",default=fast"`
	H266QP              int           `json:",default=22"`
	
	// H.264 settings (fallback)
	EnableH264          bool          `json:",default=true"`
	H264Profile         string        `json:",default=high"`
	H264Level           string        `json:",default=5.2"`
	H264Preset          string        `json:",default=fast"`
	H264CRF             int           `json:",default=23"`
	
	// VP9 settings (fallback)
	EnableVP9           bool          `json:",default=true"`
	VP9Profile          string        `json:",default=0"`
	VP9CRF              int           `json:",default=30"`
	
	// Encoding settings
	KeyFrameInterval    int           `json:",default=60"`
	BFrames             int           `json:",default=3"`
	ThreadCount         int           `json:",default=8"`
	EnableHardwareAccel bool          `json:",default=true"`
	
	// Real-time settings
	EnableRealtime      bool          `json:",default=true"`
	RealtimeDeadline    time.Duration `json:",default=16ms"` // 60fps
	LowLatencyMode      bool          `json:",default=true"`
}

// SFUConfig configuration for Selective Forwarding Unit
type SFUConfig struct {
	// Cluster settings
	EnableClustering    bool          `json:",default=true"`
	ClusterNodes        []string      `json:",optional"`
	LoadBalanceStrategy string        `json:",default=least_loaded"`
	NodeID              string        `json:",optional"`
	
	// Forwarding settings
	MaxForwardStreams   int           `json:",default=1000"`
	EnableSimulcast     bool          `json:",default=true"`
	EnableSVC           bool          `json:",default=true"`
	ForwardingStrategy  string        `json:",default=adaptive"`
	
	// Bandwidth management
	EnableBWE           bool          `json:",default=true"`
	InitialBandwidth    int           `json:",default=1000000"`   // 1 Mbps
	MaxBandwidth        int           `json:",default=100000000"` // 100 Mbps
	MinBandwidth        int           `json:",default=100000"`    // 100 Kbps
	BWEAlgorithm        string        `json:",default=gcc"`
	
	// Quality adaptation
	EnableQualityAdapt  bool          `json:",default=true"`
	AdaptationInterval  time.Duration `json:",default=5s"`
	QualityLevels       []QualityLevel `json:",optional"`
	
	// Performance settings
	MaxConcurrentRooms  int           `json:",default=10000"`
	MaxParticipantsPerRoom int        `json:",default=200000"`
	EnableGPUAccel      bool          `json:",default=true"`
	ProcessingThreads   int           `json:",default=8"`
	
	// Network settings
	UDPPortRange        PortRange     `json:",optional"`
	TCPPortRange        PortRange     `json:",optional"`
	EnableIPv6          bool          `json:",default=true"`
	
	// Security settings
	EnableAuth          bool          `json:",default=true"`
	AuthToken           string        `json:",optional"`
	EnableEncryption    bool          `json:",default=true"`
}

// AIEnhanceConfig configuration for AI video enhancement
type AIEnhanceConfig struct {
	// Basic settings
	Enabled             bool          `json:",default=true"`
	EnableRealtime      bool          `json:",default=true"`
	MaxConcurrentJobs   int           `json:",default=8"`
	ProcessingTimeout   time.Duration `json:",default=5s"`
	
	// Enhancement features
	EnableUpscaling     bool          `json:",default=true"`
	EnableDenoising     bool          `json:",default=true"`
	EnableSharpening    bool          `json:",default=true"`
	EnableColorCorrect  bool          `json:",default=true"`
	EnableLowLight      bool          `json:",default=true"`
	EnableFaceEnhance   bool          `json:",default=true"`
	EnableBackground    bool          `json:",default=true"`
	EnableStabilization bool          `json:",default=true"`
	
	// AI models
	UpscalingModel      string        `json:",default=esrgan"`
	DenoisingModel      string        `json:",default=dncnn"`
	FaceEnhanceModel    string        `json:",default=gfpgan"`
	BackgroundModel     string        `json:",default=u2net"`
	StabilizationModel  string        `json:",default=difrint"`
	
	// Performance settings
	EnableGPU           bool          `json:",default=true"`
	GPUMemoryLimit      int64         `json:",default=4294967296"` // 4GB
	CPUThreads          int           `json:",default=8"`
	BatchSize           int           `json:",default=4"`
	
	// Quality settings
	UpscalingFactor     float64       `json:",default=2.0"`
	DenoisingStrength   float64       `json:",default=0.5"`
	SharpeningStrength  float64       `json:",default=0.3"`
	ColorCorrectionLevel float64      `json:",default=0.7"`
	
	// Real-time settings
	FrameBufferSize     int           `json:",default=10"`
	ProcessingLatency   time.Duration `json:",default=16ms"` // ~60fps
	EnableFrameSkip     bool          `json:",default=true"`
	SkipThreshold       time.Duration `json:",default=33ms"` // 30fps threshold
}

// WebRTCConfig configuration for WebRTC
type WebRTCConfig struct {
	// ICE settings
	ICEServers          []ICEServer   `json:",optional"`
	ICETransportPolicy  string        `json:",default=all"`
	ICECandidatePoolSize int          `json:",default=10"`
	ICEGatheringTimeout time.Duration `json:",default=10s"`
	
	// Media settings
	EnableAudio         bool          `json:",default=true"`
	EnableVideo         bool          `json:",default=true"`
	EnableDataChannel   bool          `json:",default=true"`
	
	// Video settings
	VideoCodecs         []VideoCodec  `json:",optional"`
	AudioCodecs         []AudioCodec  `json:",optional"`
	MaxVideoBitrate     int           `json:",default=100000000"` // 100 Mbps
	MaxAudioBitrate     int           `json:",default=320000"`    // 320 kbps
	
	// Security settings
	EnableDTLS          bool          `json:",default=true"`
	EnableSRTP          bool          `json:",default=true"`
	DTLSCertificate     string        `json:",optional"`
	DTLSPrivateKey      string        `json:",optional"`
	
	// Performance settings
	MaxBandwidth        int           `json:",default=100000000"` // 100 Mbps
	MinBandwidth        int           `json:",default=1000000"`   // 1 Mbps
	StartBandwidth      int           `json:",default=10000000"`  // 10 Mbps
	EnableBWE           bool          `json:",default=true"`
	
	// Network settings
	EnableIPv6          bool          `json:",default=true"`
	EnableTCP           bool          `json:",default=true"`
	EnableUDP           bool          `json:",default=true"`
	PortRange           PortRange     `json:",optional"`
	
	// Signaling settings
	SignalingPort       int           `json:",default=8080"`
	EnableWebSocket     bool          `json:",default=true"`
	EnableHTTP          bool          `json:",default=true"`
	
	// Quality settings
	EnableJitterBuffer  bool          `json:",default=true"`
	EnableFEC           bool          `json:",default=true"`
	EnableNACK          bool          `json:",default=true"`
	EnablePLI           bool          `json:",default=true"`
	
	// Advanced settings
	EnableSimulcast     bool          `json:",default=true"`
	EnableSVC           bool          `json:",default=true"`
	EnableRED           bool          `json:",default=true"`
	EnableULPFEC        bool          `json:",default=true"`
}

// Supporting types
type QualityLevel struct {
	Name                string `json:"name"`
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	FrameRate           int    `json:"frame_rate"`
	Bitrate             int    `json:"bitrate"`
	ScalabilityMode     string `json:"scalability_mode"`
}

type PortRange struct {
	Min                 int    `json:"min"`
	Max                 int    `json:"max"`
}

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	Type       string   `json:"type,omitempty"`
}

type VideoCodec struct {
	Name        string            `json:"name"`
	PayloadType int               `json:"payload_type"`
	ClockRate   int               `json:"clock_rate"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

type AudioCodec struct {
	Name        string            `json:"name"`
	PayloadType int               `json:"payload_type"`
	ClockRate   int               `json:"clock_rate"`
	Channels    int               `json:"channels"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Video == nil {
		return nil // Video is optional
	}
	
	// Validate basic settings
	if c.Video.MaxConcurrentCalls <= 0 {
		return fmt.Errorf("max_concurrent_calls must be positive")
	}
	
	if c.Video.MaxParticipants <= 0 {
		return fmt.Errorf("max_participants must be positive")
	}
	
	if c.Video.CallTimeout <= 0 {
		return fmt.Errorf("call_timeout must be positive")
	}
	
	// Validate quality settings
	if c.Video.MaxFrameRate <= 0 || c.Video.MaxFrameRate > 120 {
		return fmt.Errorf("max_frame_rate must be between 1 and 120")
	}
	
	if c.Video.MaxBitrate <= 0 {
		return fmt.Errorf("max_bitrate must be positive")
	}
	
	// Validate latency settings
	if c.Video.TargetLatency <= 0 {
		return fmt.Errorf("target_latency must be positive")
	}
	
	if c.Video.MaxLatency <= 0 {
		return fmt.Errorf("max_latency must be positive")
	}
	
	if c.Video.TargetLatency > c.Video.MaxLatency {
		return fmt.Errorf("target_latency cannot be greater than max_latency")
	}
	
	// Validate codec config
	if c.Video.CodecConfig != nil {
		if err := c.validateCodecConfig(); err != nil {
			return fmt.Errorf("invalid codec config: %w", err)
		}
	}
	
	// Validate SFU config
	if c.Video.SFUConfig != nil {
		if err := c.validateSFUConfig(); err != nil {
			return fmt.Errorf("invalid SFU config: %w", err)
		}
	}
	
	// Validate AI enhance config
	if c.Video.AIEnhanceConfig != nil {
		if err := c.validateAIEnhanceConfig(); err != nil {
			return fmt.Errorf("invalid AI enhance config: %w", err)
		}
	}
	
	// Validate WebRTC config
	if c.Video.WebRTCConfig != nil {
		if err := c.validateWebRTCConfig(); err != nil {
			return fmt.Errorf("invalid WebRTC config: %w", err)
		}
	}
	
	return nil
}

func (c *Config) validateCodecConfig() error {
	codec := c.Video.CodecConfig
	
	if codec.KeyFrameInterval <= 0 {
		return fmt.Errorf("key_frame_interval must be positive")
	}
	
	if codec.BFrames < 0 {
		return fmt.Errorf("b_frames cannot be negative")
	}
	
	if codec.ThreadCount <= 0 {
		return fmt.Errorf("thread_count must be positive")
	}
	
	if codec.RealtimeDeadline <= 0 {
		return fmt.Errorf("realtime_deadline must be positive")
	}
	
	return nil
}

func (c *Config) validateSFUConfig() error {
	sfu := c.Video.SFUConfig
	
	if sfu.MaxForwardStreams <= 0 {
		return fmt.Errorf("max_forward_streams must be positive")
	}
	
	if sfu.InitialBandwidth <= 0 {
		return fmt.Errorf("initial_bandwidth must be positive")
	}
	
	if sfu.MaxBandwidth <= 0 {
		return fmt.Errorf("max_bandwidth must be positive")
	}
	
	if sfu.MinBandwidth <= 0 {
		return fmt.Errorf("min_bandwidth must be positive")
	}
	
	if sfu.MinBandwidth > sfu.MaxBandwidth {
		return fmt.Errorf("min_bandwidth cannot be greater than max_bandwidth")
	}
	
	if sfu.MaxConcurrentRooms <= 0 {
		return fmt.Errorf("max_concurrent_rooms must be positive")
	}
	
	if sfu.MaxParticipantsPerRoom <= 0 {
		return fmt.Errorf("max_participants_per_room must be positive")
	}
	
	if sfu.ProcessingThreads <= 0 {
		return fmt.Errorf("processing_threads must be positive")
	}
	
	return nil
}

func (c *Config) validateAIEnhanceConfig() error {
	ai := c.Video.AIEnhanceConfig
	
	if ai.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max_concurrent_jobs must be positive")
	}
	
	if ai.ProcessingTimeout <= 0 {
		return fmt.Errorf("processing_timeout must be positive")
	}
	
	if ai.GPUMemoryLimit <= 0 {
		return fmt.Errorf("gpu_memory_limit must be positive")
	}
	
	if ai.CPUThreads <= 0 {
		return fmt.Errorf("cpu_threads must be positive")
	}
	
	if ai.BatchSize <= 0 {
		return fmt.Errorf("batch_size must be positive")
	}
	
	if ai.UpscalingFactor <= 0 {
		return fmt.Errorf("upscaling_factor must be positive")
	}
	
	if ai.DenoisingStrength < 0 || ai.DenoisingStrength > 1 {
		return fmt.Errorf("denoising_strength must be between 0 and 1")
	}
	
	if ai.SharpeningStrength < 0 || ai.SharpeningStrength > 1 {
		return fmt.Errorf("sharpening_strength must be between 0 and 1")
	}
	
	if ai.ColorCorrectionLevel < 0 || ai.ColorCorrectionLevel > 1 {
		return fmt.Errorf("color_correction_level must be between 0 and 1")
	}
	
	return nil
}

func (c *Config) validateWebRTCConfig() error {
	webrtc := c.Video.WebRTCConfig
	
	if webrtc.ICECandidatePoolSize < 0 {
		return fmt.Errorf("ice_candidate_pool_size cannot be negative")
	}
	
	if webrtc.ICEGatheringTimeout <= 0 {
		return fmt.Errorf("ice_gathering_timeout must be positive")
	}
	
	if webrtc.MaxVideoBitrate <= 0 {
		return fmt.Errorf("max_video_bitrate must be positive")
	}
	
	if webrtc.MaxAudioBitrate <= 0 {
		return fmt.Errorf("max_audio_bitrate must be positive")
	}
	
	if webrtc.MaxBandwidth <= 0 {
		return fmt.Errorf("max_bandwidth must be positive")
	}
	
	if webrtc.MinBandwidth <= 0 {
		return fmt.Errorf("min_bandwidth must be positive")
	}
	
	if webrtc.MinBandwidth > webrtc.MaxBandwidth {
		return fmt.Errorf("min_bandwidth cannot be greater than max_bandwidth")
	}
	
	if webrtc.SignalingPort <= 0 || webrtc.SignalingPort > 65535 {
		return fmt.Errorf("signaling_port must be between 1 and 65535")
	}
	
	return nil
}

// GetVideoConfig returns video configuration with defaults
func (c *Config) GetVideoConfig() *VideoServiceConfig {
	if c.Video == nil {
		return &VideoServiceConfig{
			Enabled:             false,
			MaxConcurrentCalls:  10000,
			MaxParticipants:     200000,
			CallTimeout:         24 * time.Hour,
			MaxResolution:       "8K",
			MaxFrameRate:        60,
			MaxBitrate:          100000000, // 100 Mbps
			AdaptiveBitrate:     true,
			EnableGPU:           true,
			EnableHardwareCodec: true,
			MaxCPUUsage:         80.0,
			MaxMemoryUsage:      8 * 1024 * 1024 * 1024, // 8GB
			EnableP2P:           true,
			EnableRelay:         true,
			TargetLatency:       30 * time.Millisecond,
			MaxLatency:          50 * time.Millisecond,
			EnableJitterBuffer:  true,
			EnableFEC:           true,
			EnableDTLS:          true,
			EnableSRTP:          true,
			EnableAuth:          true,
			EnableMetrics:       true,
			MetricsPort:         9055,
			MetricsInterval:     30 * time.Second,
			HealthCheckInterval: 30 * time.Second,
		}
	}
	
	return c.Video
}

// IsVideoEnabled returns whether video is enabled
func (c *Config) IsVideoEnabled() bool {
	return c.Video != nil && c.Video.Enabled
}

// GetMetricsAddress returns the metrics port address
func (c *Config) GetMetricsAddress() string {
	if !c.IsVideoEnabled() || !c.Video.EnableMetrics {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.Video.MetricsPort)
}

// GetSupportedResolutions returns supported video resolutions
func (c *Config) GetSupportedResolutions() []string {
	return []string{"8K", "4K", "1080p", "720p", "480p", "360p"}
}

// GetSupportedCodecs returns supported video codecs
func (c *Config) GetSupportedCodecs() []string {
	codecs := []string{}
	
	if c.IsVideoEnabled() && c.Video.CodecConfig != nil {
		if c.Video.CodecConfig.EnableAV1 {
			codecs = append(codecs, "AV1")
		}
		if c.Video.CodecConfig.EnableH266 {
			codecs = append(codecs, "H266")
		}
		if c.Video.CodecConfig.EnableH264 {
			codecs = append(codecs, "H264")
		}
		if c.Video.CodecConfig.EnableVP9 {
			codecs = append(codecs, "VP9")
		}
	} else {
		// Default codecs
		codecs = []string{"AV1", "H266", "H264", "VP9"}
	}
	
	return codecs
}

// GetMaxParticipants returns maximum participants for a call
func (c *Config) GetMaxParticipants() int {
	if !c.IsVideoEnabled() {
		return 200000 // Default
	}
	
	return c.Video.MaxParticipants
}

// GetTargetLatency returns target latency for video calls
func (c *Config) GetTargetLatency() time.Duration {
	if !c.IsVideoEnabled() {
		return 30 * time.Millisecond // Default
	}
	
	return c.Video.TargetLatency
}

// GetMaxLatency returns maximum allowed latency
func (c *Config) GetMaxLatency() time.Duration {
	if !c.IsVideoEnabled() {
		return 50 * time.Millisecond // Default
	}
	
	return c.Video.MaxLatency
}
