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

package video

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// VideoManager manages all video services and components
type VideoManager struct {
	mutex         sync.RWMutex
	config        *VideoConfig
	sfuManager    SFUManager
	codecManager  CodecManager
	aiEnhancer    AIEnhancer
	webrtcManager WebRTCManager
	streamManager StreamManager
	metrics       *VideoMetrics
	logger        logx.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	isRunning     bool
}

// VideoConfig configuration for video services
type VideoConfig struct {
	// Basic settings
	Enabled            bool          `json:"enabled"`
	MaxConcurrentCalls int           `json:"max_concurrent_calls"`
	MaxParticipants    int           `json:"max_participants"`
	CallTimeout        time.Duration `json:"call_timeout"`

	// Video quality settings
	MaxResolution   string `json:"max_resolution"` // 8K, 4K, 1080p, etc.
	MaxFrameRate    int    `json:"max_frame_rate"` // 60, 30, etc.
	MaxBitrate      int    `json:"max_bitrate"`    // Mbps
	AdaptiveBitrate bool   `json:"adaptive_bitrate"`

	// Codec settings
	CodecConfig *CodecConfig `json:"codec_config"`

	// SFU settings
	SFUConfig *SFUConfig `json:"sfu_config"`

	// AI Enhancement settings
	AIEnhanceConfig *AIEnhanceConfig `json:"ai_enhance_config"`

	// WebRTC settings
	WebRTCConfig *WebRTCConfig `json:"webrtc_config"`

	// Performance settings
	EnableGPU           bool    `json:"enable_gpu"`
	EnableHardwareCodec bool    `json:"enable_hardware_codec"`
	MaxCPUUsage         float64 `json:"max_cpu_usage"`
	MaxMemoryUsage      int64   `json:"max_memory_usage"`

	// Network settings
	EnableP2P   bool     `json:"enable_p2p"`
	EnableRelay bool     `json:"enable_relay"`
	STUNServers []string `json:"stun_servers"`
	TURNServers []string `json:"turn_servers"`

	// Quality settings
	TargetLatency      time.Duration `json:"target_latency"`
	MaxLatency         time.Duration `json:"max_latency"`
	EnableJitterBuffer bool          `json:"enable_jitter_buffer"`
	EnableFEC          bool          `json:"enable_fec"`

	// Monitoring
	EnableMetrics   bool          `json:"enable_metrics"`
	MetricsInterval time.Duration `json:"metrics_interval"`
}

// CodecConfig configuration for video codecs
type CodecConfig struct {
	// AV1 settings
	EnableAV1  bool   `json:"enable_av1"`
	AV1Profile string `json:"av1_profile"`
	AV1Level   string `json:"av1_level"`

	// H.266/VVC settings
	EnableH266  bool   `json:"enable_h266"`
	H266Profile string `json:"h266_profile"`
	H266Level   string `json:"h266_level"`

	// H.264 settings (fallback)
	EnableH264  bool   `json:"enable_h264"`
	H264Profile string `json:"h264_profile"`
	H264Level   string `json:"h264_level"`

	// VP9 settings (fallback)
	EnableVP9  bool   `json:"enable_vp9"`
	VP9Profile string `json:"vp9_profile"`

	// Encoding settings
	EncodingPreset   string `json:"encoding_preset"`
	RateControlMode  string `json:"rate_control_mode"`
	KeyFrameInterval int    `json:"key_frame_interval"`
	BFrames          int    `json:"b_frames"`
}

// SFUConfig configuration for Selective Forwarding Unit
type SFUConfig struct {
	// Cluster settings
	EnableClustering    bool     `json:"enable_clustering"`
	ClusterNodes        []string `json:"cluster_nodes"`
	LoadBalanceStrategy string   `json:"load_balance_strategy"`

	// Forwarding settings
	MaxForwardStreams int  `json:"max_forward_streams"`
	EnableSimulcast   bool `json:"enable_simulcast"`
	EnableSVC         bool `json:"enable_svc"`

	// Bandwidth management
	EnableBWE        bool `json:"enable_bwe"`
	InitialBandwidth int  `json:"initial_bandwidth"`
	MaxBandwidth     int  `json:"max_bandwidth"`
	MinBandwidth     int  `json:"min_bandwidth"`

	// Quality adaptation
	EnableQualityAdapt bool          `json:"enable_quality_adapt"`
	AdaptationInterval time.Duration `json:"adaptation_interval"`

	// Performance settings
	MaxConcurrentRooms     int  `json:"max_concurrent_rooms"`
	MaxParticipantsPerRoom int  `json:"max_participants_per_room"`
	EnableGPUAccel         bool `json:"enable_gpu_accel"`
}

// AIEnhanceConfig configuration for AI video enhancement
type AIEnhanceConfig struct {
	// Basic settings
	Enabled        bool `json:"enabled"`
	EnableRealtime bool `json:"enable_realtime"`

	// Enhancement features
	EnableUpscaling    bool `json:"enable_upscaling"`
	EnableDenoising    bool `json:"enable_denoising"`
	EnableSharpening   bool `json:"enable_sharpening"`
	EnableColorCorrect bool `json:"enable_color_correct"`
	EnableLowLight     bool `json:"enable_low_light"`
	EnableFaceEnhance  bool `json:"enable_face_enhance"`
	EnableBackground   bool `json:"enable_background"`

	// AI models
	UpscalingModel   string `json:"upscaling_model"`
	DenoisingModel   string `json:"denoising_model"`
	FaceEnhanceModel string `json:"face_enhance_model"`

	// Performance settings
	MaxConcurrentJobs int           `json:"max_concurrent_jobs"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	EnableGPU         bool          `json:"enable_gpu"`
	GPUMemoryLimit    int64         `json:"gpu_memory_limit"`
}

// WebRTCConfig configuration for WebRTC
type WebRTCConfig struct {
	// ICE settings
	ICEServers           []ICEServer `json:"ice_servers"`
	ICETransportPolicy   string      `json:"ice_transport_policy"`
	ICECandidatePoolSize int         `json:"ice_candidate_pool_size"`

	// Media settings
	EnableAudio       bool `json:"enable_audio"`
	EnableVideo       bool `json:"enable_video"`
	EnableDataChannel bool `json:"enable_data_channel"`

	// Security settings
	EnableDTLS bool `json:"enable_dtls"`
	EnableSRTP bool `json:"enable_srtp"`

	// Performance settings
	MaxBandwidth   int `json:"max_bandwidth"`
	MinBandwidth   int `json:"min_bandwidth"`
	StartBandwidth int `json:"start_bandwidth"`
}

// ICEServer represents an ICE server configuration
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// VideoMetrics tracks video service performance
type VideoMetrics struct {
	// Call metrics
	TotalCalls      int64 `json:"total_calls"`
	ActiveCalls     int64 `json:"active_calls"`
	SuccessfulCalls int64 `json:"successful_calls"`
	FailedCalls     int64 `json:"failed_calls"`

	// Participant metrics
	TotalParticipants  int64 `json:"total_participants"`
	ActiveParticipants int64 `json:"active_participants"`
	MaxParticipants    int64 `json:"max_participants"`

	// Quality metrics
	AverageLatency time.Duration `json:"average_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinLatency     time.Duration `json:"min_latency"`
	PacketLossRate float64       `json:"packet_loss_rate"`
	JitterRate     float64       `json:"jitter_rate"`

	// Resolution metrics
	Resolution8K    int64 `json:"resolution_8k"`
	Resolution4K    int64 `json:"resolution_4k"`
	Resolution1080p int64 `json:"resolution_1080p"`
	Resolution720p  int64 `json:"resolution_720p"`

	// Codec metrics
	AV1Usage  int64 `json:"av1_usage"`
	H266Usage int64 `json:"h266_usage"`
	H264Usage int64 `json:"h264_usage"`
	VP9Usage  int64 `json:"vp9_usage"`

	// Performance metrics
	CPUUsage         float64 `json:"cpu_usage"`
	MemoryUsage      int64   `json:"memory_usage"`
	GPUUsage         float64 `json:"gpu_usage"`
	NetworkBandwidth int64   `json:"network_bandwidth"`

	// SFU metrics
	SFUNodes         int   `json:"sfu_nodes"`
	ActiveRooms      int64 `json:"active_rooms"`
	ForwardedStreams int64 `json:"forwarded_streams"`

	// AI Enhancement metrics
	AIJobsProcessed  int64         `json:"ai_jobs_processed"`
	AIProcessingTime time.Duration `json:"ai_processing_time"`

	// Error metrics
	ConnectionErrors int64 `json:"connection_errors"`
	CodecErrors      int64 `json:"codec_errors"`
	NetworkErrors    int64 `json:"network_errors"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
	StartTime   time.Time `json:"start_time"`
}

// Manager interfaces
type SFUManager interface {
	CreateRoom(ctx context.Context, roomID string, config *RoomConfig) (*Room, error)
	JoinRoom(ctx context.Context, roomID, userID string, options *JoinOptions) (*Participant, error)
	LeaveRoom(ctx context.Context, roomID, userID string) error
	GetRoom(ctx context.Context, roomID string) (*Room, error)
	GetRooms(ctx context.Context) ([]*Room, error)
	ForwardStream(ctx context.Context, roomID string, stream *MediaStream) error
	Start() error
	Stop() error
}

type CodecManager interface {
	EncodeFrame(ctx context.Context, frame *VideoFrame, codec string) (*EncodedFrame, error)
	DecodeFrame(ctx context.Context, frame *EncodedFrame) (*VideoFrame, error)
	GetSupportedCodecs() []string
	GetOptimalCodec(resolution string, bitrate int) string
	Start() error
	Stop() error
}

type AIEnhancer interface {
	EnhanceFrame(ctx context.Context, frame *VideoFrame, options *EnhanceOptions) (*VideoFrame, error)
	UpscaleFrame(ctx context.Context, frame *VideoFrame, targetRes string) (*VideoFrame, error)
	DenoiseFrame(ctx context.Context, frame *VideoFrame) (*VideoFrame, error)
	EnhanceFace(ctx context.Context, frame *VideoFrame) (*VideoFrame, error)
	ProcessBackground(ctx context.Context, frame *VideoFrame, bgType string) (*VideoFrame, error)
	Start() error
	Stop() error
}

type WebRTCManager interface {
	CreatePeerConnection(ctx context.Context, config *WebRTCConfig) (*PeerConnection, error)
	HandleOffer(ctx context.Context, pc *PeerConnection, offer *SessionDescription) (*SessionDescription, error)
	HandleAnswer(ctx context.Context, pc *PeerConnection, answer *SessionDescription) error
	AddICECandidate(ctx context.Context, pc *PeerConnection, candidate *ICECandidate) error
	Start() error
	Stop() error
}

type StreamManager interface {
	CreateStream(ctx context.Context, streamID string, config *StreamConfig) (*MediaStream, error)
	PublishStream(ctx context.Context, stream *MediaStream) error
	SubscribeStream(ctx context.Context, streamID, subscriberID string) (*MediaStream, error)
	UnsubscribeStream(ctx context.Context, streamID, subscriberID string) error
	GetStream(ctx context.Context, streamID string) (*MediaStream, error)
	Start() error
	Stop() error
}

// NewVideoManager creates a new video manager
func NewVideoManager(config *VideoConfig) (*VideoManager, error) {
	if config == nil {
		config = DefaultVideoConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &VideoManager{
		config: config,
		metrics: &VideoMetrics{
			StartTime:  time.Now(),
			MinLatency: time.Hour, // Initialize to high value
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize managers
	var err error
	manager.sfuManager, err = NewSFUManager(config.SFUConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SFU manager: %w", err)
	}

	manager.codecManager, err = NewCodecManager(config.CodecConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create codec manager: %w", err)
	}

	manager.aiEnhancer, err = NewAIEnhancer(config.AIEnhanceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create AI enhancer: %w", err)
	}

	manager.webrtcManager, err = NewWebRTCManager(config.WebRTCConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebRTC manager: %w", err)
	}

	manager.streamManager, err = NewStreamManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream manager: %w", err)
	}

	return manager, nil
}

// Start starts the video manager
func (vm *VideoManager) Start() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.isRunning {
		return fmt.Errorf("video manager is already running")
	}

	vm.logger.Info("Starting video manager...")

	// Start all managers
	if err := vm.sfuManager.Start(); err != nil {
		return fmt.Errorf("failed to start SFU manager: %w", err)
	}

	if err := vm.codecManager.Start(); err != nil {
		return fmt.Errorf("failed to start codec manager: %w", err)
	}

	if err := vm.aiEnhancer.Start(); err != nil {
		return fmt.Errorf("failed to start AI enhancer: %w", err)
	}

	if err := vm.webrtcManager.Start(); err != nil {
		return fmt.Errorf("failed to start WebRTC manager: %w", err)
	}

	if err := vm.streamManager.Start(); err != nil {
		return fmt.Errorf("failed to start stream manager: %w", err)
	}

	// Start metrics collection
	if vm.config.EnableMetrics {
		go vm.metricsLoop()
	}

	vm.isRunning = true
	vm.logger.Info("Video manager started successfully")

	return nil
}

// Stop stops the video manager
func (vm *VideoManager) Stop() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if !vm.isRunning {
		return nil
	}

	vm.logger.Info("Stopping video manager...")

	// Cancel context
	vm.cancel()

	// Stop all managers
	if vm.sfuManager != nil {
		vm.sfuManager.Stop()
	}

	if vm.codecManager != nil {
		vm.codecManager.Stop()
	}

	if vm.aiEnhancer != nil {
		vm.aiEnhancer.Stop()
	}

	if vm.webrtcManager != nil {
		vm.webrtcManager.Stop()
	}

	if vm.streamManager != nil {
		vm.streamManager.Stop()
	}

	vm.isRunning = false
	vm.logger.Info("Video manager stopped")

	return nil
}

// GetMetrics returns current video metrics
func (vm *VideoManager) GetMetrics() *VideoMetrics {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Update calculated metrics
	vm.updateCalculatedMetrics()

	// Return a copy
	metrics := *vm.metrics
	return &metrics
}

// GetHealthStatus returns current health status
func (vm *VideoManager) GetHealthStatus() (bool, []string) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	var issues []string

	// Check SFU manager
	if vm.sfuManager == nil {
		issues = append(issues, "SFU manager not initialized")
	}

	// Check codec manager
	if vm.codecManager == nil {
		issues = append(issues, "Codec manager not initialized")
	}

	// Check AI enhancer
	if vm.aiEnhancer == nil {
		issues = append(issues, "AI enhancer not initialized")
	}

	// Check WebRTC manager
	if vm.webrtcManager == nil {
		issues = append(issues, "WebRTC manager not initialized")
	}

	// Check stream manager
	if vm.streamManager == nil {
		issues = append(issues, "Stream manager not initialized")
	}

	isHealthy := len(issues) == 0
	return isHealthy, issues
}

// IsRunning returns whether the video manager is running
func (vm *VideoManager) IsRunning() bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()
	return vm.isRunning
}

// Helper methods
func (vm *VideoManager) updateCalculatedMetrics() {
	// Update calculated metrics
	if vm.metrics.TotalCalls > 0 {
		vm.metrics.SuccessfulCalls = vm.metrics.TotalCalls - vm.metrics.FailedCalls
	}
}

func (vm *VideoManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			vm.collectMetrics()
		case <-vm.ctx.Done():
			return
		}
	}
}

func (vm *VideoManager) collectMetrics() {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vm.metrics.LastUpdated = time.Now()

	// Collect metrics from sub-managers
	if vm.sfuManager != nil {
		// Collect SFU metrics (simplified)
		vm.metrics.ActiveRooms++
	}
}

// Stub implementations for missing managers
func NewSFUManager(config *SFUConfig) (SFUManager, error) {
	return &stubSFUManager{}, nil
}

func NewCodecManager(config *CodecConfig) (CodecManager, error) {
	return &stubCodecManager{}, nil
}

func NewAIEnhancer(config *AIEnhanceConfig) (AIEnhancer, error) {
	return &stubAIEnhancer{}, nil
}

func NewWebRTCManager(config *WebRTCConfig) (WebRTCManager, error) {
	return &stubWebRTCManager{}, nil
}

func NewStreamManager(config *VideoConfig) (StreamManager, error) {
	return &stubStreamManager{}, nil
}

// Stub implementations
type stubSFUManager struct{}

func (s *stubSFUManager) CreateRoom(ctx context.Context, roomID string, config *RoomConfig) (*Room, error) {
	return &Room{ID: roomID}, nil
}
func (s *stubSFUManager) JoinRoom(ctx context.Context, roomID, userID string, options *JoinOptions) (*Participant, error) {
	return &Participant{ID: roomID + "_" + userID, UserID: userID, RoomID: roomID}, nil
}
func (s *stubSFUManager) LeaveRoom(ctx context.Context, roomID, userID string) error { return nil }
func (s *stubSFUManager) GetRoom(ctx context.Context, roomID string) (*Room, error) {
	return &Room{ID: roomID}, nil
}
func (s *stubSFUManager) GetRooms(ctx context.Context) ([]*Room, error) { return []*Room{}, nil }
func (s *stubSFUManager) ForwardStream(ctx context.Context, roomID string, stream *MediaStream) error {
	return nil
}
func (s *stubSFUManager) Start() error { return nil }
func (s *stubSFUManager) Stop() error  { return nil }

type stubCodecManager struct{}

func (s *stubCodecManager) EncodeFrame(ctx context.Context, frame *VideoFrame, codec string) (*EncodedFrame, error) {
	return &EncodedFrame{}, nil
}
func (s *stubCodecManager) DecodeFrame(ctx context.Context, frame *EncodedFrame) (*VideoFrame, error) {
	return &VideoFrame{}, nil
}
func (s *stubCodecManager) GetSupportedCodecs() []string {
	return []string{"AV1", "H266", "H264", "VP9"}
}
func (s *stubCodecManager) GetOptimalCodec(resolution string, bitrate int) string { return "AV1" }
func (s *stubCodecManager) Start() error                                          { return nil }
func (s *stubCodecManager) Stop() error                                           { return nil }

type stubAIEnhancer struct{}

func (s *stubAIEnhancer) EnhanceFrame(ctx context.Context, frame *VideoFrame, options *EnhanceOptions) (*VideoFrame, error) {
	return frame, nil
}
func (s *stubAIEnhancer) UpscaleFrame(ctx context.Context, frame *VideoFrame, targetRes string) (*VideoFrame, error) {
	return frame, nil
}
func (s *stubAIEnhancer) DenoiseFrame(ctx context.Context, frame *VideoFrame) (*VideoFrame, error) {
	return frame, nil
}
func (s *stubAIEnhancer) EnhanceFace(ctx context.Context, frame *VideoFrame) (*VideoFrame, error) {
	return frame, nil
}
func (s *stubAIEnhancer) ProcessBackground(ctx context.Context, frame *VideoFrame, bgType string) (*VideoFrame, error) {
	return frame, nil
}
func (s *stubAIEnhancer) Start() error { return nil }
func (s *stubAIEnhancer) Stop() error  { return nil }

type stubWebRTCManager struct{}

func (s *stubWebRTCManager) CreatePeerConnection(ctx context.Context, config *WebRTCConfig) (*PeerConnection, error) {
	return &PeerConnection{}, nil
}
func (s *stubWebRTCManager) HandleOffer(ctx context.Context, pc *PeerConnection, offer *SessionDescription) (*SessionDescription, error) {
	return &SessionDescription{}, nil
}
func (s *stubWebRTCManager) HandleAnswer(ctx context.Context, pc *PeerConnection, answer *SessionDescription) error {
	return nil
}
func (s *stubWebRTCManager) AddICECandidate(ctx context.Context, pc *PeerConnection, candidate *ICECandidate) error {
	return nil
}
func (s *stubWebRTCManager) Start() error { return nil }
func (s *stubWebRTCManager) Stop() error  { return nil }

type stubStreamManager struct{}

func (s *stubStreamManager) CreateStream(ctx context.Context, streamID string, config *StreamConfig) (*MediaStream, error) {
	return &MediaStream{ID: streamID}, nil
}
func (s *stubStreamManager) PublishStream(ctx context.Context, stream *MediaStream) error { return nil }
func (s *stubStreamManager) SubscribeStream(ctx context.Context, streamID, subscriberID string) (*MediaStream, error) {
	return &MediaStream{ID: streamID}, nil
}
func (s *stubStreamManager) UnsubscribeStream(ctx context.Context, streamID, subscriberID string) error {
	return nil
}
func (s *stubStreamManager) GetStream(ctx context.Context, streamID string) (*MediaStream, error) {
	return &MediaStream{ID: streamID}, nil
}
func (s *stubStreamManager) Start() error { return nil }
func (s *stubStreamManager) Stop() error  { return nil }

// Missing type definitions
type Room struct {
	ID string `json:"id"`
}

type Participant struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	RoomID string `json:"room_id"`
}

type RoomConfig struct {
	MaxParticipants int            `json:"max_participants"`
	EnableRecording bool           `json:"enable_recording"`
	EnableSimulcast bool           `json:"enable_simulcast"`
	EnableSVC       bool           `json:"enable_svc"`
	QualityLevels   []QualityLevel `json:"quality_levels"`
}

type QualityLevel struct {
	Name   string `json:"name"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type JoinOptions struct {
	DisplayName  string                 `json:"display_name"`
	Role         ParticipantRole        `json:"role"`
	PublishVideo bool                   `json:"publish_video"`
	PublishAudio bool                   `json:"publish_audio"`
	SubscribeAll bool                   `json:"subscribe_all"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ParticipantRole string

const (
	ParticipantRoleHost        ParticipantRole = "host"
	ParticipantRoleModerator   ParticipantRole = "moderator"
	ParticipantRoleParticipant ParticipantRole = "participant"
)

type MediaStream struct {
	ID string `json:"id"`
}

type VideoFrame struct {
	ID string `json:"id"`
}

type EncodedFrame struct {
	ID string `json:"id"`
}

type EnhanceOptions struct {
	EnableUpscaling bool `json:"enable_upscaling"`
}

type PeerConnection struct {
	ID string `json:"id"`
}

type SessionDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type ICECandidate struct {
	Foundation string `json:"foundation"`
}

type StreamConfig struct {
	ID string `json:"id"`
}

// DefaultVideoConfig returns default video configuration
func DefaultVideoConfig() *VideoConfig {
	return &VideoConfig{
		Enabled:             true,
		MaxConcurrentCalls:  10000,
		MaxParticipants:     200000,
		CallTimeout:         24 * time.Hour,
		MaxResolution:       "8K",
		MaxFrameRate:        60,
		MaxBitrate:          100, // 100 Mbps for 8K
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
		EnableMetrics:       true,
		MetricsInterval:     30 * time.Second,
	}
}

// Additional missing types for video package compatibility
type WebRTCEngine struct {
	config *WebRTCConfig
	logger logx.Logger
}

type EncoderEngine struct {
	config *EncoderConfig
	logger logx.Logger
}

type EncoderConfig struct {
	Codec     string `json:"codec"`
	Bitrate   int    `json:"bitrate"`
	FrameRate int    `json:"frame_rate"`
}

type QualityManager struct {
	config *QualityConfig
	logger logx.Logger
}

type QualityConfig struct {
	AutoAdjust    bool `json:"auto_adjust"`
	MinQuality    int  `json:"min_quality"`
	MaxQuality    int  `json:"max_quality"`
	TargetBitrate int  `json:"target_bitrate"`
}

// Constructor functions
func NewWebRTCEngine(config *WebRTCConfig) *WebRTCEngine {
	return &WebRTCEngine{
		config: config,
		logger: logx.WithContext(context.Background()),
	}
}

func NewEncoderEngine(config *EncoderConfig) *EncoderEngine {
	return &EncoderEngine{
		config: config,
		logger: logx.WithContext(context.Background()),
	}
}

func NewQualityManager(config *QualityConfig) *QualityManager {
	return &QualityManager{
		config: config,
		logger: logx.WithContext(context.Background()),
	}
}

func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{}
}

// Additional missing types for video package compatibility
type WebRTCConnection struct {
	ID        string    `json:"id"`
	UserID    int64     `json:"user_id"`
	CallID    string    `json:"call_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	LocalSDP  string    `json:"local_sdp"`
	RemoteSDP string    `json:"remote_sdp"`
}
