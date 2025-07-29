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

package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/teamgram/teamgram-server/app/bff/video/internal/config"
	"github.com/teamgram/teamgram-server/pkg/video"
	"github.com/zeromicro/go-zero/core/logx"
)

// VideoService provides 8K video calling capabilities
type VideoService struct {
	mutex           sync.RWMutex
	config          *config.VideoServiceConfig
	videoManager    *video.VideoManager
	callManager     *CallManager
	participantMgr  *ParticipantManager
	streamManager   *StreamManager
	metricsCollector *MetricsCollector
	healthChecker   *HealthChecker
	logger          logx.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
}

// CallManager manages video calls
type CallManager struct {
	calls           map[string]*VideoCall
	callsByUser     map[int64][]string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// ParticipantManager manages call participants
type ParticipantManager struct {
	participants    map[string]*CallParticipant
	participantsByCall map[string][]string
	participantsByUser map[int64][]string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// StreamManager manages media streams
type StreamManager struct {
	streams         map[string]*MediaStream
	streamsByCall   map[string][]string
	streamsByUser   map[int64][]string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// MetricsCollector collects and aggregates metrics
type MetricsCollector struct {
	metrics         *VideoServiceMetrics
	collectors      []MetricCollector
	interval        time.Duration
	mutex           sync.RWMutex
	logger          logx.Logger
}

// HealthChecker monitors service health
type HealthChecker struct {
	checks          []HealthCheck
	interval        time.Duration
	lastCheck       time.Time
	isHealthy       bool
	issues          []string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// VideoCall represents an active video call
type VideoCall struct {
	ID              string                 `json:"id"`
	ChatID          int64                  `json:"chat_id"`
	CreatorID       int64                  `json:"creator_id"`
	Title           string                 `json:"title"`
	State           CallState              `json:"state"`
	Type            CallType               `json:"type"`
	Quality         CallQuality            `json:"quality"`
	MaxParticipants int                    `json:"max_participants"`
	Participants    map[string]*CallParticipant `json:"participants"`
	Streams         map[string]*MediaStream `json:"streams"`
	Config          *CallConfig            `json:"config"`
	Stats           *CallStats             `json:"stats"`
	CreatedAt       time.Time              `json:"created_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	EndedAt         *time.Time             `json:"ended_at,omitempty"`
	LastActivity    time.Time              `json:"last_activity"`
	Metadata        map[string]interface{} `json:"metadata"`
	mutex           sync.RWMutex
}

// CallParticipant represents a participant in a video call
type CallParticipant struct {
	ID              string                 `json:"id"`
	UserID          int64                  `json:"user_id"`
	CallID          string                 `json:"call_id"`
	DisplayName     string                 `json:"display_name"`
	Role            ParticipantRole        `json:"role"`
	State           ParticipantState       `json:"state"`
	JoinedAt        time.Time              `json:"joined_at"`
	LeftAt          *time.Time             `json:"left_at,omitempty"`
	LastActivity    time.Time              `json:"last_activity"`
	Connection      *ConnectionInfo        `json:"connection"`
	MediaSettings   *MediaSettings         `json:"media_settings"`
	Quality         *ParticipantQuality    `json:"quality"`
	Stats           *ParticipantStats      `json:"stats"`
	Metadata        map[string]interface{} `json:"metadata"`
	mutex           sync.RWMutex
}

// MediaStream represents a media stream
type MediaStream struct {
	ID              string                 `json:"id"`
	ParticipantID   string                 `json:"participant_id"`
	CallID          string                 `json:"call_id"`
	Type            StreamType             `json:"type"`
	State           StreamState            `json:"state"`
	Codec           string                 `json:"codec"`
	Resolution      Resolution             `json:"resolution"`
	FrameRate       int                    `json:"frame_rate"`
	Bitrate         int                    `json:"bitrate"`
	Quality         StreamQuality          `json:"quality"`
	Stats           *StreamStats           `json:"stats"`
	CreatedAt       time.Time              `json:"created_at"`
	LastActivity    time.Time              `json:"last_activity"`
	Metadata        map[string]interface{} `json:"metadata"`
	mutex           sync.RWMutex
}

// VideoServiceMetrics tracks service performance
type VideoServiceMetrics struct {
	// Call metrics
	TotalCalls          int64         `json:"total_calls"`
	ActiveCalls         int64         `json:"active_calls"`
	CompletedCalls      int64         `json:"completed_calls"`
	FailedCalls         int64         `json:"failed_calls"`
	
	// Participant metrics
	TotalParticipants   int64         `json:"total_participants"`
	ActiveParticipants  int64         `json:"active_participants"`
	MaxParticipants     int64         `json:"max_participants"`
	
	// Quality metrics
	AverageLatency      time.Duration `json:"average_latency"`
	MaxLatency          time.Duration `json:"max_latency"`
	MinLatency          time.Duration `json:"min_latency"`
	PacketLossRate      float64       `json:"packet_loss_rate"`
	JitterRate          float64       `json:"jitter_rate"`
	
	// Resolution metrics
	Calls8K             int64         `json:"calls_8k"`
	Calls4K             int64         `json:"calls_4k"`
	Calls1080p          int64         `json:"calls_1080p"`
	CallsHD             int64         `json:"calls_hd"`
	
	// Performance metrics
	CPUUsage            float64       `json:"cpu_usage"`
	MemoryUsage         int64         `json:"memory_usage"`
	NetworkBandwidth    int64         `json:"network_bandwidth"`
	
	// Error metrics
	ConnectionErrors    int64         `json:"connection_errors"`
	StreamingErrors     int64         `json:"streaming_errors"`
	CodecErrors         int64         `json:"codec_errors"`
	
	// Timestamps
	LastUpdated         time.Time     `json:"last_updated"`
	StartTime           time.Time     `json:"start_time"`
}

// Enums and types
type CallState string
const (
	CallStateWaiting    CallState = "waiting"
	CallStateActive     CallState = "active"
	CallStatePaused     CallState = "paused"
	CallStateEnded      CallState = "ended"
	CallStateFailed     CallState = "failed"
)

type CallType string
const (
	CallTypePrivate     CallType = "private"
	CallTypeGroup       CallType = "group"
	CallTypeBroadcast   CallType = "broadcast"
	CallTypeConference  CallType = "conference"
)

type CallQuality string
const (
	CallQuality8K       CallQuality = "8K"
	CallQuality4K       CallQuality = "4K"
	CallQuality1080p    CallQuality = "1080p"
	CallQuality720p     CallQuality = "720p"
	CallQualityAuto     CallQuality = "auto"
)

type ParticipantRole string
const (
	ParticipantRoleHost        ParticipantRole = "host"
	ParticipantRoleModerator   ParticipantRole = "moderator"
	ParticipantRoleParticipant ParticipantRole = "participant"
	ParticipantRoleObserver    ParticipantRole = "observer"
)

type ParticipantState string
const (
	ParticipantStateJoining    ParticipantState = "joining"
	ParticipantStateActive     ParticipantState = "active"
	ParticipantStateInactive   ParticipantState = "inactive"
	ParticipantStateMuted      ParticipantState = "muted"
	ParticipantStateLeft       ParticipantState = "left"
)

type StreamType string
const (
	StreamTypeVideo     StreamType = "video"
	StreamTypeAudio     StreamType = "audio"
	StreamTypeScreen    StreamType = "screen"
	StreamTypeData      StreamType = "data"
)

type StreamState string
const (
	StreamStateActive   StreamState = "active"
	StreamStateInactive StreamState = "inactive"
	StreamStatePaused   StreamState = "paused"
	StreamStateEnded    StreamState = "ended"
)

type StreamQuality string
const (
	StreamQualityUltra  StreamQuality = "ultra"  // 8K
	StreamQualityHigh   StreamQuality = "high"   // 4K
	StreamQualityMedium StreamQuality = "medium" // 1080p
	StreamQualityLow    StreamQuality = "low"    // 720p
	StreamQualityAuto   StreamQuality = "auto"
)

// Configuration types
type CallConfig struct {
	MaxParticipants     int                    `json:"max_participants"`
	EnableRecording     bool                   `json:"enable_recording"`
	EnableScreenShare   bool                   `json:"enable_screen_share"`
	EnableChat          bool                   `json:"enable_chat"`
	EnableAIEnhancement bool                   `json:"enable_ai_enhancement"`
	QualitySettings     *QualitySettings       `json:"quality_settings"`
	SecuritySettings    *SecuritySettings      `json:"security_settings"`
	Metadata            map[string]interface{} `json:"metadata"`
}

type QualitySettings struct {
	MaxResolution       Resolution `json:"max_resolution"`
	MaxFrameRate        int        `json:"max_frame_rate"`
	MaxBitrate          int        `json:"max_bitrate"`
	AdaptiveQuality     bool       `json:"adaptive_quality"`
	EnableSimulcast     bool       `json:"enable_simulcast"`
	EnableSVC           bool       `json:"enable_svc"`
}

type SecuritySettings struct {
	RequireAuth         bool   `json:"require_auth"`
	EnableEncryption    bool   `json:"enable_encryption"`
	AllowedDomains      []string `json:"allowed_domains"`
	MaxCallDuration     time.Duration `json:"max_call_duration"`
}

type Resolution struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type ConnectionInfo struct {
	PeerConnectionID    string        `json:"peer_connection_id"`
	ICEState            string        `json:"ice_state"`
	DTLSState           string        `json:"dtls_state"`
	SignalingState      string        `json:"signaling_state"`
	ConnectionQuality   float64       `json:"connection_quality"`
	RTT                 time.Duration `json:"rtt"`
	PacketLossRate      float64       `json:"packet_loss_rate"`
	Jitter              time.Duration `json:"jitter"`
	LastUpdated         time.Time     `json:"last_updated"`
}

type MediaSettings struct {
	VideoEnabled        bool          `json:"video_enabled"`
	AudioEnabled        bool          `json:"audio_enabled"`
	ScreenShareEnabled  bool          `json:"screen_share_enabled"`
	VideoResolution     Resolution    `json:"video_resolution"`
	VideoFrameRate      int           `json:"video_frame_rate"`
	VideoBitrate        int           `json:"video_bitrate"`
	AudioBitrate        int           `json:"audio_bitrate"`
	VideoCodec          string        `json:"video_codec"`
	AudioCodec          string        `json:"audio_codec"`
}

type ParticipantQuality struct {
	VideoQuality        StreamQuality `json:"video_quality"`
	AudioQuality        string        `json:"audio_quality"`
	NetworkQuality      float64       `json:"network_quality"`
	OverallScore        float64       `json:"overall_score"`
	LastUpdated         time.Time     `json:"last_updated"`
}

type ParticipantStats struct {
	BytesSent           int64         `json:"bytes_sent"`
	BytesReceived       int64         `json:"bytes_received"`
	PacketsSent         int64         `json:"packets_sent"`
	PacketsReceived     int64         `json:"packets_received"`
	PacketsLost         int64         `json:"packets_lost"`
	FramesSent          int64         `json:"frames_sent"`
	FramesReceived      int64         `json:"frames_received"`
	FramesDropped       int64         `json:"frames_dropped"`
	CallDuration        time.Duration `json:"call_duration"`
	LastUpdated         time.Time     `json:"last_updated"`
}

type CallStats struct {
	TotalParticipants   int           `json:"total_participants"`
	ActiveParticipants  int           `json:"active_participants"`
	TotalStreams        int           `json:"total_streams"`
	ActiveStreams       int           `json:"active_streams"`
	TotalBandwidth      int64         `json:"total_bandwidth"`
	AverageLatency      time.Duration `json:"average_latency"`
	PacketLossRate      float64       `json:"packet_loss_rate"`
	CallDuration        time.Duration `json:"call_duration"`
	LastUpdated         time.Time     `json:"last_updated"`
}

type StreamStats struct {
	BytesSent           int64         `json:"bytes_sent"`
	BytesReceived       int64         `json:"bytes_received"`
	PacketsSent         int64         `json:"packets_sent"`
	PacketsReceived     int64         `json:"packets_received"`
	PacketsLost         int64         `json:"packets_lost"`
	FramesSent          int64         `json:"frames_sent"`
	FramesReceived      int64         `json:"frames_received"`
	FramesDropped       int64         `json:"frames_dropped"`
	Bitrate             int           `json:"bitrate"`
	FrameRate           int           `json:"frame_rate"`
	Resolution          Resolution    `json:"resolution"`
	LastUpdated         time.Time     `json:"last_updated"`
}

// Interface types
type MetricCollector interface {
	CollectMetrics() map[string]interface{}
	GetName() string
}

type HealthCheck interface {
	Check() (bool, string)
	GetName() string
}

// NewVideoService creates a new video service
func NewVideoService(config *config.VideoServiceConfig) (*VideoService, error) {
	if config == nil {
		return nil, fmt.Errorf("video service config is required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	service := &VideoService{
		config: config,
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize video manager
	videoConfig := convertToVideoConfig(config)
	var err error
	service.videoManager, err = video.NewVideoManager(videoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create video manager: %w", err)
	}
	
	// Initialize call manager
	service.callManager = NewCallManager()
	
	// Initialize participant manager
	service.participantMgr = NewParticipantManager()
	
	// Initialize stream manager
	service.streamManager = NewStreamManager()
	
	// Initialize metrics collector
	service.metricsCollector = NewMetricsCollector(config.MetricsInterval)
	
	// Initialize health checker
	service.healthChecker = NewHealthChecker(config.HealthCheckInterval)
	
	return service, nil
}

// Start starts the video service
func (vs *VideoService) Start() error {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	
	if vs.isRunning {
		return fmt.Errorf("video service is already running")
	}
	
	vs.logger.Info("Starting video service...")
	
	// Start video manager
	if err := vs.videoManager.Start(); err != nil {
		return fmt.Errorf("failed to start video manager: %w", err)
	}
	
	// Start metrics collection
	if vs.config.EnableMetrics {
		go vs.metricsCollector.Start(vs.ctx)
	}
	
	// Start health checking
	go vs.healthChecker.Start(vs.ctx)
	
	vs.isRunning = true
	vs.logger.Info("Video service started successfully")
	
	return nil
}

// Stop stops the video service
func (vs *VideoService) Stop() error {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	
	if !vs.isRunning {
		return nil
	}
	
	vs.logger.Info("Stopping video service...")
	
	// Cancel context
	vs.cancel()
	
	// Stop video manager
	if vs.videoManager != nil {
		vs.videoManager.Stop()
	}
	
	vs.isRunning = false
	vs.logger.Info("Video service stopped")
	
	return nil
}

// Helper functions

func convertToVideoConfig(config *config.VideoServiceConfig) *video.VideoConfig {
	return &video.VideoConfig{
		Enabled:             config.Enabled,
		MaxConcurrentCalls:  config.MaxConcurrentCalls,
		MaxParticipants:     config.MaxParticipants,
		CallTimeout:         config.CallTimeout,
		MaxResolution:       config.MaxResolution,
		MaxFrameRate:        config.MaxFrameRate,
		MaxBitrate:          config.MaxBitrate,
		AdaptiveBitrate:     config.AdaptiveBitrate,
		EnableGPU:           config.EnableGPU,
		EnableHardwareCodec: config.EnableHardwareCodec,
		MaxCPUUsage:         config.MaxCPUUsage,
		MaxMemoryUsage:      config.MaxMemoryUsage,
		EnableP2P:           config.EnableP2P,
		EnableRelay:         config.EnableRelay,
		TargetLatency:       config.TargetLatency,
		MaxLatency:          config.MaxLatency,
		EnableJitterBuffer:  config.EnableJitterBuffer,
		EnableFEC:           config.EnableFEC,
		EnableMetrics:       config.EnableMetrics,
		MetricsInterval:     config.MetricsInterval,
	}
}

func NewCallManager() *CallManager {
	return &CallManager{
		calls:       make(map[string]*VideoCall),
		callsByUser: make(map[int64][]string),
	}
}

func NewParticipantManager() *ParticipantManager {
	return &ParticipantManager{
		participants:       make(map[string]*CallParticipant),
		participantsByCall: make(map[string][]string),
		participantsByUser: make(map[int64][]string),
	}
}

func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams:       make(map[string]*MediaStream),
		streamsByCall: make(map[string][]string),
		streamsByUser: make(map[int64][]string),
	}
}

func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		metrics: &VideoServiceMetrics{
			StartTime:   time.Now(),
			MinLatency:  time.Hour, // Initialize to high value
		},
		collectors: make([]MetricCollector, 0),
		interval:   interval,
	}
}

func (mc *MetricsCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(mc.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mc.collectMetrics()
		case <-ctx.Done():
			return
		}
	}
}

func (mc *MetricsCollector) collectMetrics() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	mc.metrics.LastUpdated = time.Now()
	
	// Collect metrics from all collectors
	for _, collector := range mc.collectors {
		metrics := collector.CollectMetrics()
		// Process collected metrics
		_ = metrics
	}
}

func NewHealthChecker(interval time.Duration) *HealthChecker {
	return &HealthChecker{
		checks:    make([]HealthCheck, 0),
		interval:  interval,
		isHealthy: true,
		issues:    make([]string, 0),
	}
}

func (hc *HealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			hc.performHealthChecks()
		case <-ctx.Done():
			return
		}
	}
}

func (hc *HealthChecker) performHealthChecks() {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	
	hc.lastCheck = time.Now()
	hc.issues = hc.issues[:0] // Clear issues
	
	allHealthy := true
	for _, check := range hc.checks {
		healthy, issue := check.Check()
		if !healthy {
			allHealthy = false
			hc.issues = append(hc.issues, fmt.Sprintf("%s: %s", check.GetName(), issue))
		}
	}
	
	hc.isHealthy = allHealthy
}
