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

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/video/internal/config"
	"github.com/teamgram/teamgram-server/app/bff/video/internal/server"
	"github.com/teamgram/teamgram-server/app/bff/video/internal/svc"
	"github.com/teamgram/teamgram-server/pkg/video/e2ee"
	"github.com/teamgram/teamgram-server/pkg/video/security"
	"github.com/teamgram/teamgram-server/pkg/video/tgcalls"
	"github.com/teamgram/teamgram-server/pkg/video/webrtc"
	"github.com/zeromicro/go-zero/core/logx"
)

// VideoBFFService represents the video BFF service
type VideoBFFService struct {
	mutex           sync.RWMutex
	config          *config.Config
	server          *server.Server
	serviceContext  *svc.ServiceContext
	webrtcManager   *webrtc.WebRTCManager
	tgCallsManager  *tgcalls.TGVideoCallManager
	e2eeManager     *e2ee.E2EEManager
	securityManager *security.SecurityManager
	activeCalls     map[int64]*ActiveCall
	callSessions    map[string]*CallSession
	metrics         *VideoServiceMetrics
	logger          logx.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
}

// ActiveCall represents an active video call
type ActiveCall struct {
	ID               int64                           `json:"id"`
	AccessHash       int64                           `json:"access_hash"`
	AdminID          int64                           `json:"admin_id"`
	ParticipantID    int64                           `json:"participant_id"`
	GAHash           []byte                          `json:"ga_hash"`
	GB               []byte                          `json:"gb"`
	KeyFingerprint   int64                           `json:"key_fingerprint"`
	Protocol         *mtproto.PhoneCallProtocol      `json:"protocol"`
	Connections      []*mtproto.PhoneConnection      `json:"connections"`
	P2PAllowed       bool                            `json:"p2p_allowed"`
	Video            bool                            `json:"video"`
	State            CallState                       `json:"state"`
	Date             int32                           `json:"date"`
	StartDate        int32                           `json:"start_date"`
	Duration         int32                           `json:"duration"`
	Reason           *mtproto.PhoneCallDiscardReason `json:"reason,omitempty"`
	NeedRating       bool                            `json:"need_rating"`
	NeedDebug        bool                            `json:"need_debug"`
	WebRTCConnection *webrtc.EnhancedPeerConnection  `json:"-"`
	E2EESession      *e2ee.E2EESession               `json:"-"`
	SecurityContext  *security.SecurityContext       `json:"-"`
	CreatedAt        time.Time                       `json:"created_at"`
	UpdatedAt        time.Time                       `json:"updated_at"`
	mutex            sync.RWMutex
}

// CallSession represents a call session with WebRTC details
type CallSession struct {
	CallID             int64                       `json:"call_id"`
	SessionID          string                      `json:"session_id"`
	LocalSDP           string                      `json:"local_sdp"`
	RemoteSDP          string                      `json:"remote_sdp"`
	ICECandidates      []*webrtc.ICECandidate      `json:"ice_candidates"`
	ConnectionState    webrtc.PeerConnectionState  `json:"connection_state"`
	ICEConnectionState webrtc.ICEConnectionState   `json:"ice_connection_state"`
	SignalingState     webrtc.SignalingState       `json:"signaling_state"`
	MediaStreams       map[string]*MediaStreamInfo `json:"media_streams"`
	DataChannels       map[string]*DataChannelInfo `json:"data_channels"`
	QualityMetrics     *CallQualityMetrics         `json:"quality_metrics"`
	CreatedAt          time.Time                   `json:"created_at"`
	LastActivity       time.Time                   `json:"last_activity"`
	mutex              sync.RWMutex
}

// MediaStreamInfo represents media stream information
type MediaStreamInfo struct {
	StreamID        string        `json:"stream_id"`
	TrackID         string        `json:"track_id"`
	Kind            string        `json:"kind"` // "video" or "audio"
	Codec           string        `json:"codec"`
	Resolution      *Resolution   `json:"resolution,omitempty"`
	FrameRate       int           `json:"frame_rate,omitempty"`
	Bitrate         int           `json:"bitrate"`
	PacketsSent     int64         `json:"packets_sent"`
	PacketsReceived int64         `json:"packets_received"`
	BytesSent       int64         `json:"bytes_sent"`
	BytesReceived   int64         `json:"bytes_received"`
	PacketsLost     int64         `json:"packets_lost"`
	Jitter          float64       `json:"jitter"`
	RTT             time.Duration `json:"rtt"`
	QualityScore    float64       `json:"quality_score"`
	LastUpdated     time.Time     `json:"last_updated"`
}

// DataChannelInfo represents data channel information
type DataChannelInfo struct {
	Label            string    `json:"label"`
	Protocol         string    `json:"protocol"`
	State            string    `json:"state"`
	MessagesSent     int64     `json:"messages_sent"`
	MessagesReceived int64     `json:"messages_received"`
	BytesSent        int64     `json:"bytes_sent"`
	BytesReceived    int64     `json:"bytes_received"`
	LastActivity     time.Time `json:"last_activity"`
}

// CallQualityMetrics represents call quality metrics
type CallQualityMetrics struct {
	OverallQuality float64       `json:"overall_quality"`
	VideoQuality   float64       `json:"video_quality"`
	AudioQuality   float64       `json:"audio_quality"`
	NetworkQuality string        `json:"network_quality"`
	Latency        time.Duration `json:"latency"`
	PacketLossRate float64       `json:"packet_loss_rate"`
	Jitter         time.Duration `json:"jitter"`
	Bandwidth      int64         `json:"bandwidth"`
	CPU_Usage      float64       `json:"cpu_usage"`
	Memory_Usage   int64         `json:"memory_usage"`
	LastUpdated    time.Time     `json:"last_updated"`
}

// Resolution represents video resolution
type Resolution struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// VideoServiceMetrics represents service metrics
type VideoServiceMetrics struct {
	TotalCalls          int64         `json:"total_calls"`
	ActiveCalls         int64         `json:"active_calls"`
	SuccessfulCalls     int64         `json:"successful_calls"`
	FailedCalls         int64         `json:"failed_calls"`
	AverageCallDuration time.Duration `json:"average_call_duration"`
	AverageSetupTime    time.Duration `json:"average_setup_time"`
	P2PConnectionRate   float64       `json:"p2p_connection_rate"`
	VideoCallRate       float64       `json:"video_call_rate"`
	E2EERate            float64       `json:"e2ee_rate"`
	QualityScore        float64       `json:"quality_score"`
	LastUpdated         time.Time     `json:"last_updated"`
}

// CallState represents the state of a call
type CallState string

const (
	CallStateWaiting   CallState = "waiting"
	CallStateRinging   CallState = "ringing"
	CallStateRequested CallState = "requested"
	CallStateAccepted  CallState = "accepted"
	CallStateConfirmed CallState = "confirmed"
	CallStateReady     CallState = "ready"
	CallStateActive    CallState = "active"
	CallStateEnded     CallState = "ended"
	CallStateDiscarded CallState = "discarded"
	CallStateBusy      CallState = "busy"
	CallStateMissed    CallState = "missed"
)

// NewVideoBFFService creates a new video BFF service
func NewVideoBFFService(c *config.Config) (*VideoBFFService, error) {
	ctx, cancel := context.WithCancel(context.Background())

	service := &VideoBFFService{
		config:       c,
		activeCalls:  make(map[int64]*ActiveCall),
		callSessions: make(map[string]*CallSession),
		metrics: &VideoServiceMetrics{
			LastUpdated: time.Now(),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize security manager
	securityManager, err := security.NewSecurityManager(security.DefaultSecurityConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create security manager: %w", err)
	}
	service.securityManager = securityManager

	// Initialize E2EE manager
	e2eeManager, err := e2ee.NewE2EEManager(e2ee.DefaultE2EEConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create E2EE manager: %w", err)
	}
	service.e2eeManager = e2eeManager

	// Initialize WebRTC manager
	webrtcManager, err := webrtc.NewWebRTCManager(webrtc.DefaultWebRTCConfig(), e2eeManager, securityManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebRTC manager: %w", err)
	}
	service.webrtcManager = webrtcManager

	// Initialize TG calls manager
	tgCallsManager, err := tgcalls.NewTGVideoCallManager(tgcalls.DefaultTGCallsConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create TG calls manager: %w", err)
	}
	service.tgCallsManager = tgCallsManager

	// Create service context
	service.serviceContext = svc.NewServiceContext(c)

	// Create server
	service.server = server.NewServer(service.serviceContext)

	return service, nil
}

// Start starts the video BFF service
func (s *VideoBFFService) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isRunning {
		return fmt.Errorf("video BFF service is already running")
	}

	s.logger.Info("Starting video BFF service...")

	// Start security manager
	if err := s.securityManager.Start(); err != nil {
		return fmt.Errorf("failed to start security manager: %w", err)
	}

	// Start E2EE manager
	if err := s.e2eeManager.Start(); err != nil {
		return fmt.Errorf("failed to start E2EE manager: %w", err)
	}

	// Start WebRTC manager
	if err := s.webrtcManager.Start(); err != nil {
		return fmt.Errorf("failed to start WebRTC manager: %w", err)
	}

	// Start TG calls manager
	if err := s.tgCallsManager.Start(); err != nil {
		return fmt.Errorf("failed to start TG calls manager: %w", err)
	}

	// Start metrics collection
	go s.metricsLoop()

	// Start call cleanup
	go s.callCleanupLoop()

	s.isRunning = true
	s.logger.Info("Video BFF service started successfully")

	return nil
}

// Stop stops the video BFF service
func (s *VideoBFFService) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return nil
	}

	s.logger.Info("Stopping video BFF service...")

	// Cancel context
	s.cancel()

	// Stop managers
	if s.tgCallsManager != nil {
		s.tgCallsManager.Stop()
	}

	if s.webrtcManager != nil {
		s.webrtcManager.Stop()
	}

	if s.e2eeManager != nil {
		s.e2eeManager.Stop()
	}

	if s.securityManager != nil {
		s.securityManager.Stop()
	}

	// Clean up active calls
	for _, call := range s.activeCalls {
		s.cleanupCall(call)
	}

	s.isRunning = false
	s.logger.Info("Video BFF service stopped")

	return nil
}

// GetServiceContext returns the service context
func (s *VideoBFFService) GetServiceContext() *svc.ServiceContext {
	return s.serviceContext
}

// GetServer returns the server
func (s *VideoBFFService) GetServer() *server.Server {
	return s.server
}

// GetWebRTCManager returns the WebRTC manager
func (s *VideoBFFService) GetWebRTCManager() *webrtc.WebRTCManager {
	return s.webrtcManager
}

// GetTGCallsManager returns the TG calls manager
func (s *VideoBFFService) GetTGCallsManager() *tgcalls.TGVideoCallManager {
	return s.tgCallsManager
}

// GetE2EEManager returns the E2EE manager
func (s *VideoBFFService) GetE2EEManager() *e2ee.E2EEManager {
	return s.e2eeManager
}

// GetSecurityManager returns the security manager
func (s *VideoBFFService) GetSecurityManager() *security.SecurityManager {
	return s.securityManager
}

// metricsLoop runs the metrics collection loop
func (s *VideoBFFService) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.updateMetrics()
		}
	}
}

// callCleanupLoop runs the call cleanup loop
func (s *VideoBFFService) callCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredCalls()
		}
	}
}

// updateMetrics updates service metrics
func (s *VideoBFFService) updateMetrics() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	s.metrics.ActiveCalls = int64(len(s.activeCalls))
	s.metrics.LastUpdated = time.Now()

	// Calculate additional metrics
	var totalDuration time.Duration
	var setupTimes []time.Duration
	p2pConnections := 0
	videoCalls := 0
	e2eeCalls := 0

	for _, call := range s.activeCalls {
		call.mutex.RLock()
		if call.State == CallStateActive && call.StartDate > 0 {
			duration := time.Duration(time.Now().Unix()-int64(call.StartDate)) * time.Second
			totalDuration += duration

			// Calculate setup time (time from call creation to start)
			if call.Date > 0 && call.StartDate > call.Date {
				setupTime := time.Duration(call.StartDate-call.Date) * time.Second
				setupTimes = append(setupTimes, setupTime)
			}
		}

		if call.P2PAllowed {
			p2pConnections++
		}

		if call.Video {
			videoCalls++
		}

		if call.E2EESession != nil {
			e2eeCalls++
		}
		call.mutex.RUnlock()
	}

	if len(s.activeCalls) > 0 {
		s.metrics.AverageCallDuration = totalDuration / time.Duration(len(s.activeCalls))
		s.metrics.P2PConnectionRate = float64(p2pConnections) / float64(len(s.activeCalls)) * 100
		s.metrics.VideoCallRate = float64(videoCalls) / float64(len(s.activeCalls)) * 100
		s.metrics.E2EERate = float64(e2eeCalls) / float64(len(s.activeCalls)) * 100
	}

	// Calculate average setup time
	if len(setupTimes) > 0 {
		var totalSetupTime time.Duration
		for _, setupTime := range setupTimes {
			totalSetupTime += setupTime
		}
		s.metrics.AverageSetupTime = totalSetupTime / time.Duration(len(setupTimes))
	}
}

// cleanupExpiredCalls cleans up expired calls
func (s *VideoBFFService) cleanupExpiredCalls() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	expiredCalls := make([]*ActiveCall, 0)

	for _, call := range s.activeCalls {
		call.mutex.RLock()
		if call.State == CallStateEnded || call.State == CallStateDiscarded {
			if now.Sub(call.UpdatedAt) > 5*time.Minute {
				expiredCalls = append(expiredCalls, call)
			}
		} else if now.Sub(call.CreatedAt) > 30*time.Minute {
			// Cleanup calls that have been active for too long
			expiredCalls = append(expiredCalls, call)
		}
		call.mutex.RUnlock()
	}

	for _, call := range expiredCalls {
		s.cleanupCall(call)
		delete(s.activeCalls, call.ID)
	}

	if len(expiredCalls) > 0 {
		s.logger.Infof("Cleaned up %d expired calls", len(expiredCalls))
	}
}

// cleanupCall cleans up a single call
func (s *VideoBFFService) cleanupCall(call *ActiveCall) {
	call.mutex.Lock()
	defer call.mutex.Unlock()

	// Close WebRTC connection
	if call.WebRTCConnection != nil {
		call.WebRTCConnection.Close()
	}

	// Clean up E2EE session
	if call.E2EESession != nil {
		s.e2eeManager.CloseSession(call.E2EESession.ID)
	}

	// Clean up call session
	if session, exists := s.callSessions[fmt.Sprintf("%d", call.ID)]; exists {
		session.mutex.Lock()
		// Clean up session resources
		session.mutex.Unlock()
		delete(s.callSessions, fmt.Sprintf("%d", call.ID))
	}
}
