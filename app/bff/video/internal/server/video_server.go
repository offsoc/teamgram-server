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

package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/teamgram/teamgram-server/app/bff/video/internal/config"
	"github.com/teamgram/teamgram-server/app/bff/video/internal/core"
	"github.com/zeromicro/go-zero/core/logx"
)

// VideoServer implements the video BFF service
type VideoServer struct {
	mutex        sync.RWMutex
	config       *config.Config
	videoService *core.VideoService
	callManager  *CallManager
	sessionMgr   *SessionManager
	logger       logx.Logger
	isRunning    bool
}

// CallManager manages active video calls
type CallManager struct {
	activeCalls     map[string]*ActiveCall
	callsByUser     map[int64][]string
	callsByChat     map[int64]string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// SessionManager manages user sessions
type SessionManager struct {
	sessions        map[string]*UserSession
	sessionsByUser  map[int64]string
	mutex           sync.RWMutex
	logger          logx.Logger
}

// ActiveCall represents an active video call
type ActiveCall struct {
	ID              string                 `json:"id"`
	ChatID          int64                  `json:"chat_id"`
	CreatorID       int64                  `json:"creator_id"`
	Title           string                 `json:"title"`
	State           CallState              `json:"state"`
	Type            CallType               `json:"type"`
	Quality         CallQuality            `json:"quality"`
	Participants    map[int64]*Participant `json:"participants"`
	Config          *CallConfig            `json:"config"`
	Stats           *CallStats             `json:"stats"`
	CreatedAt       time.Time              `json:"created_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	EndedAt         *time.Time             `json:"ended_at,omitempty"`
	LastActivity    time.Time              `json:"last_activity"`
	mutex           sync.RWMutex
}

// Participant represents a call participant
type Participant struct {
	UserID          int64                  `json:"user_id"`
	DisplayName     string                 `json:"display_name"`
	Role            ParticipantRole        `json:"role"`
	State           ParticipantState       `json:"state"`
	JoinedAt        time.Time              `json:"joined_at"`
	LeftAt          *time.Time             `json:"left_at,omitempty"`
	MediaSettings   *MediaSettings         `json:"media_settings"`
	Quality         *ParticipantQuality    `json:"quality"`
	Connection      *ConnectionInfo        `json:"connection"`
	LastActivity    time.Time              `json:"last_activity"`
	mutex           sync.RWMutex
}

// UserSession represents a user session
type UserSession struct {
	SessionID       string                 `json:"session_id"`
	UserID          int64                  `json:"user_id"`
	DeviceID        string                 `json:"device_id"`
	Platform        string                 `json:"platform"`
	Capabilities    *DeviceCapabilities    `json:"capabilities"`
	State           SessionState           `json:"state"`
	CreatedAt       time.Time              `json:"created_at"`
	LastActivity    time.Time              `json:"last_activity"`
	Metadata        map[string]interface{} `json:"metadata"`
	mutex           sync.RWMutex
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

type SessionState string
const (
	SessionStateActive      SessionState = "active"
	SessionStateInactive    SessionState = "inactive"
	SessionStateDisconnected SessionState = "disconnected"
)

// Configuration and info types
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
	RequireAuth         bool          `json:"require_auth"`
	EnableEncryption    bool          `json:"enable_encryption"`
	AllowedDomains      []string      `json:"allowed_domains"`
	MaxCallDuration     time.Duration `json:"max_call_duration"`
}

type Resolution struct {
	Width  int `json:"width"`
	Height int `json:"height"`
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
	VideoQuality        CallQuality `json:"video_quality"`
	AudioQuality        string      `json:"audio_quality"`
	NetworkQuality      float64     `json:"network_quality"`
	OverallScore        float64     `json:"overall_score"`
	LastUpdated         time.Time   `json:"last_updated"`
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

type DeviceCapabilities struct {
	MaxResolution       Resolution `json:"max_resolution"`
	MaxFrameRate        int        `json:"max_frame_rate"`
	SupportedCodecs     []string   `json:"supported_codecs"`
	HardwareAcceleration bool      `json:"hardware_acceleration"`
	AIEnhancement       bool       `json:"ai_enhancement"`
	Simulcast           bool       `json:"simulcast"`
	SVC                 bool       `json:"svc"`
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

// Request and response types
type CreateCallRequest struct {
	ChatID          int64                  `json:"chat_id"`
	Title           string                 `json:"title"`
	Type            CallType               `json:"type"`
	Quality         CallQuality            `json:"quality"`
	Config          *CallConfig            `json:"config"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type CreateCallResponse struct {
	Call            *ActiveCall `json:"call"`
	JoinToken       string      `json:"join_token"`
	SignalingURL    string      `json:"signaling_url"`
	ICEServers      []ICEServer `json:"ice_servers"`
}

type JoinCallRequest struct {
	CallID          string                 `json:"call_id"`
	UserID          int64                  `json:"user_id"`
	DisplayName     string                 `json:"display_name"`
	MediaSettings   *MediaSettings         `json:"media_settings"`
	Capabilities    *DeviceCapabilities    `json:"capabilities"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type JoinCallResponse struct {
	Participant     *Participant    `json:"participant"`
	Call            *ActiveCall     `json:"call"`
	JoinToken       string          `json:"join_token"`
	SignalingURL    string          `json:"signaling_url"`
	ICEServers      []ICEServer     `json:"ice_servers"`
}

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// NewVideoServer creates a new video server
func NewVideoServer(videoService *core.VideoService, config *config.Config) *VideoServer {
	server := &VideoServer{
		config:       config,
		videoService: videoService,
		callManager:  NewCallManager(),
		sessionMgr:   NewSessionManager(),
		logger:       logx.WithContext(context.Background()),
	}
	
	return server
}

// Start starts the video server
func (vs *VideoServer) Start() error {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	
	if vs.isRunning {
		return fmt.Errorf("video server is already running")
	}
	
	vs.logger.Info("Starting video server...")
	
	// Start video service if not already running
	if !vs.videoService.IsRunning() {
		if err := vs.videoService.Start(); err != nil {
			return fmt.Errorf("failed to start video service: %w", err)
		}
	}
	
	vs.isRunning = true
	vs.logger.Info("Video server started successfully")
	
	return nil
}

// Stop stops the video server
func (vs *VideoServer) Stop() error {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	
	if !vs.isRunning {
		return nil
	}
	
	vs.logger.Info("Stopping video server...")
	
	// End all active calls
	vs.callManager.EndAllCalls()
	
	// Disconnect all sessions
	vs.sessionMgr.DisconnectAllSessions()
	
	vs.isRunning = false
	vs.logger.Info("Video server stopped")
	
	return nil
}

// CreateCall creates a new video call
func (vs *VideoServer) CreateCall(ctx context.Context, req *CreateCallRequest) (*CreateCallResponse, error) {
	if !vs.isRunning {
		return nil, fmt.Errorf("video server is not running")
	}
	
	// Create call
	call, err := vs.callManager.CreateCall(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create call: %w", err)
	}
	
	// Generate join token
	joinToken := fmt.Sprintf("call_%s_%d", call.ID, time.Now().Unix())
	
	// Get signaling URL
	signalingURL := fmt.Sprintf("wss://video.teamgram.io/signaling/%s", call.ID)
	
	// Get ICE servers
	iceServers := vs.getICEServers()
	
	response := &CreateCallResponse{
		Call:         call,
		JoinToken:    joinToken,
		SignalingURL: signalingURL,
		ICEServers:   iceServers,
	}
	
	vs.logger.Infof("Created call %s for chat %d", call.ID, call.ChatID)
	
	return response, nil
}

// JoinCall joins a user to a video call
func (vs *VideoServer) JoinCall(ctx context.Context, req *JoinCallRequest) (*JoinCallResponse, error) {
	if !vs.isRunning {
		return nil, fmt.Errorf("video server is not running")
	}
	
	// Join call
	participant, call, err := vs.callManager.JoinCall(req)
	if err != nil {
		return nil, fmt.Errorf("failed to join call: %w", err)
	}
	
	// Generate join token
	joinToken := fmt.Sprintf("participant_%d_%s_%d", req.UserID, req.CallID, time.Now().Unix())
	
	// Get signaling URL
	signalingURL := fmt.Sprintf("wss://video.teamgram.io/signaling/%s", req.CallID)
	
	// Get ICE servers
	iceServers := vs.getICEServers()
	
	response := &JoinCallResponse{
		Participant:  participant,
		Call:         call,
		JoinToken:    joinToken,
		SignalingURL: signalingURL,
		ICEServers:   iceServers,
	}
	
	vs.logger.Infof("User %d joined call %s", req.UserID, req.CallID)
	
	return response, nil
}

// GetCallInfo returns information about a call
func (vs *VideoServer) GetCallInfo(ctx context.Context, callID string) (*ActiveCall, error) {
	return vs.callManager.GetCall(callID)
}

// GetCallStats returns statistics for a call
func (vs *VideoServer) GetCallStats(ctx context.Context, callID string) (*CallStats, error) {
	call, err := vs.callManager.GetCall(callID)
	if err != nil {
		return nil, err
	}
	
	return call.Stats, nil
}

// Helper methods

func (vs *VideoServer) getICEServers() []ICEServer {
	if vs.config.IsVideoEnabled() && vs.config.Video.WebRTCConfig != nil {
		servers := make([]ICEServer, len(vs.config.Video.WebRTCConfig.ICEServers))
		for i, server := range vs.config.Video.WebRTCConfig.ICEServers {
			servers[i] = ICEServer{
				URLs:       server.URLs,
				Username:   server.Username,
				Credential: server.Credential,
			}
		}
		return servers
	}
	
	// Default ICE servers
	return []ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
	}
}

// Manager implementations

func NewCallManager() *CallManager {
	return &CallManager{
		activeCalls: make(map[string]*ActiveCall),
		callsByUser: make(map[int64][]string),
		callsByChat: make(map[int64]string),
		logger:      logx.WithContext(context.Background()),
	}
}

func (cm *CallManager) CreateCall(req *CreateCallRequest) (*ActiveCall, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Check if chat already has an active call
	if existingCallID, exists := cm.callsByChat[req.ChatID]; exists {
		return nil, fmt.Errorf("chat %d already has an active call: %s", req.ChatID, existingCallID)
	}
	
	callID := fmt.Sprintf("call_%d_%d", req.ChatID, time.Now().Unix())
	
	call := &ActiveCall{
		ID:           callID,
		ChatID:       req.ChatID,
		Title:        req.Title,
		State:        CallStateWaiting,
		Type:         req.Type,
		Quality:      req.Quality,
		Participants: make(map[int64]*Participant),
		Config:       req.Config,
		Stats:        &CallStats{},
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	
	cm.activeCalls[callID] = call
	cm.callsByChat[req.ChatID] = callID
	
	return call, nil
}

func (cm *CallManager) JoinCall(req *JoinCallRequest) (*Participant, *ActiveCall, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	call, exists := cm.activeCalls[req.CallID]
	if !exists {
		return nil, nil, fmt.Errorf("call not found: %s", req.CallID)
	}
	
	call.mutex.Lock()
	defer call.mutex.Unlock()
	
	// Check if user is already in the call
	if _, exists := call.Participants[req.UserID]; exists {
		return nil, nil, fmt.Errorf("user %d is already in call %s", req.UserID, req.CallID)
	}
	
	// Check participant limit
	if len(call.Participants) >= call.Config.MaxParticipants {
		return nil, nil, fmt.Errorf("call %s is full", req.CallID)
	}
	
	participant := &Participant{
		UserID:        req.UserID,
		DisplayName:   req.DisplayName,
		Role:          ParticipantRoleParticipant,
		State:         ParticipantStateJoining,
		JoinedAt:      time.Now(),
		MediaSettings: req.MediaSettings,
		Quality:       &ParticipantQuality{},
		Connection:    &ConnectionInfo{},
		LastActivity:  time.Now(),
	}
	
	call.Participants[req.UserID] = participant
	call.LastActivity = time.Now()
	
	// Update user's calls
	if calls, exists := cm.callsByUser[req.UserID]; exists {
		cm.callsByUser[req.UserID] = append(calls, req.CallID)
	} else {
		cm.callsByUser[req.UserID] = []string{req.CallID}
	}
	
	return participant, call, nil
}

func (cm *CallManager) GetCall(callID string) (*ActiveCall, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	call, exists := cm.activeCalls[callID]
	if !exists {
		return nil, fmt.Errorf("call not found: %s", callID)
	}
	
	return call, nil
}

func (cm *CallManager) EndAllCalls() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	for callID, call := range cm.activeCalls {
		call.mutex.Lock()
		call.State = CallStateEnded
		now := time.Now()
		call.EndedAt = &now
		call.mutex.Unlock()
		
		cm.logger.Infof("Ended call %s", callID)
	}
	
	// Clear all calls
	cm.activeCalls = make(map[string]*ActiveCall)
	cm.callsByUser = make(map[int64][]string)
	cm.callsByChat = make(map[int64]string)
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*UserSession),
		sessionsByUser: make(map[int64]string),
		logger:         logx.WithContext(context.Background()),
	}
}

func (sm *SessionManager) DisconnectAllSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	for sessionID, session := range sm.sessions {
		session.mutex.Lock()
		session.State = SessionStateDisconnected
		session.mutex.Unlock()
		
		sm.logger.Infof("Disconnected session %s", sessionID)
	}
	
	// Clear all sessions
	sm.sessions = make(map[string]*UserSession)
	sm.sessionsByUser = make(map[int64]string)
}
