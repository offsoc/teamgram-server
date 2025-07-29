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

package tgcalls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/teamgram/teamgram-server/pkg/video/e2ee"
	"github.com/zeromicro/go-zero/core/logx"
)

// TGVideoCallManager implements Telegram-compatible video calling
// with enhanced security and 8K support
type TGVideoCallManager struct {
	mutex         sync.RWMutex
	config        *TGCallsConfig
	activeCalls   map[int64]*TGVideoCall
	callsByID     map[string]*TGVideoCall
	e2eeManager   *e2ee.E2EEManager
	webrtcAPI     *webrtc.API
	mediaEngine   *webrtc.MediaEngine
	settingEngine *webrtc.SettingEngine
	interceptor   interface{}
	dhConfig      *DHConfig
	callStates    map[int64]*CallState
	metrics       *TGCallsMetrics
	logger        logx.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	isRunning     bool
}

// TGCallsConfig configuration for Telegram video calls
type TGCallsConfig struct {
	// Basic settings
	Enabled            bool          `json:"enabled"`
	MaxConcurrentCalls int           `json:"max_concurrent_calls"`
	CallTimeout        time.Duration `json:"call_timeout"`
	RingTimeout        time.Duration `json:"ring_timeout"`

	// Video settings
	EnableVideo       bool   `json:"enable_video"`
	MaxResolution     string `json:"max_resolution"`
	MaxFrameRate      int    `json:"max_frame_rate"`
	MaxVideoBitrate   int    `json:"max_video_bitrate"`
	EnableScreenShare bool   `json:"enable_screen_share"`

	// Audio settings
	EnableAudio            bool     `json:"enable_audio"`
	AudioCodecs            []string `json:"audio_codecs"`
	MaxAudioBitrate        int      `json:"max_audio_bitrate"`
	EnableNoiseSuppression bool     `json:"enable_noise_suppression"`
	EnableEchoCancellation bool     `json:"enable_echo_cancellation"`

	// Security settings
	EnableE2EE            bool   `json:"enable_e2ee"`
	DHPrime               []byte `json:"dh_prime"`
	DHGenerator           int    `json:"dh_generator"`
	EnableKeyVerification bool   `json:"enable_key_verification"`

	// Network settings
	ICEServers  []ICEServer `json:"ice_servers"`
	EnableP2P   bool        `json:"enable_p2p"`
	EnableRelay bool        `json:"enable_relay"`
	EnableTCP   bool        `json:"enable_tcp"`
	EnableUDP   bool        `json:"enable_udp"`

	// Quality settings
	EnableAdaptiveQuality bool `json:"enable_adaptive_quality"`
	EnableSimulcast       bool `json:"enable_simulcast"`
	EnableSVC             bool `json:"enable_svc"`

	// Compatibility settings
	EnableLegacySupport bool `json:"enable_legacy_support"`
	MinProtocolVersion  int  `json:"min_protocol_version"`
	MaxProtocolVersion  int  `json:"max_protocol_version"`

	// Performance settings
	EnableHardwareAccel bool    `json:"enable_hardware_accel"`
	EnableGPU           bool    `json:"enable_gpu"`
	MaxCPUUsage         float64 `json:"max_cpu_usage"`
	MaxMemoryUsage      int64   `json:"max_memory_usage"`
}

// TGVideoCall represents a Telegram video call
type TGVideoCall struct {
	ID                int64                      `json:"id"`
	AccessHash        int64                      `json:"access_hash"`
	AdminID           int64                      `json:"admin_id"`
	ParticipantID     int64                      `json:"participant_id"`
	Date              int32                      `json:"date"`
	Title             string                     `json:"title"`
	StreamDCID        int32                      `json:"stream_dc_id"`
	RecordStartDate   *int32                     `json:"record_start_date,omitempty"`
	ScheduleDate      *int32                     `json:"schedule_date,omitempty"`
	UnmutedVideoCount int32                      `json:"unmuted_video_count"`
	UnmutedVideoLimit int32                      `json:"unmuted_video_limit"`
	Version           int32                      `json:"version"`
	State             TGCallState                `json:"state"`
	Protocol          *CallProtocol              `json:"protocol"`
	Connection        *CallConnection            `json:"connection"`
	Participants      map[int64]*CallParticipant `json:"participants"`
	E2EESession       *e2ee.E2EESession          `json:"e2ee_session"`
	DHConfig          *DHConfig                  `json:"dh_config"`
	GAHash            []byte                     `json:"ga_hash"`
	GB                []byte                     `json:"gb"`
	KeyFingerprint    int64                      `json:"key_fingerprint"`
	ReceiveDate       int32                      `json:"receive_date"`
	EmojisFingerprint []string                   `json:"emojis_fingerprint"`
	NeedRating        bool                       `json:"need_rating"`
	NeedDebug         bool                       `json:"need_debug"`
	P2PAllowed        bool                       `json:"p2p_allowed"`
	VideoJoined       bool                       `json:"video_joined"`
	CanSelfUnmute     bool                       `json:"can_self_unmute"`
	JoinMuted         bool                       `json:"join_muted"`
	JustJoined        bool                       `json:"just_joined"`
	TestCall          bool                       `json:"test_call"`
	CreatedAt         time.Time                  `json:"created_at"`
	StartedAt         *time.Time                 `json:"started_at,omitempty"`
	EndedAt           *time.Time                 `json:"ended_at,omitempty"`
	LastActivity      time.Time                  `json:"last_activity"`
	Metadata          map[string]interface{}     `json:"metadata"`
	mutex             sync.RWMutex
}

// CallProtocol represents the call protocol configuration
type CallProtocol struct {
	MinLayer            int32    `json:"min_layer"`
	MaxLayer            int32    `json:"max_layer"`
	UDPP2P              bool     `json:"udp_p2p"`
	UDPREFLECTOR        bool     `json:"udp_reflector"`
	LibraryVersions     []string `json:"library_versions"`
	SupportedCodecs     []string `json:"supported_codecs"`
	SupportedExtensions []string `json:"supported_extensions"`
}

// CallConnection represents the WebRTC connection
type CallConnection struct {
	ID                 string                     `json:"id"`
	IP                 string                     `json:"ip"`
	IPv6               string                     `json:"ipv6"`
	Port               int32                      `json:"port"`
	PeerTag            []byte                     `json:"peer_tag"`
	TCP                bool                       `json:"tcp"`
	PeerConnection     *webrtc.PeerConnection     `json:"-"`
	DataChannel        *webrtc.DataChannel        `json:"-"`
	LocalDescription   *webrtc.SessionDescription `json:"local_description"`
	RemoteDescription  *webrtc.SessionDescription `json:"remote_description"`
	ICECandidates      []*webrtc.ICECandidate     `json:"ice_candidates"`
	ConnectionState    webrtc.PeerConnectionState `json:"connection_state"`
	ICEConnectionState webrtc.ICEConnectionState  `json:"ice_connection_state"`
	SignalingState     webrtc.SignalingState      `json:"signaling_state"`
	CreatedAt          time.Time                  `json:"created_at"`
	ConnectedAt        *time.Time                 `json:"connected_at,omitempty"`
	LastActivity       time.Time                  `json:"last_activity"`
}

// CallParticipant represents a call participant
type CallParticipant struct {
	UserID          int64                      `json:"user_id"`
	Date            int32                      `json:"date"`
	Source          int32                      `json:"source"`
	Muted           bool                       `json:"muted"`
	Left            bool                       `json:"left"`
	CanSelfUnmute   bool                       `json:"can_self_unmute"`
	JustJoined      bool                       `json:"just_joined"`
	Versioned       bool                       `json:"versioned"`
	Min             bool                       `json:"min"`
	MutedByYou      bool                       `json:"muted_by_you"`
	VolumeByAdmin   bool                       `json:"volume_by_admin"`
	Self            bool                       `json:"self"`
	VideoJoined     bool                       `json:"video_joined"`
	About           string                     `json:"about"`
	RaiseHandRating *int64                     `json:"raise_hand_rating,omitempty"`
	Video           *GroupCallParticipantVideo `json:"video,omitempty"`
	Presentation    *GroupCallParticipantVideo `json:"presentation,omitempty"`
	Volume          int32                      `json:"volume"`
	ActiveDate      *int32                     `json:"active_date,omitempty"`
	JoinedAt        time.Time                  `json:"joined_at"`
	LastActivity    time.Time                  `json:"last_activity"`
}

// GroupCallParticipantVideo represents video stream info
type GroupCallParticipantVideo struct {
	Endpoint     string        `json:"endpoint"`
	SourceGroups []SourceGroup `json:"source_groups"`
	AudioSource  int32         `json:"audio_source"`
	Paused       bool          `json:"paused"`
}

// SourceGroup represents a source group for simulcast
type SourceGroup struct {
	Semantics string  `json:"semantics"`
	Sources   []int32 `json:"sources"`
}

// DHConfig represents Diffie-Hellman configuration
type DHConfig struct {
	G       int32  `json:"g"`
	P       []byte `json:"p"`
	Version int32  `json:"version"`
	Random  []byte `json:"random"`
}

// CallState represents the current state of a call
type CallState struct {
	State      TGCallState `json:"state"`
	LastUpdate time.Time   `json:"last_update"`
	Reason     string      `json:"reason"`
	NeedRating bool        `json:"need_rating"`
	NeedDebug  bool        `json:"need_debug"`
}

// TGCallsMetrics tracks Telegram calls performance
type TGCallsMetrics struct {
	// Call metrics
	TotalCalls      int64 `json:"total_calls"`
	ActiveCalls     int64 `json:"active_calls"`
	SuccessfulCalls int64 `json:"successful_calls"`
	FailedCalls     int64 `json:"failed_calls"`
	DroppedCalls    int64 `json:"dropped_calls"`

	// Connection metrics
	P2PConnections   int64 `json:"p2p_connections"`
	RelayConnections int64 `json:"relay_connections"`
	TCPConnections   int64 `json:"tcp_connections"`
	UDPConnections   int64 `json:"udp_connections"`

	// Quality metrics
	AverageCallDuration time.Duration `json:"average_call_duration"`
	AverageSetupTime    time.Duration `json:"average_setup_time"`
	AverageLatency      time.Duration `json:"average_latency"`
	PacketLossRate      float64       `json:"packet_loss_rate"`

	// Security metrics
	E2EECalls          int64 `json:"e2ee_calls"`
	KeyVerifications   int64 `json:"key_verifications"`
	SecurityViolations int64 `json:"security_violations"`

	// Compatibility metrics
	LegacyCalls      int64         `json:"legacy_calls"`
	ModernCalls      int64         `json:"modern_calls"`
	ProtocolVersions map[int]int64 `json:"protocol_versions"`

	// Performance metrics
	CPUUsage         float64 `json:"cpu_usage"`
	MemoryUsage      int64   `json:"memory_usage"`
	NetworkBandwidth int64   `json:"network_bandwidth"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
}

// Enums and types
type TGCallState string

const (
	TGCallStateWaiting         TGCallState = "waiting"
	TGCallStateExchangingKeys  TGCallState = "exchanging_keys"
	TGCallStateWaitingIncoming TGCallState = "waiting_incoming"
	TGCallStateRinging         TGCallState = "ringing"
	TGCallStateRequested       TGCallState = "requested"
	TGCallStateAccepted        TGCallState = "accepted"
	TGCallStateConfirmed       TGCallState = "confirmed"
	TGCallStateReady           TGCallState = "ready"
	TGCallStateHangingUp       TGCallState = "hanging_up"
	TGCallStateDiscarded       TGCallState = "discarded"
	TGCallStateEnded           TGCallState = "ended"
	TGCallStateBusy            TGCallState = "busy"
	TGCallStateMissed          TGCallState = "missed"
)

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Request and response types
type RequestCallRequest struct {
	UserID   int64         `json:"user_id"`
	RandomID int32         `json:"random_id"`
	GAHash   []byte        `json:"ga_hash"`
	Protocol *CallProtocol `json:"protocol"`
	Video    bool          `json:"video"`
}

type RequestCallResponse struct {
	Call     *TGVideoCall `json:"call"`
	DHConfig *DHConfig    `json:"dh_config"`
}

type AcceptCallRequest struct {
	CallID   int64         `json:"call_id"`
	GB       []byte        `json:"gb"`
	Protocol *CallProtocol `json:"protocol"`
}

type AcceptCallResponse struct {
	Call *TGVideoCall `json:"call"`
}

type ConfirmCallRequest struct {
	CallID         int64         `json:"call_id"`
	GA             []byte        `json:"ga"`
	KeyFingerprint int64         `json:"key_fingerprint"`
	Protocol       *CallProtocol `json:"protocol"`
}

type ConfirmCallResponse struct {
	Call        *TGVideoCall      `json:"call"`
	Connections []*CallConnection `json:"connections"`
}

type DiscardCallRequest struct {
	CallID       int64  `json:"call_id"`
	Duration     int32  `json:"duration"`
	Reason       string `json:"reason"`
	ConnectionID int64  `json:"connection_id"`
	Video        bool   `json:"video"`
}

type DiscardCallResponse struct {
	Updates interface{} `json:"updates"`
}

// NewTGVideoCallManager creates a new Telegram video call manager
func NewTGVideoCallManager(config *TGCallsConfig) (*TGVideoCallManager, error) {
	if config == nil {
		config = DefaultTGCallsConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &TGVideoCallManager{
		config:      config,
		activeCalls: make(map[int64]*TGVideoCall),
		callsByID:   make(map[string]*TGVideoCall),
		callStates:  make(map[int64]*CallState),
		metrics: &TGCallsMetrics{
			ProtocolVersions: make(map[int]int64),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize E2EE manager
	if config.EnableE2EE {
		e2eeConfig := e2ee.DefaultE2EEConfig()
		var err error
		manager.e2eeManager, err = e2ee.NewE2EEManager(e2eeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create E2EE manager: %w", err)
		}
	}

	// Initialize WebRTC API
	if err := manager.initializeWebRTC(); err != nil {
		return nil, fmt.Errorf("failed to initialize WebRTC: %w", err)
	}

	// Initialize DH config
	manager.dhConfig = &DHConfig{
		G:       2,
		P:       config.DHPrime,
		Version: 1,
	}

	return manager, nil
}

// Start starts the TG video call manager
func (tgm *TGVideoCallManager) Start() error {
	tgm.mutex.Lock()
	defer tgm.mutex.Unlock()

	if tgm.isRunning {
		return fmt.Errorf("TG video call manager is already running")
	}

	tgm.logger.Info("Starting TG video call manager...")

	// Start E2EE manager
	if tgm.e2eeManager != nil {
		if err := tgm.e2eeManager.Start(); err != nil {
			return fmt.Errorf("failed to start E2EE manager: %w", err)
		}
	}

	// Start metrics collection
	go tgm.metricsLoop()

	// Start call state monitoring
	go tgm.callStateLoop()

	tgm.isRunning = true
	tgm.logger.Info("TG video call manager started successfully")

	return nil
}

// RequestCall initiates a new video call (phone.requestCall)
func (tgm *TGVideoCallManager) RequestCall(ctx context.Context, req *RequestCallRequest) (*RequestCallResponse, error) {
	if !tgm.isRunning {
		return nil, fmt.Errorf("TG video call manager is not running")
	}

	// Generate call ID
	callID := tgm.generateCallID()

	// Create video call
	call := &TGVideoCall{
		ID:            callID,
		AccessHash:    tgm.generateAccessHash(),
		AdminID:       0, // Set by caller
		ParticipantID: req.UserID,
		Date:          int32(time.Now().Unix()),
		State:         TGCallStateRequested,
		Protocol:      req.Protocol,
		Participants:  make(map[int64]*CallParticipant),
		GAHash:        req.GAHash,
		VideoJoined:   req.Video,
		P2PAllowed:    tgm.config.EnableP2P,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		Metadata:      make(map[string]interface{}),
	}

	// Create E2EE session if enabled
	if tgm.e2eeManager != nil {
		e2eeSession, err := tgm.e2eeManager.CreateSession(
			int64(req.UserID),
			int64(req.RandomID),
			int64(len(req.GAHash)))
		if err != nil {
			return nil, fmt.Errorf("failed to create E2EE session: %w", err)
		}
		call.E2EESession = e2eeSession
	}

	// Store call
	tgm.mutex.Lock()
	tgm.activeCalls[callID] = call
	tgm.callStates[callID] = &CallState{
		State:      TGCallStateRequested,
		LastUpdate: time.Now(),
	}
	tgm.metrics.TotalCalls++
	tgm.metrics.ActiveCalls++
	tgm.mutex.Unlock()

	response := &RequestCallResponse{
		Call:     call,
		DHConfig: tgm.dhConfig,
	}

	tgm.logger.Infof("Requested call %d to user %d", callID, req.UserID)

	return response, nil
}

// AcceptCall accepts an incoming video call (phone.acceptCall)
func (tgm *TGVideoCallManager) AcceptCall(ctx context.Context, req *AcceptCallRequest) (*AcceptCallResponse, error) {
	tgm.mutex.RLock()
	call, exists := tgm.activeCalls[req.CallID]
	tgm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("call not found: %d", req.CallID)
	}

	call.mutex.Lock()
	defer call.mutex.Unlock()

	// Update call state
	call.State = TGCallStateAccepted
	call.GB = req.GB
	call.Protocol = req.Protocol
	call.LastActivity = time.Now()

	// Update call state
	tgm.mutex.Lock()
	tgm.callStates[req.CallID].State = TGCallStateAccepted
	tgm.callStates[req.CallID].LastUpdate = time.Now()
	tgm.mutex.Unlock()

	response := &AcceptCallResponse{
		Call: call,
	}

	tgm.logger.Infof("Accepted call %d", req.CallID)

	return response, nil
}

// ConfirmCall confirms a video call (phone.confirmCall)
func (tgm *TGVideoCallManager) ConfirmCall(ctx context.Context, req *ConfirmCallRequest) (*ConfirmCallResponse, error) {
	tgm.mutex.RLock()
	call, exists := tgm.activeCalls[req.CallID]
	tgm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("call not found: %d", req.CallID)
	}

	call.mutex.Lock()
	defer call.mutex.Unlock()

	// Update call state
	call.State = TGCallStateReady
	call.KeyFingerprint = req.KeyFingerprint
	call.Protocol = req.Protocol
	call.LastActivity = time.Now()
	now := time.Now()
	call.StartedAt = &now

	// Create WebRTC connection
	connection, err := tgm.createWebRTCConnection(call)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebRTC connection: %w", err)
	}
	call.Connection = connection

	// Update call state
	tgm.mutex.Lock()
	tgm.callStates[req.CallID].State = TGCallStateReady
	tgm.callStates[req.CallID].LastUpdate = time.Now()
	tgm.metrics.SuccessfulCalls++
	tgm.mutex.Unlock()

	response := &ConfirmCallResponse{
		Call:        call,
		Connections: []*CallConnection{connection},
	}

	tgm.logger.Infof("Confirmed call %d", req.CallID)

	return response, nil
}

// DiscardCall ends a video call (phone.discardCall)
func (tgm *TGVideoCallManager) DiscardCall(ctx context.Context, req *DiscardCallRequest) (*DiscardCallResponse, error) {
	tgm.mutex.Lock()
	call, exists := tgm.activeCalls[req.CallID]
	if exists {
		delete(tgm.activeCalls, req.CallID)
		delete(tgm.callStates, req.CallID)
		tgm.metrics.ActiveCalls--
	}
	tgm.mutex.Unlock()

	if !exists {
		return nil, fmt.Errorf("call not found: %d", req.CallID)
	}

	call.mutex.Lock()
	defer call.mutex.Unlock()

	// Update call state
	call.State = TGCallStateDiscarded
	call.LastActivity = time.Now()
	now := time.Now()
	call.EndedAt = &now

	// Close WebRTC connection
	if call.Connection != nil && call.Connection.PeerConnection != nil {
		call.Connection.PeerConnection.Close()
	}

	response := &DiscardCallResponse{
		Updates: nil, // Would contain MTProto updates
	}

	tgm.logger.Infof("Discarded call %d (reason: %s, duration: %ds)",
		req.CallID, req.Reason, req.Duration)

	return response, nil
}

// Helper methods

func (tgm *TGVideoCallManager) initializeWebRTC() error {
	// Create media engine
	tgm.mediaEngine = &webrtc.MediaEngine{}

	// Register codecs
	if err := tgm.mediaEngine.RegisterDefaultCodecs(); err != nil {
		return fmt.Errorf("failed to register codecs: %w", err)
	}

	// Create interceptor registry
	// tgm.interceptor = webrtc.InterceptorRegistry{}

	// Register default interceptors
	// if err := webrtc.RegisterDefaultInterceptors(tgm.mediaEngine, &tgm.interceptor); err != nil {
	// 	return fmt.Errorf("failed to register interceptors: %w", err)
	// }

	// Create setting engine
	settingEngine := webrtc.SettingEngine{}
	tgm.settingEngine = &settingEngine

	// Configure ICE
	if tgm.config.EnableUDP {
		tgm.settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	}
	if tgm.config.EnableTCP {
		tgm.settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6})
	}

	// Create WebRTC API with interceptors
	tgm.webrtcAPI = webrtc.NewAPI(
		webrtc.WithMediaEngine(tgm.mediaEngine),
		webrtc.WithSettingEngine(*tgm.settingEngine))

	return nil
}

func (tgm *TGVideoCallManager) createWebRTCConnection(call *TGVideoCall) (*CallConnection, error) {
	// Create ICE servers
	iceServers := make([]webrtc.ICEServer, len(tgm.config.ICEServers))
	for i, server := range tgm.config.ICEServers {
		iceServers[i] = webrtc.ICEServer{
			URLs:       server.URLs,
			Username:   server.Username,
			Credential: server.Credential,
		}
	}

	// Create peer connection configuration
	config := webrtc.Configuration{
		ICEServers: iceServers,
	}

	// Create peer connection
	peerConnection, err := tgm.webrtcAPI.NewPeerConnection(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}

	connection := &CallConnection{
		ID:             tgm.generateConnectionID(),
		PeerConnection: peerConnection,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	// Set up event handlers
	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		connection.ConnectionState = state
		connection.LastActivity = time.Now()

		if state == webrtc.PeerConnectionStateConnected {
			now := time.Now()
			connection.ConnectedAt = &now
		}
	})

	peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		connection.ICEConnectionState = state
		connection.LastActivity = time.Now()
	})

	peerConnection.OnSignalingStateChange(func(state webrtc.SignalingState) {
		connection.SignalingState = state
		connection.LastActivity = time.Now()
	})

	return connection, nil
}

func (tgm *TGVideoCallManager) generateCallID() int64 {
	var bytes [8]byte
	rand.Read(bytes[:])

	// Convert to int64 (ensure positive)
	callID := int64(0)
	for i, b := range bytes {
		callID |= int64(b) << (i * 8)
	}

	if callID < 0 {
		callID = -callID
	}

	return callID
}

func (tgm *TGVideoCallManager) generateAccessHash() int64 {
	var bytes [8]byte
	rand.Read(bytes[:])

	accessHash := int64(0)
	for i, b := range bytes {
		accessHash |= int64(b) << (i * 8)
	}

	return accessHash
}

func (tgm *TGVideoCallManager) generateConnectionID() string {
	var bytes [16]byte
	rand.Read(bytes[:])
	return hex.EncodeToString(bytes[:])
}

func (tgm *TGVideoCallManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tgm.collectMetrics()
		case <-tgm.ctx.Done():
			return
		}
	}
}

func (tgm *TGVideoCallManager) collectMetrics() {
	tgm.mutex.Lock()
	defer tgm.mutex.Unlock()

	tgm.metrics.LastUpdated = time.Now()
	tgm.metrics.ActiveCalls = int64(len(tgm.activeCalls))

	// Count connection types
	p2pCount := int64(0)
	relayCount := int64(0)

	for _, call := range tgm.activeCalls {
		if call.P2PAllowed {
			p2pCount++
		} else {
			relayCount++
		}
	}

	tgm.metrics.P2PConnections = p2pCount
	tgm.metrics.RelayConnections = relayCount
}

func (tgm *TGVideoCallManager) callStateLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tgm.checkCallStates()
		case <-tgm.ctx.Done():
			return
		}
	}
}

func (tgm *TGVideoCallManager) checkCallStates() {
	tgm.mutex.Lock()
	defer tgm.mutex.Unlock()

	now := time.Now()

	for callID, state := range tgm.callStates {
		// Check for timeouts
		if now.Sub(state.LastUpdate) > tgm.config.CallTimeout {
			if call, exists := tgm.activeCalls[callID]; exists {
				call.State = TGCallStateDiscarded
				delete(tgm.activeCalls, callID)
				delete(tgm.callStates, callID)
				tgm.metrics.ActiveCalls--
				tgm.metrics.DroppedCalls++

				tgm.logger.Errorf("Call %d timed out", callID)
			}
		}
	}
}

// DefaultTGCallsConfig returns default Telegram calls configuration
func DefaultTGCallsConfig() *TGCallsConfig {
	// Default DH prime (2048-bit safe prime)
	dhPrime, _ := hex.DecodeString("C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B")

	return &TGCallsConfig{
		Enabled:                true,
		MaxConcurrentCalls:     10000,
		CallTimeout:            5 * time.Minute,
		RingTimeout:            30 * time.Second,
		EnableVideo:            true,
		MaxResolution:          "8K",
		MaxFrameRate:           60,
		MaxVideoBitrate:        100000000, // 100 Mbps
		EnableScreenShare:      true,
		EnableAudio:            true,
		AudioCodecs:            []string{"OPUS", "G722", "PCMU", "PCMA"},
		MaxAudioBitrate:        320000, // 320 kbps
		EnableNoiseSuppression: true,
		EnableEchoCancellation: true,
		EnableE2EE:             true,
		DHPrime:                dhPrime,
		DHGenerator:            2,
		EnableKeyVerification:  true,
		ICEServers: []ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
		EnableP2P:             true,
		EnableRelay:           true,
		EnableTCP:             true,
		EnableUDP:             true,
		EnableAdaptiveQuality: true,
		EnableSimulcast:       true,
		EnableSVC:             true,
		EnableLegacySupport:   true,
		MinProtocolVersion:    65,
		MaxProtocolVersion:    92,
		EnableHardwareAccel:   true,
		EnableGPU:             true,
		MaxCPUUsage:           80.0,
		MaxMemoryUsage:        8 * 1024 * 1024 * 1024, // 8GB
	}
}
