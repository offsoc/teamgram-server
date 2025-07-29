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

package calls

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// CallManager manages voice and video calls
type CallManager struct {
	config      *Config
	callStore   *CallStore
	mediaEngine *MediaEngine
	signaling   *SignalingServer
	mutex       sync.RWMutex
	logger      logx.Logger
}

// Config represents call configuration
type Config struct {
	// Call settings
	MaxCallDuration     time.Duration `json:"max_call_duration"`
	MaxParticipants     int           `json:"max_participants"`
	EnableVideoCalls    bool          `json:"enable_video_calls"`
	EnableGroupCalls    bool          `json:"enable_group_calls"`
	EnableScreenShare   bool          `json:"enable_screen_share"`
	EnableCallRecording bool          `json:"enable_call_recording"`

	// Media settings
	AudioCodec      string `json:"audio_codec"`
	VideoCodec      string `json:"video_codec"`
	AudioBitrate    int    `json:"audio_bitrate"`
	VideoBitrate    int    `json:"video_bitrate"`
	AudioSampleRate int    `json:"audio_sample_rate"`
	VideoFrameRate  int    `json:"video_frame_rate"`

	// Network settings
	STUNServers []string   `json:"stun_servers"`
	TURNServers []string   `json:"turn_servers"`
	ICEConfig   *ICEConfig `json:"ice_config"`

	// Performance settings
	CallCacheSize int64         `json:"call_cache_size"`
	CallCacheTTL  time.Duration `json:"call_cache_ttl"`
}

// Call represents a voice or video call
type Call struct {
	ID             int64             `json:"id"`
	AccessHash     int64             `json:"access_hash"`
	Date           int               `json:"date"`
	AdminID        int64             `json:"admin_id"`
	ParticipantID  int64             `json:"participant_id"`
	GAOrB          []byte            `json:"g_a_or_b"`
	KeyFingerprint int64             `json:"key_fingerprint"`
	Protocol       *CallProtocol     `json:"protocol"`
	Connections    []*CallConnection `json:"connections"`
	StartDate      int               `json:"start_date"`

	// Call properties
	Type          CallType  `json:"type"`
	State         CallState `json:"state"`
	Duration      int       `json:"duration"`
	IsOutgoing    bool      `json:"is_outgoing"`
	IsVideo       bool      `json:"is_video"`
	IsGroup       bool      `json:"is_group"`
	IsScreenShare bool      `json:"is_screen_share"`
	IsRecording   bool      `json:"is_recording"`

	// Participants
	Participants      []*CallParticipant `json:"participants"`
	AdminParticipants []*CallParticipant `json:"admin_participants"`
}

// CallType represents call type
type CallType int

const (
	CallTypeVoice CallType = iota
	CallTypeVideo
	CallTypeGroupVoice
	CallTypeGroupVideo
)

// CallState represents call state
type CallState int

const (
	CallStateRequested CallState = iota
	CallStateAccepted
	CallStateConfirmed
	CallStateDiscarded
	CallStateBusy
	CallStateMissed
)

// CallProtocol represents call protocol
type CallProtocol struct {
	UDPP2P          bool     `json:"udp_p2p"`
	UDPReflector    bool     `json:"udp_reflector"`
	MinLayer        int      `json:"min_layer"`
	MaxLayer        int      `json:"max_layer"`
	LibraryVersions []string `json:"library_versions"`
}

// CallConnection represents call connection
type CallConnection struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	PeerTag []byte `json:"peer_tag"`
	IsRelay bool   `json:"is_relay"`
}

// CallParticipant represents call participant
type CallParticipant struct {
	UserID        int64                 `json:"user_id"`
	Date          int                   `json:"date"`
	Source        int                   `json:"source"`
	Muted         bool                  `json:"muted"`
	Left          bool                  `json:"left"`
	CanSelfUnmute bool                  `json:"can_self_unmute"`
	JustJoined    bool                  `json:"just_joined"`
	Versioned     bool                  `json:"versioned"`
	Min           bool                  `json:"min"`
	MutedByYou    bool                  `json:"muted_by_you"`
	VolumeByAdmin bool                  `json:"volume_by_admin"`
	Self          bool                  `json:"self"`
	Video         *CallParticipantVideo `json:"video"`
	Presentation  *CallParticipantVideo `json:"presentation"`
}

// CallParticipantVideo represents participant video
type CallParticipantVideo struct {
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
}

// CallStore manages call storage
type CallStore struct {
	config *Config
	calls  map[int64]*Call
	mutex  sync.RWMutex
}

// MediaEngine handles media processing
type MediaEngine struct {
	config *Config
	mutex  sync.RWMutex
}

// SignalingServer handles signaling
type SignalingServer struct {
	config *Config
	mutex  sync.RWMutex
}

// ICEConfig represents ICE configuration
type ICEConfig struct {
	ICEUfrag string `json:"ice_ufrag"`
	ICEPwd   string `json:"ice_pwd"`
	ICELite  bool   `json:"ice_lite"`
}

// NewCallManager creates a new call manager
func NewCallManager(config *Config) *CallManager {
	if config == nil {
		config = DefaultConfig()
	}

	return &CallManager{
		config:      config,
		callStore:   NewCallStore(config),
		mediaEngine: NewMediaEngine(config),
		signaling:   NewSignalingServer(config),
		logger:      logx.WithContext(context.Background()),
	}
}

// CreateCall creates a new call
func (m *CallManager) CreateCall(ctx context.Context, userID, peerID int64, callType CallType) (*Call, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Creating call: user=%d, peer=%d, type=%v", userID, peerID, callType)

	// Validate call type
	if callType == CallTypeVideo && !m.config.EnableVideoCalls {
		return nil, fmt.Errorf("video calls not enabled")
	}

	// Generate call ID and access hash
	callID := m.generateCallID()
	accessHash := m.generateAccessHash()

	// Generate encryption keys
	_, publicKey, err := m.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create call
	call := &Call{
		ID:                callID,
		AccessHash:        accessHash,
		Date:              int(time.Now().Unix()),
		AdminID:           userID,
		ParticipantID:     peerID,
		GAOrB:             publicKey,
		KeyFingerprint:    m.calculateFingerprint(publicKey),
		Protocol:          m.createCallProtocol(),
		Connections:       m.createCallConnections(),
		Type:              callType,
		State:             CallStateRequested,
		IsOutgoing:        true,
		IsVideo:           callType == CallTypeVideo || callType == CallTypeGroupVideo,
		IsGroup:           callType == CallTypeGroupVoice || callType == CallTypeGroupVideo,
		Participants:      []*CallParticipant{},
		AdminParticipants: []*CallParticipant{},
	}

	// Add admin as participant
	adminParticipant := &CallParticipant{
		UserID:        userID,
		Date:          int(time.Now().Unix()),
		Source:        0,
		Muted:         false,
		Left:          false,
		CanSelfUnmute: true,
		JustJoined:    true,
		Versioned:     true,
		Min:           false,
		MutedByYou:    false,
		VolumeByAdmin: false,
		Self:          true,
	}

	call.Participants = append(call.Participants, adminParticipant)
	call.AdminParticipants = append(call.AdminParticipants, adminParticipant)

	// Store call
	err = m.callStore.StoreCall(call)
	if err != nil {
		return nil, fmt.Errorf("failed to store call: %w", err)
	}

	m.logger.Infof("Call created: id=%d", call.ID)
	return call, nil
}

// AcceptCall accepts a call
func (m *CallManager) AcceptCall(ctx context.Context, callID int64, userID int64) (*Call, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Accepting call: id=%d, user=%d", callID, userID)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return nil, fmt.Errorf("call not found: %w", err)
	}

	if call.State != CallStateRequested {
		return nil, fmt.Errorf("invalid call state: %v", call.State)
	}

	// Generate response keys
	_, publicKey, err := m.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Calculate shared secret
	_, err = m.calculateSharedSecret(nil, call.GAOrB)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate shared secret: %w", err)
	}

	// Update call state
	call.State = CallStateAccepted
	call.GAOrB = publicKey
	call.KeyFingerprint = m.calculateFingerprint(publicKey)
	call.StartDate = int(time.Now().Unix())

	// Add participant
	participant := &CallParticipant{
		UserID:        userID,
		Date:          int(time.Now().Unix()),
		Source:        1,
		Muted:         false,
		Left:          false,
		CanSelfUnmute: true,
		JustJoined:    true,
		Versioned:     true,
		Min:           false,
		MutedByYou:    false,
		VolumeByAdmin: false,
		Self:          false,
	}

	call.Participants = append(call.Participants, participant)

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return nil, fmt.Errorf("failed to update call: %w", err)
	}

	m.logger.Infof("Call accepted: id=%d", call.ID)
	return call, nil
}

// ConfirmCall confirms a call
func (m *CallManager) ConfirmCall(ctx context.Context, callID int64) (*Call, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Confirming call: id=%d", callID)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return nil, fmt.Errorf("call not found: %w", err)
	}

	if call.State != CallStateAccepted {
		return nil, fmt.Errorf("invalid call state: %v", call.State)
	}

	// Update call state
	call.State = CallStateConfirmed

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return nil, fmt.Errorf("failed to update call: %w", err)
	}

	// Start call monitoring
	go m.monitorCall(callID)

	m.logger.Infof("Call confirmed: id=%d", call.ID)
	return call, nil
}

// DiscardCall discards a call
func (m *CallManager) DiscardCall(ctx context.Context, callID int64, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Discarding call: id=%d, reason=%s", callID, reason)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return fmt.Errorf("call not found: %w", err)
	}

	// Update call state
	call.State = CallStateDiscarded
	call.Duration = int(time.Now().Unix()) - call.StartDate

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return fmt.Errorf("failed to update call: %w", err)
	}

	m.logger.Infof("Call discarded: id=%d", call.ID)
	return nil
}

// CreateGroupCall creates a group call
func (m *CallManager) CreateGroupCall(ctx context.Context, chatID int64, userID int64, callType CallType) (*Call, error) {
	if !m.config.EnableGroupCalls {
		return nil, fmt.Errorf("group calls not enabled")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Creating group call: chat=%d, user=%d, type=%v", chatID, userID, callType)

	// Generate call ID and access hash
	callID := m.generateCallID()
	accessHash := m.generateAccessHash()

	// Generate encryption keys
	_, publicKey, err := m.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create group call
	call := &Call{
		ID:                callID,
		AccessHash:        accessHash,
		Date:              int(time.Now().Unix()),
		AdminID:           userID,
		ParticipantID:     chatID, // For group calls, this is the chat ID
		GAOrB:             publicKey,
		KeyFingerprint:    m.calculateFingerprint(publicKey),
		Protocol:          m.createCallProtocol(),
		Connections:       m.createCallConnections(),
		Type:              callType,
		State:             CallStateRequested,
		IsOutgoing:        true,
		IsVideo:           callType == CallTypeGroupVideo,
		IsGroup:           true,
		Participants:      []*CallParticipant{},
		AdminParticipants: []*CallParticipant{},
	}

	// Add admin as participant
	adminParticipant := &CallParticipant{
		UserID:        userID,
		Date:          int(time.Now().Unix()),
		Source:        0,
		Muted:         false,
		Left:          false,
		CanSelfUnmute: true,
		JustJoined:    true,
		Versioned:     true,
		Min:           false,
		MutedByYou:    false,
		VolumeByAdmin: false,
		Self:          true,
	}

	call.Participants = append(call.Participants, adminParticipant)
	call.AdminParticipants = append(call.AdminParticipants, adminParticipant)

	// Store call
	err = m.callStore.StoreCall(call)
	if err != nil {
		return nil, fmt.Errorf("failed to store call: %w", err)
	}

	m.logger.Infof("Group call created: id=%d", call.ID)
	return call, nil
}

// JoinGroupCall joins a group call
func (m *CallManager) JoinGroupCall(ctx context.Context, callID int64, userID int64) (*Call, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Joining group call: id=%d, user=%d", callID, userID)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return nil, fmt.Errorf("call not found: %w", err)
	}

	if !call.IsGroup {
		return nil, fmt.Errorf("not a group call")
	}

	if call.State != CallStateConfirmed {
		return nil, fmt.Errorf("call not active: state=%v", call.State)
	}

	// Check participant limit
	if len(call.Participants) >= m.config.MaxParticipants {
		return nil, fmt.Errorf("call is full")
	}

	// Add participant
	participant := &CallParticipant{
		UserID:        userID,
		Date:          int(time.Now().Unix()),
		Source:        len(call.Participants),
		Muted:         false,
		Left:          false,
		CanSelfUnmute: true,
		JustJoined:    true,
		Versioned:     true,
		Min:           false,
		MutedByYou:    false,
		VolumeByAdmin: false,
		Self:          false,
	}

	call.Participants = append(call.Participants, participant)

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return nil, fmt.Errorf("failed to update call: %w", err)
	}

	m.logger.Infof("Joined group call: id=%d, user=%d", call.ID, userID)
	return call, nil
}

// LeaveGroupCall leaves a group call
func (m *CallManager) LeaveGroupCall(ctx context.Context, callID int64, userID int64) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Leaving group call: id=%d, user=%d", callID, userID)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return fmt.Errorf("call not found: %w", err)
	}

	// Find and update participant
	for _, participant := range call.Participants {
		if participant.UserID == userID {
			participant.Left = true
			break
		}
	}

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return fmt.Errorf("failed to update call: %w", err)
	}

	m.logger.Infof("Left group call: id=%d, user=%d", call.ID, userID)
	return nil
}

// ToggleParticipantMute toggles participant mute status
func (m *CallManager) ToggleParticipantMute(ctx context.Context, callID int64, userID int64, muted bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Infof("Toggling participant mute: call=%d, user=%d, muted=%v", callID, userID, muted)

	// Get call
	call, err := m.callStore.GetCall(callID)
	if err != nil {
		return fmt.Errorf("call not found: %w", err)
	}

	// Find and update participant
	for _, participant := range call.Participants {
		if participant.UserID == userID {
			participant.Muted = muted
			break
		}
	}

	// Store updated call
	err = m.callStore.UpdateCall(call)
	if err != nil {
		return fmt.Errorf("failed to update call: %w", err)
	}

	return nil
}

// Helper methods

func (m *CallManager) generateCallID() int64 {
	return time.Now().UnixNano()
}

func (m *CallManager) generateAccessHash() int64 {
	hash := make([]byte, 8)
	rand.Read(hash)
	return int64(binary.LittleEndian.Uint64(hash))
}

func (m *CallManager) generateKeyPair() ([]byte, []byte, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	// For simplicity, using the same key as public key
	// In real implementation, use proper key generation
	publicKey := make([]byte, 32)
	copy(publicKey, privateKey)

	return privateKey, publicKey, nil
}

func (m *CallManager) calculateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	// For simplicity, using XOR
	// In real implementation, use proper key exchange
	sharedSecret := make([]byte, 32)
	for i := 0; i < 32; i++ {
		sharedSecret[i] = privateKey[i] ^ publicKey[i]
	}
	return sharedSecret, nil
}

func (m *CallManager) calculateFingerprint(key []byte) int64 {
	// Simple fingerprint calculation
	var fingerprint int64
	for i, b := range key {
		fingerprint += int64(b) * int64(i+1)
	}
	return fingerprint
}

func (m *CallManager) createCallProtocol() *CallProtocol {
	return &CallProtocol{
		UDPP2P:          true,
		UDPReflector:    true,
		MinLayer:        65,
		MaxLayer:        139,
		LibraryVersions: []string{"2.4.4"},
	}
}

func (m *CallManager) createCallConnections() []*CallConnection {
	return []*CallConnection{
		{
			ID:      "1",
			Type:    "udp",
			IP:      "127.0.0.1",
			Port:    8080,
			PeerTag: []byte{1, 2, 3, 4},
			IsRelay: false,
		},
	}
}

func (m *CallManager) monitorCall(callID int64) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-ticker.C:
			// Check call duration
			if time.Since(startTime) > m.config.MaxCallDuration {
				m.DiscardCall(context.Background(), callID, "timeout")
				return
			}

			// Check if call still exists
			call, err := m.callStore.GetCall(callID)
			if err != nil || call.State == CallStateDiscarded {
				return
			}
		}
	}
}

// NewCallStore creates a new call store
func NewCallStore(config *Config) *CallStore {
	return &CallStore{
		config: config,
		calls:  make(map[int64]*Call),
	}
}

// StoreCall stores a call
func (cs *CallStore) StoreCall(call *Call) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.calls[call.ID] = call
	return nil
}

// GetCall gets a call
func (cs *CallStore) GetCall(callID int64) (*Call, error) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	call, exists := cs.calls[callID]
	if !exists {
		return nil, fmt.Errorf("call not found")
	}

	return call, nil
}

// UpdateCall updates a call
func (cs *CallStore) UpdateCall(call *Call) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.calls[call.ID] = call
	return nil
}

// NewMediaEngine creates a new media engine
func NewMediaEngine(config *Config) *MediaEngine {
	return &MediaEngine{
		config: config,
	}
}

// NewSignalingServer creates a new signaling server
func NewSignalingServer(config *Config) *SignalingServer {
	return &SignalingServer{
		config: config,
	}
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxCallDuration:     30 * time.Minute,
		MaxParticipants:     200,
		EnableVideoCalls:    true,
		EnableGroupCalls:    true,
		EnableScreenShare:   true,
		EnableCallRecording: false,
		AudioCodec:          "opus",
		VideoCodec:          "h264",
		AudioBitrate:        64000,
		VideoBitrate:        500000,
		AudioSampleRate:     48000,
		VideoFrameRate:      30,
		STUNServers:         []string{"stun:stun.l.google.com:19302"},
		TURNServers:         []string{},
		ICEConfig: &ICEConfig{
			ICEUfrag: "iceufrag",
			ICEPwd:   "icepwd",
			ICELite:  false,
		},
		CallCacheSize: 1024,
		CallCacheTTL:  24 * time.Hour,
	}
}
