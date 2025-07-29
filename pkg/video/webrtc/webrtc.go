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

package webrtc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// WebRTCManager manages WebRTC connections
type WebRTCManager struct {
	config      *WebRTCConfig
	connections map[string]*EnhancedPeerConnection
	mutex       sync.RWMutex
	logger      logx.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	isRunning   bool
}

// WebRTCConfig represents WebRTC configuration
type WebRTCConfig struct {
	ICEServers        []ICEServer `json:"ice_servers"`
	EnableVideo       bool        `json:"enable_video"`
	EnableAudio       bool        `json:"enable_audio"`
	EnableDataChannel bool        `json:"enable_data_channel"`
	VideoCodec        string      `json:"video_codec"`
	AudioCodec        string      `json:"audio_codec"`
	Bitrate           int         `json:"bitrate"`
	FrameRate         int         `json:"frame_rate"`
	Resolution        Resolution  `json:"resolution"`
}

// ICEServer represents an ICE server configuration
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Resolution represents video resolution
type Resolution struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// EnhancedPeerConnection represents an enhanced peer connection
type EnhancedPeerConnection struct {
	ID                 string                  `json:"id"`
	PeerConnection     *PeerConnection         `json:"-"`
	LocalDescription   *SessionDescription     `json:"local_description"`
	RemoteDescription  *SessionDescription     `json:"remote_description"`
	ICECandidates      []*ICECandidate         `json:"ice_candidates"`
	ConnectionState    PeerConnectionState     `json:"connection_state"`
	ICEConnectionState ICEConnectionState      `json:"ice_connection_state"`
	SignalingState     SignalingState          `json:"signaling_state"`
	DataChannels       map[string]*DataChannel `json:"-"`
	MediaStreams       map[string]*MediaStream `json:"-"`
	CreatedAt          time.Time               `json:"created_at"`
	LastActivity       time.Time               `json:"last_activity"`
	mutex              sync.RWMutex
}

// PeerConnection represents a WebRTC peer connection
type PeerConnection struct {
	ID    string
	State PeerConnectionState
}

// SessionDescription represents a session description
type SessionDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

// ICECandidate represents an ICE candidate
type ICECandidate struct {
	Candidate     string `json:"candidate"`
	SDPMid        string `json:"sdp_mid"`
	SDPMLineIndex int    `json:"sdp_mline_index"`
}

// DataChannel represents a WebRTC data channel
type DataChannel struct {
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

// MediaStream represents a media stream
type MediaStream struct {
	ID     string        `json:"id"`
	Tracks []*MediaTrack `json:"tracks"`
}

// MediaTrack represents a media track
type MediaTrack struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// WebRTC state enums
type PeerConnectionState string
type ICEConnectionState string
type SignalingState string

const (
	PeerConnectionStateNew          PeerConnectionState = "new"
	PeerConnectionStateConnecting   PeerConnectionState = "connecting"
	PeerConnectionStateConnected    PeerConnectionState = "connected"
	PeerConnectionStateDisconnected PeerConnectionState = "disconnected"
	PeerConnectionStateFailed       PeerConnectionState = "failed"
	PeerConnectionStateClosed       PeerConnectionState = "closed"

	ICEConnectionStateNew          ICEConnectionState = "new"
	ICEConnectionStateChecking     ICEConnectionState = "checking"
	ICEConnectionStateConnected    ICEConnectionState = "connected"
	ICEConnectionStateCompleted    ICEConnectionState = "completed"
	ICEConnectionStateFailed       ICEConnectionState = "failed"
	ICEConnectionStateDisconnected ICEConnectionState = "disconnected"
	ICEConnectionStateClosed       ICEConnectionState = "closed"

	SignalingStateStable             SignalingState = "stable"
	SignalingStateHaveLocalOffer     SignalingState = "have-local-offer"
	SignalingStateHaveRemoteOffer    SignalingState = "have-remote-offer"
	SignalingStateHaveLocalPranswer  SignalingState = "have-local-pranswer"
	SignalingStateHaveRemotePranswer SignalingState = "have-remote-pranswer"
	SignalingStateClosed             SignalingState = "closed"
)

// NewWebRTCManager creates a new WebRTC manager
func NewWebRTCManager(config *WebRTCConfig, e2eeManager interface{}, securityManager interface{}) (*WebRTCManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &WebRTCManager{
		config:      config,
		connections: make(map[string]*EnhancedPeerConnection),
		logger:      logx.WithContext(ctx),
		ctx:         ctx,
		cancel:      cancel,
	}

	return manager, nil
}

// DefaultWebRTCConfig returns default WebRTC configuration
func DefaultWebRTCConfig() *WebRTCConfig {
	return &WebRTCConfig{
		ICEServers: []ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
		EnableVideo:       true,
		EnableAudio:       true,
		EnableDataChannel: true,
		VideoCodec:        "VP8",
		AudioCodec:        "OPUS",
		Bitrate:           1000000, // 1 Mbps
		FrameRate:         30,
		Resolution: Resolution{
			Width:  1280,
			Height: 720,
		},
	}
}

// Start starts the WebRTC manager
func (m *WebRTCManager) Start() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.isRunning {
		return errors.New("WebRTC manager is already running")
	}

	m.logger.Info("Starting WebRTC manager...")
	m.isRunning = true
	m.logger.Info("WebRTC manager started successfully")

	return nil
}

// Stop stops the WebRTC manager
func (m *WebRTCManager) Stop() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isRunning {
		return nil
	}

	m.logger.Info("Stopping WebRTC manager...")
	m.cancel()

	// Close all connections
	for _, conn := range m.connections {
		conn.Close()
	}

	m.isRunning = false
	m.logger.Info("WebRTC manager stopped")

	return nil
}

// CreatePeerConnection creates a new peer connection
func (m *WebRTCManager) CreatePeerConnection(id string) (*EnhancedPeerConnection, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.connections[id]; exists {
		return nil, fmt.Errorf("peer connection with ID %s already exists", id)
	}

	conn := &EnhancedPeerConnection{
		ID: id,
		PeerConnection: &PeerConnection{
			ID:    id,
			State: PeerConnectionStateNew,
		},
		ConnectionState:    PeerConnectionStateNew,
		ICEConnectionState: ICEConnectionStateNew,
		SignalingState:     SignalingStateStable,
		DataChannels:       make(map[string]*DataChannel),
		MediaStreams:       make(map[string]*MediaStream),
		CreatedAt:          time.Now(),
		LastActivity:       time.Now(),
	}

	m.connections[id] = conn
	m.logger.Infof("Created peer connection: %s", id)

	return conn, nil
}

// GetPeerConnection gets a peer connection by ID
func (m *WebRTCManager) GetPeerConnection(id string) (*EnhancedPeerConnection, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	conn, exists := m.connections[id]
	if !exists {
		return nil, fmt.Errorf("peer connection with ID %s not found", id)
	}

	return conn, nil
}

// RemovePeerConnection removes a peer connection
func (m *WebRTCManager) RemovePeerConnection(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	conn, exists := m.connections[id]
	if !exists {
		return fmt.Errorf("peer connection with ID %s not found", id)
	}

	conn.Close()
	delete(m.connections, id)
	m.logger.Infof("Removed peer connection: %s", id)

	return nil
}

// EnhancedPeerConnection methods

// Close closes the peer connection
func (c *EnhancedPeerConnection) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.ConnectionState = PeerConnectionStateClosed
	c.ICEConnectionState = ICEConnectionStateClosed
	c.SignalingState = SignalingStateClosed

	// Close data channels
	for _, dc := range c.DataChannels {
		dc.State = "closed"
	}

	return nil
}

// SetLocalDescription sets the local description
func (c *EnhancedPeerConnection) SetLocalDescription(desc *SessionDescription) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.LocalDescription = desc
	c.LastActivity = time.Now()

	return nil
}

// SetRemoteDescription sets the remote description
func (c *EnhancedPeerConnection) SetRemoteDescription(desc *SessionDescription) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.RemoteDescription = desc
	c.LastActivity = time.Now()

	return nil
}

// AddICECandidate adds an ICE candidate
func (c *EnhancedPeerConnection) AddICECandidate(candidate *ICECandidate) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.ICECandidates = append(c.ICECandidates, candidate)
	c.LastActivity = time.Now()

	return nil
}

// CreateDataChannel creates a data channel
func (c *EnhancedPeerConnection) CreateDataChannel(label string) (*DataChannel, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.DataChannels[label]; exists {
		return nil, fmt.Errorf("data channel with label %s already exists", label)
	}

	dc := &DataChannel{
		Label:    label,
		Protocol: "sctp",
		State:    "open",
	}

	c.DataChannels[label] = dc
	c.LastActivity = time.Now()

	return dc, nil
}

// AddMediaStream adds a media stream
func (c *EnhancedPeerConnection) AddMediaStream(stream *MediaStream) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.MediaStreams[stream.ID] = stream
	c.LastActivity = time.Now()

	return nil
}

// GetConnectionState returns the connection state
func (c *EnhancedPeerConnection) GetConnectionState() PeerConnectionState {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.ConnectionState
}

// UpdateConnectionState updates the connection state
func (c *EnhancedPeerConnection) UpdateConnectionState(state PeerConnectionState) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.ConnectionState = state
	c.LastActivity = time.Now()
}
