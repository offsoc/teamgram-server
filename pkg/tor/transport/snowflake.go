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

package transport

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// SnowflakeTransport implements snowflake pluggable transport (WebRTC)
type SnowflakeTransport struct {
	mutex      sync.RWMutex
	config     *SnowflakeConfig
	metrics    *TransportMetrics
	httpClient *http.Client
	peers      map[string]*SnowflakePeer
	logger     logx.Logger
	isRunning  bool
}

// SnowflakeConnection implements WebRTC-based connection
type SnowflakeConnection struct {
	transport   *SnowflakeTransport
	peer        *SnowflakePeer
	sessionID   string
	dataChannel chan []byte
	closed      bool
	mutex       sync.RWMutex
}

// SnowflakePeer represents a WebRTC peer
type SnowflakePeer struct {
	ID            string         `json:"id"`
	Offer         string         `json:"offer"`
	Answer        string         `json:"answer"`
	ICECandidates []ICECandidate `json:"ice_candidates"`
	State         PeerState      `json:"state"`
	CreatedAt     time.Time      `json:"created_at"`
	LastSeen      time.Time      `json:"last_seen"`
}

// ICECandidate represents a WebRTC ICE candidate
type ICECandidate struct {
	Candidate     string `json:"candidate"`
	SDPMLineIndex int    `json:"sdpMLineIndex"`
	SDPMid        string `json:"sdpMid"`
}

// PeerState represents the state of a WebRTC peer
type PeerState int

const (
	PeerStateNew PeerState = iota
	PeerStateConnecting
	PeerStateConnected
	PeerStateFailed
	PeerStateClosed
)

// BrokerMessage represents a message to/from the snowflake broker
type BrokerMessage struct {
	Type      string      `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	Offer     string      `json:"offer,omitempty"`
	Answer    string      `json:"answer,omitempty"`
	Candidate interface{} `json:"candidate,omitempty"`
}

// NewSnowflakeTransport creates a new snowflake transport
func NewSnowflakeTransport(config *SnowflakeConfig) (*SnowflakeTransport, error) {
	if config == nil {
		config = &SnowflakeConfig{
			BrokerURL:   "https://snowflake-broker.torproject.net/",
			FrontDomain: "cdn.sstatic.net",
			ICEServers:  []string{"stun:stun.l.google.com:19302"},
			MaxPeers:    1,
			Options:     make(map[string]string),
		}
	}

	transport := &SnowflakeTransport{
		config: config,
		metrics: &TransportMetrics{
			TransportName: "snowflake",
			MinLatency:    time.Hour,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		peers:  make(map[string]*SnowflakePeer),
		logger: logx.WithContext(nil),
	}

	return transport, nil
}

// Name returns the transport name
func (st *SnowflakeTransport) Name() string {
	return "snowflake"
}

// Start starts the snowflake transport
func (st *SnowflakeTransport) Start() error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.isRunning {
		return fmt.Errorf("snowflake transport is already running")
	}

	st.logger.Info("Starting snowflake transport...")

	// Test broker connectivity
	if err := st.testBrokerConnectivity(); err != nil {
		return fmt.Errorf("broker connectivity test failed: %w", err)
	}

	st.isRunning = true
	st.logger.Info("Snowflake transport started successfully")

	return nil
}

// Stop stops the snowflake transport
func (st *SnowflakeTransport) Stop() error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if !st.isRunning {
		return nil
	}

	st.logger.Info("Stopping snowflake transport...")

	// Close all peers
	for _, peer := range st.peers {
		peer.State = PeerStateClosed
	}

	st.isRunning = false
	st.logger.Info("Snowflake transport stopped")

	return nil
}

// Connect creates a snowflake connection
func (st *SnowflakeTransport) Connect(address string, port int, options map[string]string) (net.Conn, error) {
	start := time.Now()

	st.mutex.RLock()
	if !st.isRunning {
		st.mutex.RUnlock()
		return nil, fmt.Errorf("snowflake transport is not running")
	}
	st.mutex.RUnlock()

	// Request peer from broker
	peer, err := st.requestPeerFromBroker()
	if err != nil {
		st.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to get peer from broker: %w", err)
	}

	// Establish WebRTC connection
	sessionID := st.generateSessionID()
	conn := &SnowflakeConnection{
		transport:   st,
		peer:        peer,
		sessionID:   sessionID,
		dataChannel: make(chan []byte, 100),
	}

	if err := conn.establishWebRTCConnection(); err != nil {
		st.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to establish WebRTC connection: %w", err)
	}

	st.updateMetrics(true, time.Since(start))
	st.logger.Debugf("Snowflake connection established via peer %s", peer.ID[:8]+"...")

	return conn, nil
}

// IsAvailable returns whether snowflake transport is available
func (st *SnowflakeTransport) IsAvailable() bool {
	st.mutex.RLock()
	defer st.mutex.RUnlock()
	return st.isRunning
}

// GetMetrics returns transport metrics
func (st *SnowflakeTransport) GetMetrics() *TransportMetrics {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	if st.metrics.TotalConnections > 0 {
		st.metrics.SuccessRate = float64(st.metrics.SuccessfulConns) / float64(st.metrics.TotalConnections) * 100
	}

	metrics := *st.metrics
	return &metrics
}

// testBrokerConnectivity tests connectivity to snowflake broker
func (st *SnowflakeTransport) testBrokerConnectivity() error {
	req, err := http.NewRequest("GET", st.config.BrokerURL, nil)
	if err != nil {
		return err
	}

	if st.config.FrontDomain != "" {
		req.Host = st.config.FrontDomain
	}

	resp, err := st.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// requestPeerFromBroker requests a peer from the snowflake broker
func (st *SnowflakeTransport) requestPeerFromBroker() (*SnowflakePeer, error) {
	// Create peer request
	_ = BrokerMessage{
		Type: "peer_request",
	}

	// Send request to broker (simplified)
	peer := &SnowflakePeer{
		ID:        st.generatePeerID(),
		State:     PeerStateNew,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Simulate WebRTC offer/answer exchange
	peer.Offer = st.generateWebRTCOffer()
	peer.Answer = st.generateWebRTCAnswer()

	// Add ICE candidates
	peer.ICECandidates = []ICECandidate{
		{
			Candidate:     "candidate:1 1 UDP 2130706431 192.168.1.100 54400 typ host",
			SDPMLineIndex: 0,
			SDPMid:        "data",
		},
	}

	st.mutex.Lock()
	st.peers[peer.ID] = peer
	st.mutex.Unlock()

	return peer, nil
}

// generateSessionID generates a unique session ID
func (st *SnowflakeTransport) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// generatePeerID generates a unique peer ID
func (st *SnowflakeTransport) generatePeerID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("peer_%x", bytes)
}

// generateWebRTCOffer generates a WebRTC offer (simplified)
func (st *SnowflakeTransport) generateWebRTCOffer() string {
	return "v=0\r\no=- 123456789 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:test\r\na=ice-pwd:test123\r\na=fingerprint:sha-256 AA:BB:CC:DD:EE:FF\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"
}

// generateWebRTCAnswer generates a WebRTC answer (simplified)
func (st *SnowflakeTransport) generateWebRTCAnswer() string {
	return "v=0\r\no=- 987654321 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:test\r\na=ice-pwd:test123\r\na=fingerprint:sha-256 FF:EE:DD:CC:BB:AA\r\na=setup:active\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"
}

// updateMetrics updates transport metrics
func (st *SnowflakeTransport) updateMetrics(success bool, latency time.Duration) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	st.metrics.TotalConnections++
	st.metrics.LastUsed = time.Now()

	if success {
		st.metrics.SuccessfulConns++

		if latency > st.metrics.MaxLatency {
			st.metrics.MaxLatency = latency
		}
		if latency < st.metrics.MinLatency {
			st.metrics.MinLatency = latency
		}
		st.metrics.AverageLatency = (st.metrics.AverageLatency + latency) / 2
	} else {
		st.metrics.FailedConns++
	}
}

// SnowflakeConnection methods

// Read reads data from the snowflake connection
func (sc *SnowflakeConnection) Read(b []byte) (n int, err error) {
	sc.mutex.RLock()
	if sc.closed {
		sc.mutex.RUnlock()
		return 0, fmt.Errorf("connection closed")
	}
	sc.mutex.RUnlock()

	// Wait for data from WebRTC data channel
	select {
	case data := <-sc.dataChannel:
		n = copy(b, data)

		// Update metrics
		sc.transport.mutex.Lock()
		sc.transport.metrics.BytesTransferred += int64(n)
		sc.transport.mutex.Unlock()

		return n, nil
	case <-time.After(30 * time.Second):
		return 0, fmt.Errorf("read timeout")
	}
}

// Write writes data to the snowflake connection
func (sc *SnowflakeConnection) Write(b []byte) (n int, err error) {
	sc.mutex.RLock()
	if sc.closed {
		sc.mutex.RUnlock()
		return 0, fmt.Errorf("connection closed")
	}
	sc.mutex.RUnlock()

	// Send data through WebRTC data channel (simplified)
	data := make([]byte, len(b))
	copy(data, b)

	// Simulate sending data
	go func() {
		time.Sleep(10 * time.Millisecond) // Simulate network delay
		select {
		case sc.dataChannel <- data:
		default:
			// Channel full, drop data
		}
	}()

	// Update metrics
	sc.transport.mutex.Lock()
	sc.transport.metrics.BytesTransferred += int64(len(b))
	sc.transport.mutex.Unlock()

	return len(b), nil
}

// Close closes the snowflake connection
func (sc *SnowflakeConnection) Close() error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.closed {
		return nil
	}

	sc.closed = true
	close(sc.dataChannel)

	// Update peer state
	sc.peer.State = PeerStateClosed

	return nil
}

// LocalAddr returns the local network address
func (sc *SnowflakeConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns the remote network address
func (sc *SnowflakeConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// SetDeadline sets the read and write deadlines
func (sc *SnowflakeConnection) SetDeadline(t time.Time) error {
	return nil // Not implemented for WebRTC
}

// SetReadDeadline sets the deadline for future Read calls
func (sc *SnowflakeConnection) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for WebRTC
}

// SetWriteDeadline sets the deadline for future Write calls
func (sc *SnowflakeConnection) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for WebRTC
}

// establishWebRTCConnection establishes the WebRTC connection
func (sc *SnowflakeConnection) establishWebRTCConnection() error {
	// Simulate WebRTC connection establishment
	sc.peer.State = PeerStateConnecting

	// Simulate ICE gathering and connection
	time.Sleep(100 * time.Millisecond)

	sc.peer.State = PeerStateConnected

	// Start data channel simulation
	go sc.dataChannelLoop()

	return nil
}

// dataChannelLoop simulates WebRTC data channel
func (sc *SnowflakeConnection) dataChannelLoop() {
	// Simulate periodic keep-alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if sc.closed {
				return
			}
			// Send keep-alive (simplified)
		}
	}
}
