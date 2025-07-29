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
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Obfs4Transport implements obfs4 pluggable transport
type Obfs4Transport struct {
	mutex       sync.RWMutex
	config      *Obfs4Config
	metrics     *TransportMetrics
	logger      logx.Logger
	isRunning   bool
}

// Obfs4Connection wraps a connection with obfs4 obfuscation
type Obfs4Connection struct {
	conn        net.Conn
	transport   *Obfs4Transport
	obfuscator  *Obfs4Obfuscator
	isHandshaken bool
}

// Obfs4Obfuscator handles obfs4 protocol obfuscation
type Obfs4Obfuscator struct {
	nodeID      []byte
	publicKey   []byte
	privateKey  []byte
	sessionKey  []byte
	iatMode     int
	padding     *PaddingMachine
}

// PaddingMachine handles inter-arrival time obfuscation
type PaddingMachine struct {
	enabled     bool
	maxPadding  int
	burstLength int
}

// NewObfs4Transport creates a new obfs4 transport
func NewObfs4Transport(config *Obfs4Config) (*Obfs4Transport, error) {
	if config == nil {
		config = &Obfs4Config{
			IatMode: 0,
			Options: make(map[string]string),
		}
	}
	
	transport := &Obfs4Transport{
		config: config,
		metrics: &TransportMetrics{
			TransportName: "obfs4",
			MinLatency:    time.Hour, // Initialize to high value
		},
		logger: logx.WithContext(nil),
	}
	
	return transport, nil
}

// Name returns the transport name
func (ot *Obfs4Transport) Name() string {
	return "obfs4"
}

// Start starts the obfs4 transport
func (ot *Obfs4Transport) Start() error {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()
	
	if ot.isRunning {
		return fmt.Errorf("obfs4 transport is already running")
	}
	
	ot.logger.Info("Starting obfs4 transport...")
	
	// Initialize obfs4 parameters
	if err := ot.initializeObfs4(); err != nil {
		return fmt.Errorf("failed to initialize obfs4: %w", err)
	}
	
	ot.isRunning = true
	ot.logger.Info("Obfs4 transport started successfully")
	
	return nil
}

// Stop stops the obfs4 transport
func (ot *Obfs4Transport) Stop() error {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()
	
	if !ot.isRunning {
		return nil
	}
	
	ot.logger.Info("Stopping obfs4 transport...")
	ot.isRunning = false
	ot.logger.Info("Obfs4 transport stopped")
	
	return nil
}

// Connect creates an obfs4 connection
func (ot *Obfs4Transport) Connect(address string, port int, options map[string]string) (net.Conn, error) {
	start := time.Now()
	
	ot.mutex.RLock()
	if !ot.isRunning {
		ot.mutex.RUnlock()
		return nil, fmt.Errorf("obfs4 transport is not running")
	}
	ot.mutex.RUnlock()
	
	// Create underlying TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", address, port), 30*time.Second)
	if err != nil {
		ot.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}
	
	// Create obfs4 obfuscator
	obfuscator, err := ot.createObfuscator(options)
	if err != nil {
		conn.Close()
		ot.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to create obfuscator: %w", err)
	}
	
	// Wrap connection with obfs4
	obfs4Conn := &Obfs4Connection{
		conn:       conn,
		transport:  ot,
		obfuscator: obfuscator,
	}
	
	// Perform obfs4 handshake
	if err := obfs4Conn.performHandshake(); err != nil {
		conn.Close()
		ot.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("obfs4 handshake failed: %w", err)
	}
	
	ot.updateMetrics(true, time.Since(start))
	ot.logger.Debugf("Obfs4 connection established to %s:%d", address, port)
	
	return obfs4Conn, nil
}

// IsAvailable returns whether obfs4 transport is available
func (ot *Obfs4Transport) IsAvailable() bool {
	ot.mutex.RLock()
	defer ot.mutex.RUnlock()
	return ot.isRunning
}

// GetMetrics returns transport metrics
func (ot *Obfs4Transport) GetMetrics() *TransportMetrics {
	ot.mutex.RLock()
	defer ot.mutex.RUnlock()
	
	// Update success rate
	if ot.metrics.TotalConnections > 0 {
		ot.metrics.SuccessRate = float64(ot.metrics.SuccessfulConns) / float64(ot.metrics.TotalConnections) * 100
	}
	
	// Return a copy
	metrics := *ot.metrics
	return &metrics
}

// initializeObfs4 initializes obfs4 parameters
func (ot *Obfs4Transport) initializeObfs4() error {
	// Generate node ID if not provided
	if ot.config.NodeID == "" {
		nodeID := make([]byte, 20)
		rand.Read(nodeID)
		ot.config.NodeID = fmt.Sprintf("%x", nodeID)
	}
	
	// Generate public/private key pair if not provided
	if ot.config.PublicKey == "" {
		publicKey := make([]byte, 32)
		rand.Read(publicKey)
		ot.config.PublicKey = fmt.Sprintf("%x", publicKey)
	}
	
	ot.logger.Debugf("Initialized obfs4 with node ID: %s", ot.config.NodeID[:16]+"...")
	return nil
}

// createObfuscator creates an obfs4 obfuscator
func (ot *Obfs4Transport) createObfuscator(options map[string]string) (*Obfs4Obfuscator, error) {
	// Parse node ID
	nodeID := make([]byte, 20)
	rand.Read(nodeID) // Simplified
	
	// Parse public key
	publicKey := make([]byte, 32)
	rand.Read(publicKey) // Simplified
	
	// Generate session key
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	
	obfuscator := &Obfs4Obfuscator{
		nodeID:     nodeID,
		publicKey:  publicKey,
		sessionKey: sessionKey,
		iatMode:    ot.config.IatMode,
		padding: &PaddingMachine{
			enabled:     ot.config.IatMode > 0,
			maxPadding:  1500,
			burstLength: 16,
		},
	}
	
	return obfuscator, nil
}

// updateMetrics updates transport metrics
func (ot *Obfs4Transport) updateMetrics(success bool, latency time.Duration) {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()
	
	ot.metrics.TotalConnections++
	ot.metrics.LastUsed = time.Now()
	
	if success {
		ot.metrics.SuccessfulConns++
		
		// Update latency metrics
		if latency > ot.metrics.MaxLatency {
			ot.metrics.MaxLatency = latency
		}
		if latency < ot.metrics.MinLatency {
			ot.metrics.MinLatency = latency
		}
		ot.metrics.AverageLatency = (ot.metrics.AverageLatency + latency) / 2
	} else {
		ot.metrics.FailedConns++
	}
}

// Obfs4Connection methods

// Read reads data from the obfs4 connection
func (oc *Obfs4Connection) Read(b []byte) (n int, err error) {
	// Read from underlying connection
	n, err = oc.conn.Read(b)
	if err != nil {
		return n, err
	}
	
	// Deobfuscate data
	if oc.isHandshaken {
		oc.deobfuscateData(b[:n])
	}
	
	// Update metrics
	oc.transport.mutex.Lock()
	oc.transport.metrics.BytesTransferred += int64(n)
	oc.transport.mutex.Unlock()
	
	return n, err
}

// Write writes data to the obfs4 connection
func (oc *Obfs4Connection) Write(b []byte) (n int, err error) {
	// Obfuscate data
	obfuscatedData := make([]byte, len(b))
	copy(obfuscatedData, b)
	
	if oc.isHandshaken {
		oc.obfuscateData(obfuscatedData)
	}
	
	// Write to underlying connection
	n, err = oc.conn.Write(obfuscatedData)
	
	// Update metrics
	oc.transport.mutex.Lock()
	oc.transport.metrics.BytesTransferred += int64(n)
	oc.transport.mutex.Unlock()
	
	return n, err
}

// Close closes the obfs4 connection
func (oc *Obfs4Connection) Close() error {
	return oc.conn.Close()
}

// LocalAddr returns the local network address
func (oc *Obfs4Connection) LocalAddr() net.Addr {
	return oc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (oc *Obfs4Connection) RemoteAddr() net.Addr {
	return oc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (oc *Obfs4Connection) SetDeadline(t time.Time) error {
	return oc.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
func (oc *Obfs4Connection) SetReadDeadline(t time.Time) error {
	return oc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
func (oc *Obfs4Connection) SetWriteDeadline(t time.Time) error {
	return oc.conn.SetWriteDeadline(t)
}

// performHandshake performs the obfs4 handshake
func (oc *Obfs4Connection) performHandshake() error {
	// Generate handshake data
	handshakeData := make([]byte, 64)
	rand.Read(handshakeData)
	
	// Add obfs4 magic bytes
	copy(handshakeData[:4], []byte("obfs"))
	
	// Send handshake
	if _, err := oc.conn.Write(handshakeData); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}
	
	// Receive handshake response
	response := make([]byte, 64)
	if _, err := oc.conn.Read(response); err != nil {
		return fmt.Errorf("failed to receive handshake response: %w", err)
	}
	
	// Verify handshake (simplified)
	if len(response) < 4 {
		return fmt.Errorf("invalid handshake response")
	}
	
	oc.isHandshaken = true
	return nil
}

// obfuscateData obfuscates outgoing data
func (oc *Obfs4Connection) obfuscateData(data []byte) {
	// Simple XOR obfuscation with session key
	for i := 0; i < len(data); i++ {
		data[i] ^= oc.obfuscator.sessionKey[i%len(oc.obfuscator.sessionKey)]
	}
	
	// Add padding if IAT mode is enabled
	if oc.obfuscator.padding.enabled {
		oc.addPadding(data)
	}
}

// deobfuscateData deobfuscates incoming data
func (oc *Obfs4Connection) deobfuscateData(data []byte) {
	// Remove padding if IAT mode is enabled
	if oc.obfuscator.padding.enabled {
		oc.removePadding(data)
	}
	
	// Simple XOR deobfuscation with session key
	for i := 0; i < len(data); i++ {
		data[i] ^= oc.obfuscator.sessionKey[i%len(oc.obfuscator.sessionKey)]
	}
}

// addPadding adds padding for inter-arrival time obfuscation
func (oc *Obfs4Connection) addPadding(data []byte) {
	// Simplified padding implementation
	// In real implementation, this would add sophisticated timing obfuscation
}

// removePadding removes padding from incoming data
func (oc *Obfs4Connection) removePadding(data []byte) {
	// Simplified padding removal
	// In real implementation, this would remove timing obfuscation padding
}
