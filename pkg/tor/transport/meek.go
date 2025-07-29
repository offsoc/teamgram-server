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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// MeekTransport implements meek pluggable transport (HTTP tunneling)
type MeekTransport struct {
	mutex       sync.RWMutex
	config      *MeekConfig
	metrics     *TransportMetrics
	httpClient  *http.Client
	logger      logx.Logger
	isRunning   bool
}

// MeekConnection implements HTTP tunneling connection
type MeekConnection struct {
	transport    *MeekTransport
	sessionID    string
	readBuffer   *bytes.Buffer
	writeBuffer  *bytes.Buffer
	pollTicker   *time.Ticker
	closed       bool
	mutex        sync.RWMutex
}

// NewMeekTransport creates a new meek transport
func NewMeekTransport(config *MeekConfig) (*MeekTransport, error) {
	if config == nil {
		config = &MeekConfig{
			URL:        "https://meek.azureedge.net/",
			Front:      "ajax.aspnetcdn.com",
			MaxPadding: 1500,
			Options:    make(map[string]string),
		}
	}
	
	transport := &MeekTransport{
		config: config,
		metrics: &TransportMetrics{
			TransportName: "meek",
			MinLatency:    time.Hour,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: false,
				MaxIdleConns:      10,
				IdleConnTimeout:   90 * time.Second,
			},
		},
		logger: logx.WithContext(nil),
	}
	
	return transport, nil
}

// Name returns the transport name
func (mt *MeekTransport) Name() string {
	return "meek"
}

// Start starts the meek transport
func (mt *MeekTransport) Start() error {
	mt.mutex.Lock()
	defer mt.mutex.Unlock()
	
	if mt.isRunning {
		return fmt.Errorf("meek transport is already running")
	}
	
	mt.logger.Info("Starting meek transport...")
	
	// Test connectivity to meek server
	if err := mt.testConnectivity(); err != nil {
		return fmt.Errorf("meek connectivity test failed: %w", err)
	}
	
	mt.isRunning = true
	mt.logger.Info("Meek transport started successfully")
	
	return nil
}

// Stop stops the meek transport
func (mt *MeekTransport) Stop() error {
	mt.mutex.Lock()
	defer mt.mutex.Unlock()
	
	if !mt.isRunning {
		return nil
	}
	
	mt.logger.Info("Stopping meek transport...")
	mt.isRunning = false
	mt.logger.Info("Meek transport stopped")
	
	return nil
}

// Connect creates a meek connection
func (mt *MeekTransport) Connect(address string, port int, options map[string]string) (net.Conn, error) {
	start := time.Now()
	
	mt.mutex.RLock()
	if !mt.isRunning {
		mt.mutex.RUnlock()
		return nil, fmt.Errorf("meek transport is not running")
	}
	mt.mutex.RUnlock()
	
	// Generate session ID
	sessionID := mt.generateSessionID()
	
	// Create meek connection
	conn := &MeekConnection{
		transport:   mt,
		sessionID:   sessionID,
		readBuffer:  bytes.NewBuffer(nil),
		writeBuffer: bytes.NewBuffer(nil),
		pollTicker:  time.NewTicker(1 * time.Second),
	}
	
	// Start polling for data
	go conn.pollLoop()
	
	// Establish session
	if err := conn.establishSession(address, port); err != nil {
		conn.Close()
		mt.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to establish meek session: %w", err)
	}
	
	mt.updateMetrics(true, time.Since(start))
	mt.logger.Debugf("Meek connection established with session %s", sessionID[:8]+"...")
	
	return conn, nil
}

// IsAvailable returns whether meek transport is available
func (mt *MeekTransport) IsAvailable() bool {
	mt.mutex.RLock()
	defer mt.mutex.RUnlock()
	return mt.isRunning
}

// GetMetrics returns transport metrics
func (mt *MeekTransport) GetMetrics() *TransportMetrics {
	mt.mutex.RLock()
	defer mt.mutex.RUnlock()
	
	if mt.metrics.TotalConnections > 0 {
		mt.metrics.SuccessRate = float64(mt.metrics.SuccessfulConns) / float64(mt.metrics.TotalConnections) * 100
	}
	
	metrics := *mt.metrics
	return &metrics
}

// testConnectivity tests connectivity to meek server
func (mt *MeekTransport) testConnectivity() error {
	req, err := http.NewRequest("GET", mt.config.URL, nil)
	if err != nil {
		return err
	}
	
	// Set front domain if specified
	if mt.config.Front != "" {
		req.Host = mt.config.Front
	}
	
	resp, err := mt.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	return nil
}

// generateSessionID generates a unique session ID
func (mt *MeekTransport) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// updateMetrics updates transport metrics
func (mt *MeekTransport) updateMetrics(success bool, latency time.Duration) {
	mt.mutex.Lock()
	defer mt.mutex.Unlock()
	
	mt.metrics.TotalConnections++
	mt.metrics.LastUsed = time.Now()
	
	if success {
		mt.metrics.SuccessfulConns++
		
		if latency > mt.metrics.MaxLatency {
			mt.metrics.MaxLatency = latency
		}
		if latency < mt.metrics.MinLatency {
			mt.metrics.MinLatency = latency
		}
		mt.metrics.AverageLatency = (mt.metrics.AverageLatency + latency) / 2
	} else {
		mt.metrics.FailedConns++
	}
}

// MeekConnection methods

// Read reads data from the meek connection
func (mc *MeekConnection) Read(b []byte) (n int, err error) {
	mc.mutex.RLock()
	if mc.closed {
		mc.mutex.RUnlock()
		return 0, io.EOF
	}
	mc.mutex.RUnlock()
	
	// Wait for data in read buffer
	for mc.readBuffer.Len() == 0 {
		if mc.closed {
			return 0, io.EOF
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	mc.mutex.Lock()
	n, err = mc.readBuffer.Read(b)
	mc.mutex.Unlock()
	
	// Update metrics
	mc.transport.mutex.Lock()
	mc.transport.metrics.BytesTransferred += int64(n)
	mc.transport.mutex.Unlock()
	
	return n, err
}

// Write writes data to the meek connection
func (mc *MeekConnection) Write(b []byte) (n int, err error) {
	mc.mutex.RLock()
	if mc.closed {
		mc.mutex.RUnlock()
		return 0, fmt.Errorf("connection closed")
	}
	mc.mutex.RUnlock()
	
	// Add data to write buffer
	mc.mutex.Lock()
	n, err = mc.writeBuffer.Write(b)
	mc.mutex.Unlock()
	
	if err != nil {
		return n, err
	}
	
	// Send data immediately
	if err := mc.sendData(); err != nil {
		return n, err
	}
	
	// Update metrics
	mc.transport.mutex.Lock()
	mc.transport.metrics.BytesTransferred += int64(n)
	mc.transport.mutex.Unlock()
	
	return n, nil
}

// Close closes the meek connection
func (mc *MeekConnection) Close() error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	if mc.closed {
		return nil
	}
	
	mc.closed = true
	if mc.pollTicker != nil {
		mc.pollTicker.Stop()
	}
	
	// Send close signal
	mc.sendCloseSignal()
	
	return nil
}

// LocalAddr returns the local network address (not applicable for HTTP)
func (mc *MeekConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns the remote network address
func (mc *MeekConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

// SetDeadline sets the read and write deadlines (not implemented for HTTP)
func (mc *MeekConnection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls (not implemented)
func (mc *MeekConnection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls (not implemented)
func (mc *MeekConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

// establishSession establishes a meek session
func (mc *MeekConnection) establishSession(address string, port int) error {
	// Create session establishment request
	sessionData := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\n\r\n", address, port)
	
	req, err := http.NewRequest("POST", mc.transport.config.URL, bytes.NewReader([]byte(sessionData)))
	if err != nil {
		return err
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-Id", mc.sessionID)
	
	if mc.transport.config.Front != "" {
		req.Host = mc.transport.config.Front
	}
	
	// Send request
	resp, err := mc.transport.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("session establishment failed: %d", resp.StatusCode)
	}
	
	return nil
}

// pollLoop polls for incoming data
func (mc *MeekConnection) pollLoop() {
	defer mc.pollTicker.Stop()
	
	for {
		select {
		case <-mc.pollTicker.C:
			if mc.closed {
				return
			}
			mc.pollForData()
		}
	}
}

// pollForData polls the server for incoming data
func (mc *MeekConnection) pollForData() {
	req, err := http.NewRequest("GET", mc.transport.config.URL, nil)
	if err != nil {
		return
	}
	
	req.Header.Set("X-Session-Id", mc.sessionID)
	if mc.transport.config.Front != "" {
		req.Host = mc.transport.config.Front
	}
	
	resp, err := mc.transport.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		data, err := io.ReadAll(resp.Body)
		if err == nil && len(data) > 0 {
			mc.mutex.Lock()
			mc.readBuffer.Write(data)
			mc.mutex.Unlock()
		}
	}
}

// sendData sends buffered data to the server
func (mc *MeekConnection) sendData() error {
	mc.mutex.Lock()
	if mc.writeBuffer.Len() == 0 {
		mc.mutex.Unlock()
		return nil
	}
	
	data := make([]byte, mc.writeBuffer.Len())
	mc.writeBuffer.Read(data)
	mc.mutex.Unlock()
	
	req, err := http.NewRequest("POST", mc.transport.config.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-Id", mc.sessionID)
	
	if mc.transport.config.Front != "" {
		req.Host = mc.transport.config.Front
	}
	
	resp, err := mc.transport.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

// sendCloseSignal sends a close signal to the server
func (mc *MeekConnection) sendCloseSignal() {
	req, err := http.NewRequest("DELETE", mc.transport.config.URL, nil)
	if err != nil {
		return
	}
	
	req.Header.Set("X-Session-Id", mc.sessionID)
	if mc.transport.config.Front != "" {
		req.Host = mc.transport.config.Front
	}
	
	resp, err := mc.transport.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
