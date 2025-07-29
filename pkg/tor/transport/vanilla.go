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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// VanillaTransport implements vanilla TCP transport (no obfuscation)
type VanillaTransport struct {
	mutex       sync.RWMutex
	metrics     *TransportMetrics
	logger      logx.Logger
	isRunning   bool
}

// VanillaConnection wraps a standard TCP connection
type VanillaConnection struct {
	conn      net.Conn
	transport *VanillaTransport
}

// NewVanillaTransport creates a new vanilla transport
func NewVanillaTransport() *VanillaTransport {
	return &VanillaTransport{
		metrics: &TransportMetrics{
			TransportName: "vanilla",
			MinLatency:    time.Hour,
		},
		logger: logx.WithContext(nil),
	}
}

// Name returns the transport name
func (vt *VanillaTransport) Name() string {
	return "vanilla"
}

// Start starts the vanilla transport
func (vt *VanillaTransport) Start() error {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()
	
	if vt.isRunning {
		return fmt.Errorf("vanilla transport is already running")
	}
	
	vt.logger.Info("Starting vanilla transport...")
	vt.isRunning = true
	vt.logger.Info("Vanilla transport started successfully")
	
	return nil
}

// Stop stops the vanilla transport
func (vt *VanillaTransport) Stop() error {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()
	
	if !vt.isRunning {
		return nil
	}
	
	vt.logger.Info("Stopping vanilla transport...")
	vt.isRunning = false
	vt.logger.Info("Vanilla transport stopped")
	
	return nil
}

// Connect creates a vanilla TCP connection
func (vt *VanillaTransport) Connect(address string, port int, options map[string]string) (net.Conn, error) {
	start := time.Now()
	
	vt.mutex.RLock()
	if !vt.isRunning {
		vt.mutex.RUnlock()
		return nil, fmt.Errorf("vanilla transport is not running")
	}
	vt.mutex.RUnlock()
	
	// Create standard TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", address, port), 30*time.Second)
	if err != nil {
		vt.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}
	
	// Wrap connection
	vanillaConn := &VanillaConnection{
		conn:      conn,
		transport: vt,
	}
	
	vt.updateMetrics(true, time.Since(start))
	vt.logger.Debugf("Vanilla connection established to %s:%d", address, port)
	
	return vanillaConn, nil
}

// IsAvailable returns whether vanilla transport is available
func (vt *VanillaTransport) IsAvailable() bool {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()
	return vt.isRunning
}

// GetMetrics returns transport metrics
func (vt *VanillaTransport) GetMetrics() *TransportMetrics {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()
	
	if vt.metrics.TotalConnections > 0 {
		vt.metrics.SuccessRate = float64(vt.metrics.SuccessfulConns) / float64(vt.metrics.TotalConnections) * 100
	}
	
	metrics := *vt.metrics
	return &metrics
}

// updateMetrics updates transport metrics
func (vt *VanillaTransport) updateMetrics(success bool, latency time.Duration) {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()
	
	vt.metrics.TotalConnections++
	vt.metrics.LastUsed = time.Now()
	
	if success {
		vt.metrics.SuccessfulConns++
		
		if latency > vt.metrics.MaxLatency {
			vt.metrics.MaxLatency = latency
		}
		if latency < vt.metrics.MinLatency {
			vt.metrics.MinLatency = latency
		}
		vt.metrics.AverageLatency = (vt.metrics.AverageLatency + latency) / 2
	} else {
		vt.metrics.FailedConns++
	}
}

// VanillaConnection methods

// Read reads data from the vanilla connection
func (vc *VanillaConnection) Read(b []byte) (n int, err error) {
	n, err = vc.conn.Read(b)
	
	// Update metrics
	if n > 0 {
		vc.transport.mutex.Lock()
		vc.transport.metrics.BytesTransferred += int64(n)
		vc.transport.mutex.Unlock()
	}
	
	return n, err
}

// Write writes data to the vanilla connection
func (vc *VanillaConnection) Write(b []byte) (n int, err error) {
	n, err = vc.conn.Write(b)
	
	// Update metrics
	if n > 0 {
		vc.transport.mutex.Lock()
		vc.transport.metrics.BytesTransferred += int64(n)
		vc.transport.mutex.Unlock()
	}
	
	return n, err
}

// Close closes the vanilla connection
func (vc *VanillaConnection) Close() error {
	return vc.conn.Close()
}

// LocalAddr returns the local network address
func (vc *VanillaConnection) LocalAddr() net.Addr {
	return vc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (vc *VanillaConnection) RemoteAddr() net.Addr {
	return vc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (vc *VanillaConnection) SetDeadline(t time.Time) error {
	return vc.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
func (vc *VanillaConnection) SetReadDeadline(t time.Time) error {
	return vc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
func (vc *VanillaConnection) SetWriteDeadline(t time.Time) error {
	return vc.conn.SetWriteDeadline(t)
}
