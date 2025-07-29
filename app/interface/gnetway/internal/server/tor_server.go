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
	"net"
	"sync"
	"time"

	"github.com/teamgram/teamgram-server/app/interface/gnetway/internal/config"
	"github.com/teamgram/teamgram-server/pkg/tor"
	"github.com/zeromicro/go-zero/core/logx"
)

// TorServer implements MTProto over Tor server
type TorServer struct {
	mutex        sync.RWMutex
	config       *config.TorConfig
	torConfig    *config.TorServerConfig
	torManager   *tor.TorManager
	onionService *tor.OnionService
	listener     net.Listener
	connections  map[string]*TorConnection
	metrics      *TorServerMetrics
	logger       logx.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	isRunning    bool
}

// TorConnection represents a connection over Tor
type TorConnection struct {
	ID           string
	Conn         net.Conn
	RemoteAddr   string
	CreatedAt    time.Time
	LastActive   time.Time
	BytesRead    int64
	BytesWritten int64
	IsAnonymous  bool
}

// TorServerMetrics tracks Tor server performance
type TorServerMetrics struct {
	TotalConnections      int64         `json:"total_connections"`
	ActiveConnections     int64         `json:"active_connections"`
	AnonymousConnections  int64         `json:"anonymous_connections"`
	TotalBytesTransferred int64         `json:"total_bytes_transferred"`
	AverageLatency        time.Duration `json:"average_latency"`
	OnionServiceUptime    time.Duration `json:"onion_service_uptime"`
	LastUpdated           time.Time     `json:"last_updated"`
}

// NewTorServer creates a new Tor server
func NewTorServer(torConfig *config.TorConfig, serverConfig *config.TorServerConfig) (*TorServer, error) {
	if torConfig == nil || !torConfig.Enabled {
		return nil, fmt.Errorf("Tor is not enabled")
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &TorServer{
		config:      torConfig,
		torConfig:   serverConfig,
		connections: make(map[string]*TorConnection),
		metrics: &TorServerMetrics{
			LastUpdated: time.Now(),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize Tor manager
	var err error
	server.torManager, err = server.initializeTorManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tor manager: %w", err)
	}

	return server, nil
}

// Start starts the Tor server
func (ts *TorServer) Start(address string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if ts.isRunning {
		return fmt.Errorf("Tor server is already running")
	}

	ts.logger.Info("Starting Tor server...")

	// Start Tor manager
	if err := ts.torManager.Start(); err != nil {
		return fmt.Errorf("failed to start Tor manager: %w", err)
	}

	// Create onion service if enabled
	if ts.config.EnableOnionService {
		if err := ts.createOnionService(); err != nil {
			return fmt.Errorf("failed to create onion service: %w", err)
		}
	}

	// Start listening for connections
	if err := ts.startListener(address); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	// Start metrics collection
	go ts.metricsLoop()

	// Start connection cleanup
	go ts.cleanupLoop()

	ts.isRunning = true
	ts.logger.Infof("Tor server started on %s", address)

	if ts.onionService != nil {
		ts.logger.Infof("Onion service available at: %s", ts.onionService.Address)
	}

	return nil
}

// Stop stops the Tor server
func (ts *TorServer) Stop() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if !ts.isRunning {
		return nil
	}

	ts.logger.Info("Stopping Tor server...")

	// Cancel context
	ts.cancel()

	// Close listener
	if ts.listener != nil {
		ts.listener.Close()
	}

	// Close all connections
	for _, conn := range ts.connections {
		conn.Conn.Close()
	}

	// Stop Tor manager
	if ts.torManager != nil {
		ts.torManager.Stop()
	}

	ts.isRunning = false
	ts.logger.Info("Tor server stopped")

	return nil
}

// GetMetrics returns current server metrics
func (ts *TorServer) GetMetrics() *TorServerMetrics {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	// Update metrics
	ts.metrics.ActiveConnections = int64(len(ts.connections))
	ts.metrics.LastUpdated = time.Now()

	if ts.onionService != nil {
		ts.metrics.OnionServiceUptime = time.Since(ts.onionService.CreatedAt)
	}

	// Return a copy
	metrics := *ts.metrics
	return &metrics
}

// GetOnionAddress returns the onion service address
func (ts *TorServer) GetOnionAddress() string {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	if ts.onionService != nil {
		return ts.onionService.Address
	}
	return ""
}

// IsRunning returns whether the server is running
func (ts *TorServer) IsRunning() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.isRunning
}

// initializeTorManager initializes the Tor manager
func (ts *TorServer) initializeTorManager() (*tor.TorManager, error) {
	torConfig := &tor.TorConfig{
		SocksPort:           ts.config.SocksPort,
		ControlPort:         ts.config.ControlPort,
		DataDirectory:       ts.config.DataDirectory,
		UseBridges:          ts.config.UseBridges,
		EnableObfs4:         ts.config.EnableObfs4,
		EnableMeek:          ts.config.EnableMeek,
		EnableSnowflake:     ts.config.EnableSnowflake,
		EnableOnionService:  ts.config.EnableOnionService,
		OnionServicePort:    ts.config.OnionServicePort,
		CircuitBuildTimeout: time.Duration(ts.config.CircuitBuildTimeout) * time.Second,
		MaxCircuits:         ts.config.MaxCircuits,
		ExitNodes:           ts.config.ExitNodes,
		ExcludeNodes:        ts.config.ExcludeNodes,
	}

	return tor.NewTorManager(torConfig)
}

// createOnionService creates an onion service
func (ts *TorServer) createOnionService() error {
	// Create onion service through Tor manager's onion manager
	onionService, err := ts.torManager.GetOnionManager().CreateOnionService(ts.config.OnionServicePort)
	if err != nil {
		return fmt.Errorf("failed to create onion service: %w", err)
	}

	ts.onionService = onionService
	ts.logger.Infof("Created onion service: %s", onionService.Address)

	return nil
}

// startListener starts listening for connections
func (ts *TorServer) startListener(address string) error {
	// For onion services, we listen on localhost
	if ts.config.EnableOnionService {
		address = fmt.Sprintf("127.0.0.1:%d", ts.config.OnionServicePort)
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	ts.listener = listener

	// Start accepting connections
	go ts.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections
func (ts *TorServer) acceptLoop() {
	for {
		conn, err := ts.listener.Accept()
		if err != nil {
			select {
			case <-ts.ctx.Done():
				return
			default:
				ts.logger.Errorf("Failed to accept connection: %v", err)
				continue
			}
		}

		// Handle connection
		go ts.handleConnection(conn)
	}
}

// handleConnection handles a new connection
func (ts *TorServer) handleConnection(conn net.Conn) {
	connID := fmt.Sprintf("tor_%d", time.Now().UnixNano())

	torConn := &TorConnection{
		ID:          connID,
		Conn:        conn,
		RemoteAddr:  conn.RemoteAddr().String(),
		CreatedAt:   time.Now(),
		LastActive:  time.Now(),
		IsAnonymous: ts.isAnonymousConnection(conn),
	}

	// Store connection
	ts.mutex.Lock()
	ts.connections[connID] = torConn
	ts.metrics.TotalConnections++
	if torConn.IsAnonymous {
		ts.metrics.AnonymousConnections++
	}
	ts.mutex.Unlock()

	ts.logger.Debugf("New Tor connection: %s (anonymous: %v)", connID, torConn.IsAnonymous)

	// Handle connection (this would integrate with existing MTProto handling)
	defer func() {
		conn.Close()
		ts.mutex.Lock()
		delete(ts.connections, connID)
		ts.mutex.Unlock()
		ts.logger.Debugf("Closed Tor connection: %s", connID)
	}()

	// Connection handling loop
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}

		torConn.BytesRead += int64(n)
		torConn.LastActive = time.Now()

		// Process MTProto data (simplified)
		// In real implementation, this would integrate with existing MTProto handlers

		// Echo back for testing (remove in production)
		conn.Write(buffer[:n])
		torConn.BytesWritten += int64(n)
	}
}

// isAnonymousConnection checks if a connection is anonymous (through Tor)
func (ts *TorServer) isAnonymousConnection(conn net.Conn) bool {
	// Check if connection is from localhost (onion service)
	if ts.config.EnableOnionService {
		remoteAddr := conn.RemoteAddr().String()
		return remoteAddr == "127.0.0.1" || remoteAddr == "[::1]"
	}

	// For direct Tor connections, we assume they are anonymous
	return true
}

// metricsLoop collects server metrics
func (ts *TorServer) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ts.collectMetrics()
		case <-ts.ctx.Done():
			return
		}
	}
}

// collectMetrics collects current metrics
func (ts *TorServer) collectMetrics() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	var totalBytes int64
	for _, conn := range ts.connections {
		totalBytes += conn.BytesRead + conn.BytesWritten
	}

	ts.metrics.TotalBytesTransferred = totalBytes
	ts.metrics.LastUpdated = time.Now()
}

// cleanupLoop cleans up idle connections
func (ts *TorServer) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ts.cleanupIdleConnections()
		case <-ts.ctx.Done():
			return
		}
	}
}

// cleanupIdleConnections removes idle connections
func (ts *TorServer) cleanupIdleConnections() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	now := time.Now()
	idleTimeout := 10 * time.Minute

	for id, conn := range ts.connections {
		if now.Sub(conn.LastActive) > idleTimeout {
			conn.Conn.Close()
			delete(ts.connections, id)
			ts.logger.Debugf("Cleaned up idle Tor connection: %s", id)
		}
	}
}
