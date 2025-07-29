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
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// TransportManager manages pluggable transports for Tor
type TransportManager struct {
	mutex       sync.RWMutex
	config      *TransportConfig
	transports  map[string]Transport
	metrics     *TransportMetrics
	logger      logx.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	isRunning   bool
}

// TransportConfig configuration for pluggable transports
type TransportConfig struct {
	EnableObfs4     bool              `json:"enable_obfs4"`
	EnableMeek      bool              `json:"enable_meek"`
	EnableSnowflake bool              `json:"enable_snowflake"`
	EnableScrambleSuit bool           `json:"enable_scramblesuit"`
	TransportTimeout time.Duration    `json:"transport_timeout"`
	MaxRetries      int               `json:"max_retries"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	Obfs4Config     *Obfs4Config      `json:"obfs4_config"`
	MeekConfig      *MeekConfig       `json:"meek_config"`
	SnowflakeConfig *SnowflakeConfig  `json:"snowflake_config"`
}

// Transport interface for pluggable transports
type Transport interface {
	Name() string
	Connect(address string, port int, options map[string]string) (net.Conn, error)
	IsAvailable() bool
	GetMetrics() *TransportMetrics
	Start() error
	Stop() error
}

// TransportMetrics tracks transport performance
type TransportMetrics struct {
	TransportName     string        `json:"transport_name"`
	TotalConnections  int64         `json:"total_connections"`
	SuccessfulConns   int64         `json:"successful_connections"`
	FailedConns       int64         `json:"failed_connections"`
	AverageLatency    time.Duration `json:"average_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	BytesTransferred  int64         `json:"bytes_transferred"`
	LastUsed          time.Time     `json:"last_used"`
	SuccessRate       float64       `json:"success_rate"`
}

// Obfs4Config configuration for obfs4 transport
type Obfs4Config struct {
	CertFingerprint string            `json:"cert_fingerprint"`
	IatMode         int               `json:"iat_mode"`
	PublicKey       string            `json:"public_key"`
	NodeID          string            `json:"node_id"`
	Options         map[string]string `json:"options"`
}

// MeekConfig configuration for meek transport
type MeekConfig struct {
	URL             string            `json:"url"`
	Front           string            `json:"front"`
	HelperAddr      string            `json:"helper_addr"`
	MaxPadding      int               `json:"max_padding"`
	Options         map[string]string `json:"options"`
}

// SnowflakeConfig configuration for snowflake transport
type SnowflakeConfig struct {
	BrokerURL       string            `json:"broker_url"`
	FrontDomain     string            `json:"front_domain"`
	ICEServers      []string          `json:"ice_servers"`
	MaxPeers        int               `json:"max_peers"`
	Options         map[string]string `json:"options"`
}

// NewTransportManager creates a new transport manager
func NewTransportManager(config *TransportConfig) (*TransportManager, error) {
	if config == nil {
		config = DefaultTransportConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &TransportManager{
		config:     config,
		transports: make(map[string]Transport),
		metrics:    &TransportMetrics{},
		logger:     logx.WithContext(ctx),
		ctx:        ctx,
		cancel:     cancel,
	}
	
	// Initialize enabled transports
	if err := manager.initializeTransports(); err != nil {
		return nil, fmt.Errorf("failed to initialize transports: %w", err)
	}
	
	return manager, nil
}

// Start starts the transport manager
func (tm *TransportManager) Start() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	if tm.isRunning {
		return fmt.Errorf("transport manager is already running")
	}
	
	tm.logger.Info("Starting transport manager...")
	
	// Start all enabled transports
	for name, transport := range tm.transports {
		if err := transport.Start(); err != nil {
			tm.logger.Errorf("Failed to start transport %s: %v", name, err)
			continue
		}
		tm.logger.Infof("Started transport: %s", name)
	}
	
	// Start metrics collection
	go tm.metricsLoop()
	
	tm.isRunning = true
	tm.logger.Info("Transport manager started successfully")
	
	return nil
}

// Stop stops the transport manager
func (tm *TransportManager) Stop() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	if !tm.isRunning {
		return nil
	}
	
	tm.logger.Info("Stopping transport manager...")
	
	// Cancel context
	tm.cancel()
	
	// Stop all transports
	for name, transport := range tm.transports {
		if err := transport.Stop(); err != nil {
			tm.logger.Errorf("Failed to stop transport %s: %v", name, err)
		}
	}
	
	tm.isRunning = false
	tm.logger.Info("Transport manager stopped")
	
	return nil
}

// Connect creates a connection using the best available transport
func (tm *TransportManager) Connect(address string, port int, options map[string]string) (net.Conn, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	if len(tm.transports) == 0 {
		return nil, fmt.Errorf("no transports available")
	}
	
	// Try transports in order of preference
	transportOrder := []string{"snowflake", "meek", "obfs4", "vanilla"}
	
	for _, transportName := range transportOrder {
		transport, exists := tm.transports[transportName]
		if !exists || !transport.IsAvailable() {
			continue
		}
		
		tm.logger.Debugf("Attempting connection via %s transport", transportName)
		
		conn, err := transport.Connect(address, port, options)
		if err != nil {
			tm.logger.Errorf("Failed to connect via %s: %v", transportName, err)
			continue
		}
		
		tm.logger.Infof("Successfully connected via %s transport", transportName)
		return conn, nil
	}
	
	return nil, fmt.Errorf("all transports failed to connect")
}

// GetAvailableTransports returns list of available transports
func (tm *TransportManager) GetAvailableTransports() []string {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	var available []string
	for name, transport := range tm.transports {
		if transport.IsAvailable() {
			available = append(available, name)
		}
	}
	
	return available
}

// GetTransportMetrics returns metrics for all transports
func (tm *TransportManager) GetTransportMetrics() map[string]*TransportMetrics {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	metrics := make(map[string]*TransportMetrics)
	for name, transport := range tm.transports {
		metrics[name] = transport.GetMetrics()
	}
	
	return metrics
}

// initializeTransports initializes enabled transports
func (tm *TransportManager) initializeTransports() error {
	// Initialize obfs4 transport
	if tm.config.EnableObfs4 {
		obfs4Transport, err := NewObfs4Transport(tm.config.Obfs4Config)
		if err != nil {
			tm.logger.Errorf("Failed to initialize obfs4 transport: %v", err)
		} else {
			tm.transports["obfs4"] = obfs4Transport
		}
	}
	
	// Initialize meek transport
	if tm.config.EnableMeek {
		meekTransport, err := NewMeekTransport(tm.config.MeekConfig)
		if err != nil {
			tm.logger.Errorf("Failed to initialize meek transport: %v", err)
		} else {
			tm.transports["meek"] = meekTransport
		}
	}
	
	// Initialize snowflake transport
	if tm.config.EnableSnowflake {
		snowflakeTransport, err := NewSnowflakeTransport(tm.config.SnowflakeConfig)
		if err != nil {
			tm.logger.Errorf("Failed to initialize snowflake transport: %v", err)
		} else {
			tm.transports["snowflake"] = snowflakeTransport
		}
	}
	
	// Always include vanilla transport as fallback
	vanillaTransport := NewVanillaTransport()
	tm.transports["vanilla"] = vanillaTransport
	
	tm.logger.Infof("Initialized %d transports", len(tm.transports))
	return nil
}

// metricsLoop collects transport metrics
func (tm *TransportManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tm.collectMetrics()
		case <-tm.ctx.Done():
			return
		}
	}
}

// collectMetrics collects metrics from all transports
func (tm *TransportManager) collectMetrics() {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	for name, transport := range tm.transports {
		metrics := transport.GetMetrics()
		tm.logger.Debugf("Transport %s metrics: %d connections, %.2f%% success rate", 
			name, metrics.TotalConnections, metrics.SuccessRate)
	}
}

// DefaultTransportConfig returns default transport configuration
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		EnableObfs4:      true,
		EnableMeek:       true,
		EnableSnowflake:  true,
		EnableScrambleSuit: false,
		TransportTimeout: 30 * time.Second,
		MaxRetries:       3,
		RetryDelay:       5 * time.Second,
		Obfs4Config: &Obfs4Config{
			IatMode: 0,
			Options: make(map[string]string),
		},
		MeekConfig: &MeekConfig{
			URL:        "https://meek.azureedge.net/",
			Front:      "ajax.aspnetcdn.com",
			MaxPadding: 1500,
			Options:    make(map[string]string),
		},
		SnowflakeConfig: &SnowflakeConfig{
			BrokerURL:   "https://snowflake-broker.torproject.net/",
			FrontDomain: "cdn.sstatic.net",
			ICEServers:  []string{"stun:stun.l.google.com:19302"},
			MaxPeers:    1,
			Options:     make(map[string]string),
		},
	}
}
