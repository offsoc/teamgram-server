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

package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/teamgram/teamgram-server/app/bff/tor/internal/config"
	"github.com/teamgram/teamgram-server/pkg/tor"
	"github.com/zeromicro/go-zero/core/logx"
)

// TorService provides Tor anonymity services
type TorService struct {
	mutex       sync.RWMutex
	config      *config.TorServiceConfig
	torManager  *tor.TorManager
	metrics     *TorServiceMetrics
	healthCheck *HealthChecker
	logger      logx.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	isRunning   bool
}

// TorServiceMetrics tracks service performance
type TorServiceMetrics struct {
	// Connection metrics
	TotalConnections      int64 `json:"total_connections"`
	SuccessfulConnections int64 `json:"successful_connections"`
	FailedConnections     int64 `json:"failed_connections"`
	ActiveConnections     int64 `json:"active_connections"`

	// Circuit metrics
	TotalCircuits    int64         `json:"total_circuits"`
	ActiveCircuits   int64         `json:"active_circuits"`
	FailedCircuits   int64         `json:"failed_circuits"`
	CircuitBuildTime time.Duration `json:"circuit_build_time"`

	// Performance metrics
	AverageLatency time.Duration `json:"average_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinLatency     time.Duration `json:"min_latency"`
	Throughput     float64       `json:"throughput"` // bytes/sec

	// Anonymity metrics
	UniqueExitNodes     int     `json:"unique_exit_nodes"`
	GeographicDiversity float64 `json:"geographic_diversity"`

	// Reliability metrics
	ConnectionSuccessRate float64 `json:"connection_success_rate"`
	CircuitSuccessRate    float64 `json:"circuit_success_rate"`
	UptimePercentage      float64 `json:"uptime_percentage"`

	// Transport metrics
	TransportStats map[string]*TransportStats `json:"transport_stats"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
	StartTime   time.Time `json:"start_time"`
}

// TransportStats tracks individual transport performance
type TransportStats struct {
	Name           string        `json:"name"`
	Connections    int64         `json:"connections"`
	SuccessRate    float64       `json:"success_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	IsAvailable    bool          `json:"is_available"`
}

// HealthChecker monitors Tor service health
type HealthChecker struct {
	service   *TorService
	interval  time.Duration
	lastCheck time.Time
	isHealthy bool
	issues    []string
	logger    logx.Logger
}

// NewTorService creates a new Tor service
func NewTorService(config *config.TorServiceConfig) (*TorService, error) {
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("Tor service is not enabled")
	}

	ctx, cancel := context.WithCancel(context.Background())

	service := &TorService{
		config: config,
		metrics: &TorServiceMetrics{
			StartTime:      time.Now(),
			MinLatency:     time.Hour, // Initialize to high value
			TransportStats: make(map[string]*TransportStats),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize Tor manager
	var err error
	service.torManager, err = service.initializeTorManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tor manager: %w", err)
	}

	// Initialize health checker
	service.healthCheck = &HealthChecker{
		service:   service,
		interval:  config.HealthCheckInterval,
		isHealthy: false,
		issues:    make([]string, 0),
		logger:    logx.WithContext(ctx),
	}

	return service, nil
}

// Start starts the Tor service
func (ts *TorService) Start() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if ts.isRunning {
		return fmt.Errorf("Tor service is already running")
	}

	ts.logger.Info("Starting Tor service...")

	// Start Tor manager
	if err := ts.torManager.Start(); err != nil {
		return fmt.Errorf("failed to start Tor manager: %w", err)
	}

	// Start health checking
	go ts.healthCheck.start()

	// Start metrics collection
	go ts.metricsLoop()

	// Wait for initial circuit establishment
	if err := ts.waitForInitialCircuits(); err != nil {
		ts.logger.Errorf("Failed to establish initial circuits: %v", err)
	}

	ts.isRunning = true
	ts.logger.Info("Tor service started successfully")

	return nil
}

// Stop stops the Tor service
func (ts *TorService) Stop() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if !ts.isRunning {
		return nil
	}

	ts.logger.Info("Stopping Tor service...")

	// Cancel context
	ts.cancel()

	// Stop Tor manager
	if ts.torManager != nil {
		ts.torManager.Stop()
	}

	ts.isRunning = false
	ts.logger.Info("Tor service stopped")

	return nil
}

// Connect creates a connection through Tor
func (ts *TorService) Connect(address string, port int) (net.Conn, error) {
	start := time.Now()

	ts.mutex.RLock()
	if !ts.isRunning {
		ts.mutex.RUnlock()
		return nil, fmt.Errorf("Tor service is not running")
	}
	ts.mutex.RUnlock()

	// Create connection through Tor
	conn, err := ts.torManager.Connect(address, port)
	if err != nil {
		ts.updateConnectionMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to connect through Tor: %w", err)
	}

	ts.updateConnectionMetrics(true, time.Since(start))
	ts.logger.Debugf("Connected to %s:%d through Tor", address, port)

	return conn, nil
}

// CreateCircuit creates a new Tor circuit
func (ts *TorService) CreateCircuit(purpose string) (*tor.Circuit, error) {
	ts.mutex.RLock()
	if !ts.isRunning {
		ts.mutex.RUnlock()
		return nil, fmt.Errorf("Tor service is not running")
	}
	ts.mutex.RUnlock()

	return ts.torManager.CreateCircuit(purpose)
}

// GetMetrics returns current service metrics
func (ts *TorService) GetMetrics() *TorServiceMetrics {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	// Update calculated metrics
	ts.updateCalculatedMetrics()

	// Return a copy
	metrics := *ts.metrics
	return &metrics
}

// GetHealthStatus returns current health status
func (ts *TorService) GetHealthStatus() (bool, []string) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	return ts.healthCheck.isHealthy, ts.healthCheck.issues
}

// IsRunning returns whether the service is running
func (ts *TorService) IsRunning() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.isRunning
}

// GetAvailableTransports returns list of available transports
func (ts *TorService) GetAvailableTransports() []string {
	if ts.torManager == nil {
		return []string{}
	}

	// This would call the transport manager
	return []string{"vanilla", "obfs4", "meek", "snowflake"}
}

// initializeTorManager initializes the Tor manager with service config
func (ts *TorService) initializeTorManager() (*tor.TorManager, error) {
	torConfig := &tor.TorConfig{
		SocksPort:              ts.config.SocksPort,
		ControlPort:            ts.config.ControlPort,
		DataDirectory:          ts.config.DataDirectory,
		LogLevel:               ts.config.LogLevel,
		CircuitBuildTimeout:    ts.config.CircuitBuildTimeout,
		MaxCircuits:            ts.config.MaxCircuits,
		CircuitIdleTimeout:     ts.config.CircuitIdleTimeout,
		EnableObfs4:            ts.config.EnableObfs4,
		EnableMeek:             ts.config.EnableMeek,
		EnableSnowflake:        ts.config.EnableSnowflake,
		UseBridges:             ts.config.UseBridges,
		BridgeDiscovery:        ts.config.BridgeDiscovery,
		MaxBridges:             ts.config.MaxBridges,
		EnableOnionService:     ts.config.EnableOnionService,
		OnionServicePort:       ts.config.OnionServicePort,
		OnionKeyPath:           ts.config.OnionKeyPath,
		MaxStreamsPerCircuit:   ts.config.MaxStreamsPerCircuit,
		ConnectionTimeout:      ts.config.ConnectionTimeout,
		RequestTimeout:         ts.config.RequestTimeout,
		StrictNodes:            ts.config.StrictNodes,
		ExitNodes:              ts.config.ExitNodes,
		ExcludeNodes:           ts.config.ExcludeNodes,
		EnforceDistinctSubnets: ts.config.EnforceDistinctSubnets,
	}

	return tor.NewTorManager(torConfig)
}

// waitForInitialCircuits waits for initial circuits to be established
func (ts *TorService) waitForInitialCircuits() error {
	timeout := time.After(ts.config.CircuitBuildTimeout * 2)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for initial circuits")
		case <-ticker.C:
			metrics := ts.torManager.GetMetrics()
			if metrics.ActiveCircuits > 0 {
				ts.logger.Infof("Initial circuits established: %d active", metrics.ActiveCircuits)
				return nil
			}
		case <-ts.ctx.Done():
			return fmt.Errorf("service stopped while waiting for circuits")
		}
	}
}

// metricsLoop collects service metrics
func (ts *TorService) metricsLoop() {
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

// collectMetrics collects current metrics from Tor manager
func (ts *TorService) collectMetrics() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if ts.torManager == nil {
		return
	}

	// Get metrics from Tor manager
	torMetrics := ts.torManager.GetMetrics()

	// Update service metrics
	ts.metrics.TotalCircuits = torMetrics.TotalCircuits
	ts.metrics.ActiveCircuits = torMetrics.ActiveCircuits
	ts.metrics.FailedCircuits = torMetrics.FailedCircuits
	ts.metrics.CircuitBuildTime = torMetrics.CircuitBuildTime
	ts.metrics.AverageLatency = torMetrics.AverageLatency
	ts.metrics.MaxLatency = torMetrics.MaxLatency
	ts.metrics.MinLatency = torMetrics.MinLatency
	ts.metrics.Throughput = torMetrics.Throughput
	ts.metrics.UniqueExitNodes = torMetrics.UniqueExitNodes
	ts.metrics.GeographicDiversity = torMetrics.GeographicDiversity
	ts.metrics.ConnectionSuccessRate = torMetrics.ConnectionSuccessRate
	ts.metrics.CircuitSuccessRate = torMetrics.CircuitSuccessRate
	ts.metrics.UptimePercentage = torMetrics.UptimePercentage
	ts.metrics.LastUpdated = time.Now()
}

// updateConnectionMetrics updates connection-related metrics
func (ts *TorService) updateConnectionMetrics(success bool, latency time.Duration) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.metrics.TotalConnections++

	if success {
		ts.metrics.SuccessfulConnections++

		// Update latency metrics
		if latency > ts.metrics.MaxLatency {
			ts.metrics.MaxLatency = latency
		}
		if latency < ts.metrics.MinLatency {
			ts.metrics.MinLatency = latency
		}
		ts.metrics.AverageLatency = (ts.metrics.AverageLatency + latency) / 2
	} else {
		ts.metrics.FailedConnections++
	}
}

// updateCalculatedMetrics updates calculated metrics
func (ts *TorService) updateCalculatedMetrics() {
	// Update success rates
	if ts.metrics.TotalConnections > 0 {
		ts.metrics.ConnectionSuccessRate = float64(ts.metrics.SuccessfulConnections) / float64(ts.metrics.TotalConnections) * 100
	}

	// Update uptime percentage
	ts.metrics.UptimePercentage = 100.0 // Simplified - in real implementation, track downtime
}

// HealthChecker methods

// start starts the health checking loop
func (hc *HealthChecker) start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthCheck()
		case <-hc.service.ctx.Done():
			return
		}
	}
}

// performHealthCheck performs a health check
func (hc *HealthChecker) performHealthCheck() {
	hc.lastCheck = time.Now()
	hc.issues = hc.issues[:0] // Clear previous issues

	// Check if Tor manager is running
	if !hc.service.torManager.IsRunning() {
		hc.issues = append(hc.issues, "Tor manager is not running")
	}

	// Check circuit availability
	metrics := hc.service.torManager.GetMetrics()
	if metrics.ActiveCircuits == 0 {
		hc.issues = append(hc.issues, "No active circuits available")
	}

	// Check connection success rate
	if metrics.ConnectionSuccessRate < 90.0 {
		hc.issues = append(hc.issues, fmt.Sprintf("Low connection success rate: %.2f%%", metrics.ConnectionSuccessRate))
	}

	// Update health status
	hc.isHealthy = len(hc.issues) == 0

	if hc.isHealthy {
		hc.logger.Debug("Health check passed")
	} else {
		hc.logger.Errorf("Health check failed: %v", hc.issues)
	}
}
