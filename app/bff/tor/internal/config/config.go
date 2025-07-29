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

package config

import (
	"fmt"
	"time"

	"github.com/zeromicro/go-zero/zrpc"
)

// Config configuration for Tor BFF service
type Config struct {
	zrpc.RpcServerConf
	Tor *TorServiceConfig `json:",optional"`
}

// TorServiceConfig configuration for Tor service
type TorServiceConfig struct {
	// Basic configuration
	Enabled             bool          `json:",default=true"`
	SocksPort           int           `json:",default=9050"`
	ControlPort         int           `json:",default=9051"`
	DataDirectory       string        `json:",default=/tmp/tor"`
	LogLevel            string        `json:",default=notice"`
	
	// Circuit configuration
	CircuitBuildTimeout time.Duration `json:",default=60s"`
	MaxCircuits         int           `json:",default=10"`
	CircuitIdleTimeout  time.Duration `json:",default=10m"`
	
	// Transport configuration
	EnableObfs4         bool          `json:",default=true"`
	EnableMeek          bool          `json:",default=true"`
	EnableSnowflake     bool          `json:",default=true"`
	EnableScrambleSuit  bool          `json:",default=false"`
	
	// Bridge configuration
	UseBridges          bool          `json:",default=false"`
	BridgeDiscovery     bool          `json:",default=true"`
	MaxBridges          int           `json:",default=5"`
	BridgeList          []string      `json:",optional"`
	
	// Onion service configuration
	EnableOnionService  bool          `json:",default=false"`
	OnionServicePort    int           `json:",default=8080"`
	OnionKeyPath        string        `json:",default=/tmp/tor/onion_key"`
	OnionServiceDirs    []string      `json:",optional"`
	
	// Performance configuration
	MaxStreamsPerCircuit int          `json:",default=10"`
	ConnectionTimeout    time.Duration `json:",default=30s"`
	RequestTimeout       time.Duration `json:",default=60s"`
	
	// Security configuration
	StrictNodes         bool          `json:",default=false"`
	ExitNodes           []string      `json:",optional"`
	ExcludeNodes        []string      `json:",optional"`
	EnforceDistinctSubnets bool       `json:",default=true"`
	
	// Monitoring configuration
	EnableMetrics       bool          `json:",default=true"`
	MetricsPort         int           `json:",default=9052"`
	HealthCheckInterval time.Duration `json:",default=30s"`
	
	// Client configuration
	ClientConfig        *TorClientConfig `json:",optional"`
}

// TorClientConfig configuration for Tor client
type TorClientConfig struct {
	// Connection settings
	ConnectTimeout      time.Duration `json:",default=30s"`
	ReadTimeout         time.Duration `json:",default=60s"`
	WriteTimeout        time.Duration `json:",default=60s"`
	
	// Retry settings
	MaxRetries          int           `json:",default=3"`
	RetryDelay          time.Duration `json:",default=5s"`
	BackoffMultiplier   float64       `json:",default=2.0"`
	
	// Circuit preferences
	PreferredExitNodes  []string      `json:",optional"`
	AvoidNodes          []string      `json:",optional"`
	RequireIPv6         bool          `json:",default=false"`
	
	// Anonymity settings
	IsolateDestAddr     bool          `json:",default=true"`
	IsolateDestPort     bool          `json:",default=false"`
	IsolateClientAddr   bool          `json:",default=true"`
	IsolateClientProtocol bool        `json:",default=false"`
	
	// Performance settings
	CircuitPriority     int           `json:",default=1"`
	StreamIsolation     bool          `json:",default=true"`
	OptimisticData      bool          `json:",default=true"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Tor == nil {
		return nil // Tor is optional
	}
	
	// Validate ports
	if c.Tor.SocksPort <= 0 || c.Tor.SocksPort > 65535 {
		return fmt.Errorf("invalid SOCKS port: %d", c.Tor.SocksPort)
	}
	
	if c.Tor.ControlPort <= 0 || c.Tor.ControlPort > 65535 {
		return fmt.Errorf("invalid control port: %d", c.Tor.ControlPort)
	}
	
	if c.Tor.EnableMetrics && (c.Tor.MetricsPort <= 0 || c.Tor.MetricsPort > 65535) {
		return fmt.Errorf("invalid metrics port: %d", c.Tor.MetricsPort)
	}
	
	// Validate timeouts
	if c.Tor.CircuitBuildTimeout <= 0 {
		return fmt.Errorf("invalid circuit build timeout: %v", c.Tor.CircuitBuildTimeout)
	}
	
	if c.Tor.ConnectionTimeout <= 0 {
		return fmt.Errorf("invalid connection timeout: %v", c.Tor.ConnectionTimeout)
	}
	
	// Validate directories
	if c.Tor.DataDirectory == "" {
		return fmt.Errorf("data directory cannot be empty")
	}
	
	return nil
}

// GetTorConfig returns Tor configuration with defaults
func (c *Config) GetTorConfig() *TorServiceConfig {
	if c.Tor == nil {
		return &TorServiceConfig{
			Enabled:             false,
			SocksPort:           9050,
			ControlPort:         9051,
			DataDirectory:       "/tmp/tor",
			LogLevel:            "notice",
			CircuitBuildTimeout: 60 * time.Second,
			MaxCircuits:         10,
			CircuitIdleTimeout:  10 * time.Minute,
			EnableObfs4:         true,
			EnableMeek:          true,
			EnableSnowflake:     true,
			UseBridges:          false,
			BridgeDiscovery:     true,
			MaxBridges:          5,
			EnableOnionService:  false,
			OnionServicePort:    8080,
			OnionKeyPath:        "/tmp/tor/onion_key",
			MaxStreamsPerCircuit: 10,
			ConnectionTimeout:   30 * time.Second,
			RequestTimeout:      60 * time.Second,
			StrictNodes:         false,
			EnforceDistinctSubnets: true,
			EnableMetrics:       true,
			MetricsPort:         9052,
			HealthCheckInterval: 30 * time.Second,
		}
	}
	
	return c.Tor
}

// IsTorEnabled returns whether Tor is enabled
func (c *Config) IsTorEnabled() bool {
	return c.Tor != nil && c.Tor.Enabled
}

// GetSocksProxy returns the SOCKS proxy address
func (c *Config) GetSocksProxy() string {
	if !c.IsTorEnabled() {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.Tor.SocksPort)
}

// GetControlAddress returns the control port address
func (c *Config) GetControlAddress() string {
	if !c.IsTorEnabled() {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.Tor.ControlPort)
}

// GetMetricsAddress returns the metrics port address
func (c *Config) GetMetricsAddress() string {
	if !c.IsTorEnabled() || !c.Tor.EnableMetrics {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.Tor.MetricsPort)
}
