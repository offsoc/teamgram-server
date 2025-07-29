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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/teamgram/teamgram-server/app/bff/tor/internal/config"
	"github.com/teamgram/teamgram-server/app/bff/tor/internal/core"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/logx"
)

var configFile = flag.String("f", "etc/tor.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)

	// Validate configuration
	if err := c.Validate(); err != nil {
		logx.Errorf("Invalid configuration: %v", err)
		os.Exit(1)
	}

	logx.Infof("Starting Teamgram Tor Service...")
	logx.Infof("Config file: %s", *configFile)

	// Check if Tor is enabled
	if !c.IsTorEnabled() {
		logx.Info("Tor service is disabled in configuration")
		os.Exit(0)
	}

	// Create Tor service
	torService, err := core.NewTorService(c.GetTorConfig())
	if err != nil {
		logx.Errorf("Failed to create Tor service: %v", err)
		os.Exit(1)
	}

	// Start Tor service
	if err := torService.Start(); err != nil {
		logx.Errorf("Failed to start Tor service: %v", err)
		os.Exit(1)
	}

	logx.Info("Tor service started successfully")

	// Print service information
	printServiceInfo(c, torService)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start health monitoring
	go monitorHealth(ctx, torService)

	// Start metrics reporting
	if c.GetTorConfig().EnableMetrics {
		go reportMetrics(ctx, torService)
	}

	// Wait for shutdown signal
	<-sigChan
	logx.Info("Received shutdown signal, stopping Tor service...")

	// Stop Tor service
	if err := torService.Stop(); err != nil {
		logx.Errorf("Error stopping Tor service: %v", err)
	}

	logx.Info("Tor service stopped gracefully")
}

// printServiceInfo prints service configuration and status
func printServiceInfo(c config.Config, service *core.TorService) {
	torConfig := c.GetTorConfig()

	fmt.Println("\n=== Teamgram Tor Service ===")
	fmt.Printf("SOCKS Proxy: %s\n", c.GetSocksProxy())
	fmt.Printf("Control Port: %s\n", c.GetControlAddress())

	if torConfig.EnableMetrics {
		fmt.Printf("Metrics: %s\n", c.GetMetricsAddress())
	}

	fmt.Printf("Data Directory: %s\n", torConfig.DataDirectory)
	fmt.Printf("Max Circuits: %d\n", torConfig.MaxCircuits)

	// Transport information
	fmt.Println("\nEnabled Transports:")
	if torConfig.EnableObfs4 {
		fmt.Println("  ✓ obfs4")
	}
	if torConfig.EnableMeek {
		fmt.Println("  ✓ meek")
	}
	if torConfig.EnableSnowflake {
		fmt.Println("  ✓ snowflake")
	}

	// Bridge information
	if torConfig.UseBridges {
		fmt.Println("\nBridge Mode: Enabled")
		if torConfig.BridgeDiscovery {
			fmt.Println("  ✓ Bridge discovery enabled")
		}
		fmt.Printf("  Max bridges: %d\n", torConfig.MaxBridges)
	}

	// Onion service information
	if torConfig.EnableOnionService {
		fmt.Println("\nOnion Service: Enabled")
		fmt.Printf("  Port: %d\n", torConfig.OnionServicePort)
		fmt.Printf("  Key path: %s\n", torConfig.OnionKeyPath)
	}

	fmt.Println("\n=== Service Status ===")
	fmt.Printf("Running: %v\n", service.IsRunning())

	isHealthy, issues := service.GetHealthStatus()
	fmt.Printf("Healthy: %v\n", isHealthy)
	if !isHealthy {
		fmt.Println("Issues:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
	}

	// Available transports
	transports := service.GetAvailableTransports()
	fmt.Printf("Available Transports: %v\n", transports)

	fmt.Println("\n=== Ready for Connections ===")
	fmt.Println("Use SOCKS proxy for anonymous connections")
	fmt.Println("Press Ctrl+C to stop the service")
	fmt.Println()
}

// monitorHealth monitors service health
func monitorHealth(ctx context.Context, service *core.TorService) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			isHealthy, issues := service.GetHealthStatus()
			if !isHealthy {
				logx.Errorf("Health check failed: %v", issues)
			} else {
				logx.Debug("Health check passed")
			}
		}
	}
}

// reportMetrics reports service metrics
func reportMetrics(ctx context.Context, service *core.TorService) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()
			logx.Infof("Metrics - Connections: %d (%.2f%% success), Circuits: %d, Latency: %v",
				metrics.TotalConnections,
				metrics.ConnectionSuccessRate,
				metrics.ActiveCircuits,
				metrics.AverageLatency)
		}
	}
}
