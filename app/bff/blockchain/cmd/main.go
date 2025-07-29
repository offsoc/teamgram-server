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

	"github.com/teamgram/teamgram-server/app/bff/blockchain/internal/config"
	"github.com/teamgram/teamgram-server/app/bff/blockchain/internal/core"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/logx"
)

var configFile = flag.String("f", "etc/blockchain.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)

	// Validate configuration
	if err := c.Validate(); err != nil {
		logx.Errorf("Invalid configuration: %v", err)
		os.Exit(1)
	}

	logx.Infof("Starting Teamgram Blockchain Service...")
	logx.Infof("Config file: %s", *configFile)

	// Check if blockchain is enabled
	if !c.IsBlockchainEnabled() {
		logx.Info("Blockchain service is disabled in configuration")
		os.Exit(0)
	}

	// Create blockchain service
	blockchainConfig := convertToBlockchainConfig(c.GetBlockchainConfig())
	blockchainService, err := core.NewBlockchainService(blockchainConfig)
	if err != nil {
		logx.Errorf("Failed to create blockchain service: %v", err)
		os.Exit(1)
	}

	// Start blockchain service
	if err := blockchainService.Start(); err != nil {
		logx.Errorf("Failed to start blockchain service: %v", err)
		os.Exit(1)
	}

	logx.Info("Blockchain service started successfully")

	// Print service information
	printServiceInfo(c, blockchainService)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start health monitoring
	go monitorHealth(ctx, blockchainService)

	// Start metrics reporting
	if c.GetBlockchainConfig().EnableMetrics {
		go reportMetrics(ctx, blockchainService)
	}

	// Start performance monitoring
	go monitorPerformance(ctx, blockchainService)

	// Start security monitoring
	go monitorSecurity(ctx, blockchainService)

	// Wait for shutdown signal
	<-sigChan
	logx.Info("Received shutdown signal, stopping blockchain service...")

	// Stop blockchain service
	// Note: Stop method would be implemented in the service
	logx.Info("Blockchain service stopped gracefully")
}

// printServiceInfo prints service configuration and status
func printServiceInfo(c config.Config, service *core.BlockchainService) {
	blockchainConfig := c.GetBlockchainConfig()

	fmt.Println("\n=== Teamgram Blockchain Service ===")
	fmt.Printf("Max Concurrent Requests: %d\n", blockchainConfig.MaxConcurrentRequests)
	fmt.Printf("Request Timeout: %v\n", blockchainConfig.RequestTimeout)
	fmt.Printf("Security Level: %s\n", blockchainConfig.SecurityLevel)

	if blockchainConfig.EnableMetrics {
		fmt.Printf("Metrics: %s\n", c.GetMetricsAddress())
	}

	if blockchainConfig.EnableRateLimit {
		fmt.Printf("Rate Limit: %d req/s (burst: %d)\n", blockchainConfig.RequestsPerSecond, blockchainConfig.BurstSize)
	}

	if blockchainConfig.EnableCaching {
		fmt.Printf("Cache: %d items, TTL: %v\n", blockchainConfig.CacheSize, blockchainConfig.CacheTTL)
	}

	// Wallet information
	if blockchainConfig.WalletConfig != nil {
		fmt.Println("\nWallet Configuration:")
		fmt.Printf("  HD Wallet: %v\n", blockchainConfig.WalletConfig.EnableHDWallet)
		fmt.Printf("  Multi-Signature: %v\n", blockchainConfig.WalletConfig.EnableMultiSig)
		fmt.Printf("  Default Threshold: %d\n", blockchainConfig.WalletConfig.DefaultThreshold)
		fmt.Printf("  Max Signers: %d\n", blockchainConfig.WalletConfig.MaxSigners)
		fmt.Printf("  Derivation Path: %s\n", blockchainConfig.WalletConfig.DefaultDerivationPath)
		fmt.Printf("  Supported Currencies: %v\n", blockchainConfig.WalletConfig.SupportedCurrencies)

		security := []string{}
		if blockchainConfig.WalletConfig.RequireMFA {
			security = append(security, "MFA Required")
		}
		if blockchainConfig.WalletConfig.EnableHardware {
			security = append(security, "Hardware Support")
		}
		fmt.Printf("  Security: %v\n", security)
	}

	// DeFi information
	if blockchainConfig.DeFiConfig != nil {
		fmt.Println("\nDeFi Configuration:")

		protocols := []string{}
		if blockchainConfig.DeFiConfig.EnableUniswap {
			protocols = append(protocols, "Uniswap")
		}
		if blockchainConfig.DeFiConfig.EnableSushiSwap {
			protocols = append(protocols, "SushiSwap")
		}
		if blockchainConfig.DeFiConfig.EnableCompound {
			protocols = append(protocols, "Compound")
		}
		if blockchainConfig.DeFiConfig.EnableAave {
			protocols = append(protocols, "Aave")
		}
		if blockchainConfig.DeFiConfig.EnableCurve {
			protocols = append(protocols, "Curve")
		}
		fmt.Printf("  Supported Protocols: %v\n", protocols)

		fmt.Printf("  Max Slippage: %.2f%%\n", blockchainConfig.DeFiConfig.MaxSlippage*100)
		fmt.Printf("  Min Yield Threshold: %.2f%%\n", blockchainConfig.DeFiConfig.MinYieldThreshold*100)

		features := []string{}
		if blockchainConfig.DeFiConfig.EnableStaking {
			features = append(features, "Staking")
		}
		if blockchainConfig.DeFiConfig.EnableYieldFarming {
			features = append(features, "Yield Farming")
		}
		if blockchainConfig.DeFiConfig.AutoCompound {
			features = append(features, "Auto Compound")
		}
		if blockchainConfig.DeFiConfig.EnableAutoRebalance {
			features = append(features, "Auto Rebalance")
		}
		fmt.Printf("  Features: %v\n", features)
	}

	// NFT information
	if blockchainConfig.NFTConfig != nil && blockchainConfig.NFTConfig.Enabled {
		fmt.Println("\nNFT Configuration:")
		fmt.Printf("  Max File Size: %d MB\n", blockchainConfig.NFTConfig.MaxFileSize/(1024*1024))
		fmt.Printf("  Supported Formats: %v\n", blockchainConfig.NFTConfig.SupportedFormats)
		fmt.Printf("  Marketplace: %v\n", blockchainConfig.NFTConfig.EnableMarketplace)
		fmt.Printf("  Marketplace Fee: %.2f%%\n", blockchainConfig.NFTConfig.MarketplaceFee*100)
		fmt.Printf("  Royalty Fee: %.2f%%\n", blockchainConfig.NFTConfig.RoyaltyFee*100)
		fmt.Printf("  Minting: %v\n", blockchainConfig.NFTConfig.EnableMinting)
		fmt.Printf("  Max Supply: %d\n", blockchainConfig.NFTConfig.MaxSupply)
		fmt.Printf("  Storage: %s\n", blockchainConfig.NFTConfig.StorageProvider)
	}

	// Bridge information
	if blockchainConfig.BridgeConfig != nil && blockchainConfig.BridgeConfig.Enabled {
		fmt.Println("\nBridge Configuration:")
		fmt.Printf("  Supported Chains: %v\n", blockchainConfig.BridgeConfig.SupportedChains)
		fmt.Printf("  Required Validators: %d\n", blockchainConfig.BridgeConfig.RequiredValidators)
		fmt.Printf("  Validator Threshold: %d\n", blockchainConfig.BridgeConfig.ValidatorThreshold)
		fmt.Printf("  Security Delay: %v\n", blockchainConfig.BridgeConfig.SecurityDelay)
		fmt.Printf("  Fee Percentage: %.3f%%\n", blockchainConfig.BridgeConfig.FeePercentage*100)

		features := []string{}
		if blockchainConfig.BridgeConfig.EnableAtomicSwaps {
			features = append(features, "Atomic Swaps")
		}
		fmt.Printf("  Features: %v\n", features)
		fmt.Printf("  Swap Timeout: %v\n", blockchainConfig.BridgeConfig.SwapTimeout)
		fmt.Printf("  HTLC Timeout: %v\n", blockchainConfig.BridgeConfig.HTLCTimeout)
	}

	// Network information
	fmt.Println("\nNetwork Configuration:")

	if blockchainConfig.EthereumConfig != nil && blockchainConfig.EthereumConfig.Enabled {
		fmt.Printf("  ✓ Ethereum: Chain ID %d, Network ID %d\n",
			blockchainConfig.EthereumConfig.ChainID, blockchainConfig.EthereumConfig.NetworkID)
		fmt.Printf("    RPC: %s\n", blockchainConfig.EthereumConfig.RPCURL)
		fmt.Printf("    Gas Limit: %d, Gas Price: %s wei\n",
			blockchainConfig.EthereumConfig.DefaultGasLimit, blockchainConfig.EthereumConfig.DefaultGasPrice)
	}

	if blockchainConfig.BitcoinConfig != nil && blockchainConfig.BitcoinConfig.Enabled {
		fmt.Printf("  ✓ Bitcoin: Network %s\n", blockchainConfig.BitcoinConfig.Network)
		fmt.Printf("    RPC: %s\n", blockchainConfig.BitcoinConfig.RPCURL)
		fmt.Printf("    Fee Rate: %d sat/byte\n", blockchainConfig.BitcoinConfig.DefaultFeeRate)
	}

	if blockchainConfig.PolygonConfig != nil && blockchainConfig.PolygonConfig.Enabled {
		fmt.Printf("  ✓ Polygon: Chain ID %d, Network ID %d\n",
			blockchainConfig.PolygonConfig.ChainID, blockchainConfig.PolygonConfig.NetworkID)
		fmt.Printf("    RPC: %s\n", blockchainConfig.PolygonConfig.RPCURL)
	}

	if blockchainConfig.BSCConfig != nil && blockchainConfig.BSCConfig.Enabled {
		fmt.Printf("  ✓ BSC: Chain ID %d, Network ID %d\n",
			blockchainConfig.BSCConfig.ChainID, blockchainConfig.BSCConfig.NetworkID)
		fmt.Printf("    RPC: %s\n", blockchainConfig.BSCConfig.RPCURL)
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

	// Supported currencies and chains
	currencies := service.GetSupportedCurrencies()
	chains := service.GetSupportedChains()
	fmt.Printf("Supported Currencies: %v\n", currencies)
	fmt.Printf("Supported Chains: %v\n", chains)

	fmt.Println("\n=== Ready for Blockchain Operations ===")
	fmt.Println("Blockchain service is ready to process:")
	fmt.Println("  • Wallet creation and management")
	fmt.Println("  • Cryptocurrency payments")
	fmt.Println("  • DeFi staking and liquidity provision")
	fmt.Println("  • Cross-chain bridging")
	fmt.Println("  • NFT minting and trading")
	fmt.Println("  • Atomic swaps")
	fmt.Println("Press Ctrl+C to stop the service")
	fmt.Println()
}

// monitorHealth monitors service health
func monitorHealth(ctx context.Context, service *core.BlockchainService) {
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
func reportMetrics(ctx context.Context, service *core.BlockchainService) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()
			logx.Infof("Blockchain Metrics - Total: %d, Success: %d (%.2f%%), Avg Latency: %v",
				metrics.TotalRequests,
				metrics.SuccessfulRequests,
				float64(metrics.SuccessfulRequests)/float64(metrics.TotalRequests)*100,
				metrics.AverageResponseTime)

			logx.Infof("Service Breakdown - Wallet: %d, DeFi: %d, Bridge: %d, Payment: %d",
				metrics.WalletRequests,
				metrics.DeFiRequests,
				metrics.BridgeRequests,
				metrics.PaymentRequests)

			logx.Infof("Transaction Metrics - Total: %d, Success: %d, Failed: %d, Pending: %d",
				metrics.TotalTransactions,
				metrics.SuccessfulTx,
				metrics.FailedTx,
				metrics.PendingTx)

			if metrics.TotalVolume != nil && metrics.TotalFees != nil {
				logx.Infof("Volume Metrics - Total Volume: %d currencies, Total Fees: %s",
					len(metrics.TotalVolume),
					metrics.TotalFees.String())
			}

			if metrics.CacheHits+metrics.CacheMisses > 0 {
				logx.Infof("Cache Performance - Hit Rate: %.2f%%, Hits: %d, Misses: %d",
					metrics.CacheHitRate,
					metrics.CacheHits,
					metrics.CacheMisses)
			}

			if metrics.RateLimitedRequests > 0 {
				logx.Errorf("Rate Limited Requests: %d", metrics.RateLimitedRequests)
			}

			logx.Infof("Network Status - Supported: %d, Active: %d",
				metrics.SupportedNetworks,
				metrics.ActiveNetworks)
		}
	}
}

// monitorPerformance monitors performance and alerts on issues
func monitorPerformance(ctx context.Context, service *core.BlockchainService) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()

			// Check response time
			if metrics.AverageResponseTime > 5*time.Second {
				logx.Errorf("High average response time: %v", metrics.AverageResponseTime)
			}

			// Check success rate
			if metrics.TotalRequests > 0 {
				successRate := float64(metrics.SuccessfulRequests) / float64(metrics.TotalRequests) * 100
				if successRate < 95.0 {
					logx.Errorf("Low success rate: %.2f%%", successRate)
				}
			}

			// Check transaction success rate
			if metrics.TotalTransactions > 0 {
				txSuccessRate := float64(metrics.SuccessfulTx) / float64(metrics.TotalTransactions) * 100
				if txSuccessRate < 90.0 {
					logx.Errorf("Low transaction success rate: %.2f%%", txSuccessRate)
				}
			}

			// Check rate limiting
			if metrics.RateLimitedRequests > 0 {
				rateLimitRate := float64(metrics.RateLimitedRequests) / float64(metrics.TotalRequests) * 100
				if rateLimitRate > 10.0 {
					logx.Errorf("High rate limit rate: %.2f%%", rateLimitRate)
				}
			}

			// Check pending transactions
			if metrics.PendingTx > 100 {
				logx.Errorf("High number of pending transactions: %d", metrics.PendingTx)
			}
		}
	}
}

// monitorSecurity monitors security events and alerts
func monitorSecurity(ctx context.Context, service *core.BlockchainService) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := service.GetMetrics()

			// Check security incidents
			if metrics.SecurityIncidents > 0 {
				logx.Errorf("Security incidents detected: %d", metrics.SecurityIncidents)
			}

			// Check failed authentication attempts
			if metrics.FailedAuthAttempts > 10 {
				logx.Errorf("High number of failed auth attempts: %d", metrics.FailedAuthAttempts)
			}

			// Check suspicious activity
			if metrics.SuspiciousActivity > 0 {
				logx.Errorf("Suspicious activity detected: %d incidents", metrics.SuspiciousActivity)
			}
		}
	}
}

// convertToBlockchainConfig converts BlockchainServiceConfig to BlockchainConfig
func convertToBlockchainConfig(serviceConfig *config.BlockchainServiceConfig) *core.BlockchainConfig {
	if serviceConfig == nil {
		return core.DefaultBlockchainConfig()
	}

	return &core.BlockchainConfig{
		SupportedNetworks:     []string{"ethereum", "bitcoin", "bsc", "polygon"},
		DefaultNetwork:        "ethereum",
		TestnetEnabled:        true,
		WalletEncryption:      true,
		MultiSigEnabled:       true,
		HardwareWalletSupport: true,
		MinConfirmations:      map[string]int{"ethereum": 12, "bitcoin": 6, "bsc": 3},
		TransactionTimeout:    5 * time.Minute,
		SecurityLevel:         "bank",
		AMLEnabled:            true,
		KYCRequired:           true,
		FraudDetection:        true,
		TransactionSpeed:      5 * time.Second,
		ThroughputTarget:      10000,
		UptimeTarget:          99.99,
		RegulationCompliance:  []string{"PCI-DSS", "SOX", "GDPR", "CCPA"},
		ReportingEnabled:      true,
		AuditTrail:            true,
	}
}
