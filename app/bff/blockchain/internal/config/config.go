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
	"math/big"
	"time"

	"github.com/zeromicro/go-zero/zrpc"
)

// Config configuration for Blockchain BFF service
type Config struct {
	zrpc.RpcServerConf
	Blockchain *BlockchainServiceConfig `json:",optional"`
}

// BlockchainServiceConfig configuration for blockchain service
type BlockchainServiceConfig struct {
	// Basic configuration
	Enabled               bool          `json:",default=true"`
	MaxConcurrentRequests int           `json:",default=100"`
	RequestTimeout        time.Duration `json:",default=30s"`
	
	// Wallet configuration
	WalletConfig          *WalletConfig `json:",optional"`
	
	// DeFi configuration
	DeFiConfig            *DeFiConfig   `json:",optional"`
	
	// NFT configuration
	NFTConfig             *NFTConfig    `json:",optional"`
	
	// Bridge configuration
	BridgeConfig          *BridgeConfig `json:",optional"`
	
	// Network configurations
	EthereumConfig        *EthereumConfig `json:",optional"`
	BitcoinConfig         *BitcoinConfig  `json:",optional"`
	PolygonConfig         *PolygonConfig  `json:",optional"`
	BSCConfig             *BSCConfig      `json:",optional"`
	
	// Security settings
	SecurityLevel         string        `json:",default=banking"`
	EnableMFA             bool          `json:",default=true"`
	RequireHardware       bool          `json:",default=false"`
	
	// Performance settings
	EnableCaching         bool          `json:",default=true"`
	CacheSize             int           `json:",default=1000"`
	CacheTTL              time.Duration `json:",default=1h"`
	
	// Rate limiting
	EnableRateLimit       bool          `json:",default=true"`
	RequestsPerSecond     int           `json:",default=10"`
	BurstSize             int           `json:",default=20"`
	
	// Monitoring
	EnableMetrics         bool          `json:",default=true"`
	MetricsPort           int           `json:",default=9054"`
	HealthCheckInterval   time.Duration `json:",default=30s"`
}

// WalletConfig configuration for wallet services
type WalletConfig struct {
	// HD Wallet settings
	EnableHDWallet        bool          `json:",default=true"`
	DefaultDerivationPath string        `json:",default=m/44'/0'/0'"`
	MaxAddressGap         int           `json:",default=20"`
	
	// Multi-signature settings
	EnableMultiSig        bool          `json:",default=true"`
	DefaultThreshold      int           `json:",default=2"`
	MaxSigners            int           `json:",default=15"`
	
	// Supported currencies
	SupportedCurrencies   []string      `json:",default=[\"BTC\",\"ETH\",\"USDT\",\"USDC\",\"BNB\",\"ADA\",\"DOT\",\"MATIC\",\"AVAX\",\"SOL\"]"`
	
	// Security settings
	RequireMFA            bool          `json:",default=true"`
	EnableHardware        bool          `json:",default=false"`
	KeyDerivationRounds   int           `json:",default=100000"`
	
	// Performance settings
	SyncInterval          time.Duration `json:",default=5m"`
	CacheSize             int           `json:",default=1000"`
	CacheTTL              time.Duration `json:",default=1h"`
}

// DeFiConfig configuration for DeFi services
type DeFiConfig struct {
	// Protocol support
	EnableUniswap         bool          `json:",default=true"`
	EnableSushiSwap       bool          `json:",default=true"`
	EnableCompound        bool          `json:",default=true"`
	EnableAave            bool          `json:",default=true"`
	EnableCurve           bool          `json:",default=false"`
	
	// Risk management
	MaxSlippage           float64       `json:",default=0.05"`
	MaxGasPrice           string        `json:",default=100000000000"` // 100 gwei
	MinLiquidity          string        `json:",default=1000000000000000000"` // 1 ETH
	
	// Staking settings
	EnableStaking         bool          `json:",default=true"`
	MinStakeAmount        string        `json:",default=100000000000000000"` // 0.1 ETH
	UnstakingPeriod       time.Duration `json:",default=168h"` // 7 days
	
	// Yield farming settings
	EnableYieldFarming    bool          `json:",default=true"`
	MinYieldThreshold     float64       `json:",default=0.05"` // 5% APY
	AutoCompound          bool          `json:",default=false"`
	
	// Performance settings
	UpdateInterval        time.Duration `json:",default=1m"`
	MaxConcurrentOps      int           `json:",default=10"`
	EnableAutoRebalance   bool          `json:",default=false"`
}

// NFTConfig configuration for NFT services
type NFTConfig struct {
	// Basic settings
	Enabled               bool          `json:",default=true"`
	MaxFileSize           int64         `json:",default=104857600"` // 100MB
	SupportedFormats      []string      `json:",default=[\"jpg\",\"png\",\"gif\",\"mp4\",\"mp3\"]"`
	
	// Marketplace settings
	EnableMarketplace     bool          `json:",default=true"`
	MarketplaceFee        float64       `json:",default=0.025"` // 2.5%
	RoyaltyFee            float64       `json:",default=0.1"`   // 10%
	
	// Minting settings
	EnableMinting         bool          `json:",default=true"`
	MintingFee            string        `json:",default=10000000000000000"` // 0.01 ETH
	MaxSupply             int64         `json:",default=10000"`
	
	// Storage settings
	StorageProvider       string        `json:",default=ipfs"`
	IPFSGateway           string        `json:",default=https://ipfs.io/ipfs/"`
	
	// Performance settings
	ProcessingTimeout     time.Duration `json:",default=60s"`
	MaxConcurrentMints    int           `json:",default=10"`
}

// BridgeConfig configuration for bridge services
type BridgeConfig struct {
	// Basic settings
	Enabled               bool          `json:",default=true"`
	SupportedChains       []string      `json:",default=[\"ethereum\",\"polygon\",\"bsc\",\"bitcoin\"]"`
	
	// Bridge limits
	MinBridgeAmount       string        `json:",default=1000000000000000000"`   // 1 ETH
	MaxBridgeAmount       string        `json:",default=100000000000000000000"` // 100 ETH
	BridgeFee             string        `json:",default=10000000000000000"`     // 0.01 ETH
	FeePercentage         float64       `json:",default=0.001"`                 // 0.1%
	
	// Security settings
	RequiredValidators    int           `json:",default=3"`
	ValidatorThreshold    int           `json:",default=2"`
	SecurityDelay         time.Duration `json:",default=5m"`
	
	// Atomic swap settings
	EnableAtomicSwaps     bool          `json:",default=true"`
	SwapTimeout           time.Duration `json:",default=24h"`
	HTLCTimeout           time.Duration `json:",default=2h"`
	
	// Performance settings
	MaxConcurrentBridges  int           `json:",default=100"`
	ConfirmationBlocks    map[string]int64 `json:",optional"`
}

// Network configurations
type EthereumConfig struct {
	Enabled               bool          `json:",default=true"`
	NetworkID             int64         `json:",default=1"`
	ChainID               int64         `json:",default=1"`
	RPCURL                string        `json:",default=https://mainnet.infura.io/v3/YOUR-PROJECT-ID"`
	WSUrl                 string        `json:",optional"`
	DefaultGasLimit       uint64        `json:",default=21000"`
	DefaultGasPrice       string        `json:",default=20000000000"` // 20 gwei
	MaxGasPrice           string        `json:",default=100000000000"` // 100 gwei
	SupportedTokens       map[string]string `json:",optional"`
}

type BitcoinConfig struct {
	Enabled               bool          `json:",default=true"`
	Network               string        `json:",default=mainnet"`
	RPCURL                string        `json:",default=http://localhost:8332"`
	RPCUser               string        `json:",optional"`
	RPCPassword           string        `json:",optional"`
	DefaultFeeRate        int64         `json:",default=10"` // sat/byte
	MinFeeRate            int64         `json:",default=1"`
	MaxFeeRate            int64         `json:",default=1000"`
}

type PolygonConfig struct {
	Enabled               bool          `json:",default=true"`
	NetworkID             int64         `json:",default=137"`
	ChainID               int64         `json:",default=137"`
	RPCURL                string        `json:",default=https://polygon-rpc.com"`
	DefaultGasLimit       uint64        `json:",default=21000"`
	DefaultGasPrice       string        `json:",default=30000000000"` // 30 gwei
}

type BSCConfig struct {
	Enabled               bool          `json:",default=true"`
	NetworkID             int64         `json:",default=56"`
	ChainID               int64         `json:",default=56"`
	RPCURL                string        `json:",default=https://bsc-dataseed.binance.org"`
	DefaultGasLimit       uint64        `json:",default=21000"`
	DefaultGasPrice       string        `json:",default=5000000000"` // 5 gwei
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Blockchain == nil {
		return nil // Blockchain is optional
	}
	
	// Validate basic settings
	if c.Blockchain.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("max_concurrent_requests must be positive")
	}
	
	if c.Blockchain.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout must be positive")
	}
	
	// Validate wallet config
	if c.Blockchain.WalletConfig != nil {
		if err := c.validateWalletConfig(); err != nil {
			return fmt.Errorf("invalid wallet config: %w", err)
		}
	}
	
	// Validate DeFi config
	if c.Blockchain.DeFiConfig != nil {
		if err := c.validateDeFiConfig(); err != nil {
			return fmt.Errorf("invalid DeFi config: %w", err)
		}
	}
	
	// Validate NFT config
	if c.Blockchain.NFTConfig != nil {
		if err := c.validateNFTConfig(); err != nil {
			return fmt.Errorf("invalid NFT config: %w", err)
		}
	}
	
	// Validate bridge config
	if c.Blockchain.BridgeConfig != nil {
		if err := c.validateBridgeConfig(); err != nil {
			return fmt.Errorf("invalid bridge config: %w", err)
		}
	}
	
	// Validate network configs
	if err := c.validateNetworkConfigs(); err != nil {
		return fmt.Errorf("invalid network config: %w", err)
	}
	
	return nil
}

func (c *Config) validateWalletConfig() error {
	wallet := c.Blockchain.WalletConfig
	
	if wallet.MaxAddressGap <= 0 {
		return fmt.Errorf("max_address_gap must be positive")
	}
	
	if wallet.DefaultThreshold <= 0 {
		return fmt.Errorf("default_threshold must be positive")
	}
	
	if wallet.MaxSigners <= 0 {
		return fmt.Errorf("max_signers must be positive")
	}
	
	if wallet.DefaultThreshold > wallet.MaxSigners {
		return fmt.Errorf("default_threshold cannot be greater than max_signers")
	}
	
	if len(wallet.SupportedCurrencies) == 0 {
		return fmt.Errorf("supported_currencies cannot be empty")
	}
	
	return nil
}

func (c *Config) validateDeFiConfig() error {
	defi := c.Blockchain.DeFiConfig
	
	if defi.MaxSlippage < 0 || defi.MaxSlippage > 1 {
		return fmt.Errorf("max_slippage must be between 0 and 1")
	}
	
	if defi.MinYieldThreshold < 0 {
		return fmt.Errorf("min_yield_threshold must be non-negative")
	}
	
	if defi.MaxConcurrentOps <= 0 {
		return fmt.Errorf("max_concurrent_ops must be positive")
	}
	
	// Validate big int strings
	if _, ok := new(big.Int).SetString(defi.MaxGasPrice, 10); !ok {
		return fmt.Errorf("invalid max_gas_price format")
	}
	
	if _, ok := new(big.Int).SetString(defi.MinLiquidity, 10); !ok {
		return fmt.Errorf("invalid min_liquidity format")
	}
	
	return nil
}

func (c *Config) validateNFTConfig() error {
	nft := c.Blockchain.NFTConfig
	
	if nft.MaxFileSize <= 0 {
		return fmt.Errorf("max_file_size must be positive")
	}
	
	if len(nft.SupportedFormats) == 0 {
		return fmt.Errorf("supported_formats cannot be empty")
	}
	
	if nft.MarketplaceFee < 0 || nft.MarketplaceFee > 1 {
		return fmt.Errorf("marketplace_fee must be between 0 and 1")
	}
	
	if nft.RoyaltyFee < 0 || nft.RoyaltyFee > 1 {
		return fmt.Errorf("royalty_fee must be between 0 and 1")
	}
	
	if nft.MaxSupply <= 0 {
		return fmt.Errorf("max_supply must be positive")
	}
	
	return nil
}

func (c *Config) validateBridgeConfig() error {
	bridge := c.Blockchain.BridgeConfig
	
	if len(bridge.SupportedChains) == 0 {
		return fmt.Errorf("supported_chains cannot be empty")
	}
	
	if bridge.RequiredValidators <= 0 {
		return fmt.Errorf("required_validators must be positive")
	}
	
	if bridge.ValidatorThreshold <= 0 {
		return fmt.Errorf("validator_threshold must be positive")
	}
	
	if bridge.ValidatorThreshold > bridge.RequiredValidators {
		return fmt.Errorf("validator_threshold cannot be greater than required_validators")
	}
	
	if bridge.FeePercentage < 0 || bridge.FeePercentage > 1 {
		return fmt.Errorf("fee_percentage must be between 0 and 1")
	}
	
	// Validate big int strings
	if _, ok := new(big.Int).SetString(bridge.MinBridgeAmount, 10); !ok {
		return fmt.Errorf("invalid min_bridge_amount format")
	}
	
	if _, ok := new(big.Int).SetString(bridge.MaxBridgeAmount, 10); !ok {
		return fmt.Errorf("invalid max_bridge_amount format")
	}
	
	if _, ok := new(big.Int).SetString(bridge.BridgeFee, 10); !ok {
		return fmt.Errorf("invalid bridge_fee format")
	}
	
	return nil
}

func (c *Config) validateNetworkConfigs() error {
	// Validate Ethereum config
	if c.Blockchain.EthereumConfig != nil {
		eth := c.Blockchain.EthereumConfig
		if eth.Enabled {
			if eth.NetworkID <= 0 {
				return fmt.Errorf("ethereum network_id must be positive")
			}
			if eth.ChainID <= 0 {
				return fmt.Errorf("ethereum chain_id must be positive")
			}
			if eth.RPCURL == "" {
				return fmt.Errorf("ethereum rpc_url is required")
			}
		}
	}
	
	// Validate Bitcoin config
	if c.Blockchain.BitcoinConfig != nil {
		btc := c.Blockchain.BitcoinConfig
		if btc.Enabled {
			if btc.Network == "" {
				return fmt.Errorf("bitcoin network is required")
			}
			if btc.RPCURL == "" {
				return fmt.Errorf("bitcoin rpc_url is required")
			}
			if btc.DefaultFeeRate <= 0 {
				return fmt.Errorf("bitcoin default_fee_rate must be positive")
			}
		}
	}
	
	return nil
}

// GetBlockchainConfig returns blockchain configuration with defaults
func (c *Config) GetBlockchainConfig() *BlockchainServiceConfig {
	if c.Blockchain == nil {
		return &BlockchainServiceConfig{
			Enabled:               false,
			MaxConcurrentRequests: 100,
			RequestTimeout:        30 * time.Second,
			SecurityLevel:         "banking",
			EnableMFA:             true,
			RequireHardware:       false,
			EnableCaching:         true,
			CacheSize:             1000,
			CacheTTL:              1 * time.Hour,
			EnableRateLimit:       true,
			RequestsPerSecond:     10,
			BurstSize:             20,
			EnableMetrics:         true,
			MetricsPort:           9054,
			HealthCheckInterval:   30 * time.Second,
		}
	}
	
	return c.Blockchain
}

// IsBlockchainEnabled returns whether blockchain is enabled
func (c *Config) IsBlockchainEnabled() bool {
	return c.Blockchain != nil && c.Blockchain.Enabled
}

// GetMetricsAddress returns the metrics port address
func (c *Config) GetMetricsAddress() string {
	if !c.IsBlockchainEnabled() || !c.Blockchain.EnableMetrics {
		return ""
	}
	
	return fmt.Sprintf("127.0.0.1:%d", c.Blockchain.MetricsPort)
}

// GetSupportedCurrencies returns supported currencies
func (c *Config) GetSupportedCurrencies() []string {
	if !c.IsBlockchainEnabled() || c.Blockchain.WalletConfig == nil {
		return []string{"BTC", "ETH", "USDT", "USDC", "BNB"}
	}
	
	return c.Blockchain.WalletConfig.SupportedCurrencies
}

// GetSupportedChains returns supported blockchain networks
func (c *Config) GetSupportedChains() []string {
	if !c.IsBlockchainEnabled() || c.Blockchain.BridgeConfig == nil {
		return []string{"ethereum", "bitcoin", "polygon", "bsc"}
	}
	
	return c.Blockchain.BridgeConfig.SupportedChains
}
