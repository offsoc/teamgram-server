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

package blockchain

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// BlockchainManager manages all blockchain services and integrations
type BlockchainManager struct {
	mutex          sync.RWMutex
	config         *BlockchainConfig
	walletManager  WalletManager
	defiManager    DeFiManager
	nftManager     NFTManager
	ethereumClient EthereumClient
	bitcoinClient  BitcoinClient
	bridgeManager  BridgeManager
	metrics        *BlockchainMetrics
	logger         logx.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	isRunning      bool
}

// BlockchainConfig configuration for blockchain services
type BlockchainConfig struct {
	// Network configurations
	EthereumConfig *EthereumConfig `json:"ethereum_config"`
	BitcoinConfig  *BitcoinConfig  `json:"bitcoin_config"`
	PolygonConfig  *PolygonConfig  `json:"polygon_config"`
	BSCConfig      *BSCConfig      `json:"bsc_config"`

	// Wallet configurations
	WalletConfig *WalletConfig `json:"wallet_config"`

	// DeFi configurations
	DeFiConfig *DeFiConfig `json:"defi_config"`

	// NFT configurations
	NFTConfig *NFTConfig `json:"nft_config"`

	// Bridge configurations
	BridgeConfig *BridgeConfig `json:"bridge_config"`

	// Security settings
	SecurityLevel   SecurityLevel `json:"security_level"`
	EnableMFA       bool          `json:"enable_mfa"`
	RequireHardware bool          `json:"require_hardware"`

	// Performance settings
	MaxConcurrentTx int           `json:"max_concurrent_tx"`
	TxTimeout       time.Duration `json:"tx_timeout"`
	ConfirmBlocks   int           `json:"confirm_blocks"`

	// Monitoring
	EnableMetrics   bool          `json:"enable_metrics"`
	MetricsInterval time.Duration `json:"metrics_interval"`
}

// Network configurations
type EthereumConfig struct {
	NetworkID int64    `json:"network_id"`
	RPCURL    string   `json:"rpc_url"`
	WSUrl     string   `json:"ws_url"`
	ChainID   int64    `json:"chain_id"`
	GasLimit  uint64   `json:"gas_limit"`
	GasPrice  *big.Int `json:"gas_price"`
	Enabled   bool     `json:"enabled"`
}

type BitcoinConfig struct {
	Network     string `json:"network"` // mainnet, testnet, regtest
	RPCURL      string `json:"rpc_url"`
	RPCUser     string `json:"rpc_user"`
	RPCPassword string `json:"rpc_password"`
	FeeRate     int64  `json:"fee_rate"` // satoshis per byte
	Enabled     bool   `json:"enabled"`
}

type PolygonConfig struct {
	NetworkID int64  `json:"network_id"`
	RPCURL    string `json:"rpc_url"`
	ChainID   int64  `json:"chain_id"`
	Enabled   bool   `json:"enabled"`
}

type BSCConfig struct {
	NetworkID int64  `json:"network_id"`
	RPCURL    string `json:"rpc_url"`
	ChainID   int64  `json:"chain_id"`
	Enabled   bool   `json:"enabled"`
}

// BlockchainMetrics tracks blockchain service performance
type BlockchainMetrics struct {
	// Transaction metrics
	TotalTransactions int64 `json:"total_transactions"`
	SuccessfulTx      int64 `json:"successful_tx"`
	FailedTx          int64 `json:"failed_tx"`
	PendingTx         int64 `json:"pending_tx"`

	// Performance metrics
	AverageConfirmTime time.Duration `json:"average_confirm_time"`
	MaxConfirmTime     time.Duration `json:"max_confirm_time"`
	MinConfirmTime     time.Duration `json:"min_confirm_time"`

	// Network-specific metrics
	EthereumMetrics *NetworkMetrics `json:"ethereum_metrics"`
	BitcoinMetrics  *NetworkMetrics `json:"bitcoin_metrics"`
	PolygonMetrics  *NetworkMetrics `json:"polygon_metrics"`
	BSCMetrics      *NetworkMetrics `json:"bsc_metrics"`

	// Wallet metrics
	TotalWallets  int64    `json:"total_wallets"`
	ActiveWallets int64    `json:"active_wallets"`
	TotalBalance  *big.Int `json:"total_balance"`

	// DeFi metrics
	TotalDeFiValue      *big.Int `json:"total_defi_value"`
	ActiveDeFiPositions int64    `json:"active_defi_positions"`

	// Security metrics
	SecurityIncidents  int64 `json:"security_incidents"`
	FailedAuthAttempts int64 `json:"failed_auth_attempts"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
	StartTime   time.Time `json:"start_time"`
}

// NetworkMetrics tracks individual network performance
type NetworkMetrics struct {
	NetworkName        string        `json:"network_name"`
	Transactions       int64         `json:"transactions"`
	Successes          int64         `json:"successes"`
	Failures           int64         `json:"failures"`
	AverageGasPrice    *big.Int      `json:"average_gas_price"`
	AverageConfirmTime time.Duration `json:"average_confirm_time"`
	LastBlockNumber    int64         `json:"last_block_number"`
	IsHealthy          bool          `json:"is_healthy"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string                 `json:"id"`
	Hash          string                 `json:"hash"`
	From          string                 `json:"from"`
	To            string                 `json:"to"`
	Amount        *big.Int               `json:"amount"`
	Currency      string                 `json:"currency"`
	Network       string                 `json:"network"`
	GasPrice      *big.Int               `json:"gas_price,omitempty"`
	GasLimit      uint64                 `json:"gas_limit,omitempty"`
	GasUsed       uint64                 `json:"gas_used,omitempty"`
	Fee           *big.Int               `json:"fee"`
	Status        TransactionStatus      `json:"status"`
	BlockNumber   int64                  `json:"block_number"`
	BlockHash     string                 `json:"block_hash"`
	Confirmations int64                  `json:"confirmations"`
	Data          []byte                 `json:"data,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	ConfirmedAt   *time.Time             `json:"confirmed_at,omitempty"`
}

// Enums
type SecurityLevel string

const (
	SecurityLevelBasic    SecurityLevel = "basic"
	SecurityLevelStandard SecurityLevel = "standard"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelBanking  SecurityLevel = "banking"
)

type TransactionStatus string

const (
	TxStatusPending   TransactionStatus = "pending"
	TxStatusConfirmed TransactionStatus = "confirmed"
	TxStatusFailed    TransactionStatus = "failed"
	TxStatusDropped   TransactionStatus = "dropped"
)

// Manager interfaces
type WalletManager interface {
	CreateWallet(ctx context.Context, userID int64, walletType string) (*Wallet, error)
	GetWallet(ctx context.Context, walletID string) (*Wallet, error)
	GetBalance(ctx context.Context, walletID, currency string) (*big.Int, error)
	SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error)
	GetTransactionHistory(ctx context.Context, walletID string, limit int) ([]*Transaction, error)
	Start() error
	Stop() error
}

type DeFiManager interface {
	GetProtocols() []string
	Stake(ctx context.Context, protocol, token string, amount *big.Int) (*Transaction, error)
	Unstake(ctx context.Context, protocol, token string, amount *big.Int) (*Transaction, error)
	GetStakingRewards(ctx context.Context, userID int64) (*big.Int, error)
	ProvideLiquidity(ctx context.Context, protocol, tokenA, tokenB string, amountA, amountB *big.Int) (*Transaction, error)
	RemoveLiquidity(ctx context.Context, protocol, pair string, amount *big.Int) (*Transaction, error)
	Start() error
	Stop() error
}

type NFTManager interface {
	MintNFT(ctx context.Context, collection, tokenURI string, metadata map[string]interface{}) (*NFT, error)
	TransferNFT(ctx context.Context, from, to, tokenID string) (*Transaction, error)
	GetNFT(ctx context.Context, tokenID string) (*NFT, error)
	GetUserNFTs(ctx context.Context, userID int64) ([]*NFT, error)
	Start() error
	Stop() error
}

type EthereumClient interface {
	GetBalance(ctx context.Context, address string) (*big.Int, error)
	SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error)
	GetTransaction(ctx context.Context, hash string) (*Transaction, error)
	GetBlockNumber(ctx context.Context) (int64, error)
	EstimateGas(ctx context.Context, tx *Transaction) (uint64, error)
	Start() error
	Stop() error
}

type BitcoinClient interface {
	GetBalance(ctx context.Context, address string) (*big.Int, error)
	SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error)
	GetTransaction(ctx context.Context, hash string) (*Transaction, error)
	GetBlockHeight(ctx context.Context) (int64, error)
	EstimateFee(ctx context.Context, blocks int) (*big.Int, error)
	Start() error
	Stop() error
}

type BridgeManager interface {
	GetSupportedChains() []string
	BridgeTokens(ctx context.Context, fromChain, toChain, token string, amount *big.Int) (*Transaction, error)
	GetBridgeStatus(ctx context.Context, txHash string) (*BridgeStatus, error)
	Start() error
	Stop() error
}

// NewBlockchainManager creates a new blockchain manager
func NewBlockchainManager(config *BlockchainConfig) (*BlockchainManager, error) {
	if config == nil {
		config = DefaultBlockchainConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &BlockchainManager{
		config: config,
		metrics: &BlockchainMetrics{
			StartTime:       time.Now(),
			MinConfirmTime:  time.Hour, // Initialize to high value
			TotalBalance:    big.NewInt(0),
			TotalDeFiValue:  big.NewInt(0),
			EthereumMetrics: &NetworkMetrics{NetworkName: "ethereum"},
			BitcoinMetrics:  &NetworkMetrics{NetworkName: "bitcoin"},
			PolygonMetrics:  &NetworkMetrics{NetworkName: "polygon"},
			BSCMetrics:      &NetworkMetrics{NetworkName: "bsc"},
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize managers
	var err error
	manager.walletManager, err = NewWalletManager(config.WalletConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet manager: %w", err)
	}

	manager.defiManager, err = NewDeFiManager(config.DeFiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DeFi manager: %w", err)
	}

	manager.nftManager, err = NewNFTManager(config.NFTConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NFT manager: %w", err)
	}

	manager.ethereumClient, err = NewEthereumClient(config.EthereumConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ethereum client: %w", err)
	}

	manager.bitcoinClient, err = NewBitcoinClient(config.BitcoinConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bitcoin client: %w", err)
	}

	manager.bridgeManager, err = NewBridgeManager(config.BridgeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge manager: %w", err)
	}

	return manager, nil
}

// Start starts the blockchain manager
func (bm *BlockchainManager) Start() error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if bm.isRunning {
		return fmt.Errorf("blockchain manager is already running")
	}

	bm.logger.Info("Starting blockchain manager...")

	// Start all managers
	if err := bm.walletManager.Start(); err != nil {
		return fmt.Errorf("failed to start wallet manager: %w", err)
	}

	if err := bm.defiManager.Start(); err != nil {
		return fmt.Errorf("failed to start DeFi manager: %w", err)
	}

	if err := bm.nftManager.Start(); err != nil {
		return fmt.Errorf("failed to start NFT manager: %w", err)
	}

	if err := bm.ethereumClient.Start(); err != nil {
		return fmt.Errorf("failed to start Ethereum client: %w", err)
	}

	if err := bm.bitcoinClient.Start(); err != nil {
		return fmt.Errorf("failed to start Bitcoin client: %w", err)
	}

	if err := bm.bridgeManager.Start(); err != nil {
		return fmt.Errorf("failed to start bridge manager: %w", err)
	}

	// Start metrics collection
	if bm.config.EnableMetrics {
		go bm.metricsLoop()
	}

	bm.isRunning = true
	bm.logger.Info("Blockchain manager started successfully")

	return nil
}

// GetMetrics returns blockchain metrics
func (bm *BlockchainManager) GetMetrics() *BlockchainMetrics {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	// Update calculated metrics
	bm.updateCalculatedMetrics()

	// Return a copy
	metrics := *bm.metrics
	return &metrics
}

// GetHealthStatus returns health status
func (bm *BlockchainManager) GetHealthStatus() (bool, []string) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	var issues []string

	// Check wallet manager
	if bm.walletManager == nil {
		issues = append(issues, "Wallet manager not initialized")
	}

	// Check DeFi manager
	if bm.defiManager == nil {
		issues = append(issues, "DeFi manager not initialized")
	}

	// Check bridge manager
	if bm.bridgeManager == nil {
		issues = append(issues, "Bridge manager not initialized")
	}

	// Check network clients
	if bm.ethereumClient == nil {
		issues = append(issues, "Ethereum client not initialized")
	}

	if bm.bitcoinClient == nil {
		issues = append(issues, "Bitcoin client not initialized")
	}

	isHealthy := len(issues) == 0
	return isHealthy, issues
}

// updateCalculatedMetrics updates calculated metrics
func (bm *BlockchainManager) updateCalculatedMetrics() {
	if bm.metrics.TotalTransactions > 0 {
		bm.metrics.SuccessfulTx = bm.metrics.TotalTransactions - bm.metrics.FailedTx
	}
}

// metricsLoop collects metrics periodically
func (bm *BlockchainManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.collectMetrics()
		case <-bm.ctx.Done():
			return
		}
	}
}

// collectMetrics collects current metrics
func (bm *BlockchainManager) collectMetrics() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.metrics.LastUpdated = time.Now()

	// Collect metrics from sub-managers
	if bm.walletManager != nil {
		// Collect wallet metrics (simplified)
		bm.metrics.TotalWallets++
	}

	if bm.defiManager != nil {
		// Collect DeFi metrics (simplified)
		bm.metrics.ActiveDeFiPositions++
	}
}

// Stop stops the blockchain manager
func (bm *BlockchainManager) Stop() error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if !bm.isRunning {
		return nil
	}

	bm.logger.Info("Stopping blockchain manager...")

	// Cancel context
	bm.cancel()

	// Stop all managers
	if bm.walletManager != nil {
		bm.walletManager.Stop()
	}

	if bm.defiManager != nil {
		bm.defiManager.Stop()
	}

	if bm.nftManager != nil {
		bm.nftManager.Stop()
	}

	if bm.ethereumClient != nil {
		bm.ethereumClient.Stop()
	}

	if bm.bitcoinClient != nil {
		bm.bitcoinClient.Stop()
	}

	if bm.bridgeManager != nil {
		bm.bridgeManager.Stop()
	}

	bm.isRunning = false
	bm.logger.Info("Blockchain manager stopped")

	return nil
}

// IsRunning returns whether the blockchain manager is running
func (bm *BlockchainManager) IsRunning() bool {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()
	return bm.isRunning
}

// GetAvailableModels returns available models (for compatibility)
func (bm *BlockchainManager) GetAvailableModels() map[string][]string {
	models := make(map[string][]string)

	// Blockchain networks
	models["networks"] = []string{"ethereum", "bitcoin", "polygon", "bsc", "avalanche"}

	// Supported currencies
	models["currencies"] = []string{"BTC", "ETH", "USDT", "USDC", "BNB", "ADA", "DOT", "MATIC", "AVAX", "SOL"}

	// DeFi protocols
	models["defi"] = []string{"uniswap", "sushiswap", "compound", "aave", "curve"}

	return models
}

// Stub implementations for missing managers
func NewWalletManager(config *WalletConfig) (WalletManager, error) {
	return &stubWalletManager{}, nil
}

func NewDeFiManager(config *DeFiConfig) (DeFiManager, error) {
	return &stubDeFiManager{}, nil
}

func NewNFTManager(config *NFTConfig) (NFTManager, error) {
	return &stubNFTManager{}, nil
}

func NewEthereumClient(config *EthereumConfig) (EthereumClient, error) {
	return &stubEthereumClient{}, nil
}

func NewBitcoinClient(config *BitcoinConfig) (BitcoinClient, error) {
	return &stubBitcoinClient{}, nil
}

func NewBridgeManager(config *BridgeConfig) (BridgeManager, error) {
	return &stubBridgeManager{}, nil
}

// Stub implementations
type stubWalletManager struct{}

func (s *stubWalletManager) CreateWallet(ctx context.Context, userID int64, walletType string) (*Wallet, error) {
	return &Wallet{}, nil
}
func (s *stubWalletManager) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	return &Wallet{}, nil
}
func (s *stubWalletManager) GetBalance(ctx context.Context, walletID, currency string) (*big.Int, error) {
	return big.NewInt(1000000000000000000), nil
}
func (s *stubWalletManager) SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error) {
	return tx, nil
}
func (s *stubWalletManager) GetTransactionHistory(ctx context.Context, walletID string, limit int) ([]*Transaction, error) {
	return []*Transaction{}, nil
}
func (s *stubWalletManager) Start() error { return nil }
func (s *stubWalletManager) Stop() error  { return nil }

type stubDeFiManager struct{}

func (s *stubDeFiManager) GetProtocols() []string { return []string{"uniswap", "compound"} }
func (s *stubDeFiManager) Stake(ctx context.Context, protocol, token string, amount *big.Int) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubDeFiManager) Unstake(ctx context.Context, protocol, token string, amount *big.Int) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubDeFiManager) GetStakingRewards(ctx context.Context, userID int64) (*big.Int, error) {
	return big.NewInt(100000000000000000), nil
}
func (s *stubDeFiManager) ProvideLiquidity(ctx context.Context, protocol, tokenA, tokenB string, amountA, amountB *big.Int) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubDeFiManager) RemoveLiquidity(ctx context.Context, protocol, pair string, amount *big.Int) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubDeFiManager) Start() error { return nil }
func (s *stubDeFiManager) Stop() error  { return nil }

type stubNFTManager struct{}

func (s *stubNFTManager) MintNFT(ctx context.Context, collection, tokenURI string, metadata map[string]interface{}) (*NFT, error) {
	return &NFT{}, nil
}
func (s *stubNFTManager) TransferNFT(ctx context.Context, from, to, tokenID string) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubNFTManager) GetNFT(ctx context.Context, tokenID string) (*NFT, error) {
	return &NFT{}, nil
}
func (s *stubNFTManager) GetUserNFTs(ctx context.Context, userID int64) ([]*NFT, error) {
	return []*NFT{}, nil
}
func (s *stubNFTManager) Start() error { return nil }
func (s *stubNFTManager) Stop() error  { return nil }

type stubEthereumClient struct{}

func (s *stubEthereumClient) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	return big.NewInt(1000000000000000000), nil
}
func (s *stubEthereumClient) SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error) {
	return tx, nil
}
func (s *stubEthereumClient) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubEthereumClient) GetBlockNumber(ctx context.Context) (int64, error) {
	return 18000000, nil
}
func (s *stubEthereumClient) EstimateGas(ctx context.Context, tx *Transaction) (uint64, error) {
	return 21000, nil
}
func (s *stubEthereumClient) Start() error { return nil }
func (s *stubEthereumClient) Stop() error  { return nil }

type stubBitcoinClient struct{}

func (s *stubBitcoinClient) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	return big.NewInt(100000000), nil
}
func (s *stubBitcoinClient) SendTransaction(ctx context.Context, tx *Transaction) (*Transaction, error) {
	return tx, nil
}
func (s *stubBitcoinClient) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubBitcoinClient) GetBlockHeight(ctx context.Context) (int64, error) {
	return 800000, nil
}
func (s *stubBitcoinClient) EstimateFee(ctx context.Context, blocks int) (*big.Int, error) {
	return big.NewInt(10), nil
}
func (s *stubBitcoinClient) Start() error { return nil }
func (s *stubBitcoinClient) Stop() error  { return nil }

type stubBridgeManager struct{}

func (s *stubBridgeManager) GetSupportedChains() []string {
	return []string{"ethereum", "polygon", "bsc", "bitcoin"}
}
func (s *stubBridgeManager) BridgeTokens(ctx context.Context, fromChain, toChain, token string, amount *big.Int) (*Transaction, error) {
	return &Transaction{}, nil
}
func (s *stubBridgeManager) GetBridgeStatus(ctx context.Context, txHash string) (*BridgeStatus, error) {
	return &BridgeStatus{}, nil
}
func (s *stubBridgeManager) Start() error { return nil }
func (s *stubBridgeManager) Stop() error  { return nil }

// Missing type definitions
type Wallet struct{}

func (w *Wallet) GetID() string      { return "stub-wallet-id" }
func (w *Wallet) GetAddress() string { return "stub-address" }

type PerformanceMonitor struct{}

func (p *PerformanceMonitor) GetUptimePercentage() float64 { return 99.99 }

type PaymentProcessor struct{}

func (p *PaymentProcessor) ProcessPayment(ctx context.Context, spec *PaymentSpec) (*Payment, error) {
	return &Payment{}, nil
}

type SecurityEngine struct{}

func (s *SecurityEngine) ValidateTransaction(ctx context.Context, req interface{}) error { return nil }

type ComplianceEngine struct{}

func (c *ComplianceEngine) ValidateTransaction(ctx context.Context, req interface{}) error {
	return nil
}

type NFT struct{}
type BridgeStatus struct{}
type WalletConfig struct{}
type DeFiConfig struct{}
type NFTConfig struct{}

type BridgeConfig struct {
	Enabled bool `json:"enabled"`
}

// DefaultBlockchainConfig returns default blockchain configuration
func DefaultBlockchainConfig() *BlockchainConfig {
	return &BlockchainConfig{
		SecurityLevel:   SecurityLevelBanking,
		EnableMFA:       true,
		RequireHardware: false,
		MaxConcurrentTx: 100,
		TxTimeout:       5 * time.Minute,
		ConfirmBlocks:   6,
		EnableMetrics:   true,
		MetricsInterval: 30 * time.Second,
	}
}
