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

package ethereum

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// EthereumClient manages Ethereum blockchain interactions
type EthereumClient struct {
	mutex         sync.RWMutex
	config        *EthereumConfig
	rpcClient     RPCClient
	wsClient      WSClient
	tokenManager  *TokenManager
	contractCache map[string]*Contract
	metrics       *EthereumMetrics
	logger        logx.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	isRunning     bool
}

// EthereumConfig configuration for Ethereum client
type EthereumConfig struct {
	// Network settings
	NetworkID       int64    `json:"network_id"`
	ChainID         int64    `json:"chain_id"`
	RPCURL          string   `json:"rpc_url"`
	WSUrl           string   `json:"ws_url"`
	
	// Gas settings
	DefaultGasLimit uint64   `json:"default_gas_limit"`
	DefaultGasPrice *big.Int `json:"default_gas_price"`
	MaxGasPrice     *big.Int `json:"max_gas_price"`
	GasPriceBuffer  float64  `json:"gas_price_buffer"`
	
	// Transaction settings
	TxTimeout       time.Duration `json:"tx_timeout"`
	ConfirmBlocks   int64         `json:"confirm_blocks"`
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	
	// Token settings
	SupportedTokens map[string]string `json:"supported_tokens"` // symbol -> contract address
	
	// Performance settings
	MaxConcurrentTx int           `json:"max_concurrent_tx"`
	CacheSize       int           `json:"cache_size"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	
	// Monitoring
	EnableMetrics   bool          `json:"enable_metrics"`
	MetricsInterval time.Duration `json:"metrics_interval"`
}

// EthereumTransaction represents an Ethereum transaction
type EthereumTransaction struct {
	Hash            string                 `json:"hash"`
	From            string                 `json:"from"`
	To              string                 `json:"to"`
	Value           *big.Int               `json:"value"`
	Gas             uint64                 `json:"gas"`
	GasPrice        *big.Int               `json:"gas_price"`
	GasUsed         uint64                 `json:"gas_used"`
	Nonce           uint64                 `json:"nonce"`
	Data            []byte                 `json:"data"`
	BlockNumber     int64                  `json:"block_number"`
	BlockHash       string                 `json:"block_hash"`
	TransactionIndex int                   `json:"transaction_index"`
	Status          TransactionStatus      `json:"status"`
	Receipt         *TransactionReceipt    `json:"receipt,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	ConfirmedAt     *time.Time             `json:"confirmed_at,omitempty"`
}

// TransactionReceipt represents a transaction receipt
type TransactionReceipt struct {
	TransactionHash   string    `json:"transaction_hash"`
	BlockNumber       int64     `json:"block_number"`
	BlockHash         string    `json:"block_hash"`
	TransactionIndex  int       `json:"transaction_index"`
	From              string    `json:"from"`
	To                string    `json:"to"`
	GasUsed           uint64    `json:"gas_used"`
	CumulativeGasUsed uint64    `json:"cumulative_gas_used"`
	Status            int       `json:"status"`
	Logs              []Log     `json:"logs"`
	LogsBloom         string    `json:"logs_bloom"`
}

// Log represents an event log
type Log struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockNumber      int64    `json:"block_number"`
	TransactionHash  string   `json:"transaction_hash"`
	TransactionIndex int      `json:"transaction_index"`
	BlockHash        string   `json:"block_hash"`
	LogIndex         int      `json:"log_index"`
	Removed          bool     `json:"removed"`
}

// Contract represents a smart contract
type Contract struct {
	Address     string                 `json:"address"`
	ABI         string                 `json:"abi"`
	Bytecode    string                 `json:"bytecode"`
	Name        string                 `json:"name"`
	Symbol      string                 `json:"symbol"`
	Decimals    int                    `json:"decimals"`
	TotalSupply *big.Int               `json:"total_supply"`
	Type        ContractType           `json:"type"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
}

// TokenManager manages ERC-20 tokens
type TokenManager struct {
	tokens    map[string]*Token
	balances  map[string]map[string]*big.Int // address -> token -> balance
	allowances map[string]map[string]map[string]*big.Int // owner -> spender -> token -> allowance
	mutex     sync.RWMutex
}

// Token represents an ERC-20 token
type Token struct {
	Address     string   `json:"address"`
	Name        string   `json:"name"`
	Symbol      string   `json:"symbol"`
	Decimals    int      `json:"decimals"`
	TotalSupply *big.Int `json:"total_supply"`
	IsVerified  bool     `json:"is_verified"`
	CreatedAt   time.Time `json:"created_at"`
}

// EthereumMetrics tracks Ethereum client performance
type EthereumMetrics struct {
	// Network metrics
	CurrentBlockNumber  int64         `json:"current_block_number"`
	NetworkID           int64         `json:"network_id"`
	ChainID             int64         `json:"chain_id"`
	PeerCount           int           `json:"peer_count"`
	IsSyncing           bool          `json:"is_syncing"`
	
	// Transaction metrics
	TotalTransactions   int64         `json:"total_transactions"`
	PendingTransactions int64         `json:"pending_transactions"`
	FailedTransactions  int64         `json:"failed_transactions"`
	AverageGasPrice     *big.Int      `json:"average_gas_price"`
	AverageGasUsed      uint64        `json:"average_gas_used"`
	
	// Performance metrics
	AverageBlockTime    time.Duration `json:"average_block_time"`
	AverageTxTime       time.Duration `json:"average_tx_time"`
	RPCLatency          time.Duration `json:"rpc_latency"`
	
	// Token metrics
	TotalTokens         int64         `json:"total_tokens"`
	TokenTransfers      int64         `json:"token_transfers"`
	
	// Error metrics
	RPCErrors           int64         `json:"rpc_errors"`
	ConnectionErrors    int64         `json:"connection_errors"`
	
	// Timestamps
	LastUpdated         time.Time     `json:"last_updated"`
	LastBlockTime       time.Time     `json:"last_block_time"`
}

// Enums
type TransactionStatus string
const (
	TxStatusPending   TransactionStatus = "pending"
	TxStatusConfirmed TransactionStatus = "confirmed"
	TxStatusFailed    TransactionStatus = "failed"
	TxStatusDropped   TransactionStatus = "dropped"
)

type ContractType string
const (
	ContractTypeERC20  ContractType = "erc20"
	ContractTypeERC721 ContractType = "erc721"
	ContractTypeERC1155 ContractType = "erc1155"
	ContractTypeCustom ContractType = "custom"
)

// Interfaces
type RPCClient interface {
	Call(ctx context.Context, method string, params ...interface{}) (interface{}, error)
	GetBalance(ctx context.Context, address string) (*big.Int, error)
	GetBlockNumber(ctx context.Context) (int64, error)
	SendTransaction(ctx context.Context, tx *EthereumTransaction) (string, error)
	GetTransaction(ctx context.Context, hash string) (*EthereumTransaction, error)
	GetTransactionReceipt(ctx context.Context, hash string) (*TransactionReceipt, error)
	EstimateGas(ctx context.Context, tx *EthereumTransaction) (uint64, error)
	GetGasPrice(ctx context.Context) (*big.Int, error)
}

type WSClient interface {
	Subscribe(ctx context.Context, channel string) (<-chan interface{}, error)
	Unsubscribe(ctx context.Context, channel string) error
	IsConnected() bool
}

// NewEthereumClient creates a new Ethereum client
func NewEthereumClient(config *EthereumConfig) (*EthereumClient, error) {
	if config == nil {
		config = DefaultEthereumConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	client := &EthereumClient{
		config:        config,
		contractCache: make(map[string]*Contract),
		metrics: &EthereumMetrics{
			NetworkID:       config.NetworkID,
			ChainID:         config.ChainID,
			AverageGasPrice: big.NewInt(0),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize RPC client
	var err error
	client.rpcClient, err = NewRPCClient(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}
	
	// Initialize WebSocket client
	if config.WSUrl != "" {
		client.wsClient, err = NewWSClient(config.WSUrl)
		if err != nil {
			client.logger.Errorf("Failed to create WebSocket client: %v", err)
		}
	}
	
	// Initialize token manager
	client.tokenManager = NewTokenManager()
	
	return client, nil
}

// Start starts the Ethereum client
func (ec *EthereumClient) Start() error {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	
	if ec.isRunning {
		return fmt.Errorf("Ethereum client is already running")
	}
	
	ec.logger.Info("Starting Ethereum client...")
	
	// Test connection
	if err := ec.testConnection(); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	// Load supported tokens
	if err := ec.loadSupportedTokens(); err != nil {
		ec.logger.Errorf("Failed to load supported tokens: %v", err)
	}
	
	// Start monitoring
	if ec.config.EnableMetrics {
		go ec.monitoringLoop()
	}
	
	// Start block subscription
	if ec.wsClient != nil && ec.wsClient.IsConnected() {
		go ec.subscribeToBlocks()
	}
	
	ec.isRunning = true
	ec.logger.Info("Ethereum client started successfully")
	
	return nil
}

// GetBalance retrieves the balance of an address
func (ec *EthereumClient) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	if !ec.isRunning {
		return nil, fmt.Errorf("Ethereum client is not running")
	}
	
	balance, err := ec.rpcClient.GetBalance(ctx, address)
	if err != nil {
		ec.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	
	return balance, nil
}

// GetTokenBalance retrieves the token balance of an address
func (ec *EthereumClient) GetTokenBalance(ctx context.Context, address, tokenAddress string) (*big.Int, error) {
	if !ec.isRunning {
		return nil, fmt.Errorf("Ethereum client is not running")
	}
	
	// Get token contract
	token, err := ec.getTokenContract(tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get token contract: %w", err)
	}
	
	// Call balanceOf function
	balance, err := ec.callTokenFunction(ctx, tokenAddress, "balanceOf", address)
	if err != nil {
		return nil, fmt.Errorf("failed to get token balance: %w", err)
	}
	
	// Update cache
	ec.tokenManager.updateBalance(address, token.Symbol, balance.(*big.Int))
	
	return balance.(*big.Int), nil
}

// SendTransaction sends a transaction
func (ec *EthereumClient) SendTransaction(ctx context.Context, tx *EthereumTransaction) (*EthereumTransaction, error) {
	if !ec.isRunning {
		return nil, fmt.Errorf("Ethereum client is not running")
	}
	
	// Set default gas values if not provided
	if tx.Gas == 0 {
		gasEstimate, err := ec.rpcClient.EstimateGas(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("failed to estimate gas: %w", err)
		}
		tx.Gas = gasEstimate
	}
	
	if tx.GasPrice == nil {
		gasPrice, err := ec.rpcClient.GetGasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get gas price: %w", err)
		}
		// Add buffer to gas price
		buffer := new(big.Int).Mul(gasPrice, big.NewInt(int64(ec.config.GasPriceBuffer*100)))
		buffer = new(big.Int).Div(buffer, big.NewInt(100))
		tx.GasPrice = new(big.Int).Add(gasPrice, buffer)
	}
	
	// Check gas price limit
	if ec.config.MaxGasPrice != nil && tx.GasPrice.Cmp(ec.config.MaxGasPrice) > 0 {
		return nil, fmt.Errorf("gas price %s exceeds maximum %s", tx.GasPrice.String(), ec.config.MaxGasPrice.String())
	}
	
	// Send transaction
	hash, err := ec.rpcClient.SendTransaction(ctx, tx)
	if err != nil {
		ec.updateErrorMetrics("transaction")
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}
	
	tx.Hash = hash
	tx.Status = TxStatusPending
	tx.CreatedAt = time.Now()
	
	// Update metrics
	ec.updateTransactionMetrics(tx)
	
	ec.logger.Infof("Sent transaction %s", hash)
	
	return tx, nil
}

// GetTransaction retrieves a transaction by hash
func (ec *EthereumClient) GetTransaction(ctx context.Context, hash string) (*EthereumTransaction, error) {
	if !ec.isRunning {
		return nil, fmt.Errorf("Ethereum client is not running")
	}
	
	tx, err := ec.rpcClient.GetTransaction(ctx, hash)
	if err != nil {
		ec.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	
	// Get receipt if transaction is mined
	if tx.BlockNumber > 0 {
		receipt, err := ec.rpcClient.GetTransactionReceipt(ctx, hash)
		if err == nil {
			tx.Receipt = receipt
			tx.GasUsed = receipt.GasUsed
			
			if receipt.Status == 1 {
				tx.Status = TxStatusConfirmed
			} else {
				tx.Status = TxStatusFailed
			}
			
			if tx.ConfirmedAt == nil {
				now := time.Now()
				tx.ConfirmedAt = &now
			}
		}
	}
	
	return tx, nil
}

// GetBlockNumber retrieves the current block number
func (ec *EthereumClient) GetBlockNumber(ctx context.Context) (int64, error) {
	if !ec.isRunning {
		return 0, fmt.Errorf("Ethereum client is not running")
	}
	
	blockNumber, err := ec.rpcClient.GetBlockNumber(ctx)
	if err != nil {
		ec.updateErrorMetrics("rpc")
		return 0, fmt.Errorf("failed to get block number: %w", err)
	}
	
	// Update metrics
	ec.mutex.Lock()
	ec.metrics.CurrentBlockNumber = blockNumber
	ec.metrics.LastBlockTime = time.Now()
	ec.mutex.Unlock()
	
	return blockNumber, nil
}

// EstimateGas estimates gas for a transaction
func (ec *EthereumClient) EstimateGas(ctx context.Context, tx *EthereumTransaction) (uint64, error) {
	if !ec.isRunning {
		return 0, fmt.Errorf("Ethereum client is not running")
	}
	
	gas, err := ec.rpcClient.EstimateGas(ctx, tx)
	if err != nil {
		ec.updateErrorMetrics("rpc")
		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}
	
	return gas, nil
}

// Helper methods

func (ec *EthereumClient) testConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err := ec.rpcClient.GetBlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	return nil
}

func (ec *EthereumClient) loadSupportedTokens() error {
	for symbol, address := range ec.config.SupportedTokens {
		token, err := ec.loadTokenInfo(address)
		if err != nil {
			ec.logger.Errorf("Failed to load token %s (%s): %v", symbol, address, err)
			continue
		}
		
		ec.tokenManager.addToken(token)
		ec.logger.Infof("Loaded token %s (%s)", symbol, address)
	}
	
	return nil
}

func (ec *EthereumClient) loadTokenInfo(address string) (*Token, error) {
	// Simplified token info loading
	token := &Token{
		Address:     address,
		Name:        "Token Name",
		Symbol:      "TKN",
		Decimals:    18,
		TotalSupply: big.NewInt(1000000000000000000),
		IsVerified:  true,
		CreatedAt:   time.Now(),
	}
	
	return token, nil
}

func (ec *EthereumClient) getTokenContract(address string) (*Token, error) {
	return ec.tokenManager.getToken(address)
}

func (ec *EthereumClient) callTokenFunction(ctx context.Context, tokenAddress, function string, params ...interface{}) (interface{}, error) {
	// Simplified token function call
	return big.NewInt(1000000000000000000), nil
}

func (ec *EthereumClient) updateTransactionMetrics(tx *EthereumTransaction) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	
	ec.metrics.TotalTransactions++
	
	if tx.Status == TxStatusPending {
		ec.metrics.PendingTransactions++
	} else if tx.Status == TxStatusFailed {
		ec.metrics.FailedTransactions++
	}
	
	if tx.GasPrice != nil {
		// Update average gas price
		if ec.metrics.AverageGasPrice.Cmp(big.NewInt(0)) == 0 {
			ec.metrics.AverageGasPrice = new(big.Int).Set(tx.GasPrice)
		} else {
			ec.metrics.AverageGasPrice = new(big.Int).Add(ec.metrics.AverageGasPrice, tx.GasPrice)
			ec.metrics.AverageGasPrice = new(big.Int).Div(ec.metrics.AverageGasPrice, big.NewInt(2))
		}
	}
	
	if tx.GasUsed > 0 {
		// Update average gas used
		if ec.metrics.AverageGasUsed == 0 {
			ec.metrics.AverageGasUsed = tx.GasUsed
		} else {
			ec.metrics.AverageGasUsed = (ec.metrics.AverageGasUsed + tx.GasUsed) / 2
		}
	}
}

func (ec *EthereumClient) updateErrorMetrics(errorType string) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	
	switch errorType {
	case "rpc":
		ec.metrics.RPCErrors++
	case "connection":
		ec.metrics.ConnectionErrors++
	case "transaction":
		ec.metrics.FailedTransactions++
	}
}

func (ec *EthereumClient) monitoringLoop() {
	ticker := time.NewTicker(ec.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ec.updateMetrics()
		case <-ec.ctx.Done():
			return
		}
	}
}

func (ec *EthereumClient) updateMetrics() {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	
	ec.metrics.LastUpdated = time.Now()
	ec.metrics.TotalTokens = int64(len(ec.tokenManager.tokens))
}

func (ec *EthereumClient) subscribeToBlocks() {
	if ec.wsClient == nil {
		return
	}
	
	blockChan, err := ec.wsClient.Subscribe(ec.ctx, "newHeads")
	if err != nil {
		ec.logger.Errorf("Failed to subscribe to blocks: %v", err)
		return
	}
	
	for {
		select {
		case block := <-blockChan:
			ec.handleNewBlock(block)
		case <-ec.ctx.Done():
			return
		}
	}
}

func (ec *EthereumClient) handleNewBlock(block interface{}) {
	// Handle new block
	ec.logger.Debug("Received new block")
}

// TokenManager methods

func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens:     make(map[string]*Token),
		balances:   make(map[string]map[string]*big.Int),
		allowances: make(map[string]map[string]map[string]*big.Int),
	}
}

func (tm *TokenManager) addToken(token *Token) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	tm.tokens[token.Address] = token
}

func (tm *TokenManager) getToken(address string) (*Token, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	token, exists := tm.tokens[address]
	if !exists {
		return nil, fmt.Errorf("token not found: %s", address)
	}
	
	return token, nil
}

func (tm *TokenManager) updateBalance(address, token string, balance *big.Int) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	if tm.balances[address] == nil {
		tm.balances[address] = make(map[string]*big.Int)
	}
	
	tm.balances[address][token] = balance
}

// Stub implementations for interfaces

type stubRPCClient struct{}

func NewRPCClient(url string) (RPCClient, error) {
	return &stubRPCClient{}, nil
}

func (s *stubRPCClient) Call(ctx context.Context, method string, params ...interface{}) (interface{}, error) {
	return nil, nil
}

func (s *stubRPCClient) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	return big.NewInt(1000000000000000000), nil
}

func (s *stubRPCClient) GetBlockNumber(ctx context.Context) (int64, error) {
	return 18000000, nil
}

func (s *stubRPCClient) SendTransaction(ctx context.Context, tx *EthereumTransaction) (string, error) {
	return "0x1234567890abcdef", nil
}

func (s *stubRPCClient) GetTransaction(ctx context.Context, hash string) (*EthereumTransaction, error) {
	return &EthereumTransaction{Hash: hash}, nil
}

func (s *stubRPCClient) GetTransactionReceipt(ctx context.Context, hash string) (*TransactionReceipt, error) {
	return &TransactionReceipt{TransactionHash: hash}, nil
}

func (s *stubRPCClient) EstimateGas(ctx context.Context, tx *EthereumTransaction) (uint64, error) {
	return 21000, nil
}

func (s *stubRPCClient) GetGasPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(20000000000), nil
}

type stubWSClient struct{}

func NewWSClient(url string) (WSClient, error) {
	return &stubWSClient{}, nil
}

func (s *stubWSClient) Subscribe(ctx context.Context, channel string) (<-chan interface{}, error) {
	ch := make(chan interface{})
	return ch, nil
}

func (s *stubWSClient) Unsubscribe(ctx context.Context, channel string) error {
	return nil
}

func (s *stubWSClient) IsConnected() bool {
	return true
}

// DefaultEthereumConfig returns default Ethereum configuration
func DefaultEthereumConfig() *EthereumConfig {
	return &EthereumConfig{
		NetworkID:       1,
		ChainID:         1,
		RPCURL:          "https://mainnet.infura.io/v3/YOUR-PROJECT-ID",
		DefaultGasLimit: 21000,
		DefaultGasPrice: big.NewInt(20000000000), // 20 gwei
		MaxGasPrice:     big.NewInt(100000000000), // 100 gwei
		GasPriceBuffer:  1.1, // 10% buffer
		TxTimeout:       5 * time.Minute,
		ConfirmBlocks:   6,
		MaxRetries:      3,
		RetryDelay:      1 * time.Second,
		SupportedTokens: map[string]string{
			"USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
			"USDC": "0xA0b86a33E6441b8C4505B8C4505B8C4505B8C4505",
		},
		MaxConcurrentTx: 10,
		CacheSize:       1000,
		CacheTTL:        5 * time.Minute,
		EnableMetrics:   true,
		MetricsInterval: 30 * time.Second,
	}
}
