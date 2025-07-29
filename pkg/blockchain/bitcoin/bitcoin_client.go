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

package bitcoin

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// BitcoinClient manages Bitcoin blockchain interactions
type BitcoinClient struct {
	mutex         sync.RWMutex
	config        *BitcoinConfig
	rpcClient     BitcoinRPCClient
	utxoManager   *UTXOManager
	addressCache  map[string]*AddressInfo
	metrics       *BitcoinMetrics
	logger        logx.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	isRunning     bool
}

// BitcoinConfig configuration for Bitcoin client
type BitcoinConfig struct {
	// Network settings
	Network         string `json:"network"` // mainnet, testnet, regtest
	RPCURL          string `json:"rpc_url"`
	RPCUser         string `json:"rpc_user"`
	RPCPassword     string `json:"rpc_password"`
	
	// Fee settings
	DefaultFeeRate  int64 `json:"default_fee_rate"` // satoshis per byte
	MinFeeRate      int64 `json:"min_fee_rate"`
	MaxFeeRate      int64 `json:"max_fee_rate"`
	FeeBuffer       float64 `json:"fee_buffer"`
	
	// Transaction settings
	TxTimeout       time.Duration `json:"tx_timeout"`
	ConfirmBlocks   int64         `json:"confirm_blocks"`
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	
	// UTXO settings
	MinUTXOValue    int64         `json:"min_utxo_value"` // satoshis
	MaxUTXOs        int           `json:"max_utxos"`
	UTXOCacheSize   int           `json:"utxo_cache_size"`
	
	// Performance settings
	MaxConcurrentTx int           `json:"max_concurrent_tx"`
	CacheSize       int           `json:"cache_size"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	
	// Monitoring
	EnableMetrics   bool          `json:"enable_metrics"`
	MetricsInterval time.Duration `json:"metrics_interval"`
}

// BitcoinTransaction represents a Bitcoin transaction
type BitcoinTransaction struct {
	TxID            string                 `json:"txid"`
	Hash            string                 `json:"hash"`
	Version         int32                  `json:"version"`
	Size            int                    `json:"size"`
	VSize           int                    `json:"vsize"`
	Weight          int                    `json:"weight"`
	LockTime        uint32                 `json:"locktime"`
	Inputs          []TransactionInput     `json:"inputs"`
	Outputs         []TransactionOutput    `json:"outputs"`
	Fee             int64                  `json:"fee"` // satoshis
	FeeRate         float64                `json:"fee_rate"` // sat/byte
	BlockHeight     int64                  `json:"block_height"`
	BlockHash       string                 `json:"block_hash"`
	BlockTime       int64                  `json:"block_time"`
	Confirmations   int64                  `json:"confirmations"`
	Status          BitcoinTxStatus        `json:"status"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	ConfirmedAt     *time.Time             `json:"confirmed_at,omitempty"`
}

// TransactionInput represents a transaction input
type TransactionInput struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	ScriptSig    string `json:"script_sig"`
	Witness      []string `json:"witness"`
	Sequence     uint32 `json:"sequence"`
	PrevOut      *UTXO  `json:"prev_out,omitempty"`
}

// TransactionOutput represents a transaction output
type TransactionOutput struct {
	Value        int64  `json:"value"` // satoshis
	N            uint32 `json:"n"`
	ScriptPubKey string `json:"script_pubkey"`
	Address      string `json:"address"`
	Type         string `json:"type"`
}

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	Value        int64  `json:"value"` // satoshis
	Address      string `json:"address"`
	ScriptPubKey string `json:"script_pubkey"`
	Confirmations int64 `json:"confirmations"`
	Spendable    bool   `json:"spendable"`
	Solvable     bool   `json:"solvable"`
	Safe         bool   `json:"safe"`
}

// AddressInfo represents Bitcoin address information
type AddressInfo struct {
	Address       string    `json:"address"`
	Balance       int64     `json:"balance"` // satoshis
	TotalReceived int64     `json:"total_received"`
	TotalSent     int64     `json:"total_sent"`
	TxCount       int64     `json:"tx_count"`
	UTXOs         []*UTXO   `json:"utxos"`
	Type          string    `json:"type"` // P2PKH, P2SH, P2WPKH, P2WSH
	IsWatchOnly   bool      `json:"is_watch_only"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// UTXOManager manages unspent transaction outputs
type UTXOManager struct {
	utxos     map[string][]*UTXO // address -> UTXOs
	spent     map[string]bool    // txid:vout -> spent
	mutex     sync.RWMutex
	logger    logx.Logger
}

// BitcoinMetrics tracks Bitcoin client performance
type BitcoinMetrics struct {
	// Network metrics
	CurrentBlockHeight  int64         `json:"current_block_height"`
	NetworkHashRate     *big.Int      `json:"network_hash_rate"`
	Difficulty          float64       `json:"difficulty"`
	MempoolSize         int           `json:"mempool_size"`
	
	// Transaction metrics
	TotalTransactions   int64         `json:"total_transactions"`
	PendingTransactions int64         `json:"pending_transactions"`
	FailedTransactions  int64         `json:"failed_transactions"`
	AverageFeeRate      float64       `json:"average_fee_rate"`
	AverageConfirmTime  time.Duration `json:"average_confirm_time"`
	
	// UTXO metrics
	TotalUTXOs          int64         `json:"total_utxos"`
	TotalUTXOValue      int64         `json:"total_utxo_value"`
	AverageUTXOValue    int64         `json:"average_utxo_value"`
	
	// Performance metrics
	AverageBlockTime    time.Duration `json:"average_block_time"`
	RPCLatency          time.Duration `json:"rpc_latency"`
	
	// Error metrics
	RPCErrors           int64         `json:"rpc_errors"`
	ConnectionErrors    int64         `json:"connection_errors"`
	
	// Timestamps
	LastUpdated         time.Time     `json:"last_updated"`
	LastBlockTime       time.Time     `json:"last_block_time"`
}

// Enums
type BitcoinTxStatus string
const (
	BtcTxStatusPending   BitcoinTxStatus = "pending"
	BtcTxStatusConfirmed BitcoinTxStatus = "confirmed"
	BtcTxStatusFailed    BitcoinTxStatus = "failed"
)

// BitcoinRPCClient interface for Bitcoin RPC operations
type BitcoinRPCClient interface {
	GetBalance(ctx context.Context, address string) (int64, error)
	GetBlockHeight(ctx context.Context) (int64, error)
	GetBlockHash(ctx context.Context, height int64) (string, error)
	GetBlock(ctx context.Context, hash string) (*Block, error)
	GetTransaction(ctx context.Context, txid string) (*BitcoinTransaction, error)
	SendRawTransaction(ctx context.Context, rawTx string) (string, error)
	GetUTXOs(ctx context.Context, address string) ([]*UTXO, error)
	EstimateFee(ctx context.Context, blocks int) (float64, error)
	GetMempoolInfo(ctx context.Context) (*MempoolInfo, error)
	GetNetworkInfo(ctx context.Context) (*NetworkInfo, error)
}

// Block represents a Bitcoin block
type Block struct {
	Hash              string    `json:"hash"`
	Height            int64     `json:"height"`
	Version           int32     `json:"version"`
	MerkleRoot        string    `json:"merkleroot"`
	Time              int64     `json:"time"`
	MedianTime        int64     `json:"mediantime"`
	Nonce             uint32    `json:"nonce"`
	Bits              string    `json:"bits"`
	Difficulty        float64   `json:"difficulty"`
	ChainWork         string    `json:"chainwork"`
	PreviousBlockHash string    `json:"previousblockhash"`
	NextBlockHash     string    `json:"nextblockhash"`
	Size              int       `json:"size"`
	Weight            int       `json:"weight"`
	TxCount           int       `json:"tx_count"`
	Transactions      []string  `json:"transactions"`
}

// MempoolInfo represents mempool information
type MempoolInfo struct {
	Size          int     `json:"size"`
	Bytes         int64   `json:"bytes"`
	Usage         int64   `json:"usage"`
	MaxMempool    int64   `json:"maxmempool"`
	MempoolMinFee float64 `json:"mempoolminfee"`
	MinRelayTxFee float64 `json:"minrelaytxfee"`
}

// NetworkInfo represents network information
type NetworkInfo struct {
	Version         int     `json:"version"`
	SubVersion      string  `json:"subversion"`
	ProtocolVersion int     `json:"protocolversion"`
	LocalServices   string  `json:"localservices"`
	LocalRelay      bool    `json:"localrelay"`
	TimeOffset      int     `json:"timeoffset"`
	Connections     int     `json:"connections"`
	NetworkActive   bool    `json:"networkactive"`
	Networks        []NetworkDetails `json:"networks"`
	RelayFee        float64 `json:"relayfee"`
	IncrementalFee  float64 `json:"incrementalfee"`
}

// NetworkDetails represents network details
type NetworkDetails struct {
	Name                      string `json:"name"`
	Limited                   bool   `json:"limited"`
	Reachable                 bool   `json:"reachable"`
	Proxy                     string `json:"proxy"`
	ProxyRandomizeCredentials bool   `json:"proxy_randomize_credentials"`
}

// NewBitcoinClient creates a new Bitcoin client
func NewBitcoinClient(config *BitcoinConfig) (*BitcoinClient, error) {
	if config == nil {
		config = DefaultBitcoinConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	client := &BitcoinClient{
		config:       config,
		addressCache: make(map[string]*AddressInfo),
		metrics: &BitcoinMetrics{
			NetworkHashRate: big.NewInt(0),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize RPC client
	var err error
	client.rpcClient, err = NewBitcoinRPCClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}
	
	// Initialize UTXO manager
	client.utxoManager = NewUTXOManager(logx.WithContext(ctx))
	
	return client, nil
}

// Start starts the Bitcoin client
func (bc *BitcoinClient) Start() error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	
	if bc.isRunning {
		return fmt.Errorf("Bitcoin client is already running")
	}
	
	bc.logger.Info("Starting Bitcoin client...")
	
	// Test connection
	if err := bc.testConnection(); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	// Start monitoring
	if bc.config.EnableMetrics {
		go bc.monitoringLoop()
	}
	
	bc.isRunning = true
	bc.logger.Info("Bitcoin client started successfully")
	
	return nil
}

// GetBalance retrieves the balance of an address
func (bc *BitcoinClient) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	if !bc.isRunning {
		return nil, fmt.Errorf("Bitcoin client is not running")
	}
	
	balance, err := bc.rpcClient.GetBalance(ctx, address)
	if err != nil {
		bc.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	
	// Update cache
	bc.updateAddressCache(address, balance)
	
	return big.NewInt(balance), nil
}

// SendTransaction sends a Bitcoin transaction
func (bc *BitcoinClient) SendTransaction(ctx context.Context, tx *BitcoinTransaction) (*BitcoinTransaction, error) {
	if !bc.isRunning {
		return nil, fmt.Errorf("Bitcoin client is not running")
	}
	
	// Build raw transaction
	rawTx, err := bc.buildRawTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to build raw transaction: %w", err)
	}
	
	// Send raw transaction
	txid, err := bc.rpcClient.SendRawTransaction(ctx, rawTx)
	if err != nil {
		bc.updateErrorMetrics("transaction")
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}
	
	tx.TxID = txid
	tx.Hash = txid
	tx.Status = BtcTxStatusPending
	tx.CreatedAt = time.Now()
	
	// Update UTXO manager
	bc.utxoManager.markUTXOsAsSpent(tx.Inputs)
	
	// Update metrics
	bc.updateTransactionMetrics(tx)
	
	bc.logger.Infof("Sent Bitcoin transaction %s", txid)
	
	return tx, nil
}

// GetTransaction retrieves a transaction by ID
func (bc *BitcoinClient) GetTransaction(ctx context.Context, txid string) (*BitcoinTransaction, error) {
	if !bc.isRunning {
		return nil, fmt.Errorf("Bitcoin client is not running")
	}
	
	tx, err := bc.rpcClient.GetTransaction(ctx, txid)
	if err != nil {
		bc.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	
	// Update status based on confirmations
	if tx.Confirmations >= bc.config.ConfirmBlocks {
		tx.Status = BtcTxStatusConfirmed
		if tx.ConfirmedAt == nil {
			now := time.Now()
			tx.ConfirmedAt = &now
		}
	}
	
	return tx, nil
}

// GetBlockHeight retrieves the current block height
func (bc *BitcoinClient) GetBlockHeight(ctx context.Context) (int64, error) {
	if !bc.isRunning {
		return 0, fmt.Errorf("Bitcoin client is not running")
	}
	
	height, err := bc.rpcClient.GetBlockHeight(ctx)
	if err != nil {
		bc.updateErrorMetrics("rpc")
		return 0, fmt.Errorf("failed to get block height: %w", err)
	}
	
	// Update metrics
	bc.mutex.Lock()
	bc.metrics.CurrentBlockHeight = height
	bc.metrics.LastBlockTime = time.Now()
	bc.mutex.Unlock()
	
	return height, nil
}

// EstimateFee estimates fee for a transaction
func (bc *BitcoinClient) EstimateFee(ctx context.Context, blocks int) (*big.Int, error) {
	if !bc.isRunning {
		return nil, fmt.Errorf("Bitcoin client is not running")
	}
	
	feeRate, err := bc.rpcClient.EstimateFee(ctx, blocks)
	if err != nil {
		bc.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to estimate fee: %w", err)
	}
	
	// Convert BTC/kB to satoshis/byte
	satoshisPerByte := int64(feeRate * 100000000 / 1000)
	
	return big.NewInt(satoshisPerByte), nil
}

// GetUTXOs retrieves UTXOs for an address
func (bc *BitcoinClient) GetUTXOs(ctx context.Context, address string) ([]*UTXO, error) {
	if !bc.isRunning {
		return nil, fmt.Errorf("Bitcoin client is not running")
	}
	
	utxos, err := bc.rpcClient.GetUTXOs(ctx, address)
	if err != nil {
		bc.updateErrorMetrics("rpc")
		return nil, fmt.Errorf("failed to get UTXOs: %w", err)
	}
	
	// Update UTXO manager
	bc.utxoManager.updateUTXOs(address, utxos)
	
	return utxos, nil
}

// Helper methods

func (bc *BitcoinClient) testConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err := bc.rpcClient.GetBlockHeight(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	return nil
}

func (bc *BitcoinClient) buildRawTransaction(tx *BitcoinTransaction) (string, error) {
	// Simplified raw transaction building
	return "0100000001...", nil
}

func (bc *BitcoinClient) updateAddressCache(address string, balance int64) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	
	if info, exists := bc.addressCache[address]; exists {
		info.Balance = balance
		info.UpdatedAt = time.Now()
	} else {
		bc.addressCache[address] = &AddressInfo{
			Address:   address,
			Balance:   balance,
			UpdatedAt: time.Now(),
		}
	}
}

func (bc *BitcoinClient) updateTransactionMetrics(tx *BitcoinTransaction) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	
	bc.metrics.TotalTransactions++
	
	if tx.Status == BtcTxStatusPending {
		bc.metrics.PendingTransactions++
	} else if tx.Status == BtcTxStatusFailed {
		bc.metrics.FailedTransactions++
	}
	
	if tx.FeeRate > 0 {
		// Update average fee rate
		if bc.metrics.AverageFeeRate == 0 {
			bc.metrics.AverageFeeRate = tx.FeeRate
		} else {
			bc.metrics.AverageFeeRate = (bc.metrics.AverageFeeRate + tx.FeeRate) / 2
		}
	}
}

func (bc *BitcoinClient) updateErrorMetrics(errorType string) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	
	switch errorType {
	case "rpc":
		bc.metrics.RPCErrors++
	case "connection":
		bc.metrics.ConnectionErrors++
	case "transaction":
		bc.metrics.FailedTransactions++
	}
}

func (bc *BitcoinClient) monitoringLoop() {
	ticker := time.NewTicker(bc.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			bc.updateMetrics()
		case <-bc.ctx.Done():
			return
		}
	}
}

func (bc *BitcoinClient) updateMetrics() {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	
	bc.metrics.LastUpdated = time.Now()
	
	// Update UTXO metrics
	bc.metrics.TotalUTXOs = int64(bc.utxoManager.getTotalUTXOCount())
	bc.metrics.TotalUTXOValue = bc.utxoManager.getTotalUTXOValue()
	
	if bc.metrics.TotalUTXOs > 0 {
		bc.metrics.AverageUTXOValue = bc.metrics.TotalUTXOValue / bc.metrics.TotalUTXOs
	}
}

// UTXOManager methods

func NewUTXOManager(logger logx.Logger) *UTXOManager {
	return &UTXOManager{
		utxos:  make(map[string][]*UTXO),
		spent:  make(map[string]bool),
		logger: logger,
	}
}

func (um *UTXOManager) updateUTXOs(address string, utxos []*UTXO) {
	um.mutex.Lock()
	defer um.mutex.Unlock()
	
	um.utxos[address] = utxos
}

func (um *UTXOManager) markUTXOsAsSpent(inputs []TransactionInput) {
	um.mutex.Lock()
	defer um.mutex.Unlock()
	
	for _, input := range inputs {
		key := fmt.Sprintf("%s:%d", input.TxID, input.Vout)
		um.spent[key] = true
	}
}

func (um *UTXOManager) getTotalUTXOCount() int {
	um.mutex.RLock()
	defer um.mutex.RUnlock()
	
	count := 0
	for _, utxos := range um.utxos {
		count += len(utxos)
	}
	
	return count
}

func (um *UTXOManager) getTotalUTXOValue() int64 {
	um.mutex.RLock()
	defer um.mutex.RUnlock()
	
	total := int64(0)
	for _, utxos := range um.utxos {
		for _, utxo := range utxos {
			total += utxo.Value
		}
	}
	
	return total
}

// Stub implementation for BitcoinRPCClient

type stubBitcoinRPCClient struct{}

func NewBitcoinRPCClient(config *BitcoinConfig) (BitcoinRPCClient, error) {
	return &stubBitcoinRPCClient{}, nil
}

func (s *stubBitcoinRPCClient) GetBalance(ctx context.Context, address string) (int64, error) {
	return 100000000, nil // 1 BTC in satoshis
}

func (s *stubBitcoinRPCClient) GetBlockHeight(ctx context.Context) (int64, error) {
	return 800000, nil
}

func (s *stubBitcoinRPCClient) GetBlockHash(ctx context.Context, height int64) (string, error) {
	return "00000000000000000001234567890abcdef", nil
}

func (s *stubBitcoinRPCClient) GetBlock(ctx context.Context, hash string) (*Block, error) {
	return &Block{Hash: hash}, nil
}

func (s *stubBitcoinRPCClient) GetTransaction(ctx context.Context, txid string) (*BitcoinTransaction, error) {
	return &BitcoinTransaction{TxID: txid}, nil
}

func (s *stubBitcoinRPCClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	return "1234567890abcdef1234567890abcdef", nil
}

func (s *stubBitcoinRPCClient) GetUTXOs(ctx context.Context, address string) ([]*UTXO, error) {
	return []*UTXO{
		{
			TxID:  "abcdef1234567890",
			Vout:  0,
			Value: 100000000,
			Address: address,
		},
	}, nil
}

func (s *stubBitcoinRPCClient) EstimateFee(ctx context.Context, blocks int) (float64, error) {
	return 0.00001, nil // BTC/kB
}

func (s *stubBitcoinRPCClient) GetMempoolInfo(ctx context.Context) (*MempoolInfo, error) {
	return &MempoolInfo{Size: 1000}, nil
}

func (s *stubBitcoinRPCClient) GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	return &NetworkInfo{Connections: 8}, nil
}

// DefaultBitcoinConfig returns default Bitcoin configuration
func DefaultBitcoinConfig() *BitcoinConfig {
	return &BitcoinConfig{
		Network:         "mainnet",
		RPCURL:          "http://localhost:8332",
		RPCUser:         "bitcoin",
		RPCPassword:     "password",
		DefaultFeeRate:  10, // 10 sat/byte
		MinFeeRate:      1,
		MaxFeeRate:      1000,
		FeeBuffer:       1.1, // 10% buffer
		TxTimeout:       10 * time.Minute,
		ConfirmBlocks:   6,
		MaxRetries:      3,
		RetryDelay:      1 * time.Second,
		MinUTXOValue:    546, // dust limit
		MaxUTXOs:        100,
		UTXOCacheSize:   1000,
		MaxConcurrentTx: 10,
		CacheSize:       1000,
		CacheTTL:        5 * time.Minute,
		EnableMetrics:   true,
		MetricsInterval: 30 * time.Second,
	}
}
