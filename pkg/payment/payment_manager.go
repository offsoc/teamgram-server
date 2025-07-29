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

package payment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// PaymentManager handles payment processing and cryptocurrency transactions
type PaymentManager struct {
	config    *PaymentConfig
	payments  map[string]*Payment
	refunds   map[string]*Refund
	wallets   map[int64]*Wallet
	providers map[string]*PaymentProvider
	mutex     sync.RWMutex
	logger    logx.Logger
}

// PaymentConfig represents payment configuration
type PaymentConfig struct {
	// Payment settings
	SupportedCurrencies []string      `json:"supported_currencies"`
	MinAmount           float64       `json:"min_amount"`
	MaxAmount           float64       `json:"max_amount"`
	TransactionTimeout  time.Duration `json:"transaction_timeout"`

	// Cryptocurrency settings
	SupportedCryptos        []string `json:"supported_cryptos"`
	BlockchainConfirmations int      `json:"blockchain_confirmations"`
	CryptoExchangeRate      bool     `json:"crypto_exchange_rate"`

	// Security settings
	EnableEncryption bool `json:"enable_encryption"`
	FraudDetection   bool `json:"fraud_detection"`
	RateLimiting     bool `json:"rate_limiting"`

	// Fee settings
	ProcessingFee float64 `json:"processing_fee"`
	NetworkFee    float64 `json:"network_fee"`
	RefundFee     float64 `json:"refund_fee"`
}

// Payment represents a payment transaction
type Payment struct {
	ID              string        `json:"id"`
	UserID          int64         `json:"user_id"`
	Amount          float64       `json:"amount"`
	Currency        string        `json:"currency"`
	CryptoAmount    float64       `json:"crypto_amount"`
	CryptoCurrency  string        `json:"crypto_currency"`
	Status          PaymentStatus `json:"status"`
	Type            PaymentType   `json:"type"`
	Provider        string        `json:"provider"`
	TransactionHash string        `json:"transaction_hash"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	CompletedAt     time.Time     `json:"completed_at"`

	// Payment details
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	RecipientID int64                  `json:"recipient_id"`

	// Fees
	ProcessingFee float64 `json:"processing_fee"`
	NetworkFee    float64 `json:"network_fee"`
	TotalFee      float64 `json:"total_fee"`

	// Security
	IPAddress  string  `json:"ip_address"`
	UserAgent  string  `json:"user_agent"`
	FraudScore float64 `json:"fraud_score"`
}

// PaymentStatus represents payment status
type PaymentStatus string

const (
	PaymentStatusPending    PaymentStatus = "pending"
	PaymentStatusProcessing PaymentStatus = "processing"
	PaymentStatusCompleted  PaymentStatus = "completed"
	PaymentStatusFailed     PaymentStatus = "failed"
	PaymentStatusCancelled  PaymentStatus = "cancelled"
	PaymentStatusRefunded   PaymentStatus = "refunded"
)

// PaymentType represents payment type
type PaymentType string

const (
	PaymentTypeCrypto PaymentType = "crypto"
	PaymentTypeFiat   PaymentType = "fiat"
	PaymentTypeMixed  PaymentType = "mixed"
)

// Refund represents a payment refund
type Refund struct {
	ID          string       `json:"id"`
	PaymentID   string       `json:"payment_id"`
	UserID      int64        `json:"user_id"`
	Amount      float64      `json:"amount"`
	Currency    string       `json:"currency"`
	Reason      string       `json:"reason"`
	Status      RefundStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	ProcessedAt time.Time    `json:"processed_at"`

	// Refund details
	Type            RefundType `json:"type"`
	TransactionHash string     `json:"transaction_hash"`
	Fee             float64    `json:"fee"`
}

// RefundStatus represents refund status
type RefundStatus string

const (
	RefundStatusPending    RefundStatus = "pending"
	RefundStatusProcessing RefundStatus = "processing"
	RefundStatusCompleted  RefundStatus = "completed"
	RefundStatusFailed     RefundStatus = "failed"
)

// RefundType represents refund type
type RefundType string

const (
	RefundTypeFull    RefundType = "full"
	RefundTypePartial RefundType = "partial"
)

// Wallet represents a user's cryptocurrency wallet
type Wallet struct {
	UserID     int64     `json:"user_id"`
	Currency   string    `json:"currency"`
	Address    string    `json:"address"`
	PrivateKey string    `json:"private_key"`
	Balance    float64   `json:"balance"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Security
	Encrypted     bool      `json:"encrypted"`
	BackupEnabled bool      `json:"backup_enabled"`
	LastBackup    time.Time `json:"last_backup"`
}

// PaymentProvider represents a payment provider
type PaymentProvider struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Type                string    `json:"type"`
	SupportedCurrencies []string  `json:"supported_currencies"`
	APIKey              string    `json:"api_key"`
	SecretKey           string    `json:"secret_key"`
	Endpoint            string    `json:"endpoint"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`

	// Provider settings
	ProcessingFee float64       `json:"processing_fee"`
	SuccessRate   float64       `json:"success_rate"`
	AverageTime   time.Duration `json:"average_time"`
}

// NewPaymentManager creates a new payment manager
func NewPaymentManager(config *PaymentConfig) (*PaymentManager, error) {
	if config == nil {
		config = DefaultPaymentConfig()
	}

	manager := &PaymentManager{
		config:    config,
		payments:  make(map[string]*Payment),
		refunds:   make(map[string]*Refund),
		wallets:   make(map[int64]*Wallet),
		providers: make(map[string]*PaymentProvider),
		logger:    logx.WithContext(context.Background()),
	}

	// Initialize payment providers
	manager.initializeProviders()

	return manager, nil
}

// CreatePayment creates a new payment
func (m *PaymentManager) CreatePayment(ctx context.Context, userID int64, amount float64, currency string, paymentType PaymentType, description string) (*Payment, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate amount
	if amount < m.config.MinAmount || amount > m.config.MaxAmount {
		return nil, fmt.Errorf("invalid amount: %f", amount)
	}

	// Validate currency
	if !m.isCurrencySupported(currency) {
		return nil, fmt.Errorf("unsupported currency: %s", currency)
	}

	// Generate payment ID
	paymentID := m.generatePaymentID()

	// Calculate fees
	processingFee := amount * m.config.ProcessingFee
	networkFee := m.config.NetworkFee
	totalFee := processingFee + networkFee

	// Create payment
	payment := &Payment{
		ID:            paymentID,
		UserID:        userID,
		Amount:        amount,
		Currency:      currency,
		Status:        PaymentStatusPending,
		Type:          paymentType,
		Description:   description,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ProcessingFee: processingFee,
		NetworkFee:    networkFee,
		TotalFee:      totalFee,
		Metadata:      make(map[string]interface{}),
	}

	// Set crypto amount if crypto payment
	if paymentType == PaymentTypeCrypto || paymentType == PaymentTypeMixed {
		cryptoAmount, cryptoCurrency, err := m.convertToCrypto(amount, currency)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to crypto: %w", err)
		}
		payment.CryptoAmount = cryptoAmount
		payment.CryptoCurrency = cryptoCurrency
	}

	m.payments[paymentID] = payment

	m.logger.Infof("Created payment: %s, amount: %f %s", paymentID, amount, currency)
	return payment, nil
}

// ProcessPayment processes a payment
func (m *PaymentManager) ProcessPayment(ctx context.Context, paymentID string, providerID string) (*Payment, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	payment, exists := m.payments[paymentID]
	if !exists {
		return nil, fmt.Errorf("payment not found")
	}

	if payment.Status != PaymentStatusPending {
		return nil, fmt.Errorf("payment cannot be processed in current status: %s", payment.Status)
	}

	// Get provider
	provider, exists := m.providers[providerID]
	if !exists || !provider.Active {
		return nil, fmt.Errorf("payment provider not found or inactive")
	}

	// Update payment status
	payment.Status = PaymentStatusProcessing
	payment.Provider = providerID
	payment.UpdatedAt = time.Now()

	// Process payment based on type
	switch payment.Type {
	case PaymentTypeCrypto:
		return m.processCryptoPayment(payment, provider)
	case PaymentTypeFiat:
		return m.processFiatPayment(payment, provider)
	case PaymentTypeMixed:
		return m.processMixedPayment(payment, provider)
	default:
		return nil, fmt.Errorf("unsupported payment type: %s", payment.Type)
	}
}

// CompletePayment completes a payment
func (m *PaymentManager) CompletePayment(ctx context.Context, paymentID string, transactionHash string) (*Payment, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	payment, exists := m.payments[paymentID]
	if !exists {
		return nil, fmt.Errorf("payment not found")
	}

	if payment.Status != PaymentStatusProcessing {
		return nil, fmt.Errorf("payment cannot be completed in current status: %s", payment.Status)
	}

	// Update payment
	payment.Status = PaymentStatusCompleted
	payment.TransactionHash = transactionHash
	payment.CompletedAt = time.Now()
	payment.UpdatedAt = time.Now()

	// Update wallet balance if crypto payment
	if payment.Type == PaymentTypeCrypto || payment.Type == PaymentTypeMixed {
		m.updateWalletBalance(payment.UserID, payment.CryptoCurrency, payment.CryptoAmount)
	}

	m.logger.Infof("Completed payment: %s", paymentID)
	return payment, nil
}

// CreateRefund creates a refund for a payment
func (m *PaymentManager) CreateRefund(ctx context.Context, paymentID string, amount float64, reason string) (*Refund, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	payment, exists := m.payments[paymentID]
	if !exists {
		return nil, fmt.Errorf("payment not found")
	}

	if payment.Status != PaymentStatusCompleted {
		return nil, fmt.Errorf("payment must be completed to create refund")
	}

	if amount > payment.Amount {
		return nil, fmt.Errorf("refund amount cannot exceed payment amount")
	}

	// Generate refund ID
	refundID := m.generateRefundID()

	// Determine refund type
	refundType := RefundTypePartial
	if amount == payment.Amount {
		refundType = RefundTypeFull
	}

	// Create refund
	refund := &Refund{
		ID:        refundID,
		PaymentID: paymentID,
		UserID:    payment.UserID,
		Amount:    amount,
		Currency:  payment.Currency,
		Reason:    reason,
		Status:    RefundStatusPending,
		Type:      refundType,
		Fee:       m.config.RefundFee,
		CreatedAt: time.Now(),
	}

	m.refunds[refundID] = refund

	// Update payment status
	payment.Status = PaymentStatusRefunded
	payment.UpdatedAt = time.Now()

	m.logger.Infof("Created refund: %s for payment: %s", refundID, paymentID)
	return refund, nil
}

// ProcessRefund processes a refund
func (m *PaymentManager) ProcessRefund(ctx context.Context, refundID string) (*Refund, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	refund, exists := m.refunds[refundID]
	if !exists {
		return nil, fmt.Errorf("refund not found")
	}

	if refund.Status != RefundStatusPending {
		return nil, fmt.Errorf("refund cannot be processed in current status: %s", refund.Status)
	}

	// Update refund status
	refund.Status = RefundStatusProcessing
	refund.ProcessedAt = time.Now()

	// Process refund based on payment type
	payment, exists := m.payments[refund.PaymentID]
	if !exists {
		return nil, fmt.Errorf("original payment not found")
	}

	if payment.Type == PaymentTypeCrypto || payment.Type == PaymentTypeMixed {
		// Process crypto refund
		transactionHash, err := m.processCryptoRefund(refund, payment)
		if err != nil {
			refund.Status = RefundStatusFailed
			return nil, fmt.Errorf("failed to process crypto refund: %w", err)
		}
		refund.TransactionHash = transactionHash
	}

	// Complete refund
	refund.Status = RefundStatusCompleted

	m.logger.Infof("Processed refund: %s", refundID)
	return refund, nil
}

// GetPayment returns a payment
func (m *PaymentManager) GetPayment(ctx context.Context, paymentID string) (*Payment, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	payment, exists := m.payments[paymentID]
	if !exists {
		return nil, fmt.Errorf("payment not found")
	}

	return payment, nil
}

// GetUserPayments returns user's payment history
func (m *PaymentManager) GetUserPayments(ctx context.Context, userID int64, limit int) ([]*Payment, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var userPayments []*Payment
	for _, payment := range m.payments {
		if payment.UserID == userID {
			userPayments = append(userPayments, payment)
		}
	}

	// Sort by creation date (descending)
	sort.Slice(userPayments, func(i, j int) bool {
		return userPayments[i].CreatedAt.After(userPayments[j].CreatedAt)
	})

	// Limit results
	if limit > 0 && len(userPayments) > limit {
		userPayments = userPayments[:limit]
	}

	return userPayments, nil
}

// GetWallet returns user's wallet
func (m *PaymentManager) GetWallet(ctx context.Context, userID int64, currency string) (*Wallet, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	wallet, exists := m.wallets[userID]
	if !exists {
		return nil, fmt.Errorf("wallet not found")
	}

	if wallet.Currency != currency {
		return nil, fmt.Errorf("wallet currency mismatch")
	}

	return wallet, nil
}

// CreateWallet creates a new wallet for a user
func (m *PaymentManager) CreateWallet(ctx context.Context, userID int64, currency string) (*Wallet, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if wallet already exists
	if _, exists := m.wallets[userID]; exists {
		return nil, fmt.Errorf("wallet already exists")
	}

	// Generate wallet address and private key
	address, privateKey, err := m.generateWallet(currency)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wallet: %w", err)
	}

	// Create wallet
	wallet := &Wallet{
		UserID:     userID,
		Currency:   currency,
		Address:    address,
		PrivateKey: privateKey,
		Balance:    0.0,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Encrypted:  m.config.EnableEncryption,
	}

	m.wallets[userID] = wallet

	m.logger.Infof("Created wallet for user %d: %s", userID, currency)
	return wallet, nil
}

// isCurrencySupported checks if currency is supported
func (m *PaymentManager) isCurrencySupported(currency string) bool {
	for _, supported := range m.config.SupportedCurrencies {
		if supported == currency {
			return true
		}
	}
	return false
}

// convertToCrypto converts fiat amount to crypto
func (m *PaymentManager) convertToCrypto(amount float64, currency string) (float64, string, error) {
	// Simplified conversion - in real implementation, use exchange rate API
	exchangeRates := map[string]map[string]float64{
		"USD": {
			"BTC": 0.000025,
			"ETH": 0.0004,
			"LTC": 0.01,
		},
		"EUR": {
			"BTC": 0.000023,
			"ETH": 0.00037,
			"LTC": 0.009,
		},
	}

	rates, exists := exchangeRates[currency]
	if !exists {
		return 0, "", fmt.Errorf("unsupported currency for conversion: %s", currency)
	}

	// Use first available crypto
	for crypto, rate := range rates {
		return amount * rate, crypto, nil
	}

	return 0, "", fmt.Errorf("no crypto conversion available")
}

// processCryptoPayment processes a crypto payment
func (m *PaymentManager) processCryptoPayment(payment *Payment, provider *PaymentProvider) (*Payment, error) {
	// Simulate crypto payment processing
	time.Sleep(100 * time.Millisecond)

	// Generate transaction hash
	payment.TransactionHash = m.generateTransactionHash()

	return payment, nil
}

// processFiatPayment processes a fiat payment
func (m *PaymentManager) processFiatPayment(payment *Payment, provider *PaymentProvider) (*Payment, error) {
	// Simulate fiat payment processing
	time.Sleep(200 * time.Millisecond)

	return payment, nil
}

// processMixedPayment processes a mixed payment
func (m *PaymentManager) processMixedPayment(payment *Payment, provider *PaymentProvider) (*Payment, error) {
	// Process both crypto and fiat components
	return m.processCryptoPayment(payment, provider)
}

// processCryptoRefund processes a crypto refund
func (m *PaymentManager) processCryptoRefund(refund *Refund, payment *Payment) (string, error) {
	// Simulate crypto refund processing
	time.Sleep(150 * time.Millisecond)

	// Generate transaction hash
	transactionHash := m.generateTransactionHash()

	return transactionHash, nil
}

// updateWalletBalance updates wallet balance
func (m *PaymentManager) updateWalletBalance(userID int64, currency string, amount float64) {
	wallet, exists := m.wallets[userID]
	if exists && wallet.Currency == currency {
		wallet.Balance += amount
		wallet.UpdatedAt = time.Now()
	}
}

// generateWallet generates a new wallet
func (m *PaymentManager) generateWallet(currency string) (string, string, error) {
	// Simplified wallet generation
	address := make([]byte, 32)
	rand.Read(address)

	privateKey := make([]byte, 64)
	rand.Read(privateKey)

	return hex.EncodeToString(address), hex.EncodeToString(privateKey), nil
}

// generatePaymentID generates a unique payment ID
func (m *PaymentManager) generatePaymentID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// generateRefundID generates a unique refund ID
func (m *PaymentManager) generateRefundID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// generateTransactionHash generates a transaction hash
func (m *PaymentManager) generateTransactionHash() string {
	hash := make([]byte, 32)
	rand.Read(hash)
	return hex.EncodeToString(hash)
}

// initializeProviders initializes payment providers
func (m *PaymentManager) initializeProviders() {
	// Initialize crypto providers
	cryptoProviders := []struct {
		id         string
		name       string
		currencies []string
	}{
		{"bitcoin", "Bitcoin", []string{"BTC"}},
		{"ethereum", "Ethereum", []string{"ETH"}},
		{"litecoin", "Litecoin", []string{"LTC"}},
	}

	for _, provider := range cryptoProviders {
		m.providers[provider.id] = &PaymentProvider{
			ID:                  provider.id,
			Name:                provider.name,
			Type:                "crypto",
			SupportedCurrencies: provider.currencies,
			Active:              true,
			CreatedAt:           time.Now(),
			ProcessingFee:       0.001, // 0.1%
			SuccessRate:         0.999,
			AverageTime:         5 * time.Minute,
		}
	}
}

// DefaultPaymentConfig returns default payment configuration
func DefaultPaymentConfig() *PaymentConfig {
	return &PaymentConfig{
		SupportedCurrencies:     []string{"USD", "EUR", "GBP", "JPY"},
		MinAmount:               0.01,
		MaxAmount:               1000000.0,
		TransactionTimeout:      30 * time.Minute,
		SupportedCryptos:        []string{"BTC", "ETH", "LTC", "BCH"},
		BlockchainConfirmations: 6,
		CryptoExchangeRate:      true,
		EnableEncryption:        true,
		FraudDetection:          true,
		RateLimiting:            true,
		ProcessingFee:           0.029, // 2.9%
		NetworkFee:              0.30,  // $0.30
		RefundFee:               0.10,  // $0.10
	}
}
