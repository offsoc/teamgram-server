package blockchain

import (
	"math/big"
)

type WalletSpec struct {
	UserID     int64
	Network    string
	WalletType string
	MultiSig   bool
	Encryption bool
}

type PaymentSpec struct {
	FromAddress string
	ToAddress   string
	Amount      *big.Int
	Currency    string
	Network     string
	Priority    string
	UserID      int64
}

type Payment struct{}

func (p *Payment) GetTxHash() string { return "stub-tx-hash" }
func (p *Payment) GetStatus() string { return "success" }
func (p *Payment) GetFee() *big.Int  { return big.NewInt(0) }

type BalanceQuery struct {
	Address    string
	Currencies []string
	Network    string
}
