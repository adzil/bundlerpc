package bundlerpc

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// SignerFunc is a generic hash signer function placeholder to support custom
// keystore implementation.
type SignerFunc func(hash []byte) ([]byte, error)

// RPCError represents error that is returned from the RPC server.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// HashSigner abstracts an external hash signer.
type HashSigner interface {
	SignHash(acc accounts.Account, hash []byte) ([]byte, error)
}

// BundleIdentifier abstracts bundle identification that can be used to fetch
// its status using GetBundleStats.
type BundleIdentifier interface {
	Identifier() (hash common.Hash, blockNumber uint64)
}

type SendBundleParam struct {
	Txs            []*types.Transaction
	BlockNumber    uint64
	MinTimestamp   time.Time
	MaxTimestamp   time.Time
	AllowRevertTxs []*types.Transaction
}

type SentBundle struct {
	BundleHash  common.Hash `json:"bundleHash"`
	BlockNumber uint64      `json:"-"`
}

func (b *SentBundle) Identifier() (hash common.Hash, blockNumber uint64) {
	return b.BundleHash, b.BlockNumber
}

type CallBundleParam struct {
	Txs              []*types.Transaction
	BlockNumber      uint64
	StateBlockNumber rpc.BlockNumber
	Timestamp        time.Time
}

type TxResult struct {
	CoinbaseDiff      *big.Int       `json:"coinbaseDiff"`
	ETHSentToCoinbase *big.Int       `json:"ethSentToCoinbase"`
	GasFees           *big.Int       `json:"gasFees"`
	GasPrice          *big.Int       `json:"gasPrice"`
	GasUsed           uint64         `json:"gasUsed"`
	From              common.Address `json:"fromAddress"`
	To                common.Address `json:"toAddress"`
	Hash              common.Hash    `json:"txHash"`
	Value             *big.Int       `json:"value"`
	Error             string         `json:"error"`
	Revert            string         `json:"revert"`
}

type CalledBundle struct {
	BundleHash        common.Hash `json:"bundleHash"`
	BlockNumber       uint64      `json:"-"`
	CoinbaseDiff      *big.Int    `json:"coinbaseDiff"`
	ETHSentToCoinbase *big.Int    `json:"ethSentToCoinbase"`
	GasFees           *big.Int    `json:"gasFees"`
	TotalGasUsed      uint64      `json:"totalGasUsed"`
	StateBlockNumber  uint64      `json:"stateBlockNumber"`
	Results           []TxResult  `json:"results"`
	FirstRevert       *TxResult   `json:"firstRevert"`
}

func (b *CalledBundle) Identifier() (hash common.Hash, blockNumber uint64) {
	return b.BundleHash, b.BlockNumber
}

type BundleStats struct {
	IsSimulated    bool      `json:"isSimulated"`
	IsSentToMiners bool      `json:"isSentToMiners"`
	IsHighPriority bool      `json:"isHighPriority"`
	SimulatedAt    time.Time `json:"simulatedAt"`
	SubmittedAt    time.Time `json:"submittedAt"`
	SentToMinersAt time.Time `json:"sentToMinersAt"`
}

type UserStats struct {
	IsHighPriority       bool     `json:"is_high_priority"`
	AllTimeMinerPayments *big.Int `json:"all_time_miner_payments"`
	AllTimeGasSimulated  *big.Int `json:"all_time_gas_simulated"`
	Last7dMinerPayments  *big.Int `json:"last_7d_miner_payments"`
	Last7dGasSimulated   *big.Int `json:"last_7d_gas_simulated"`
	Last1dMinerPayments  *big.Int `json:"last_1d_miner_payments"`
	Last1dGasSimulated   *big.Int `json:"last_1d_gas_simulated"`
}
