package bundlerpc

import (
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func isSubsetTxs(a []*types.Transaction, b []*types.Transaction) bool {
	if len(b) == 0 {
		return true
	}
	if len(a) == 0 && len(b) > 0 {
		return false
	}

	txs := make(map[*types.Transaction]struct{})
	for _, tx := range a {
		txs[tx] = struct{}{}
	}

	for _, tx := range b {
		if _, ok := txs[tx]; !ok {
			return false
		}
	}

	return true
}

func unixTime(t time.Time) int64 {
	if !t.IsZero() {
		return t.Unix()
	}
	return 0
}

func hexTxsFrom(txs []*types.Transaction) ([]hexutil.Bytes, error) {
	hexTxs := make([]hexutil.Bytes, 0, len(txs))
	for _, tx := range txs {
		encTx, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		hexTxs = append(hexTxs, encTx)
	}
	return hexTxs, nil
}

func standardHash(payload []byte) []byte {
	hash := crypto.Keccak256Hash(payload).Hex()
	return accounts.TextHash([]byte(hash))
}

func recoverPubkey(hash []byte, sign []byte) (pubkey []byte, addr common.Address, err error) {
	pubkey, err = crypto.Ecrecover(hash, sign)
	if err != nil {
		return
	}
	addr = common.BytesToAddress(crypto.Keccak256(pubkey[1:])[12:])
	return
}
