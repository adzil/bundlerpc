package bundlerpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

type HashSigner interface {
	SignHash(acc accounts.Account, hash []byte) ([]byte, error)
}

type Bundle interface {
	bundleHash() common.Hash
	blockNumber() uint64
}

type Client struct {
	uri      string
	pubkey   common.Address
	signerFn func(hash []byte) ([]byte, error)
}

type jsonrpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

func (c *Client) authHeaderFrom(payload []byte) (string, error) {
	hash := crypto.Keccak256Hash(payload).Hex()
	sig, err := c.signerFn(accounts.TextHash([]byte(hash)))
	if err != nil {
		return "", err
	}
	return c.pubkey.Hex() + ":" + hexutil.Encode(sig), nil
}

func (c *Client) Call(ctx context.Context, result interface{}, method string, params ...interface{}) error {
	if result != nil && reflect.ValueOf(result).Kind() != reflect.Pointer {
		return errors.New("result must be a pointer or nil")
	}

	payload, err := json.Marshal(&jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return err
	}
	authHeader, err := c.authHeaderFrom(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.uri, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Flashbots-Signature", authHeader)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var resBody jsonrpcResponse
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return err
	}
	if resBody.Error != nil {
		return resBody.Error
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resBody.Result, result)
}

type SendBundleRequest struct {
	Txs            []*types.Transaction
	BlockNumber    uint64
	MinTimestamp   time.Time
	MaxTimestamp   time.Time
	AllowRevertTxs []*types.Transaction
}

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

type sendBundleRequest struct {
	Txs               []hexutil.Bytes `json:"txs"`
	BlockNumber       hexutil.Uint64  `json:"blockNumber"`
	MinTimestamp      int64           `json:"minTimestamp,omitempty"`
	MaxTimestamp      int64           `json:"maxTimestamp,omitempty"`
	RevertingTxHashes []common.Hash   `json:"revertingTxHashes"`
}

type SentBundle struct {
	BundleHash  common.Hash `json:"bundleHash"`
	BlockNumber uint64      `json:"-"`
}

func (b *SentBundle) bundleHash() common.Hash {
	return b.BundleHash
}

func (b *SentBundle) blockNumber() uint64 {
	return b.BlockNumber
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

func (c *Client) SendBundle(ctx context.Context, req SendBundleRequest) (*SentBundle, error) {
	if len(req.Txs) == 0 {
		return nil, errors.New("cannot send bundle with empty txs")
	}
	if req.BlockNumber == 0 {
		return nil, errors.New("cannot send bundle without block number")
	}
	if !isSubsetTxs(req.Txs, req.AllowRevertTxs) {
		return nil, errors.New("allow revert txs must be a subset of txs")
	}

	hexTxs, err := hexTxsFrom(req.Txs)
	if err != nil {
		return nil, err
	}
	jsonReq := sendBundleRequest{
		Txs:               hexTxs,
		BlockNumber:       hexutil.Uint64(req.BlockNumber),
		MinTimestamp:      unixTime(req.MinTimestamp),
		MaxTimestamp:      unixTime(req.MaxTimestamp),
		RevertingTxHashes: make([]common.Hash, 0, len(req.AllowRevertTxs)),
	}
	for _, tx := range req.AllowRevertTxs {
		jsonReq.RevertingTxHashes = append(jsonReq.RevertingTxHashes, tx.Hash())
	}

	jsonRes := &SentBundle{
		BlockNumber: req.BlockNumber,
	}
	return jsonRes, c.Call(ctx, jsonRes, "eth_sendBundle", &jsonReq)
}

type CallBundleRequest struct {
	Txs              []*types.Transaction
	BlockNumber      uint64
	StateBlockNumber rpc.BlockNumber
	Timestamp        time.Time
}

type callBundleRequest struct {
	Txs              []hexutil.Bytes `json:"txs"`
	BlockNumber      uint64          `json:"blockNumber"`
	StateBlockNumber rpc.BlockNumber `json:"stateBlockNumber"`
	Timestamp        int64           `json:"timestamp"`
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

func (b *CalledBundle) bundleHash() common.Hash {
	return b.BundleHash
}

func (b *CalledBundle) blockNumber() uint64 {
	return b.BlockNumber
}

func (c *Client) CallBundle(ctx context.Context, req CallBundleRequest) (*CalledBundle, error) {
	if len(req.Txs) == 0 {
		return nil, errors.New("cannot call bundle with empty txs")
	}
	if req.BlockNumber == 0 {
		return nil, errors.New("cannot call bundle without block number")
	}
	if req.StateBlockNumber == 0 {
		req.StateBlockNumber = rpc.LatestBlockNumber
	}

	hexTx, err := hexTxsFrom(req.Txs)
	if err != nil {
		return nil, err
	}
	jsonReq := callBundleRequest{
		Txs:              hexTx,
		BlockNumber:      req.BlockNumber,
		StateBlockNumber: req.StateBlockNumber,
		Timestamp:        unixTime(req.Timestamp),
	}

	jsonRes := &CalledBundle{
		BlockNumber: req.BlockNumber,
	}
	return jsonRes, c.Call(ctx, jsonRes, "eth_callBundle", jsonReq)
}

func dial(uri string, pubkey common.Address, signerFn func(hash []byte) ([]byte, error)) (*Client, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	switch parsedURI.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", parsedURI.Scheme)
	}

	return &Client{
		uri:      uri,
		pubkey:   pubkey,
		signerFn: signerFn,
	}, nil
}

func Dial(uri string, privkey *ecdsa.PrivateKey) (*Client, error) {
	return dial(uri, crypto.PubkeyToAddress(privkey.PublicKey), func(hash []byte) ([]byte, error) {
		return crypto.Sign(hash, privkey)
	})
}

func DialWithSigner(uri string, pubkey common.Address, signer HashSigner) (*Client, error) {
	return dial(uri, pubkey, func(hash []byte) ([]byte, error) {
		return signer.SignHash(accounts.Account{Address: pubkey}, hash)
	})
}
