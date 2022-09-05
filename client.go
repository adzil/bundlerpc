package bundlerpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client implements the Flashbots RPC client. Use Dial or DialWithSigner to
// instantiate a new Client.
type Client struct {
	uri      string
	address  common.Address
	signerFn func(hash []byte) ([]byte, error)
}

type jsonrpcRequest struct {
	RPCVersion string        `json:"jsonrpc"`
	ID         int           `json:"id"`
	Method     string        `json:"method"`
	Params     []interface{} `json:"params"`
}

type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

func standardHash(payload []byte) []byte {
	hash := crypto.Keccak256Hash(payload).Hex()
	return accounts.TextHash([]byte(hash))
}

func (c *Client) authFrom(payload []byte) (string, error) {
	sig, err := c.signerFn(standardHash(payload))
	if err != nil {
		return "", err
	}
	return c.address.Hex() + ":" + hexutil.Encode(sig), nil
}

// Call arbitrary RPC method with params and optional result interface. If
// result set to nil it will not decode returned values from the server. Any
// errors generated from the RPC server will be returned as *RPCError.
func (c *Client) Call(ctx context.Context, result interface{}, method string, params ...interface{}) error {
	if result != nil && reflect.ValueOf(result).Kind() != reflect.Pointer {
		return errors.New("result must be a pointer or nil")
	}

	payload, err := json.Marshal(&jsonrpcRequest{
		RPCVersion: "2.0",
		ID:         1,
		Method:     method,
		Params:     params,
	})
	if err != nil {
		return err
	}
	authHeader, err := c.authFrom(payload)
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
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errors.New("rpc server returns no error but the status code is not 2XX")
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resBody.Result, result)
}

type sendBundleParam struct {
	Txs               []hexutil.Bytes `json:"txs"`
	BlockNumber       hexutil.Uint64  `json:"blockNumber"`
	MinTimestamp      int64           `json:"minTimestamp,omitempty"`
	MaxTimestamp      int64           `json:"maxTimestamp,omitempty"`
	RevertingTxHashes []common.Hash   `json:"revertingTxHashes"`
}

// SendBundle sends signed transaction bundle to the Flashbots relay. The
// returned SentBundle can be passed to GetBundleStats to check the bundle
// status inside the relay.
func (c *Client) SendBundle(ctx context.Context, req SendBundleParam) (*SentBundle, error) {
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
	jsonReq := sendBundleParam{
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

type callBundleParam struct {
	Txs              []hexutil.Bytes `json:"txs"`
	BlockNumber      hexutil.Uint    `json:"blockNumber"`
	StateBlockNumber rpc.BlockNumber `json:"stateBlockNumber"`
	Timestamp        int64           `json:"timestamp"`
}

// CallBundle simulates the transaction bundle and returns the execution result
// in CalledBundle.
func (c *Client) CallBundle(ctx context.Context, req CallBundleParam) (*CalledBundle, error) {
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
	jsonReq := callBundleParam{
		Txs:              hexTx,
		BlockNumber:      hexutil.Uint(req.BlockNumber),
		StateBlockNumber: req.StateBlockNumber,
		Timestamp:        unixTime(req.Timestamp),
	}

	jsonRes := &CalledBundle{
		BlockNumber: req.BlockNumber,
	}
	return jsonRes, c.Call(ctx, jsonRes, "eth_callBundle", jsonReq)
}

type privateTransactionPreferences struct {
	Fast bool `json:"fast"`
}

type sendPrivateTransactionParam struct {
	Tx             hexutil.Bytes                 `json:"tx"`
	MaxBlockNumber hexutil.Uint                  `json:"maxBlockNumber"`
	Preferences    privateTransactionPreferences `json:"preferences"`
}

// SendPrivateTransaction sends private transaction to the Flashbots RPC. The
// returned transaction hash can be used to cancel the transaction using the
// CancelPrivateTransaction.
func (c *Client) SendPrivateTransaction(
	ctx context.Context, tx *types.Transaction, maxBlockNumber uint64, fastMode bool,
) (common.Hash, error) {
	encTx, err := tx.MarshalBinary()
	if err != nil {
		return common.Hash{}, err
	}

	var hash common.Hash
	return hash, c.Call(ctx, &hash, "eth_sendPrivateTransaction", sendPrivateTransactionParam{
		Tx:             encTx,
		MaxBlockNumber: hexutil.Uint(maxBlockNumber),
		Preferences:    privateTransactionPreferences{Fast: fastMode},
	})
}

type cancelPrivateTransactionParam struct {
	TxHash common.Hash `json:"txHash"`
}

// CancelPrivateTransaction cancels the ongoing private transaction inside the
// Flashbots relay.
func (c *Client) CancelPrivateTransaction(ctx context.Context, hash common.Hash) (bool, error) {
	var success bool
	return success, c.Call(ctx, &success, "eth_cancelPrivateTransaction", cancelPrivateTransactionParam{
		TxHash: hash,
	})
}

type getUserStatsParam struct {
	BlockNumber hexutil.Uint `json:"blockNumber"`
}

// GetUserStats returns the current user status.
func (c *Client) GetUserStats(ctx context.Context, blockNumber uint64) (*UserStats, error) {
	var userStats UserStats
	return &userStats, c.Call(ctx, &userStats, "flashbots_getUserStats", getUserStatsParam{
		BlockNumber: hexutil.Uint(blockNumber),
	})
}

type getBundleStatsParam struct {
	BundleHash  common.Hash  `json:"bundleHash"`
	BlockNumber hexutil.Uint `json:"blockNumber"`
}

// GetBundleStats returns the bundle status.
func (c *Client) GetBundleStats(ctx context.Context, bundle BundleIdentifier) (*BundleStats, error) {
	hash, blockNumber := bundle.Identifier()

	var jsonRes BundleStats
	return &jsonRes, c.Call(ctx, &jsonRes, "flashbots_getBundleStats", getBundleStatsParam{
		BundleHash:  hash,
		BlockNumber: hexutil.Uint(blockNumber),
	})
}

func dial(uri string, address common.Address, signerFn func(hash []byte) ([]byte, error)) (*Client, error) {
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
		address:  address,
		signerFn: signerFn,
	}, nil
}

// Dial creates new Flashbots RPC client using private key to sign the payload.
func Dial(uri string, privkey *ecdsa.PrivateKey) (*Client, error) {
	return dial(uri, crypto.PubkeyToAddress(privkey.PublicKey), func(hash []byte) ([]byte, error) {
		return crypto.Sign(hash, privkey)
	})
}

// DialWithSigner creates new Flashbots RPC client using an external hash
// signer.
func DialWithSigner(uri string, address common.Address, signer HashSigner) (*Client, error) {
	return dial(uri, address, func(hash []byte) ([]byte, error) {
		return signer.SignHash(accounts.Account{Address: address}, hash)
	})
}
