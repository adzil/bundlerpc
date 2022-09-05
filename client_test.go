package bundlerpc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adzil/bundlerpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonrpcRequest struct {
	RPCVersion string            `json:"jsonrpc"`
	ID         int               `json:"id"`
	Method     string            `json:"method"`
	Params     []json.RawMessage `json:"params"`
}

func (req *jsonrpcRequest) DecodeParams(v ...interface{}) error {
	if len(req.Params) != len(v) {
		return errors.New("mismatched param count")
	}
	for i, param := range req.Params {
		if err := json.Unmarshal(param, v[i]); err != nil {
			return err
		}
	}
	return nil
}

type jsonrpcResponse struct {
	Result interface{}         `json:"result,omitempty"`
	Error  *bundlerpc.RPCError `json:"error,omitempty"`
}

type jsonrpcFunc func(req jsonrpcRequest) (interface{}, error)

func verifySignature(header string, hash []byte) bool {
	pos := strings.IndexByte(header, ':')
	if pos <= 0 {
		return false
	}
	addr, err := hexutil.Decode(header[:pos])
	if err != nil {
		return false
	}
	sign, err := hexutil.Decode(header[pos+1:])
	if err != nil {
		return false
	}
	pubkey, err := crypto.Ecrecover(hash, sign)
	if err != nil {
		return false
	}
	extractedAddr := common.BytesToAddress(crypto.Keccak256(pubkey[1:])[12:])
	if !bytes.Equal(addr, extractedAddr[:]) {
		return false
	}
	return crypto.VerifySignature(pubkey, hash, sign[:len(sign)-1])
}

func newRPCError(msg string) *bundlerpc.RPCError {
	return &bundlerpc.RPCError{Message: msg, Code: -1000}
}

func (fn jsonrpcFunc) serveRPC(r *http.Request) (interface{}, error) {
	if r.Method != "POST" {
		return nil, newRPCError("http method is not post")
	}
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, newRPCError("http content type header is not json")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if !verifySignature(r.Header.Get("X-Flashbots-Signature"), bundlerpc.StandardHash(body)) {
		return nil, newRPCError("invalid http signature header")
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	return fn(req)
}

func (fn jsonrpcFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeResponse := func(v jsonrpcResponse) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	res, err := fn.serveRPC(r)
	if err == nil {
		writeResponse(jsonrpcResponse{Result: res})
		return
	}

	berr, ok := err.(*bundlerpc.RPCError)
	if !ok {
		berr = &bundlerpc.RPCError{
			Code:    -100,
			Message: "server error: " + err.Error(),
		}
	}
	writeResponse(jsonrpcResponse{Error: berr})
}

func TestClientCall(t *testing.T) {
	server := httptest.NewServer(jsonrpcFunc(func(req jsonrpcRequest) (interface{}, error) {
		if req.Method != "rpc_echo" {
			return nil, &bundlerpc.RPCError{Code: -1, Message: "invalid method or params"}
		}
		var msg string
		if err := req.DecodeParams(&msg); err != nil {
			return nil, err
		}
		return msg, nil
	}))
	defer server.Close()

	privkey, err := crypto.GenerateKey()
	require.NoError(t, err)
	rpc, err := bundlerpc.Dial(server.URL, privkey)
	require.NoError(t, err)

	expected := "Hello, RPC!"
	var actual string
	err = rpc.Call(context.Background(), &actual, "rpc_echo", expected)
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}
