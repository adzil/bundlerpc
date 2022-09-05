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

func (fn jsonrpcFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeResponse := func(v jsonrpcResponse) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	writeError := func(err error) {
		berr, ok := err.(*bundlerpc.RPCError)
		if !ok {
			berr = &bundlerpc.RPCError{
				Code:    -1,
				Message: "server error: " + err.Error(),
			}
		}
		writeResponse(jsonrpcResponse{Error: berr})
	}

	if r.Method != "POST" {
		writeError(&bundlerpc.RPCError{Code: -1, Message: "http method is not post"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(&bundlerpc.RPCError{Code: -1, Message: "http content type header is not json"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(err)
		return
	}
	if !verifySignature(r.Header.Get("X-Flashbots-Signature"), bundlerpc.StandardHash(body)) {
		writeError(&bundlerpc.RPCError{Code: -1, Message: "invalid signature http header"})
		return
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(err)
		return
	}
	result, err := fn(req)
	if err != nil {
		writeError(err)
		return
	}
	writeResponse(jsonrpcResponse{Result: result})
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
