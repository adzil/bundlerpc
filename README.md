# Flashbots Bundle RPC

[![Go Reference](https://pkg.go.dev/badge/github.com/adzil/bundlerpc.svg)](https://pkg.go.dev/github.com/adzil/bundlerpc)
[![Go Report Card](https://goreportcard.com/badge/github.com/adzil/bundlerpc)](https://goreportcard.com/report/github.com/adzil/bundlerpc)

BundleRPC implements Flashbots JSON-RPC client that is compatible with the standard Go-Ethereum data types.

For more information about Flashbots RPC, please visit [their documentation website](https://docs.flashbots.net/flashbots-auction/searchers/advanced/rpc-endpoint/).

## Quick Start by Example

The following code snippet is incomplete and cannot be run as-is. However, it can be used as the starting point for interacting with the Flashbots RPC.

```go
package main

import (
    "fmt"

    "github.com/adzil/bundlerpc"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/ethereum/go-ethereum/rpc"
)

func main() {
    // Create random private key for signing the Flashbots JSON-RPC payload.
    // Consider using stored private key for long-term usage to build
    // reputation with the Flashbots relay.
    flashbotsKey, err := crypto.GenerateKey()
    if err != nil {
        panic(err)
    }

    // Create new JSON-RPC client using the previously generated private key.
    flashbots, err := bundlerpc.Dial("https://relay.flashbots.net", flashbotsKey)
    if err != nil {
        panic(err)
    }

    // Instantiate the Eth client to obtain the latest block number.
    ethrpc, err := rpc.Dial("http://localhost:8545")
    if err != nil {
        panic(err)
    }
    defer ethrpc.Close()
    eth := ethclient.NewClient(ethrpc)

    // ...Build the actual transactions here...
    var txOne, txTwo *types.Transaction

    // Get the latest block number.
    blockNumber, err := eth.BlockNumber(context.Background())
    if err != nil {
        panic(err)
    }

    // Send transaction bundle of txOne and txTwo using Flashbots relay. Note
    // that you must explicitly set NoSend field in the bind.TransactionOpts to
    // prevent sending them into the public mempool.
    bundle, err := flashbots.SendBundle(context.Background(), bundlerpc.SendBundleParam{
        Txs: []*types.Transaction{
            txOne,
            txTwo,
        },
        BlockNumber: blockNumber,
    })
    if err != nil {
        panic(err)
    }

    // Print the resulting bundle hash.
    fmt.Printf("%#v\n", bundle)
}
```
