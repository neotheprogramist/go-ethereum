// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

// TestMint tests the mint endpoint
func TestMint(t *testing.T) {
	// Create a test backend
	backend := newTestBackendForMint(t)

	// Create the API
	nonceLock := new(AddrLocker)
	api := NewMintAPI(backend, nonceLock)

	// Create a recipient address
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create a mint request
	amount := big.NewInt(1000000000000000000) // 1 ETH
	req := MintRequest{
		To:     recipient,
		Amount: (*hexutil.Big)(amount),
	}

	// Call the mint function
	resp, err := api.Mint(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.TxHash)

	// Verify the transaction was sent
	isPending, tx, _, _, _ := backend.GetTransaction(resp.TxHash)
	assert.True(t, isPending)
	assert.NotNil(t, tx)
	assert.Equal(t, recipient, *tx.To())
	assert.Equal(t, amount, tx.Value())

	// Extract the from address and verify it's the minter address
	signer := types.NewEIP155Signer(params.TestChainConfig.ChainID)
	from, err := types.Sender(signer, tx)
	assert.NoError(t, err)
	assert.Equal(t, minterAddress, from)
}

// TestMintInvalidAmount tests the mint endpoint with an invalid amount
func TestMintInvalidAmount(t *testing.T) {
	// Create a test backend
	backend := newTestBackendForMint(t)

	// Create the API
	nonceLock := new(AddrLocker)
	api := NewMintAPI(backend, nonceLock)

	// Create a recipient address
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Test with zero amount
	zeroAmount := big.NewInt(0)
	req := MintRequest{
		To:     recipient,
		Amount: (*hexutil.Big)(zeroAmount),
	}

	resp, err := api.Mint(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "amount must be greater than 0")

	// Test with nil amount
	req = MintRequest{
		To:     recipient,
		Amount: nil,
	}

	resp, err = api.Mint(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "amount must be greater than 0")
}

// newTestBackendForMint creates a test backend with the minter account having funds
func newTestBackendForMint(t *testing.T) *testBackend {
	// Create a genesis block with the minter having some initial balance
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: core.GenesisAlloc{
			minterAddress: {Balance: big.NewInt(1000000000000000000)}, // 1 ETH
		},
	}

	// Create the backend with 10 blocks
	backend := newTestBackend(t, 10, genesis, ethash.NewFaker(), func(i int, b *core.BlockGen) {
		// Add some transactions in the blocks if needed
	})

	return backend
}
