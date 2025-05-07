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
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	// ErrInsufficientMintPermissions is returned if the user doesn't have permission to mint tokens
	ErrInsufficientMintPermissions = errors.New("insufficient permissions to mint tokens")

	// minterKey is a predefined private key for testing purposes
	minterKey, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")

	// minterAddress is the address corresponding to the minterKey
	minterAddress = crypto.PubkeyToAddress(minterKey.PublicKey)
)

// MintAPI provides an API to mint tokens (for testing purposes)
type MintAPI struct {
	b         Backend
	nonceLock *AddrLocker
}

// NewMintAPI creates a new API for minting tokens
func NewMintAPI(b Backend, nonceLock *AddrLocker) *MintAPI {
	return &MintAPI{b: b, nonceLock: nonceLock}
}

// MintRequest represents the parameters for a mint operation
type MintRequest struct {
	To     common.Address `json:"to"`
	Amount *hexutil.Big   `json:"amount"`
}

// MintResponse represents the response from a mint operation
type MintResponse struct {
	TxHash common.Hash `json:"txHash"`
}

// Mint creates a transaction that mints tokens to the specified address
// This is for testing purposes only and would typically require proper authentication
// in a production environment
func (api *MintAPI) Mint(ctx context.Context, req MintRequest) (*MintResponse, error) {
	// For a real implementation, we would check permissions here
	// For this example, we'll allow minting to any address

	if req.Amount == nil || req.Amount.ToInt().Cmp(common.Big0) <= 0 {
		return nil, errors.New("mint amount must be greater than 0")
	}

	// Create a transaction to send the minted amount to the recipient
	// In a real implementation, this would call a specific contract method
	// For this example, we'll just create a simple value transfer

	// Get the next nonce for the sender (using the predefined minter address)
	nonce, err := api.b.GetPoolNonce(ctx, minterAddress)
	if err != nil {
		log.Error("Failed to get nonce for mint operation", "err", err)
		return nil, err
	}

	// Create the transaction
	tx := types.NewTransaction(
		nonce,
		req.To,
		req.Amount.ToInt(),
		21000,         // Standard gas limit for transfers
		big.NewInt(1), // 1 wei gas price for simplicity
		nil,           // No additional data
	)

	// Sign the transaction with the minter's key
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(api.b.ChainConfig().ChainID), minterKey)
	if err != nil {
		log.Error("Failed to sign mint transaction", "err", err)
		return nil, err
	}

	// Send the transaction
	if err := api.b.SendTx(ctx, signedTx); err != nil {
		log.Error("Failed to send mint transaction", "err", err)
		return nil, err
	}

	return &MintResponse{
		TxHash: signedTx.Hash(),
	}, nil
}
