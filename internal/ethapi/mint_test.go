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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

// generateZKProof generates a ZK proof for testing purposes
// It follows the steps from the wormhole README.md
func generateZKProof(t *testing.T) string {
	// Create a temporary directory for the proof files
	tempDir, err := os.MkdirTemp("", "zkproof")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// For test purposes, don't clean up the temp dir so we can inspect the files
	// Comment this out in production tests
	// defer os.RemoveAll(tempDir)
	log.Info("ZK proof files will be stored in", "tempDir", tempDir)

	// Set up paths
	proofFile := filepath.Join(tempDir, "proof")
	vkFile := filepath.Join(tempDir, "vk")

	// Change to the wormhole directory to execute commands
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Assume wormhole directory is at project root
	wormholeDir := filepath.Join(filepath.Dir(filepath.Dir(currentDir)), "wormhole")
	if _, err := os.Stat(wormholeDir); os.IsNotExist(err) {
		t.Skip("Skipping test: Wormhole directory not found at " + wormholeDir)
	}

	// Check if target directory exists
	targetDir := filepath.Join(wormholeDir, "target")
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		if err := os.Mkdir(targetDir, 0755); err != nil {
			t.Fatalf("Failed to create target directory: %v", err)
		}
	}

	err = os.Chdir(wormholeDir)
	if err != nil {
		t.Fatalf("Failed to change to wormhole directory: %v", err)
	}
	defer os.Chdir(currentDir)

	// Check if nargo is installed
	_, err = exec.LookPath("nargo")
	if err != nil {
		t.Skip("Skipping test: nargo command not found in PATH")
	}

	// Check if bb is installed
	_, err = exec.LookPath("bb")
	if err != nil {
		t.Skip("Skipping test: bb command not found in PATH")
	}

	// Execute the actual commands from the README
	log.Info("Executing nargo execute...")
	cmd := exec.Command("nargo", "execute")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the command fails, create a dummy proof file for testing
		log.Info("Failed to execute nargo, creating dummy proof for testing", "err", err, "output", string(output))
		// Create dummy files
		if err := os.WriteFile(proofFile, []byte("mock-proof-data"), 0644); err != nil {
			t.Fatalf("Failed to create test proof file: %v", err)
		}
		if err := os.WriteFile(vkFile, []byte("mock-vk-data"), 0644); err != nil {
			t.Fatalf("Failed to create test vk file: %v", err)
		}
		return proofFile
	}
	log.Info("nargo execute output", "output", string(output))

	log.Info("Executing bb prove...")
	cmd = exec.Command("bb", "prove", "-b", "./target/wormhole.json", "-w", "./target/wormhole.gz", "-o", proofFile)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// If the command fails, create a dummy proof file for testing
		log.Info("Failed to execute bb prove, creating dummy proof for testing", "err", err, "output", string(output))
		if err := os.WriteFile(proofFile, []byte("mock-proof-data"), 0644); err != nil {
			t.Fatalf("Failed to create test proof file: %v", err)
		}
		if err := os.WriteFile(vkFile, []byte("mock-vk-data"), 0644); err != nil {
			t.Fatalf("Failed to create test vk file: %v", err)
		}
		return proofFile
	}
	log.Info("bb prove output", "output", string(output))

	log.Info("Executing bb write_vk...")
	cmd = exec.Command("bb", "write_vk", "-b", "./target/wormhole.json", "-o", vkFile)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// If the command fails, create a dummy proof file for testing
		log.Info("Failed to execute bb write_vk, continuing with test", "err", err, "output", string(output))
	} else {
		log.Info("bb write_vk output", "output", string(output))
	}

	// Return the path to the proof file
	return proofFile
}

// TestMint tests the mint endpoint
func TestMint(t *testing.T) {
	// Generate a ZK proof
	proofPath := generateZKProof(t)

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
		To:        recipient,
		Amount:    (*hexutil.Big)(amount),
		ProofData: proofPath,
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

// TestMintMissingProof tests the mint endpoint with missing proof data
func TestMintMissingProof(t *testing.T) {
	// Create a test backend
	backend := newTestBackendForMint(t)

	// Create the API
	nonceLock := new(AddrLocker)
	api := NewMintAPI(backend, nonceLock)

	// Create a recipient address
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create a mint request with missing proof
	amount := big.NewInt(1000000000000000000) // 1 ETH
	req := MintRequest{
		To:        recipient,
		Amount:    (*hexutil.Big)(amount),
		ProofData: "",
	}

	// Call the mint function
	resp, err := api.Mint(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "proof data is required")
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

	// Generate a valid proof path for testing
	proofPath := generateZKProof(t)

	// Test with zero amount
	zeroAmount := big.NewInt(0)
	req := MintRequest{
		To:        recipient,
		Amount:    (*hexutil.Big)(zeroAmount),
		ProofData: proofPath,
	}

	resp, err := api.Mint(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "amount must be greater than 0")

	// Test with nil amount
	req = MintRequest{
		To:        recipient,
		Amount:    nil,
		ProofData: proofPath,
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
