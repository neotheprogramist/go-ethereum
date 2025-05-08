# ZK-Wormhole (EIP-7503) Reference Implementation

This is a Noir language implementation of the Zero-Knowledge Wormholes protocol described in [EIP-7503](https://eips.ethereum.org/EIPS/eip-7503). The implementation demonstrates the core concepts of the protocol, which enables a privacy-preserving mechanism for Ethereum users.

## Overview

Zero-Knowledge Wormholes (ZK-Wormholes) is a protocol that allows users to:

1. "Burn" ETH by sending it to an unspendable address derived from a secret
2. Later generate a ZK-proof that they know the secret to some burned ETH
3. Use this proof to mint the same amount of ETH at a new address

This provides strong privacy guarantees with plausible deniability for the sender, as there's no way to prove that a sender has participated in the privacy protocol.

## Implementation Details

This implementation includes:

- The main ZK circuit for verifying wormhole transactions
- Helper functions for nullifier generation, receipt hash computation, and Merkle proof verification
- Test cases that demonstrate the protocol's functionality

### Key Components

1. **Deposit Mechanism**: ETH is sent to an address derived from a secret
2. **Withdrawal Mechanism**: A ZK proof is generated to mint equivalent ETH
3. **Privacy Pool**: Proofs verify membership in a privacy pool for additional privacy
4. **Change Mechanism**: Allows partial withdrawals with remainder sent to a new deposit

## Usage

To build and test the circuit:

```bash
# Build the project
nargo build

# Execute the tests
nargo test

# Generate a proof
nargo prove

# Verify a proof
nargo verify
```

## Advanced Usage

For more detailed operations:

- `nargo execute`
- `bb prove -b ./target/wormhole.json -w ./target/wormhole.gz -o ./target/proof`
- `bb write_vk -b ./target/wormhole.json -o ./target/vk`
- `bb verify -k ./target/vk -p ./target/proof`

## Security Considerations

This is a reference implementation for educational purposes. In a production environment:

1. A proper proof of work implementation would be required
2. The circuit would need extensive auditing
3. The implementation would need to follow best practices for cryptographic implementations

## Future Work

- Complete SHA-256 implementation for proper protocol compliance
- Implementation of actual proof of work verification
- Integration with Ethereum blockchain for real-world usage

## References

- [EIP-7503: Zero-Knowledge Wormholes](https://eips.ethereum.org/EIPS/eip-7503)
- [Ethereum Privacy and Regulatory Compliance](https://ssrn.com/abstract=4563364)
