# Crypto Go Library

A comprehensive Go cryptographic library providing secure key generation, signing, verification, and Ethereum-compatible cryptographic operations with libp2p integration.

## Overview

This library provides a complete cryptographic toolkit for Go applications, offering support for multiple key types, secure key generation, signing and verification operations, and Ethereum-compatible cryptographic functions. It's designed to work seamlessly with libp2p and provides a clean, type-safe API for cryptographic operations.

## Features

- **Multiple Key Types**: Support for Ed25519, Secp256k1, and Ethereum-compatible keys
- **Secure Key Generation**: Cryptographically secure random key pair generation
- **Signing & Verification**: Complete signing and verification operations
- **Ethereum Compatibility**: Ethereum message signing and verification support
- **libp2p Integration**: Native support for libp2p cryptographic operations
- **Key Management**: Secure key storage and retrieval with keystore functionality
- **ID System**: Unique identifier generation and management based on public keys
- **Comprehensive Testing**: Extensive test coverage for all cryptographic operations

## Installation

```bash
go get gitlab.com/nunet/depinkit/crypto
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "gitlab.com/nunet/depinkit/crypto"
)

func main() {
    // Generate a new Ed25519 key pair
    privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a unique ID from the public key
    id, err := crypto.IDFromPublicKey(pubKey)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Generated ID: %s\n", id.String())
    
    // Sign some data
    data := []byte("Hello, Crypto!")
    signature, err := privKey.Sign(data)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify the signature
    ok, err := pubKey.Verify(data, signature)
    if err != nil {
        log.Fatal(err)
    }
    
    if ok {
        fmt.Println("Signature verified successfully!")
    } else {
        fmt.Println("Signature verification failed!")
    }
}
```

## Core Concepts

### Key Types

The library supports multiple key types:

```go
const (
    Ed25519   = crypto.Ed25519   // Fast, secure elliptic curve
    Secp256k1 = crypto.Secp256k1 // Bitcoin/Ethereum compatible
    Eth       = 127              // Ethereum-specific key type
)
```

### Key Generation

Generate key pairs for different algorithms:

```go
// Ed25519 keys (fast, secure)
privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519)

// Secp256k1 keys (Bitcoin/Ethereum compatible)
privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Secp256k1)
```

### ID System

The library provides a unique ID system based on public keys:

```go
type ID struct{ PublicKey []byte }

// Create ID from public key
id, err := crypto.IDFromPublicKey(pubKey)

// Convert ID back to public key
pubKey, err := crypto.PublicKeyFromID(id)

// String representation (base32 encoded)
idString := id.String() // e.g., "ABC123..."

// Parse ID from string
id, err := crypto.IDFromString("ABC123...")
```

## Usage Examples

### 1. Basic Key Operations

```go
// Generate key pair
privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519)
if err != nil {
    log.Fatal(err)
}

// Convert keys to/from bytes
privBytes, err := crypto.PrivateKeyToBytes(privKey)
pubBytes, err := crypto.PublicKeyToBytes(pubKey)

// Reconstruct keys from bytes
privKey, err = crypto.BytesToPrivateKey(privBytes)
pubKey, err = crypto.BytesToPublicKey(pubBytes)
```

### 2. Signing and Verification

```go
// Sign data
data := []byte("Important message")
signature, err := privKey.Sign(data)
if err != nil {
    log.Fatal(err)
}

// Verify signature
ok, err := pubKey.Verify(data, signature)
if err != nil {
    log.Fatal(err)
}

if ok {
    fmt.Println("Signature is valid!")
}
```

### 3. Ethereum-Compatible Operations

```go
// Create Ethereum public key from raw bytes
ethPubKey, err := crypto.UnmarshalEthPublicKey(ethKeyBytes)
if err != nil {
    log.Fatal(err)
}

// Verify Ethereum signature
ok, err := ethPubKey.Verify(message, signature)
if err != nil {
    log.Fatal(err)
}

// Get raw key bytes
rawBytes, err := ethPubKey.Raw()
```

### 4. Cryptographic Utilities

```go
// Generate random entropy
entropy, err := crypto.RandomEntropy(32) // 32 bytes of random data
if err != nil {
    log.Fatal(err)
}

// Calculate SHA3 hash
data := []byte("data to hash")
hash, err := crypto.Sha3(data)
if err != nil {
    log.Fatal(err)
}

// Hash multiple byte arrays
hash, err := crypto.Sha3(data1, data2, data3)
```

### 5. Key Validation

```go
// Check if key type is supported
if crypto.AllowedKey(crypto.Ed25519) {
    fmt.Println("Ed25519 is supported")
}

// Validate key types
switch keyType {
case crypto.Ed25519:
    // Handle Ed25519
case crypto.Secp256k1:
    // Handle Secp256k1
default:
    return fmt.Errorf("unsupported key type: %d", keyType)
}
```

### 6. Keystore Operations

```go
// Create a new keystore
keystore := crypto.NewKeystore()

// Store a key with a name
err := keystore.StoreKey("my-key", privKey, passphrase)
if err != nil {
    log.Fatal(err)
}

// Retrieve a key
retrievedKey, err := keystore.GetKey("my-key", passphrase)
if err != nil {
    log.Fatal(err)
}

// List all keys
keys := keystore.ListKeys()
for _, keyName := range keys {
    fmt.Printf("Stored key: %s\n", keyName)
}
```

## API Reference

### Core Types

- `Key`: Interface for all cryptographic keys
- `PrivKey`: Interface for private keys
- `PubKey`: Interface for public keys
- `ID`: Unique identifier based on public key

### Key Functions

- `GenerateKeyPair(t int) (PrivKey, PubKey, error)`: Generate new key pair
- `AllowedKey(t int) bool`: Check if key type is supported
- `PublicKeyToBytes(k PubKey) ([]byte, error)`: Convert public key to bytes
- `BytesToPublicKey(data []byte) (PubKey, error)`: Convert bytes to public key
- `PrivateKeyToBytes(k PrivKey) ([]byte, error)`: Convert private key to bytes
- `BytesToPrivateKey(data []byte) (PrivKey, error)`: Convert bytes to private key

### ID Functions

- `IDFromPublicKey(k PubKey) (ID, error)`: Create ID from public key
- `PublicKeyFromID(id ID) (PubKey, error)`: Get public key from ID
- `IDFromString(s string) (ID, error)`: Parse ID from string

### Utility Functions

- `RandomEntropy(length int) ([]byte, error)`: Generate random entropy
- `Sha3(data ...[]byte) ([]byte, error)`: Calculate SHA3 hash

### Ethereum Functions

- `UnmarshalEthPublicKey(data []byte) (PubKey, error)`: Parse Ethereum public key
- `EthPublicKey`: Ethereum-compatible public key implementation

## Testing

The library includes comprehensive tests for all functionality:

```bash
go test ./...
```

### Test Coverage

- Key generation and validation
- Signing and verification operations
- ID creation and parsing
- Ethereum compatibility
- Keystore operations
- Error handling

## Dependencies

- `github.com/libp2p/go-libp2p/core`: libp2p cryptographic operations
- `github.com/decred/dcrd/dcrec/secp256k1/v4`: Secp256k1 curve support
- `golang.org/x/crypto`: SHA3 and other cryptographic primitives
- `github.com/stretchr/testify`: Testing utilities

## Security Considerations

- **Key Storage**: Always use secure storage for private keys
- **Random Generation**: The library uses cryptographically secure random generation
- **Key Validation**: Always validate key types before use
- **Memory Safety**: Keys are properly zeroed when possible
- **Constant Time**: Critical operations use constant-time implementations

## Performance

- **Ed25519**: Fast signing and verification, small key sizes
- **Secp256k1**: Compatible with Bitcoin/Ethereum, moderate performance
- **SHA3**: Optimized implementation for hashing operations

## License

Apache License 2.0 - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and add tests for new functionality.

## Related Projects

- [DID](https://github.com/depinkit/did): Decentralized Identifiers
- [UCAN](https://github.com/depinkit/ucan): User Controlled Authorization Networks
- [Actor](https://github.com/depinkit/actor): Actor model implementation
