# CRYSTALS-Dilithium

This package implements the CRYSTALS-Dilithium post-quantum digital signature algorithm, which is a NIST PQC standard.

## Overview

CRYSTALS-Dilithium is a lattice-based digital signature scheme that is secure against attacks from both classical and quantum computers. It is based on the hardness of the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems.

This implementation provides:

- Key generation, signing, and verification functions
- Support for all three security levels: Dilithium2, Dilithium3, and Dilithium5
- Optimized implementation with AVX2/AVX-512 support when available
- Side-channel attack protection
- Batch verification for improved performance

## Security Levels

| Variant    | NIST Level | Public Key Size | Private Key Size | Signature Size |
|------------|------------|-----------------|------------------|----------------|
| Dilithium2 | 2          | 1312 bytes      | 2528 bytes       | 2420 bytes     |
| Dilithium3 | 3          | 1952 bytes      | 4000 bytes       | 3293 bytes     |
| Dilithium5 | 5          | 2592 bytes      | 4864 bytes       | 4595 bytes     |

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/teamgram/teamgram-server/pkg/crypto/pqc/dilithium"
)

func main() {
	// Create a new Dilithium signer with security level 2
	signer, err := dilithium.NewSigner(dilithium.Dilithium2)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Generate a new key pair
	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Sign a message
	message := []byte("This is a test message")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	if signer.Verify(publicKey, message, signature) {
		fmt.Println("Signature verified successfully")
	} else {
		fmt.Println("Signature verification failed")
	}

	// Clean up private key when done
	privateKey.Zeroize()
}
```

## Batch Verification

For improved performance when verifying multiple signatures, you can use batch verification:

```go
// Create batch verifier
batchVerifier := signer.NewBatchVerifier()

// Add signatures to batch
batchVerifier.Add(publicKey1, message1, signature1)
batchVerifier.Add(publicKey2, message2, signature2)
batchVerifier.Add(publicKey3, message3, signature3)

// Verify all signatures in batch
if batchVerifier.Verify() {
	fmt.Println("All signatures verified successfully")
} else {
	fmt.Println("At least one signature verification failed")
}
```

## Performance

Performance benchmarks on a modern CPU:

- Key generation: < 3ms
- Signing: < 500μs
- Verification: < 200μs

## Implementation Details

This implementation follows the NIST standard specification for CRYSTALS-Dilithium. It includes:

- Optimized Number Theoretic Transform (NTT) for polynomial multiplication
- Constant-time implementation to prevent timing attacks
- AVX2/AVX-512 optimizations when available
- Side-channel attack protection

## References

1. NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization
2. CRYSTALS-Dilithium Specification: https://pq-crystals.org/dilithium/
3. FIPS 204 (Draft): https://csrc.nist.gov/publications/detail/fips/204/draft