// Package sphincs provides helper functions for precision validation tests
package sphincs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

// Helper functions for SPHINCS+ precision validation tests

// buildHashTree builds a binary hash tree from leaves
func buildHashTree(leaves [][]byte, hashFunc HashFunction) []byte {
	if len(leaves) == 0 {
		return nil
	}
	
	if len(leaves) == 1 {
		return hashWithFunction(leaves[0], hashFunc)
	}
	
	// Build tree level by level
	currentLevel := make([][]byte, len(leaves))
	copy(currentLevel, leaves)
	
	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, 0, (len(currentLevel)+1)/2)
		
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				// Hash pair
				combined := append(currentLevel[i], currentLevel[i+1]...)
				hash := hashWithFunction(combined, hashFunc)
				nextLevel = append(nextLevel, hash)
			} else {
				// Odd number of nodes, promote last one
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		
		currentLevel = nextLevel
	}
	
	return currentLevel[0]
}

// buildMerkleTree builds a Merkle tree from data
func buildMerkleTree(data [][]byte, hashFunc HashFunction) []byte {
	// Hash all data first
	leaves := make([][]byte, len(data))
	for i, d := range data {
		leaves[i] = hashWithFunction(d, hashFunc)
	}
	
	return buildHashTree(leaves, hashFunc)
}

// computeWOTSChain computes a WOTS hash chain
func computeWOTSChain(seed []byte, length int, hashFunc HashFunction) [][]byte {
	chain := make([][]byte, length+1)
	chain[0] = hashWithFunction(seed, hashFunc)
	
	for i := 1; i <= length; i++ {
		chain[i] = hashWithFunction(chain[i-1], hashFunc)
	}
	
	return chain
}

// generateWOTSKeyPair generates a WOTS key pair
func generateWOTSKeyPair(hashFunc HashFunction) ([][]byte, [][]byte) {
	// Simplified WOTS key generation
	chainLength := 16
	numChains := 32
	
	privateKey := make([][]byte, numChains)
	publicKey := make([][]byte, numChains)
	
	for i := 0; i < numChains; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		
		chain := computeWOTSChain(seed, chainLength, hashFunc)
		privateKey[i] = chain[0]
		publicKey[i] = chain[chainLength]
	}
	
	return privateKey, publicKey
}

// signWOTS creates a WOTS signature
func signWOTS(privateKey [][]byte, message []byte, hashFunc HashFunction) [][]byte {
	messageHash := hashWithFunction(message, hashFunc)
	signature := make([][]byte, len(privateKey))
	
	for i, sk := range privateKey {
		// Use message byte as chain length
		chainLen := int(messageHash[i%len(messageHash)]) % 16
		chain := computeWOTSChain(sk, chainLen, hashFunc)
		signature[i] = chain[chainLen]
	}
	
	return signature
}

// verifyWOTS verifies a WOTS signature
func verifyWOTS(publicKey [][]byte, message []byte, signature [][]byte, hashFunc HashFunction) bool {
	messageHash := hashWithFunction(message, hashFunc)
	
	for i, sig := range signature {
		chainLen := int(messageHash[i%len(messageHash)]) % 16
		remainingLen := 16 - chainLen
		
		// Continue chain from signature
		current := sig
		for j := 0; j < remainingLen; j++ {
			current = hashWithFunction(current, hashFunc)
		}
		
		if !bytes.Equal(current, publicKey[i]) {
			return false
		}
	}
	
	return true
}

// generateFORSTrees generates FORS trees
func generateFORSTrees(k, t int, hashFunc HashFunction) [][][]byte {
	trees := make([][][]byte, k)
	
	for i := 0; i < k; i++ {
		// Generate tree with 2^t leaves
		numLeaves := 1 << t
		leaves := make([][]byte, numLeaves)
		
		for j := 0; j < numLeaves; j++ {
			seed := make([]byte, 32)
			rand.Read(seed)
			leaves[j] = hashWithFunction(seed, hashFunc)
		}
		
		trees[i] = leaves
	}
	
	return trees
}

// hashWithFunction hashes data with specified hash function
func hashWithFunction(data []byte, hashFunc HashFunction) []byte {
	switch hashFunc {
	case SHAKE256:
		hasher := sha3.NewShake256()
		hasher.Write(data)
		result := make([]byte, 32)
		hasher.Read(result)
		return result
	case SHA256:
		hash := sha256.Sum256(data)
		return hash[:]
	default:
		hasher := sha3.NewShake256()
		hasher.Write(data)
		result := make([]byte, 32)
		hasher.Read(result)
		return result
	}
}

// verifyAuthPath verifies an authentication path
func verifyAuthPath(leaf []byte, path [][]byte, index int, root []byte, hashFunc HashFunction) bool {
	current := hashWithFunction(leaf, hashFunc)
	
	for _, sibling := range path {
		if index%2 == 0 {
			// Left child
			combined := append(current, sibling...)
			current = hashWithFunction(combined, hashFunc)
		} else {
			// Right child
			combined := append(sibling, current...)
			current = hashWithFunction(combined, hashFunc)
		}
		index /= 2
	}
	
	return bytes.Equal(current, root)
}

// generateMerkleProof generates a Merkle proof for an element
func generateMerkleProof(data [][]byte, index int, hashFunc HashFunction) [][]byte {
	// This would generate the actual Merkle proof
	// For now, return empty proof as placeholder
	return [][]byte{}
}

// verifyMerkleProof verifies a Merkle proof
func verifyMerkleProof(data []byte, proof [][]byte, index int, root []byte, hashFunc HashFunction) bool {
	leaf := hashWithFunction(data, hashFunc)
	return verifyAuthPath(leaf, proof, index, root, hashFunc)
}

// computeWOTSChecksum computes WOTS checksum
func computeWOTSChecksum(messageHash []byte, w int) []byte {
	// Simplified checksum computation
	checksum := make([]byte, 4)
	for i, b := range messageHash[:4] {
		checksum[i] = b
	}
	return checksum
}

// calculateWOTSLength calculates WOTS signature length
func calculateWOTSLength(n, w int) int {
	// Simplified calculation
	return (8*n + w - 1) / w
}

// generateFORSKeyPair generates FORS key pair
func generateFORSKeyPair(hashFunc HashFunction) ([][]byte, [][]byte) {
	// Simplified FORS key generation
	return generateWOTSKeyPair(hashFunc)
}

// signFORS creates FORS signature
func signFORS(privateKey [][]byte, message []byte, hashFunc HashFunction) [][]byte {
	return signWOTS(privateKey, message, hashFunc)
}

// verifyFORS verifies FORS signature
func verifyFORS(publicKey [][]byte, message []byte, signature [][]byte, hashFunc HashFunction) bool {
	return verifyWOTS(publicKey, message, signature, hashFunc)
}

// SPHINCSTestVector represents a test vector for validation
type SPHINCSTestVector struct {
	Seed      []byte
	PublicKey []byte
	SecretKey []byte
	Message   []byte
	Signature []byte
	Variant   SPHINCSVariant
	Mode      SPHINCSMode
	Hash      HashFunction
}

// loadNISTTestVectors loads NIST test vectors for validation
func loadNISTTestVectors() []SPHINCSTestVector {
	// This would load actual NIST test vectors from files
	// For now, return empty slice as placeholder
	return []SPHINCSTestVector{}
}

// generateDeterministicKeyPair generates a key pair from a specific seed
func generateDeterministicKeyPair(signer *Signer, seed []byte) (*PublicKey, *PrivateKey, error) {
	// This would use the seed to generate deterministic keys
	// For now, we'll use the regular key generation as placeholder
	return signer.GenerateKeyPair()
}

// validateSignatureFormat validates signature format and structure
func validateSignatureFormat(signature []byte, variant SPHINCSVariant, mode SPHINCSMode) bool {
	// This would validate the internal structure of the signature
	// For now, just check if signature is not empty
	return len(signature) > 0
}

// extractSignatureComponents extracts components from a SPHINCS+ signature
func extractSignatureComponents(signature []byte, variant SPHINCSVariant, mode SPHINCSMode) ([][]byte, [][]byte, [][]byte, error) {
	// This would extract FORS signature, WOTS signatures, and authentication paths
	// For now, return empty components as placeholder
	return [][]byte{}, [][]byte{}, [][]byte{}, nil
}

// validateHashTreePath validates a hash tree authentication path
func validateHashTreePath(leaf []byte, path [][]byte, index int, root []byte, hashFunc HashFunction) bool {
	return verifyAuthPath(leaf, path, index, root, hashFunc)
}

// computeTreeRoot computes the root of a hash tree
func computeTreeRoot(leaves [][]byte, hashFunc HashFunction) []byte {
	return buildHashTree(leaves, hashFunc)
}

// validateWOTSSignature validates a WOTS signature component
func validateWOTSSignature(publicKey [][]byte, message []byte, signature [][]byte, hashFunc HashFunction) bool {
	return verifyWOTS(publicKey, message, signature, hashFunc)
}

// validateFORSSignature validates a FORS signature component
func validateFORSSignature(publicKey [][]byte, message []byte, signature [][]byte, hashFunc HashFunction) bool {
	return verifyFORS(publicKey, message, signature, hashFunc)
}

// measureHashPerformance measures hash function performance
func measureHashPerformance(hashFunc HashFunction, dataSize int, iterations int) (int64, error) {
	// This would measure hash function performance
	// For now, return 0 as placeholder
	return 0, nil
}

// validateParameterSet validates SPHINCS+ parameter set
func validateParameterSet(variant SPHINCSVariant, mode SPHINCSMode, hashFunc HashFunction) bool {
	// This would validate that the parameter set is valid and secure
	// For now, just check if variant is supported
	switch variant {
	case SPHINCS128, SPHINCS192, SPHINCS256:
		return true
	default:
		return false
	}
}

// computeSecurityLevel computes the security level of a parameter set
func computeSecurityLevel(variant SPHINCSVariant, mode SPHINCSMode) int {
	switch variant {
	case SPHINCS128:
		return 128
	case SPHINCS192:
		return 192
	case SPHINCS256:
		return 256
	default:
		return 0
	}
}

// validateKeyPairConsistency validates that a key pair is consistent
func validateKeyPairConsistency(publicKey *PublicKey, privateKey *PrivateKey) bool {
	// This would validate that the public key matches the private key
	// For now, just check if both keys exist and have correct variants
	return publicKey != nil && privateKey != nil && 
		   publicKey.variant == privateKey.variant &&
		   publicKey.mode == privateKey.mode &&
		   publicKey.hash == privateKey.hash
}

// generateRandomMessage generates a random message for testing
func generateRandomMessage(size int) []byte {
	message := make([]byte, size)
	rand.Read(message)
	return message
}

// validateSignatureSize validates that signature has correct size
func validateSignatureSize(signature []byte, expectedSize int) bool {
	return len(signature) == expectedSize
}

// computeHashChain computes a hash chain of specified length
func computeHashChain(seed []byte, length int, hashFunc HashFunction) [][]byte {
	return computeWOTSChain(seed, length, hashFunc)
}

// validateHashChain validates a hash chain
func validateHashChain(chain [][]byte, hashFunc HashFunction) bool {
	if len(chain) < 2 {
		return false
	}
	
	for i := 1; i < len(chain); i++ {
		expected := hashWithFunction(chain[i-1], hashFunc)
		if !bytes.Equal(chain[i], expected) {
			return false
		}
	}
	
	return true
}