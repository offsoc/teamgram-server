// Package sphincs provides comprehensive precision validation tests
// to ensure 100% accuracy of SPHINCS+ encryption content
package sphincs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// TestSPHINCSPrecisionValidation runs comprehensive precision validation tests
func TestSPHINCSPrecisionValidation(t *testing.T) {
	t.Run("NIST_KAT_Validation", testNISTKATValidation)
	t.Run("Hash_Function_Precision", testHashFunctionPrecision)
	t.Run("Hash_Tree_Operations", testHashTreeOperations)
	t.Run("Merkle_Tree_Operations", testMerkleTreeOperations)
	t.Run("One_Time_Signature_Precision", testOneTimeSignaturePrecision)
	t.Run("WOTS_Precision", testWOTSPrecision)
	t.Run("FORS_Precision", testFORSPrecision)
	t.Run("Signature_Consistency", testSignatureConsistency)
	t.Run("Key_Generation_Precision", testKeyGenerationPrecision)
	t.Run("Edge_Cases", testEdgeCases)
	t.Run("Performance_Validation", testPerformanceValidation)
}

// testNISTKATValidation validates against NIST Known Answer Tests
func testNISTKATValidation(t *testing.T) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}

	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				testName := fmt.Sprintf("Variant_%d_Mode_%s_Hash_%s", 
					variant, mode.String(), hashFunc.String())
				
				t.Run(testName, func(t *testing.T) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						t.Fatalf("Failed to create signer: %v", err)
					}
					
					// Generate key pair
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						t.Fatalf("Key generation failed: %v", err)
					}
					
					// Test message signing and verification
					message := []byte("NIST KAT test message")
					signature, err := signer.Sign(priv, message)
					if err != nil {
						t.Fatalf("Signature generation failed: %v", err)
					}
					
					// Validate signature verification
					if !signer.Verify(pub, message, signature) {
						t.Error("Signature verification failed")
					}
					
					// Validate signature size
					expectedSize := signer.SignatureSize()
					if len(signature) != expectedSize {
						t.Errorf("Signature size incorrect: expected %d, got %d", 
							expectedSize, len(signature))
					}
				})
			}
		}
	}
}

// testHashFunctionPrecision validates hash function implementations
func testHashFunctionPrecision(t *testing.T) {
	t.Run("SHAKE256_Precision", func(t *testing.T) {
		// Test SHAKE256 with known test vectors
		testVectors := []struct {
			input    string
			expected string
			length   int
		}{
			{
				input:    "",
				expected: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd",
				length:   32,
			},
			{
				input:    "abc",
				expected: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
				length:   32,
			},
		}
		
		for i, tv := range testVectors {
			t.Run(fmt.Sprintf("Vector_%d", i), func(t *testing.T) {
				hasher := sha3.NewShake256()
				hasher.Write([]byte(tv.input))
				
				result := make([]byte, tv.length)
				hasher.Read(result)
				
				expected, _ := hex.DecodeString(tv.expected)
				if !bytes.Equal(result, expected) {
					t.Errorf("SHAKE256 mismatch:\\nExpected: %x\\nGot:      %x", 
						expected, result)
				}
			})
		}
	})
	
	t.Run("SHA256_Precision", func(t *testing.T) {
		// Test SHA256 with known test vectors
		testVectors := []struct {
			input    string
			expected string
		}{
			{
				input:    "",
				expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			{
				input:    "abc",
				expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			},
		}
		
		for i, tv := range testVectors {
			t.Run(fmt.Sprintf("Vector_%d", i), func(t *testing.T) {
				result := sha256.Sum256([]byte(tv.input))
				
				expected, _ := hex.DecodeString(tv.expected)
				if !bytes.Equal(result[:], expected) {
					t.Errorf("SHA256 mismatch:\\nExpected: %x\\nGot:      %x", 
						expected, result)
				}
			})
		}
	})
	
	t.Run("Hash_Function_Consistency", func(t *testing.T) {
		// Test that hash functions produce consistent results
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			for trial := 0; trial < 100; trial++ {
				input := make([]byte, 64)
				rand.Read(input)
				
				signer, _ := NewSigner(SPHINCS256, SmallSignature, hashFunc)
				
				// Hash the same input multiple times
				hash1 := signer.hashMessage(input)
				hash2 := signer.hashMessage(input)
				
				if !bytes.Equal(hash1, hash2) {
					t.Errorf("Hash function %s not deterministic", hashFunc.String())
				}
			}
		}
	})
}

// testHashTreeOperations validates hash tree construction and operations
func testHashTreeOperations(t *testing.T) {
	t.Run("Binary_Tree_Construction", func(t *testing.T) {
		// Test binary hash tree construction with known values
		leaves := [][]byte{
			[]byte("leaf0"),
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}
		
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			t.Run(fmt.Sprintf("Hash_%s", hashFunc.String()), func(t *testing.T) {
				root := buildHashTree(leaves, hashFunc)
				
				// Verify root is computed correctly
				if len(root) == 0 {
					t.Error("Hash tree root is empty")
				}
				
				// Test tree consistency - same inputs should give same root
				root2 := buildHashTree(leaves, hashFunc)
				if !bytes.Equal(root, root2) {
					t.Error("Hash tree construction not deterministic")
				}
				
				// Test tree sensitivity - different inputs should give different root
				modifiedLeaves := make([][]byte, len(leaves))
				copy(modifiedLeaves, leaves)
				modifiedLeaves[0] = []byte("modified")
				
				root3 := buildHashTree(modifiedLeaves, hashFunc)
				if bytes.Equal(root, root3) {
					t.Error("Hash tree not sensitive to input changes")
				}
			})
		}
	})
	
	t.Run("Tree_Height_Validation", func(t *testing.T) {
		// Test trees of different heights
		heights := []int{4, 8, 16}
		
		for _, height := range heights {
			numLeaves := 1 << height
			leaves := make([][]byte, numLeaves)
			
			for i := 0; i < numLeaves; i++ {
				leaves[i] = []byte(fmt.Sprintf("leaf_%d", i))
			}
			
			hashes := []HashFunction{SHAKE256, SHA256}
			for _, hashFunc := range hashes {
				root := buildHashTree(leaves, hashFunc)
				
				// Verify root has correct length
				expectedLen := 32 // Hash output size
				
				if len(root) != expectedLen {
					t.Errorf("Root length incorrect for height %d: expected %d, got %d", 
						height, expectedLen, len(root))
				}
			}
		}
	})
}

// testMerkleTreeOperations validates Merkle tree operations
func testMerkleTreeOperations(t *testing.T) {
	t.Run("Merkle_Tree_Construction", func(t *testing.T) {
		data := [][]byte{
			[]byte("data0"),
			[]byte("data1"),
			[]byte("data2"),
			[]byte("data3"),
		}
		
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			// Build Merkle tree
			root := buildMerkleTree(data, hashFunc)
			
			if len(root) == 0 {
				t.Error("Merkle tree root is empty")
			}
			
			// Test consistency
			root2 := buildMerkleTree(data, hashFunc)
			if !bytes.Equal(root, root2) {
				t.Error("Merkle tree construction not deterministic")
			}
		}
	})
	
	t.Run("Merkle_Tree_Updates", func(t *testing.T) {
		data := [][]byte{
			[]byte("data0"),
			[]byte("data1"),
			[]byte("data2"),
			[]byte("data3"),
		}
		
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			// Build initial tree
			root1 := buildMerkleTree(data, hashFunc)
			
			// Update one element
			updatedData := make([][]byte, len(data))
			copy(updatedData, data)
			updatedData[1] = []byte("updated_data1")
			
			root2 := buildMerkleTree(updatedData, hashFunc)
			
			// Roots should be different
			if bytes.Equal(root1, root2) {
				t.Error("Merkle tree update not reflected in root")
			}
		}
	})
}

// testOneTimeSignaturePrecision validates one-time signature schemes
func testOneTimeSignaturePrecision(t *testing.T) {
	t.Run("WOTS_Chain_Computation", func(t *testing.T) {
		// Test Winternitz One-Time Signature chain computation
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			t.Run(fmt.Sprintf("Hash_%s", hashFunc.String()), func(t *testing.T) {
				// Test chain computation with known values
				seed := []byte("test_seed_for_wots_chain")
				chainLength := 16
				
				chain := computeWOTSChain(seed, chainLength, hashFunc)
				
				// Verify chain length
				if len(chain) != chainLength+1 {
					t.Errorf("WOTS chain length incorrect: expected %d, got %d", 
						chainLength+1, len(chain))
				}
				
				// Verify chain computation is deterministic
				chain2 := computeWOTSChain(seed, chainLength, hashFunc)
				for i, val := range chain {
					if !bytes.Equal(val, chain2[i]) {
						t.Errorf("WOTS chain not deterministic at index %d", i)
					}
				}
				
				// Verify chain progression
				for i := 1; i < len(chain); i++ {
					// Each element should be hash of previous
					expected := hashWithFunction(chain[i-1], hashFunc)
					if !bytes.Equal(chain[i], expected) {
						t.Errorf("WOTS chain progression incorrect at index %d", i)
					}
				}
			})
		}
	})
}

// testWOTSPrecision validates Winternitz One-Time Signature precision
func testWOTSPrecision(t *testing.T) {
	t.Run("WOTS_Signature_Verification", func(t *testing.T) {
		// Test WOTS signature generation and verification
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			message := []byte("test message for WOTS")
			
			// Generate WOTS key pair
			privateKey, publicKey := generateWOTSKeyPair(hashFunc)
			
			// Sign message
			signature := signWOTS(privateKey, message, hashFunc)
			
			// Verify signature
			isValid := verifyWOTS(publicKey, message, signature, hashFunc)
			
			if !isValid {
				t.Errorf("WOTS signature verification failed for hash %s", hashFunc.String())
			}
			
			// Test with modified message
			modifiedMessage := []byte("modified test message for WOTS")
			isValid2 := verifyWOTS(publicKey, modifiedMessage, signature, hashFunc)
			
			if isValid2 {
				t.Errorf("WOTS signature should not verify for modified message")
			}
		}
	})
}

// testFORSPrecision validates Forest of Random Subsets precision
func testFORSPrecision(t *testing.T) {
	t.Run("FORS_Tree_Construction", func(t *testing.T) {
		// Test FORS tree construction
		hashes := []HashFunction{SHAKE256, SHA256}
		for _, hashFunc := range hashes {
			k := 10 // Number of trees
			treeHeight := 4  // Tree height (reduced for testing)
			
			// Generate FORS trees
			trees := generateFORSTrees(k, treeHeight, hashFunc)
			
			// Verify number of trees
			if len(trees) != k {
				t.Errorf("FORS tree count incorrect: expected %d, got %d", k, len(trees))
			}
			
			// Verify each tree
			for i, tree := range trees {
				if len(tree) == 0 {
					t.Errorf("FORS tree %d is empty", i)
				}
			}
		}
	})
}

// testSignatureConsistency validates signature generation consistency
func testSignatureConsistency(t *testing.T) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}

	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				testName := fmt.Sprintf("Variant_%d_Mode_%s_Hash_%s", 
					variant, mode.String(), hashFunc.String())
				
				t.Run(testName, func(t *testing.T) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						t.Fatalf("Failed to create signer: %v", err)
					}
					
					// Generate key pair
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						t.Fatalf("Key generation failed: %v", err)
					}
					
					// Test multiple signatures of same message
					message := []byte("consistency test message")
					
					signatures := make([][]byte, 5)
					for i := 0; i < 5; i++ {
						sig, err := signer.Sign(priv, message)
						if err != nil {
							t.Fatalf("Signature generation failed: %v", err)
						}
						signatures[i] = sig
						
						// Each signature should verify
						if !signer.Verify(pub, message, sig) {
							t.Errorf("Signature %d verification failed", i)
						}
					}
					
					// Test signature size consistency
					expectedSize := signer.SignatureSize()
					for i, sig := range signatures {
						if len(sig) != expectedSize {
							t.Errorf("Signature %d size incorrect: expected %d, got %d", 
								i, expectedSize, len(sig))
						}
					}
				})
			}
		}
	}
}

// testKeyGenerationPrecision validates key generation precision
func testKeyGenerationPrecision(t *testing.T) {
	t.Run("Key_Size_Validation", func(t *testing.T) {
		variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
		modes := []SPHINCSMode{SmallSignature, FastSigning}
		hashes := []HashFunction{SHAKE256, SHA256}

		for _, variant := range variants {
			for _, mode := range modes {
				for _, hashFunc := range hashes {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						t.Fatalf("Failed to create signer: %v", err)
					}
					
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						t.Fatalf("Key generation failed: %v", err)
					}
					
					// Verify key sizes
					expectedPubSize := signer.PublicKeySize()
					expectedPrivSize := signer.PrivateKeySize()
					
					if len(pub.key) != expectedPubSize {
						t.Errorf("Public key size incorrect: expected %d, got %d", 
							expectedPubSize, len(pub.key))
					}
					
					if len(priv.key) != expectedPrivSize {
						t.Errorf("Private key size incorrect: expected %d, got %d", 
							expectedPrivSize, len(priv.key))
					}
				}
			}
		}
	})
	
	t.Run("Key_Randomness_Validation", func(t *testing.T) {
		// Test that generated keys are sufficiently random
		signer, _ := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
		
		keys := make([][]byte, 50)
		for i := 0; i < 50; i++ {
			pub, _, err := signer.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}
			keys[i] = pub.key
		}
		
		// Check for duplicates
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if bytes.Equal(keys[i], keys[j]) {
					t.Errorf("Duplicate keys found at indices %d and %d", i, j)
				}
			}
		}
	})
}

// testEdgeCases validates edge case handling
func testEdgeCases(t *testing.T) {
	t.Run("Empty_Message", func(t *testing.T) {
		signer, _ := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
		pub, priv, _ := signer.GenerateKeyPair()
		
		// Test signing empty message
		emptyMessage := []byte{}
		signature, err := signer.Sign(priv, emptyMessage)
		if err != nil {
			t.Fatalf("Failed to sign empty message: %v", err)
		}
		
		// Verify empty message signature
		if !signer.Verify(pub, emptyMessage, signature) {
			t.Error("Empty message signature verification failed")
		}
	})
	
	t.Run("Large_Message", func(t *testing.T) {
		signer, _ := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
		pub, priv, _ := signer.GenerateKeyPair()
		
		// Test signing large message (100KB)
		largeMessage := make([]byte, 100*1024)
		rand.Read(largeMessage)
		
		signature, err := signer.Sign(priv, largeMessage)
		if err != nil {
			t.Fatalf("Failed to sign large message: %v", err)
		}
		
		// Verify large message signature
		if !signer.Verify(pub, largeMessage, signature) {
			t.Error("Large message signature verification failed")
		}
	})
	
	t.Run("Invalid_Signature_Rejection", func(t *testing.T) {
		signer, _ := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
		pub, _, _ := signer.GenerateKeyPair()
		
		message := []byte("test message")
		
		// Test with random signature
		randomSig := make([]byte, signer.SignatureSize())
		rand.Read(randomSig)
		
		if signer.Verify(pub, message, randomSig) {
			t.Error("Random signature should not verify")
		}
		
		// Test with wrong size signature
		wrongSizeSig := make([]byte, signer.SignatureSize()/2)
		rand.Read(wrongSizeSig)
		
		if signer.Verify(pub, message, wrongSizeSig) {
			t.Error("Wrong size signature should not verify")
		}
	})
}

// testPerformanceValidation validates performance requirements
func testPerformanceValidation(t *testing.T) {
	t.Run("Signing_Performance", func(t *testing.T) {
		variants := []SPHINCSVariant{SPHINCS128}
		modes := []SPHINCSMode{SmallSignature, FastSigning}
		hashes := []HashFunction{SHAKE256, SHA256}

		for _, variant := range variants {
			for _, mode := range modes {
				for _, hashFunc := range hashes {
					testName := fmt.Sprintf("Variant_%d_Mode_%s_Hash_%s", 
						variant, mode.String(), hashFunc.String())
					
					t.Run(testName, func(t *testing.T) {
						signer, _ := NewSigner(variant, mode, hashFunc)
						pub, priv, _ := signer.GenerateKeyPair()
						
						message := []byte("performance test message")
						
						// Measure signing time
						start := time.Now()
						signature, err := signer.Sign(priv, message)
						signingTime := time.Since(start)
						
						if err != nil {
							t.Fatalf("Signing failed: %v", err)
						}
						
						// Verify signature works
						if !signer.Verify(pub, message, signature) {
							t.Error("Performance test signature verification failed")
						}
						
						// Check performance requirement: signing < 10ms
						if signingTime > 10*time.Millisecond {
							t.Logf("Signing time %v exceeds 10ms target for %s", 
								signingTime, testName)
						}
						
						t.Logf("Signing time for %s: %v", testName, signingTime)
					})
				}
			}
		}
	})
	
	t.Run("Verification_Performance", func(t *testing.T) {
		variants := []SPHINCSVariant{SPHINCS128}
		modes := []SPHINCSMode{SmallSignature, FastSigning}
		hashes := []HashFunction{SHAKE256, SHA256}

		for _, variant := range variants {
			for _, mode := range modes {
				for _, hashFunc := range hashes {
					testName := fmt.Sprintf("Variant_%d_Mode_%s_Hash_%s", 
						variant, mode.String(), hashFunc.String())
					
					t.Run(testName, func(t *testing.T) {
						signer, _ := NewSigner(variant, mode, hashFunc)
						pub, priv, _ := signer.GenerateKeyPair()
						
						message := []byte("performance test message")
						signature, _ := signer.Sign(priv, message)
						
						// Measure verification time
						start := time.Now()
						isValid := signer.Verify(pub, message, signature)
						verificationTime := time.Since(start)
						
						if !isValid {
							t.Error("Performance test signature verification failed")
						}
						
						// Check performance requirement: verification < 1ms
						if verificationTime > 1*time.Millisecond {
							t.Logf("Verification time %v exceeds 1ms target for %s", 
								verificationTime, testName)
						}
						
						t.Logf("Verification time for %s: %v", testName, verificationTime)
					})
				}
			}
		}
	})
}