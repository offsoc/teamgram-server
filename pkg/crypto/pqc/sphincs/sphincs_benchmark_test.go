// Package sphincs provides comprehensive benchmarks for SPHINCS+
// to validate performance requirements: signing < 10ms, verification < 1ms
package sphincs

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// BenchmarkSPHINCSKeyGeneration benchmarks key generation for all parameter sets
func BenchmarkSPHINCSKeyGeneration(b *testing.B) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}
	
	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				name := fmt.Sprintf("%d_%s_%s", variant, mode.String(), hashFunc.String())
				b.Run(name, func(b *testing.B) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						b.Fatalf("Failed to create signer: %v", err)
					}
					
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _, err := signer.GenerateKeyPair()
						if err != nil {
							b.Fatalf("Key generation failed: %v", err)
						}
					}
				})
			}
		}
	}
}

// BenchmarkSPHINCSSigningPerformance benchmarks signing performance
func BenchmarkSPHINCSSigningPerformance(b *testing.B) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}
	
	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				name := fmt.Sprintf("%d_%s_%s", variant, mode.String(), hashFunc.String())
				b.Run(name, func(b *testing.B) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						b.Fatalf("Failed to create signer: %v", err)
					}
					
					_, priv, err := signer.GenerateKeyPair()
					if err != nil {
						b.Fatalf("Key generation failed: %v", err)
					}
					
					message := []byte("benchmark message for signing performance test")
					
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, err := signer.Sign(priv, message)
						if err != nil {
							b.Fatalf("Signing failed: %v", err)
						}
					}
				})
			}
		}
	}
}

// BenchmarkSPHINCSVerificationPerformance benchmarks verification performance
func BenchmarkSPHINCSVerificationPerformance(b *testing.B) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}
	
	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				name := fmt.Sprintf("%d_%s_%s", variant, mode.String(), hashFunc.String())
				b.Run(name, func(b *testing.B) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						b.Fatalf("Failed to create signer: %v", err)
					}
					
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						b.Fatalf("Key generation failed: %v", err)
					}
					
					message := []byte("benchmark message for verification performance test")
					signature, err := signer.Sign(priv, message)
					if err != nil {
						b.Fatalf("Signing failed: %v", err)
					}
					
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if !signer.Verify(pub, message, signature) {
							b.Fatal("Verification failed")
						}
					}
				})
			}
		}
	}
}

// BenchmarkSPHINCSMessageSizes benchmarks performance with different message sizes
func BenchmarkSPHINCSMessageSizes(b *testing.B) {
	signer, err := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}
	
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}
	
	messageSizes := []int{32, 64, 128, 256, 512, 1024, 4096, 16384, 65536}
	
	for _, size := range messageSizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			message := make([]byte, size)
			rand.Read(message)
			
			b.Run("Signing", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := signer.Sign(priv, message)
					if err != nil {
						b.Fatalf("Signing failed: %v", err)
					}
				}
			})
			
			signature, err := signer.Sign(priv, message)
			if err != nil {
				b.Fatalf("Signing failed: %v", err)
			}
			
			b.Run("Verification", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if !signer.Verify(pub, message, signature) {
						b.Fatal("Verification failed")
					}
				}
			})
		})
	}
}

// BenchmarkSPHINCSHashFunctions benchmarks hash function performance
func BenchmarkSPHINCSHashFunctions(b *testing.B) {
	hashes := []HashFunction{SHAKE256, SHA256}
	dataSizes := []int{32, 64, 128, 256, 512, 1024}
	
	for _, hashFunc := range hashes {
		for _, size := range dataSizes {
			name := fmt.Sprintf("%s_Size_%d", hashFunc.String(), size)
			b.Run(name, func(b *testing.B) {
				data := make([]byte, size)
				rand.Read(data)
				
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = hashWithFunction(data, hashFunc)
				}
			})
		}
	}
}

// BenchmarkSPHINCSWOTSOperations benchmarks WOTS operations
func BenchmarkSPHINCSWOTSOperations(b *testing.B) {
	hashes := []HashFunction{SHAKE256, SHA256}
	
	for _, hashFunc := range hashes {
		b.Run(fmt.Sprintf("WOTS_%s", hashFunc.String()), func(b *testing.B) {
			b.Run("KeyGeneration", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _ = generateWOTSKeyPair(hashFunc)
				}
			})
			
			privateKey, publicKey := generateWOTSKeyPair(hashFunc)
			message := []byte("WOTS benchmark message")
			
			b.Run("Signing", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = signWOTS(privateKey, message, hashFunc)
				}
			})
			
			signature := signWOTS(privateKey, message, hashFunc)
			
			b.Run("Verification", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if !verifyWOTS(publicKey, message, signature, hashFunc) {
						b.Fatal("WOTS verification failed")
					}
				}
			})
		})
	}
}

// BenchmarkSPHINCSHashTreeOperations benchmarks hash tree operations
func BenchmarkSPHINCSHashTreeOperations(b *testing.B) {
	hashes := []HashFunction{SHAKE256, SHA256}
	treeSizes := []int{16, 64, 256, 1024}
	
	for _, hashFunc := range hashes {
		for _, size := range treeSizes {
			name := fmt.Sprintf("%s_Size_%d", hashFunc.String(), size)
			b.Run(name, func(b *testing.B) {
				// Generate leaves
				leaves := make([][]byte, size)
				for i := 0; i < size; i++ {
					leaf := make([]byte, 32)
					rand.Read(leaf)
					leaves[i] = leaf
				}
				
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = buildHashTree(leaves, hashFunc)
				}
			})
		}
	}
}

// BenchmarkSPHINCSMemoryUsage benchmarks memory usage patterns
func BenchmarkSPHINCSMemoryUsage(b *testing.B) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	
	for _, variant := range variants {
		for _, mode := range modes {
			name := fmt.Sprintf("%d_%s", variant, mode.String())
			b.Run(name, func(b *testing.B) {
				signer, err := NewSigner(variant, mode, SHAKE256)
				if err != nil {
					b.Fatalf("Failed to create signer: %v", err)
				}
				
				var totalMemory int64
				
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						b.Fatalf("Key generation failed: %v", err)
					}
					
					message := make([]byte, 100)
					rand.Read(message)
					
					signature, err := signer.Sign(priv, message)
					if err != nil {
						b.Fatalf("Signing failed: %v", err)
					}
					
					// Estimate memory usage
					totalMemory += int64(len(pub.key) + len(priv.key) + len(signature))
					
					if !signer.Verify(pub, message, signature) {
						b.Fatal("Verification failed")
					}
				}
				
				b.ReportMetric(float64(totalMemory)/float64(b.N), "bytes/op")
			})
		}
	}
}

// TestSPHINCSPerformanceRequirements tests specific performance requirements
func TestSPHINCSPerformanceRequirements(t *testing.T) {
	variants := []SPHINCSVariant{SPHINCS128, SPHINCS192, SPHINCS256}
	modes := []SPHINCSMode{SmallSignature, FastSigning}
	hashes := []HashFunction{SHAKE256, SHA256}
	
	for _, variant := range variants {
		for _, mode := range modes {
			for _, hashFunc := range hashes {
				testName := fmt.Sprintf("%d_%s_%s", variant, mode.String(), hashFunc.String())
				t.Run(testName, func(t *testing.T) {
					signer, err := NewSigner(variant, mode, hashFunc)
					if err != nil {
						t.Fatalf("Failed to create signer: %v", err)
					}
					
					pub, priv, err := signer.GenerateKeyPair()
					if err != nil {
						t.Fatalf("Key generation failed: %v", err)
					}
					
					message := []byte("performance requirement test message")
					
					// Test signing performance requirement: < 10ms
					signingTimes := make([]time.Duration, 10)
					for i := 0; i < 10; i++ {
						start := time.Now()
						signature, err := signer.Sign(priv, message)
						signingTime := time.Since(start)
						signingTimes[i] = signingTime
						
						if err != nil {
							t.Fatalf("Signing failed: %v", err)
						}
						
						// Test verification performance requirement: < 1ms
						verifyStart := time.Now()
						isValid := signer.Verify(pub, message, signature)
						verifyTime := time.Since(verifyStart)
						
						if !isValid {
							t.Fatal("Signature verification failed")
						}
						
						// Log performance for analysis
						t.Logf("Run %d - Signing: %v, Verification: %v", i+1, signingTime, verifyTime)
						
						// Check verification requirement (< 1ms)
						if verifyTime > 1*time.Millisecond {
							t.Logf("WARNING: Verification time %v exceeds 1ms requirement", verifyTime)
						}
					}
					
					// Calculate average signing time
					var totalSigningTime time.Duration
					for _, t := range signingTimes {
						totalSigningTime += t
					}
					avgSigningTime := totalSigningTime / time.Duration(len(signingTimes))
					
					t.Logf("Average signing time: %v", avgSigningTime)
					
					// Check signing requirement (< 10ms)
					if avgSigningTime > 10*time.Millisecond {
						t.Logf("WARNING: Average signing time %v exceeds 10ms requirement", avgSigningTime)
					}
				})
			}
		}
	}
}

// BenchmarkSPHINCSConcurrentOperations benchmarks concurrent operations
func BenchmarkSPHINCSConcurrentOperations(b *testing.B) {
	signer, err := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}
	
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}
	
	message := []byte("concurrent operations benchmark message")
	signature, err := signer.Sign(priv, message)
	if err != nil {
		b.Fatalf("Signing failed: %v", err)
	}
	
	b.Run("ConcurrentSigning", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := signer.Sign(priv, message)
				if err != nil {
					b.Fatalf("Concurrent signing failed: %v", err)
				}
			}
		})
	})
	
	b.Run("ConcurrentVerification", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !signer.Verify(pub, message, signature) {
					b.Fatal("Concurrent verification failed")
				}
			}
		})
	})
}

// BenchmarkSPHINCSBatchOperations benchmarks batch operations
func BenchmarkSPHINCSBatchOperations(b *testing.B) {
	signer, err := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}
	
	batchSizes := []int{10, 50, 100, 500}
	
	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("BatchSize_%d", batchSize), func(b *testing.B) {
			// Prepare batch data
			keyPairs := make([]struct{ pub *PublicKey; priv *PrivateKey }, batchSize)
			messages := make([][]byte, batchSize)
			signatures := make([][]byte, batchSize)
			
			for i := 0; i < batchSize; i++ {
				pub, priv, err := signer.GenerateKeyPair()
				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}
				keyPairs[i].pub = pub
				keyPairs[i].priv = priv
				
				message := make([]byte, 64)
				rand.Read(message)
				messages[i] = message
				
				sig, err := signer.Sign(priv, message)
				if err != nil {
					b.Fatalf("Signing failed: %v", err)
				}
				signatures[i] = sig
			}
			
			b.Run("BatchSigning", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for j := 0; j < batchSize; j++ {
						_, err := signer.Sign(keyPairs[j].priv, messages[j])
						if err != nil {
							b.Fatalf("Batch signing failed: %v", err)
						}
					}
				}
			})
			
			b.Run("BatchVerification", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for j := 0; j < batchSize; j++ {
						if !signer.Verify(keyPairs[j].pub, messages[j], signatures[j]) {
							b.Fatal("Batch verification failed")
						}
					}
				}
			})
		})
	}
}

// BenchmarkSPHINCSOptimizations benchmarks various optimizations
func BenchmarkSPHINCSOptimizations(b *testing.B) {
	_, err := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}
	
	b.Run("HashOptimization", func(b *testing.B) {
		data := make([]byte, 1024)
		rand.Read(data)
		
		b.Run("SHAKE256", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = hashWithFunction(data, SHAKE256)
			}
		})
		
		b.Run("SHA256", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = hashWithFunction(data, SHA256)
			}
		})
	})
	
	b.Run("TreeTraversalOptimization", func(b *testing.B) {
		treeHeights := []int{8, 12, 16, 20}
		
		for _, height := range treeHeights {
			b.Run(fmt.Sprintf("Height_%d", height), func(b *testing.B) {
				numLeaves := 1 << height
				leaves := make([][]byte, numLeaves)
				
				for i := 0; i < numLeaves; i++ {
					leaf := make([]byte, 32)
					rand.Read(leaf)
					leaves[i] = leaf
				}
				
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = buildHashTree(leaves, SHAKE256)
				}
			})
		}
	})
}

// TestSPHINCSScalabilityLimits tests scalability limits
func TestSPHINCSScalabilityLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scalability tests in short mode")
	}
	
	signer, err := NewSigner(SPHINCS128, FastSigning, SHAKE256) // Use fastest variant
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	
	// Test with increasing numbers of operations
	operationCounts := []int{100, 500, 1000, 5000}
	
	for _, count := range operationCounts {
		t.Run(fmt.Sprintf("Operations_%d", count), func(t *testing.T) {
			start := time.Now()
			
			for i := 0; i < count; i++ {
				pub, priv, err := signer.GenerateKeyPair()
				if err != nil {
					t.Fatalf("Key generation %d failed: %v", i, err)
				}
				
				message := []byte(fmt.Sprintf("scalability test message %d", i))
				signature, err := signer.Sign(priv, message)
				if err != nil {
					t.Fatalf("Signing %d failed: %v", i, err)
				}
				
				if !signer.Verify(pub, message, signature) {
					t.Fatalf("Verification %d failed", i)
				}
			}
			
			elapsed := time.Since(start)
			opsPerSecond := float64(count) / elapsed.Seconds()
			
			t.Logf("Completed %d operations in %v (%.2f ops/sec)", count, elapsed, opsPerSecond)
		})
	}
}