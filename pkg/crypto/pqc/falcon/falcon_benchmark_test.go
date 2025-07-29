package falcon

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// BenchmarkFalconOperations provides comprehensive benchmarking for Falcon operations
func BenchmarkFalconOperations(b *testing.B) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		benchmarkVariant(b, variant)
	}
}

func benchmarkVariant(b *testing.B, variant FalconVariant) {
	variantName := getVariantName(variant)

	// Benchmark key generation
	b.Run(variantName+"/KeyGeneration", func(b *testing.B) {
		signer, err := NewSigner(variant)
		if err != nil {
			b.Fatalf("Failed to create signer: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _, err := signer.GenerateKeyPair()
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}
		}
	})

	// Benchmark signing
	b.Run(variantName+"/Signing", func(b *testing.B) {
		signer, err := NewSigner(variant)
		if err != nil {
			b.Fatalf("Failed to create signer: %v", err)
		}

		_, privKey, err := signer.GenerateKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}

		message := []byte("Benchmark message for Falcon signing performance measurement")

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := signer.Sign(privKey, message)
			if err != nil {
				b.Fatalf("Signing failed: %v", err)
			}
		}
	})

	// Benchmark verification
	b.Run(variantName+"/Verification", func(b *testing.B) {
		signer, err := NewSigner(variant)
		if err != nil {
			b.Fatalf("Failed to create signer: %v", err)
		}

		pubKey, privKey, err := signer.GenerateKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}

		message := []byte("Benchmark message for Falcon verification performance measurement")
		signature, err := signer.Sign(privKey, message)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			if !signer.Verify(pubKey, message, signature) {
				b.Fatal("Verification failed")
			}
		}
	})

	// Benchmark key serialization
	b.Run(variantName+"/KeySerialization", func(b *testing.B) {
		signer, err := NewSigner(variant)
		if err != nil {
			b.Fatalf("Failed to create signer: %v", err)
		}

		pubKey, privKey, err := signer.GenerateKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = pubKey.ToBytes()
			_ = privKey.ToBytes()
		}
	})

	// Benchmark key deserialization
	b.Run(variantName+"/KeyDeserialization", func(b *testing.B) {
		signer, err := NewSigner(variant)
		if err != nil {
			b.Fatalf("Failed to create signer: %v", err)
		}

		pubKey, privKey, err := signer.GenerateKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}

		pubKeyBytes := pubKey.ToBytes()
		privKeyBytes := privKey.ToBytes()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			newPubKey := &PublicKey{}
			newPrivKey := &PrivateKey{}

			if err := newPubKey.FromBytes(pubKeyBytes); err != nil {
				b.Fatalf("Public key deserialization failed: %v", err)
			}

			if err := newPrivKey.FromBytes(privKeyBytes); err != nil {
				b.Fatalf("Private key deserialization failed: %v", err)
			}
		}
	})
}

// BenchmarkFalconMessageSizes tests performance with different message sizes
func BenchmarkFalconMessageSizes(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	messageSizes := []int{32, 64, 128, 256, 512, 1024, 2048, 4096, 8192}

	for _, size := range messageSizes {
		b.Run(formatSize(size), func(b *testing.B) {
			message := make([]byte, size)
			rand.Read(message)

			// Benchmark signing
			b.Run("Sign", func(b *testing.B) {
				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					_, err := signer.Sign(privKey, message)
					if err != nil {
						b.Fatalf("Signing failed: %v", err)
					}
				}
			})

			// Benchmark verification
			signature, err := signer.Sign(privKey, message)
			if err != nil {
				b.Fatalf("Signing failed: %v", err)
			}

			b.Run("Verify", func(b *testing.B) {
				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					if !signer.Verify(pubKey, message, signature) {
						b.Fatal("Verification failed")
					}
				}
			})
		})
	}
}

// BenchmarkFalconConcurrency tests concurrent operations
func BenchmarkFalconConcurrency(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := []byte("Concurrent benchmark message")
	signature, err := signer.Sign(privKey, message)
	if err != nil {
		b.Fatalf("Signing failed: %v", err)
	}

	// Benchmark concurrent signing
	b.Run("ConcurrentSigning", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := signer.Sign(privKey, message)
				if err != nil {
					b.Fatalf("Concurrent signing failed: %v", err)
				}
			}
		})
	})

	// Benchmark concurrent verification
	b.Run("ConcurrentVerification", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !signer.Verify(pubKey, message, signature) {
					b.Fatal("Concurrent verification failed")
				}
			}
		})
	})
}

// BenchmarkFalconMemoryUsage measures memory usage patterns
func BenchmarkFalconMemoryUsage(b *testing.B) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		b.Run(getVariantName(variant), func(b *testing.B) {
			signer, err := NewSigner(variant)
			if err != nil {
				b.Fatalf("Failed to create signer: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				pubKey, privKey, err := signer.GenerateKeyPair()
				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}

				message := []byte("Memory usage benchmark message")
				signature, err := signer.Sign(privKey, message)
				if err != nil {
					b.Fatalf("Signing failed: %v", err)
				}

				if !signer.Verify(pubKey, message, signature) {
					b.Fatal("Verification failed")
				}

				// Clean up sensitive data
				privKey.Zeroize()
			}
		})
	}
}

// BenchmarkFalconPolynomialOperations benchmarks core polynomial operations
func BenchmarkFalconPolynomialOperations(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	// Generate test polynomials
	poly1 := make([]int16, signer.n)
	poly2 := make([]int16, signer.n)

	for i := 0; i < signer.n; i++ {
		poly1[i] = int16(i % 100)
		poly2[i] = int16((i * 2) % 100)
	}

	// Benchmark polynomial addition
	b.Run("PolynomialAddition", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = signer.polyAdd(poly1, poly2)
		}
	})

	// Benchmark polynomial subtraction
	b.Run("PolynomialSubtraction", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = signer.polySub(poly1, poly2)
		}
	})

	// Benchmark polynomial multiplication
	b.Run("PolynomialMultiplication", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = signer.polyMul(poly1, poly2)
		}
	})
}

// BenchmarkFalconGaussianSampling benchmarks Gaussian sampling performance
func BenchmarkFalconGaussianSampling(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := signer.sampleDiscreteGaussian(signer.sigma)
		if err != nil {
			b.Fatalf("Gaussian sampling failed: %v", err)
		}
	}
}

// BenchmarkFalconHashToPoint benchmarks message hashing
func BenchmarkFalconHashToPoint(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Benchmark message for hash-to-point performance testing")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = signer.hashToPoint(message)
	}
}

// BenchmarkFalconSignaturePacking benchmarks signature packing/unpacking
func BenchmarkFalconSignaturePacking(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	// Generate test signature components
	s1 := make([]int16, signer.n)
	s2 := make([]int16, signer.n)

	for i := 0; i < signer.n; i++ {
		s1[i] = int16(i % 1000)
		s2[i] = int16((i * 3) % 1000)
	}

	// Benchmark packing
	b.Run("SignaturePacking", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := signer.packSignature(s1, s2)
			if err != nil {
				b.Fatalf("Signature packing failed: %v", err)
			}
		}
	})

	// Benchmark unpacking
	signature, err := signer.packSignature(s1, s2)
	if err != nil {
		b.Fatalf("Signature packing failed: %v", err)
	}

	b.Run("SignatureUnpacking", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _, err := signer.unpackSignature(signature)
			if err != nil {
				b.Fatalf("Signature unpacking failed: %v", err)
			}
		}
	})
}

// BenchmarkFalconConstantTimeOperations benchmarks constant-time operations
func BenchmarkFalconConstantTimeOperations(b *testing.B) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := []byte("Constant-time benchmark message")
	signature, err := signer.Sign(privKey, message)
	if err != nil {
		b.Fatalf("Signing failed: %v", err)
	}

	s1, s2, err := signer.unpackSignature(signature)
	if err != nil {
		b.Fatalf("Signature unpacking failed: %v", err)
	}

	c := signer.hashToPoint(message)

	b.Run("ConstantTimeVerification", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = signer.verifyEquationConstantTime(pubKey.h, s1, s2, c)
		}
	})
}

// Performance comparison benchmark
func BenchmarkFalconComparison(b *testing.B) {
	// Compare Falcon-512 vs Falcon-1024 performance
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		b.Run(getVariantName(variant)+"/FullCycle", func(b *testing.B) {
			signer, err := NewSigner(variant)
			if err != nil {
				b.Fatalf("Failed to create signer: %v", err)
			}

			message := []byte("Full cycle benchmark message")

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Full cryptographic cycle
				pubKey, privKey, err := signer.GenerateKeyPair()
				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}

				signature, err := signer.Sign(privKey, message)
				if err != nil {
					b.Fatalf("Signing failed: %v", err)
				}

				if !signer.Verify(pubKey, message, signature) {
					b.Fatal("Verification failed")
				}

				privKey.Zeroize()
			}
		})
	}
}

// Helper functions
func formatSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	return fmt.Sprintf("%dKB", size/1024)
}

// Benchmark results analysis
func BenchmarkFalconAnalysis(b *testing.B) {
	// This benchmark provides analysis of performance characteristics
	signer, err := NewSigner(Falcon512)
	if err != nil {
		b.Fatalf("Failed to create signer: %v", err)
	}

	// Measure operation times
	var keyGenTimes []time.Duration
	var signTimes []time.Duration
	var verifyTimes []time.Duration

	iterations := 100

	for i := 0; i < iterations; i++ {
		// Key generation timing
		start := time.Now()
		pubKey, privKey, err := signer.GenerateKeyPair()
		keyGenTime := time.Since(start)
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
		keyGenTimes = append(keyGenTimes, keyGenTime)

		message := []byte("Analysis benchmark message")

		// Signing timing
		start = time.Now()
		signature, err := signer.Sign(privKey, message)
		signTime := time.Since(start)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
		signTimes = append(signTimes, signTime)

		// Verification timing
		start = time.Now()
		valid := signer.Verify(pubKey, message, signature)
		verifyTime := time.Since(start)
		if !valid {
			b.Fatal("Verification failed")
		}
		verifyTimes = append(verifyTimes, verifyTime)

		privKey.Zeroize()
	}

	// Calculate statistics
	avgKeyGen := calculateAverage(keyGenTimes)
	avgSign := calculateAverage(signTimes)
	avgVerify := calculateAverage(verifyTimes)

	b.Logf("Performance Analysis (n=%d):", iterations)
	b.Logf("  Key Generation: avg=%v", avgKeyGen)
	b.Logf("  Signing: avg=%v", avgSign)
	b.Logf("  Verification: avg=%v", avgVerify)

	// Check against requirements
	if avgKeyGen > 3*time.Millisecond {
		b.Logf("WARNING: Key generation exceeds 3ms requirement: %v", avgKeyGen)
	}
	if avgSign > 2*time.Millisecond {
		b.Logf("WARNING: Signing exceeds 2ms requirement: %v", avgSign)
	}
	if avgVerify > 500*time.Microsecond {
		b.Logf("WARNING: Verification exceeds 500μs requirement: %v", avgVerify)
	}
}

func calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var total time.Duration
	for _, d := range durations {
		total += d
	}

	return total / time.Duration(len(durations))
}
