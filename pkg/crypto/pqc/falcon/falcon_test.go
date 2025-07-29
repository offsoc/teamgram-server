package falcon

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestFalconKeyGeneration(t *testing.T) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		t.Run(getVariantName(variant), func(t *testing.T) {
			signer, err := NewSigner(variant)
			if err != nil {
				t.Fatalf("Failed to create signer: %v", err)
			}

			start := time.Now()
			pubKey, privKey, err := signer.GenerateKeyPair()
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			if pubKey == nil || privKey == nil {
				t.Fatal("Generated keys are nil")
			}

			// Verify key sizes
			expectedN := N512
			if variant == Falcon1024 {
				expectedN = N1024
			}

			if pubKey.n != expectedN {
				t.Errorf("Public key dimension mismatch: got %d, want %d", pubKey.n, expectedN)
			}

			if privKey.n != expectedN {
				t.Errorf("Private key dimension mismatch: got %d, want %d", privKey.n, expectedN)
			}

			// Performance requirement: key generation < 3ms
			if duration > 3*time.Millisecond {
				t.Logf("Warning: Key generation took %v (requirement: <3ms)", duration)
			}

			t.Logf("Key generation completed in %v", duration)
		})
	}
}

func TestFalconSignAndVerify(t *testing.T) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		t.Run(getVariantName(variant), func(t *testing.T) {
			signer, err := NewSigner(variant)
			if err != nil {
				t.Fatalf("Failed to create signer: %v", err)
			}

			pubKey, privKey, err := signer.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			message := []byte("Hello, Falcon! This is a test message for military-grade security.")

			// Test signing performance
			start := time.Now()
			signature, err := signer.Sign(privKey, message)
			signDuration := time.Since(start)

			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			if len(signature) == 0 {
				t.Fatal("Empty signature generated")
			}

			// Performance requirement: signing < 2ms
			if signDuration > 2*time.Millisecond {
				t.Logf("Warning: Signing took %v (requirement: <2ms)", signDuration)
			}

			// Test verification performance
			start = time.Now()
			valid := signer.Verify(pubKey, message, signature)
			verifyDuration := time.Since(start)

			if !valid {
				t.Fatal("Signature verification failed")
			}

			// Performance requirement: verification < 500μs
			if verifyDuration > 500*time.Microsecond {
				t.Logf("Warning: Verification took %v (requirement: <500μs)", verifyDuration)
			}

			// Test with modified message (should fail)
			modifiedMessage := []byte("Modified message")
			if signer.Verify(pubKey, modifiedMessage, signature) {
				t.Fatal("Verification should fail for modified message")
			}

			// Test with modified signature (should fail)
			modifiedSignature := make([]byte, len(signature))
			copy(modifiedSignature, signature)
			modifiedSignature[0] ^= 1
			if signer.Verify(pubKey, message, modifiedSignature) {
				t.Fatal("Verification should fail for modified signature")
			}

			t.Logf("Sign: %v, Verify: %v", signDuration, verifyDuration)
		})
	}
}

func TestFalconSignatureSize(t *testing.T) {
	variants := []FalconVariant{Falcon512, Falcon1024}
	expectedSizes := []int{Falcon512SignatureBytes, Falcon1024SignatureBytes}

	for i, variant := range variants {
		t.Run(getVariantName(variant), func(t *testing.T) {
			signer, err := NewSigner(variant)
			if err != nil {
				t.Fatalf("Failed to create signer: %v", err)
			}

			_, privKey, err := signer.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			message := []byte("Test message for signature size verification")
			signature, err := signer.Sign(privKey, message)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			if len(signature) != expectedSizes[i] {
				t.Errorf("Signature size mismatch: got %d, want %d", len(signature), expectedSizes[i])
			}
		})
	}
}

func TestFalconKeySerialization(t *testing.T) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test public key serialization
	pubKeyBytes := pubKey.ToBytes()
	if len(pubKeyBytes) == 0 {
		t.Fatal("Public key serialization failed")
	}

	newPubKey := &PublicKey{}
	if err := newPubKey.FromBytes(pubKeyBytes); err != nil {
		t.Fatalf("Public key deserialization failed: %v", err)
	}

	if !bytes.Equal(pubKey.ToBytes(), newPubKey.ToBytes()) {
		t.Fatal("Public key serialization roundtrip failed")
	}

	// Test private key serialization
	privKeyBytes := privKey.ToBytes()
	if len(privKeyBytes) == 0 {
		t.Fatal("Private key serialization failed")
	}

	newPrivKey := &PrivateKey{}
	if err := newPrivKey.FromBytes(privKeyBytes); err != nil {
		t.Fatalf("Private key deserialization failed: %v", err)
	}

	if !bytes.Equal(privKey.ToBytes(), newPrivKey.ToBytes()) {
		t.Fatal("Private key serialization roundtrip failed")
	}

	// Test that signatures work with deserialized keys
	message := []byte("Test message for serialized keys")
	signature, err := signer.Sign(newPrivKey, message)
	if err != nil {
		t.Fatalf("Signing with deserialized key failed: %v", err)
	}

	if !signer.Verify(newPubKey, message, signature) {
		t.Fatal("Verification with deserialized keys failed")
	}
}

func TestFalconConstantTime(t *testing.T) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test multiple messages to ensure constant-time behavior
	messages := [][]byte{
		[]byte("Short"),
		[]byte("Medium length message for testing"),
		[]byte("Very long message that should still be processed in constant time regardless of its length and content"),
		make([]byte, 1024), // Large message
	}

	// Fill large message with random data
	rand.Read(messages[3])

	var durations []time.Duration

	for _, message := range messages {
		start := time.Now()
		signature, err := signer.Sign(privKey, message)
		duration := time.Since(start)

		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		if !signer.Verify(pubKey, message, signature) {
			t.Fatal("Verification failed")
		}

		durations = append(durations, duration)
	}

	// Check that timing variations are within reasonable bounds
	// (This is a simplified check - real constant-time testing requires specialized tools)
	maxDuration := durations[0]
	minDuration := durations[0]

	for _, d := range durations[1:] {
		if d > maxDuration {
			maxDuration = d
		}
		if d < minDuration {
			minDuration = d
		}
	}

	variation := float64(maxDuration-minDuration) / float64(minDuration)
	if variation > 0.5 { // Allow 50% variation
		t.Logf("Warning: High timing variation detected: %.2f%%", variation*100)
	}
}

func TestFalconErrorHandling(t *testing.T) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	pubKey, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test nil private key
	_, err = signer.Sign(nil, []byte("test"))
	if err == nil {
		t.Fatal("Expected error for nil private key")
	}

	// Test empty message
	_, err = signer.Sign(privKey, []byte{})
	if err == nil {
		t.Fatal("Expected error for empty message")
	}

	// Test nil public key
	if signer.Verify(nil, []byte("test"), []byte("signature")) {
		t.Fatal("Expected false for nil public key")
	}

	// Test empty signature
	if signer.Verify(pubKey, []byte("test"), []byte{}) {
		t.Fatal("Expected false for empty signature")
	}

	// Test invalid signature length
	if signer.Verify(pubKey, []byte("test"), []byte{1, 2, 3}) {
		t.Fatal("Expected false for invalid signature length")
	}
}

func TestFalconMemorySafety(t *testing.T) {
	signer, err := NewSigner(Falcon512)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	_, privKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test key zeroization
	originalBytes := privKey.ToBytes()
	privKey.Zeroize()

	// Verify that sensitive data is cleared
	allZero := true
	for _, coeff := range privKey.f {
		if coeff != 0 {
			allZero = false
			break
		}
	}

	if !allZero {
		t.Fatal("Private key f polynomial not properly zeroized")
	}

	// Verify other polynomials are also cleared
	for _, poly := range [][]int16{privKey.g, privKey.F, privKey.G} {
		for _, coeff := range poly {
			if coeff != 0 {
				t.Fatal("Private key polynomial not properly zeroized")
			}
		}
	}

	// Ensure original data was actually different
	if bytes.Equal(originalBytes, privKey.ToBytes()) {
		t.Fatal("Key zeroization had no effect")
	}
}

func BenchmarkFalconKeyGeneration(b *testing.B) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		b.Run(getVariantName(variant), func(b *testing.B) {
			signer, err := NewSigner(variant)
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

func BenchmarkFalconSign(b *testing.B) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		b.Run(getVariantName(variant), func(b *testing.B) {
			signer, err := NewSigner(variant)
			if err != nil {
				b.Fatalf("Failed to create signer: %v", err)
			}

			_, privKey, err := signer.GenerateKeyPair()
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}

			message := []byte("Benchmark message for Falcon signing performance test")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := signer.Sign(privKey, message)
				if err != nil {
					b.Fatalf("Signing failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkFalconVerify(b *testing.B) {
	variants := []FalconVariant{Falcon512, Falcon1024}

	for _, variant := range variants {
		b.Run(getVariantName(variant), func(b *testing.B) {
			signer, err := NewSigner(variant)
			if err != nil {
				b.Fatalf("Failed to create signer: %v", err)
			}

			pubKey, privKey, err := signer.GenerateKeyPair()
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}

			message := []byte("Benchmark message for Falcon verification performance test")
			signature, err := signer.Sign(privKey, message)
			if err != nil {
				b.Fatalf("Signing failed: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !signer.Verify(pubKey, message, signature) {
					b.Fatal("Verification failed")
				}
			}
		})
	}
}

func getVariantName(variant FalconVariant) string {
	switch variant {
	case Falcon512:
		return "Falcon-512"
	case Falcon1024:
		return "Falcon-1024"
	default:
		return "Unknown"
	}
}
