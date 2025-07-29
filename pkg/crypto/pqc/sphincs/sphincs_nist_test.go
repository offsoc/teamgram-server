package sphincs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestSPHINCS128SmallSignature tests SPHINCS+-128 with small signatures
func TestSPHINCS128SmallSignature(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-128 signer: %v", err)
	}

	// Test key generation
	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Verify key sizes
	if len(publicKey.Bytes()) != SPHINCS128PublicKeySize {
		t.Errorf("Public key size mismatch: got %d, want %d", len(publicKey.Bytes()), SPHINCS128PublicKeySize)
	}
	if len(privateKey.Bytes()) != SPHINCS128PrivateKeySize {
		t.Errorf("Private key size mismatch: got %d, want %d", len(privateKey.Bytes()), SPHINCS128PrivateKeySize)
	}

	// Test signing and verification
	message := []byte("Hello, SPHINCS+!")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature size
	if len(signature) != SPHINCS128SignatureSize {
		t.Errorf("Signature size mismatch: got %d, want %d", len(signature), SPHINCS128SignatureSize)
	}

	// Verify signature
	if !signer.Verify(publicKey, message, signature) {
		t.Error("Signature verification failed")
	}

	// Test with different message (should fail)
	differentMessage := []byte("Different message")
	if signer.Verify(publicKey, differentMessage, signature) {
		t.Error("Signature verification should have failed for different message")
	}

	// Clean up
	privateKey.Zeroize()
}

// TestSPHINCS128FastSigning tests SPHINCS+-128 with fast signing
func TestSPHINCS128FastSigning(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, FastSigning, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-128 fast signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Fast signing test")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature size for fast variant
	if len(signature) != SPHINCS128FastSignatureSize {
		t.Errorf("Fast signature size mismatch: got %d, want %d", len(signature), SPHINCS128FastSignatureSize)
	}

	if !signer.Verify(publicKey, message, signature) {
		t.Error("Fast signature verification failed")
	}

	privateKey.Zeroize()
}

// TestSPHINCS192 tests SPHINCS+-192
func TestSPHINCS192(t *testing.T) {
	signer, err := NewSigner(SPHINCS192, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-192 signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Verify key sizes
	if len(publicKey.Bytes()) != SPHINCS192PublicKeySize {
		t.Errorf("Public key size mismatch: got %d, want %d", len(publicKey.Bytes()), SPHINCS192PublicKeySize)
	}
	if len(privateKey.Bytes()) != SPHINCS192PrivateKeySize {
		t.Errorf("Private key size mismatch: got %d, want %d", len(privateKey.Bytes()), SPHINCS192PrivateKeySize)
	}

	message := []byte("SPHINCS+-192 test message")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) != SPHINCS192SignatureSize {
		t.Errorf("Signature size mismatch: got %d, want %d", len(signature), SPHINCS192SignatureSize)
	}

	if !signer.Verify(publicKey, message, signature) {
		t.Error("SPHINCS+-192 signature verification failed")
	}

	privateKey.Zeroize()
}

// TestSPHINCS256 tests SPHINCS+-256
func TestSPHINCS256(t *testing.T) {
	signer, err := NewSigner(SPHINCS256, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-256 signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Verify key sizes
	if len(publicKey.Bytes()) != SPHINCS256PublicKeySize {
		t.Errorf("Public key size mismatch: got %d, want %d", len(publicKey.Bytes()), SPHINCS256PublicKeySize)
	}
	if len(privateKey.Bytes()) != SPHINCS256PrivateKeySize {
		t.Errorf("Private key size mismatch: got %d, want %d", len(privateKey.Bytes()), SPHINCS256PrivateKeySize)
	}

	message := []byte("SPHINCS+-256 maximum security test")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) != SPHINCS256SignatureSize {
		t.Errorf("Signature size mismatch: got %d, want %d", len(signature), SPHINCS256SignatureSize)
	}

	if !signer.Verify(publicKey, message, signature) {
		t.Error("SPHINCS+-256 signature verification failed")
	}

	privateKey.Zeroize()
}

// TestSPHINCSWithSHA256 tests SPHINCS+ with SHA-256 hash function
func TestSPHINCSWithSHA256(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHA256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+ SHA-256 signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("SHA-256 hash function test")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !signer.Verify(publicKey, message, signature) {
		t.Error("SHA-256 signature verification failed")
	}

	privateKey.Zeroize()
}

// TestSPHINCSMultipleSignatures tests multiple signatures with same key pair
func TestSPHINCSMultipleSignatures(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message with different content"),
		[]byte(""),  // Empty message
		make([]byte, 1000), // Large message
	}

	// Fill large message with random data
	rand.Read(messages[4])

	signatures := make([][]byte, len(messages))

	// Sign all messages
	for i, message := range messages {
		sig, err := signer.Sign(privateKey, message)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}
		signatures[i] = sig
	}

	// Verify all signatures
	for i, message := range messages {
		if !signer.Verify(publicKey, message, signatures[i]) {
			t.Errorf("Signature verification failed for message %d", i)
		}
	}

	// Cross-verify (should fail)
	for i := 0; i < len(messages); i++ {
		for j := 0; j < len(messages); j++ {
			if i != j {
				if signer.Verify(publicKey, messages[i], signatures[j]) {
					t.Errorf("Cross-verification should have failed for messages %d and %d", i, j)
				}
			}
		}
	}

	privateKey.Zeroize()
}

// TestSPHINCSKeyPairConsistency tests key pair consistency
func TestSPHINCSKeyPairConsistency(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check that private key contains reference to public key
	if privateKey.Public() != publicKey {
		t.Error("Private key does not reference correct public key")
	}

	// Check key parameters
	if publicKey.GetVariant() != SPHINCS128 {
		t.Errorf("Public key variant mismatch: got %v, want %v", publicKey.GetVariant(), SPHINCS128)
	}
	if publicKey.GetMode() != SmallSignature {
		t.Errorf("Public key mode mismatch: got %v, want %v", publicKey.GetMode(), SmallSignature)
	}
	if publicKey.GetHashFunction() != SHAKE256 {
		t.Errorf("Public key hash function mismatch: got %v, want %v", publicKey.GetHashFunction(), SHAKE256)
	}

	privateKey.Zeroize()
}

// TestSPHINCSInvalidSignature tests invalid signature detection
func TestSPHINCSInvalidSignature(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Test message")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test with corrupted signature
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 1 // Flip one bit

	if signer.Verify(publicKey, message, corruptedSignature) {
		t.Error("Verification should have failed for corrupted signature")
	}

	// Test with wrong signature size
	wrongSizeSignature := signature[:len(signature)-1]
	if signer.Verify(publicKey, message, wrongSizeSignature) {
		t.Error("Verification should have failed for wrong size signature")
	}

	// Test with empty signature
	if signer.Verify(publicKey, message, []byte{}) {
		t.Error("Verification should have failed for empty signature")
	}

	privateKey.Zeroize()
}

// TestSPHINCSParameterMismatch tests parameter mismatch detection
func TestSPHINCSParameterMismatch(t *testing.T) {
	signer128, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-128 signer: %v", err)
	}

	signer192, err := NewSigner(SPHINCS192, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+-192 signer: %v", err)
	}

	publicKey128, privateKey128, err := signer128.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate SPHINCS+-128 key pair: %v", err)
	}

	message := []byte("Parameter mismatch test")

	// Try to sign with wrong signer
	_, err = signer192.Sign(privateKey128, message)
	if err == nil {
		t.Error("Signing should have failed with parameter mismatch")
	}

	// Sign with correct signer
	signature, err := signer128.Sign(privateKey128, message)
	if err != nil {
		t.Fatalf("Failed to sign with correct signer: %v", err)
	}

	// Try to verify with wrong signer
	if signer192.Verify(publicKey128, message, signature) {
		t.Error("Verification should have failed with parameter mismatch")
	}

	privateKey128.Zeroize()
}

// TestSPHINCSZeroization tests secure key zeroization
func TestSPHINCSZeroization(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	_, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Get reference to key bytes before zeroization
	keyBytes := privateKey.Bytes()
	originalKey := make([]byte, len(keyBytes))
	copy(originalKey, keyBytes)

	// Zeroize the key
	privateKey.Zeroize()

	// Check that key bytes are zeroed
	zeroBytes := make([]byte, len(keyBytes))
	if !bytes.Equal(keyBytes, zeroBytes) {
		t.Error("Private key was not properly zeroized")
	}

	// Ensure original key was not all zeros
	if bytes.Equal(originalKey, zeroBytes) {
		t.Error("Original key was already zeros (test invalid)")
	}
}

// BenchmarkSPHINCS128KeyGeneration benchmarks key generation
func BenchmarkSPHINCS128KeyGeneration(b *testing.B) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, privateKey, err := signer.GenerateKeyPair()
		if err != nil {
			b.Fatalf("Failed to generate key pair: %v", err)
		}
		privateKey.Zeroize()
	}
}

// BenchmarkSPHINCS128Signing benchmarks signing
func BenchmarkSPHINCS128Signing(b *testing.B) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	_, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}
	defer privateKey.Zeroize()

	message := []byte("Benchmark message for signing performance test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(privateKey, message)
		if err != nil {
			b.Fatalf("Failed to sign message: %v", err)
		}
	}
}

// BenchmarkSPHINCS128Verification benchmarks verification
func BenchmarkSPHINCS128Verification(b *testing.B) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		b.Fatalf("Failed to create SPHINCS+ signer: %v", err)
	}

	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}
	defer privateKey.Zeroize()

	message := []byte("Benchmark message for verification performance test")
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		b.Fatalf("Failed to sign message: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !signer.Verify(publicKey, message, signature) {
			b.Fatal("Signature verification failed")
		}
	}
}