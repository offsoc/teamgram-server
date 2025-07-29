package pqc

import (
	"testing"
)

func TestPQCBasicFunctionality(t *testing.T) {
	// Test PQC Engine creation
	config := &PQCConfig{
		EnableHSM:         false,
		KeyRotationPeriod: 24 * 60 * 60 * 1000000000, // 24 hours in nanoseconds
		EnableMetrics:     true,
		MaxConcurrentOps:  1000,
	}

	engine, err := NewPQCEngine(config)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}

	// Test Kyber key generation
	t.Log("Testing Kyber key generation...")
	kyberKeyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	if kyberKeyPair == nil {
		t.Fatal("Kyber key pair is nil")
	}

	if kyberKeyPair.Type != "Kyber-1024" {
		t.Errorf("Expected Kyber-1024, got %s", kyberKeyPair.Type)
	}

	t.Logf("Kyber key pair generated successfully: ID=%s, Type=%s", kyberKeyPair.ID, kyberKeyPair.Type)

	// Test Dilithium key generation
	t.Log("Testing Dilithium key generation...")
	dilithiumKeyPair, err := engine.GenerateDilithiumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Dilithium key pair: %v", err)
	}

	if dilithiumKeyPair == nil {
		t.Fatal("Dilithium key pair is nil")
	}

	if dilithiumKeyPair.Type != "Dilithium-5" {
		t.Errorf("Expected Dilithium-5, got %s", dilithiumKeyPair.Type)
	}

	t.Logf("Dilithium key pair generated successfully: ID=%s, Type=%s", dilithiumKeyPair.ID, dilithiumKeyPair.Type)

	// Test message encryption/decryption
	t.Log("Testing message encryption/decryption...")
	message := []byte("Hello, Post-Quantum World!")

	encryptedMsg, err := engine.EncryptMessage(message, kyberKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	if encryptedMsg == nil {
		t.Fatal("Encrypted message is nil")
	}

	t.Logf("Message encrypted successfully: Algorithm=%s", encryptedMsg.Algorithm)

	// Test decryption
	t.Logf("Attempting to decrypt message with key ID: %s", kyberKeyPair.ID)
	decryptedMsg, err := engine.DecryptMessage(encryptedMsg, kyberKeyPair.ID)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	if string(decryptedMsg) != string(message) {
		t.Errorf("Decrypted message doesn't match original. Expected: %s, Got: %s", string(message), string(decryptedMsg))
	}

	t.Log("Message decrypted successfully")

	// Test digital signature
	t.Log("Testing digital signature...")
	signature, err := engine.SignMessage(message, dilithiumKeyPair.ID)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}

	t.Log("Message signed successfully")

	// Test signature verification
	err = engine.VerifySignature(message, signature, dilithiumKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	t.Log("Signature verified successfully")

	// Test metrics
	metrics := engine.GetMetrics()
	if metrics == nil {
		t.Fatal("Metrics is nil")
	}

	if metrics.OperationsCount == 0 {
		t.Error("Expected operations count > 0")
	}

	t.Logf("Metrics: Operations=%d, Errors=%d", metrics.OperationsCount, metrics.ErrorCount)

	// Test cleanup
	err = engine.Close()
	if err != nil {
		t.Errorf("Failed to close engine: %v", err)
	}

	t.Log("PQC engine closed successfully")
}

func TestPQCEngineWithNilConfig(t *testing.T) {
	// Test with nil config (should use defaults)
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine with nil config: %v", err)
	}

	if engine == nil {
		t.Fatal("Engine is nil")
	}

	// Test basic functionality
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair with default config: %v", err)
	}

	if keyPair == nil {
		t.Fatal("Key pair is nil")
	}

	t.Log("PQC engine with default config works correctly")

	err = engine.Close()
	if err != nil {
		t.Errorf("Failed to close engine: %v", err)
	}
}
