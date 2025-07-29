package sphincs

import (
	"testing"
)

func TestSimpleSPHINCS(t *testing.T) {
	signer, err := NewSigner(SPHINCS128, SmallSignature, SHAKE256)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Generate key pair
	publicKey, privateKey, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test message
	message := []byte("Hello SPHINCS+")

	// Sign message
	signature, err := signer.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	t.Logf("Public key size: %d", len(publicKey.Bytes()))
	t.Logf("Private key size: %d", len(privateKey.Bytes()))
	t.Logf("Signature size: %d", len(signature))
	
	// Debug: print first few bytes
	t.Logf("Public key first 16 bytes: %x", publicKey.Bytes()[:16])
	t.Logf("Private key first 16 bytes: %x", privateKey.Bytes()[:16])
	t.Logf("Signature first 16 bytes: %x", signature[:16])

	// Verify signature
	if !signer.Verify(publicKey, message, signature) {
		t.Error("Signature verification failed")
		
		// Debug verification
		n := signer.params.n
		pkSeed := publicKey.Bytes()[0:n]
		pkRoot := publicKey.Bytes()[n:2*n]
		randomizer := signature[0:n]
		
		t.Logf("pkSeed: %x", pkSeed)
		t.Logf("pkRoot: %x", pkRoot)
		t.Logf("randomizer: %x", randomizer)
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	if signer.Verify(publicKey, wrongMessage, signature) {
		t.Error("Verification should have failed for wrong message")
	}

	privateKey.Zeroize()
}