package sphincs

import (
	"crypto/subtle"
	"testing"
	"golang.org/x/crypto/sha3"
)

func TestDebugSignVerify(t *testing.T) {
	// Test the core signing/verification logic directly
	n := 16
	message := []byte("test")
	
	// Create test keys
	skPrf := make([]byte, n)
	pkSeed := make([]byte, n)
	pkRoot := make([]byte, n)
	
	// Fill with test data
	for i := 0; i < n; i++ {
		skPrf[i] = byte(i)
		pkSeed[i] = byte(i + 16)
		pkRoot[i] = byte(i + 32)
	}
	
	// Generate randomizer
	randomizer := make([]byte, n)
	hasher := sha3.NewShake256()
	hasher.Write(skPrf)
	hasher.Write(message)
	hasher.Read(randomizer)
	
	t.Logf("randomizer: %x", randomizer)
	
	// Create signature
	sigSize := 100 // Small test signature
	signature := make([]byte, sigSize)
	copy(signature[0:n], randomizer)
	
	// Generate signature body
	hasher.Reset()
	hasher.Write(randomizer)
	hasher.Write(pkRoot)
	hasher.Write(pkSeed)
	hasher.Write(message)
	hasher.Read(signature[n:])
	
	t.Logf("signature first 32 bytes: %x", signature[:32])
	
	// Verify signature
	// Extract randomizer
	extractedRandomizer := signature[0:n]
	
	// Recompute expected signature body
	hasher.Reset()
	hasher.Write(extractedRandomizer)
	hasher.Write(pkRoot)
	hasher.Write(pkSeed)
	hasher.Write(message)
	
	expectedSigBody := make([]byte, sigSize-n)
	hasher.Read(expectedSigBody)
	
	t.Logf("expected sig body first 16 bytes: %x", expectedSigBody[:16])
	t.Logf("actual sig body first 16 bytes: %x", signature[n:n+16])
	
	// Compare
	result := subtle.ConstantTimeCompare(signature[n:], expectedSigBody)
	if result != 1 {
		t.Error("Signature verification failed")
	} else {
		t.Log("Signature verification succeeded")
	}
}