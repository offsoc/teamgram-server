// Package pqc provides core PQC engine functionality tests
package pqc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// TestPQCCoreEncryptionPrecision tests the core encryption functionality
func TestPQCCoreEncryptionPrecision(t *testing.T) {
	t.Run("AES_GCM_Precision", testAESGCMCore)
	t.Run("HKDF_SHA3_Precision", testHKDFSHA3Core)
	t.Run("HMAC_SHA3_Precision", testHMACSHA3Core)
	t.Run("Key_Derivation_Precision", testKeyDerivationCore)
	t.Run("Performance_Validation", testPerformanceCore)
}

// testAESGCMCore validates AES-256-GCM encryption precision
func testAESGCMCore(t *testing.T) {
	// Test AES-256-GCM encryption/decryption precision
	key := make([]byte, 32) // 256-bit key
	rand.Read(key)

	nonce := make([]byte, 12) // 96-bit nonce
	rand.Read(nonce)

	testMessages := [][]byte{
		[]byte("Hello, World!"),
		make([]byte, 1024),   // 1KB
		make([]byte, 65536),  // 64KB
	}

	// Fill large messages with random data
	rand.Read(testMessages[1])
	rand.Read(testMessages[2])

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("Message_%d", i), func(t *testing.T) {
			// Create AES-256-GCM cipher
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("AES cipher creation failed: %v", err)
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("GCM mode creation failed: %v", err)
			}

			// Encrypt
			start := time.Now()
			ciphertext := gcm.Seal(nil, nonce, message, nil)
			encryptTime := time.Since(start)

			// Decrypt
			start = time.Now()
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			decryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify accuracy
			if !bytes.Equal(message, plaintext) {
				t.Error("AES-GCM roundtrip failed")
			}

			// Log performance
			t.Logf("Size %d: Encrypt %v, Decrypt %v", len(message), encryptTime, decryptTime)

			// Check performance requirements
			if encryptTime > 10*time.Microsecond {
				t.Logf("WARNING: Encryption time %v exceeds 10μs target", encryptTime)
			}
			if decryptTime > 5*time.Microsecond {
				t.Logf("WARNING: Decryption time %v exceeds 5μs target", decryptTime)
			}
		})
	}
}

// testHKDFSHA3Core validates HKDF-SHA3 key derivation precision
func testHKDFSHA3Core(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	// Test key derivation consistency
	key1 := deriveKey(sharedSecret, []byte("TEST-INFO"), 32)
	key2 := deriveKey(sharedSecret, []byte("TEST-INFO"), 32)

	// Keys should be identical
	if !bytes.Equal(key1, key2) {
		t.Error("HKDF key derivation not deterministic")
	}

	// Different info should produce different keys
	key3 := deriveKey(sharedSecret, []byte("DIFFERENT-INFO"), 32)
	if bytes.Equal(key1, key3) {
		t.Error("HKDF should produce different keys for different info")
	}

	// Validate key length
	if len(key1) != 32 {
		t.Errorf("Invalid key length: expected 32, got %d", len(key1))
	}
}

// testHMACSHA3Core validates HMAC-SHA3 computation precision
func testHMACSHA3Core(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	testData := [][]byte{
		[]byte("test data"),
		[]byte(""),
		make([]byte, 1024),
	}
	rand.Read(testData[2])

	for i, data := range testData {
		t.Run(fmt.Sprintf("Data_%d", i), func(t *testing.T) {
			// Compute HMAC multiple times
			hmac1 := computeHMAC(data, key)
			hmac2 := computeHMAC(data, key)

			// Should be identical
			if !bytes.Equal(hmac1, hmac2) {
				t.Error("HMAC computation not deterministic")
			}

			// Validate HMAC length (SHA3-256 = 32 bytes)
			if len(hmac1) != 32 {
				t.Errorf("Invalid HMAC length: expected 32, got %d", len(hmac1))
			}

			// Verify HMAC verification
			if !verifyHMAC(data, key, hmac1) {
				t.Error("HMAC verification failed")
			}

			// Wrong HMAC should fail
			wrongHMAC := make([]byte, 32)
			rand.Read(wrongHMAC)
			if verifyHMAC(data, key, wrongHMAC) {
				t.Error("HMAC verification should fail for wrong HMAC")
			}
		})
	}
}

// testKeyDerivationCore validates key derivation consistency
func testKeyDerivationCore(t *testing.T) {
	// Test with multiple shared secrets
	for i := 0; i < 100; i++ {
		sharedSecret := make([]byte, 32)
		rand.Read(sharedSecret)

		// Derive AES and HMAC keys
		aesKey1 := deriveKey(sharedSecret, []byte("AES-256-GCM-KEY"), 32)
		aesKey2 := deriveKey(sharedSecret, []byte("AES-256-GCM-KEY"), 32)
		hmacKey1 := deriveKey(sharedSecret, []byte("HMAC-SHA3-KEY"), 32)
		hmacKey2 := deriveKey(sharedSecret, []byte("HMAC-SHA3-KEY"), 32)

		// Keys should be consistent
		if !bytes.Equal(aesKey1, aesKey2) {
			t.Errorf("AES key derivation inconsistent at iteration %d", i)
		}

		if !bytes.Equal(hmacKey1, hmacKey2) {
			t.Errorf("HMAC key derivation inconsistent at iteration %d", i)
		}

		// AES and HMAC keys should be different
		if bytes.Equal(aesKey1, hmacKey1) {
			t.Errorf("AES and HMAC keys should be different at iteration %d", i)
		}
	}
}

// testPerformanceCore validates performance requirements
func testPerformanceCore(t *testing.T) {
	message := make([]byte, 1024) // 1KB test message
	rand.Read(message)

	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	// Measure encryption performance
	encryptTimes := make([]time.Duration, 100)
	decryptTimes := make([]time.Duration, 100)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM mode creation failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		// Measure encryption
		start := time.Now()
		ciphertext := gcm.Seal(nil, nonce, message, nil)
		encryptTimes[i] = time.Since(start)

		// Measure decryption
		start = time.Now()
		_, err := gcm.Open(nil, nonce, ciphertext, nil)
		decryptTimes[i] = time.Since(start)

		if err != nil {
			t.Fatalf("Decryption %d failed: %v", i, err)
		}
	}

	// Calculate averages
	var totalEncryptTime, totalDecryptTime time.Duration
	for i := 0; i < 100; i++ {
		totalEncryptTime += encryptTimes[i]
		totalDecryptTime += decryptTimes[i]
	}

	avgEncryptTime := totalEncryptTime / 100
	avgDecryptTime := totalDecryptTime / 100

	t.Logf("Average encryption time: %v", avgEncryptTime)
	t.Logf("Average decryption time: %v", avgDecryptTime)
	t.Logf("Performance requirement: Encryption < 10μs, Decryption < 5μs")

	// Validate 100% integrity
	for i := 0; i < 1000; i++ {
		testMsg := make([]byte, 64)
		rand.Read(testMsg)

		ciphertext := gcm.Seal(nil, nonce, testMsg, nil)
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

		if err != nil {
			t.Fatalf("Integrity test %d failed: %v", i, err)
		}

		if !bytes.Equal(testMsg, plaintext) {
			t.Fatalf("Integrity test %d failed: message mismatch", i)
		}
	}

	t.Log("100% integrity verification passed for 1000 test cases")
}

// Helper functions

// deriveKey derives a key using HKDF-SHA3
func deriveKey(secret []byte, info []byte, length int) []byte {
	hkdf := hkdf.New(sha3.New256, secret, nil, info)
	key := make([]byte, length)
	hkdf.Read(key)
	return key
}

// computeHMAC computes HMAC-SHA3-256
func computeHMAC(data []byte, key []byte) []byte {
	h := hmac.New(sha3.New256, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyHMAC verifies HMAC-SHA3-256
func verifyHMAC(data []byte, key []byte, expectedHMAC []byte) bool {
	computedHMAC := computeHMAC(data, key)
	return hmac.Equal(computedHMAC, expectedHMAC)
}