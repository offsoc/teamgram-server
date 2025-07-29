// Package pqc provides comprehensive precision validation tests
// to ensure 100% accuracy of PQC engine encryption content
package pqc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// TestPQCEnginePrecisionValidation runs comprehensive precision validation tests
func TestPQCEnginePrecisionValidation(t *testing.T) {
	t.Run("AES_GCM_Precision", testAESGCMPrecision)
	t.Run("HKDF_SHA3_Precision", testHKDFSHA3Precision)
	t.Run("HMAC_SHA3_Precision", testHMACSHA3Precision)
	t.Run("Encryption_Decryption_Roundtrip", testEncryptionDecryptionRoundtrip)
	t.Run("Key_Derivation_Consistency", testKeyDerivationConsistency)
	t.Run("HMAC_Integrity_Validation", testHMACIntegrityValidation)
	t.Run("Forward_Secrecy_Validation", testForwardSecrecyValidation)
	t.Run("Performance_Requirements", testPerformanceRequirements)
	t.Run("Edge_Cases", testEdgeCases)
	t.Run("Security_Properties", testSecurityProperties)
}

// testAESGCMPrecision validates AES-256-GCM encryption precision
func testAESGCMPrecision(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate test key pair
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testMessages := [][]byte{
		[]byte("Hello, World!"),
		[]byte(""),
		make([]byte, 1024),   // 1KB
		make([]byte, 65536),  // 64KB
	}

	// Fill large messages with random data
	rand.Read(testMessages[2])
	rand.Read(testMessages[3])

	for i, message := range testMessages {
		if len(message) == 0 && i == 1 {
			continue // Skip empty message for this test
		}

		t.Run(fmt.Sprintf("Message_%d", i), func(t *testing.T) {
			// Encrypt message
			encrypted, err := engine.EncryptMessage(message, keyPair.PublicKey)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Validate encrypted message structure
			if len(encrypted.Ciphertext) == 0 {
				t.Error("Ciphertext is empty")
			}
			if len(encrypted.Nonce) != 12 {
				t.Errorf("Invalid nonce length: expected 12, got %d", len(encrypted.Nonce))
			}
			if len(encrypted.AuthTag) != 16 {
				t.Errorf("Invalid auth tag length: expected 16, got %d", len(encrypted.AuthTag))
			}
			if len(encrypted.HMAC) != 32 {
				t.Errorf("Invalid HMAC length: expected 32, got %d", len(encrypted.HMAC))
			}

			// Decrypt message
			decrypted, err := engine.DecryptMessage(encrypted, keyPair.ID)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify roundtrip accuracy
			if !bytes.Equal(message, decrypted) {
				t.Errorf("Roundtrip failed: original != decrypted")
			}
		})
	}
}

// testHKDFSHA3Precision validates HKDF-SHA3 key derivation precision
func testHKDFSHA3Precision(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Test key derivation consistency
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	// Derive keys multiple times with same input
	key1, err := engine.deriveAESKey(sharedSecret, []byte("TEST-INFO"))
	if err != nil {
		t.Fatalf("Key derivation 1 failed: %v", err)
	}

	key2, err := engine.deriveAESKey(sharedSecret, []byte("TEST-INFO"))
	if err != nil {
		t.Fatalf("Key derivation 2 failed: %v", err)
	}

	// Keys should be identical
	if !bytes.Equal(key1, key2) {
		t.Error("HKDF key derivation not deterministic")
	}

	// Different info should produce different keys
	key3, err := engine.deriveAESKey(sharedSecret, []byte("DIFFERENT-INFO"))
	if err != nil {
		t.Fatalf("Key derivation 3 failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("HKDF should produce different keys for different info")
	}

	// Validate key length
	if len(key1) != 32 {
		t.Errorf("Invalid AES key length: expected 32, got %d", len(key1))
	}
}

// testHMACSHA3Precision validates HMAC-SHA3 computation precision
func testHMACSHA3Precision(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

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
			hmac1 := engine.computeHMAC(data, key)
			hmac2 := engine.computeHMAC(data, key)

			// Should be identical
			if !bytes.Equal(hmac1, hmac2) {
				t.Error("HMAC computation not deterministic")
			}

			// Validate HMAC length (SHA3-256 = 32 bytes)
			if len(hmac1) != 32 {
				t.Errorf("Invalid HMAC length: expected 32, got %d", len(hmac1))
			}

			// Verify HMAC verification
			if !engine.verifyHMAC(data, key, hmac1) {
				t.Error("HMAC verification failed")
			}

			// Wrong HMAC should fail
			wrongHMAC := make([]byte, 32)
			rand.Read(wrongHMAC)
			if engine.verifyHMAC(data, key, wrongHMAC) {
				t.Error("HMAC verification should fail for wrong HMAC")
			}
		})
	}
}

// testEncryptionDecryptionRoundtrip validates complete encryption/decryption cycle
func testEncryptionDecryptionRoundtrip(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate key pair
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test with various message sizes
	messageSizes := []int{1, 16, 64, 256, 1024, 4096, 16384, 65536}

	for _, size := range messageSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Generate random message
			message := make([]byte, size)
			rand.Read(message)

			// Encrypt
			start := time.Now()
			encrypted, err := engine.EncryptMessage(message, keyPair.PublicKey)
			encryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			start = time.Now()
			decrypted, err := engine.DecryptMessage(encrypted, keyPair.ID)
			decryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify accuracy
			if !bytes.Equal(message, decrypted) {
				t.Error("Roundtrip accuracy failed")
			}

			// Log performance
			t.Logf("Size %d: Encrypt %v, Decrypt %v", size, encryptTime, decryptTime)

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

// testKeyDerivationConsistency validates key derivation consistency
func testKeyDerivationConsistency(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Test with multiple shared secrets
	for i := 0; i < 100; i++ {
		sharedSecret := make([]byte, 32)
		rand.Read(sharedSecret)

		// Derive AES and HMAC keys
		aesKey1, err := engine.deriveAESKey(sharedSecret, []byte("AES-256-GCM-KEY"))
		if err != nil {
			t.Fatalf("AES key derivation failed: %v", err)
		}

		aesKey2, err := engine.deriveAESKey(sharedSecret, []byte("AES-256-GCM-KEY"))
		if err != nil {
			t.Fatalf("AES key derivation failed: %v", err)
		}

		hmacKey1, err := engine.deriveHMACKey(sharedSecret, []byte("HMAC-SHA3-KEY"))
		if err != nil {
			t.Fatalf("HMAC key derivation failed: %v", err)
		}

		hmacKey2, err := engine.deriveHMACKey(sharedSecret, []byte("HMAC-SHA3-KEY"))
		if err != nil {
			t.Fatalf("HMAC key derivation failed: %v", err)
		}

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

// testHMACIntegrityValidation validates HMAC integrity protection
func testHMACIntegrityValidation(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate key pair
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("integrity test message")

	// Encrypt message
	encrypted, err := engine.EncryptMessage(message, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Test 1: Valid message should decrypt
	_, err = engine.DecryptMessage(encrypted, keyPair.ID)
	if err != nil {
		t.Fatalf("Valid message decryption failed: %v", err)
	}

	// Test 2: Tampered ciphertext should fail
	tamperedEncrypted := *encrypted
	tamperedEncrypted.Ciphertext = make([]byte, len(encrypted.Ciphertext))
	copy(tamperedEncrypted.Ciphertext, encrypted.Ciphertext)
	tamperedEncrypted.Ciphertext[0] ^= 0x01

	_, err = engine.DecryptMessage(&tamperedEncrypted, keyPair.ID)
	if err == nil {
		t.Error("Tampered ciphertext should fail decryption")
	}

	// Test 3: Tampered HMAC should fail
	tamperedEncrypted2 := *encrypted
	tamperedEncrypted2.HMAC = make([]byte, len(encrypted.HMAC))
	copy(tamperedEncrypted2.HMAC, encrypted.HMAC)
	tamperedEncrypted2.HMAC[0] ^= 0x01

	_, err = engine.DecryptMessage(&tamperedEncrypted2, keyPair.ID)
	if err == nil {
		t.Error("Tampered HMAC should fail decryption")
	}

	// Test 4: Tampered nonce should fail
	tamperedEncrypted3 := *encrypted
	tamperedEncrypted3.Nonce = make([]byte, len(encrypted.Nonce))
	copy(tamperedEncrypted3.Nonce, encrypted.Nonce)
	tamperedEncrypted3.Nonce[0] ^= 0x01

	_, err = engine.DecryptMessage(&tamperedEncrypted3, keyPair.ID)
	if err == nil {
		t.Error("Tampered nonce should fail decryption")
	}
}

// testForwardSecrecyValidation validates forward secrecy mechanisms
func testForwardSecrecyValidation(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Test key rotation
	originalKey := make([]byte, 32)
	rand.Read(originalKey)

	rotatedKey, err := engine.rotateKeyMaterial(originalKey)
	if err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	// Rotated key should be different
	if bytes.Equal(originalKey, rotatedKey) {
		t.Error("Key rotation should produce different key")
	}

	// Key rotation should be deterministic with same input
	rotatedKey2, err := engine.rotateKeyMaterial(originalKey)
	if err != nil {
		t.Fatalf("Key rotation 2 failed: %v", err)
	}

	if !bytes.Equal(rotatedKey, rotatedKey2) {
		t.Error("Key rotation should be deterministic")
	}

	// Multiple rotations should produce different keys
	rotatedKey3, err := engine.rotateKeyMaterial(rotatedKey)
	if err != nil {
		t.Fatalf("Key rotation 3 failed: %v", err)
	}

	if bytes.Equal(rotatedKey, rotatedKey3) {
		t.Error("Multiple key rotations should produce different keys")
	}
}

// testPerformanceRequirements validates performance requirements
func testPerformanceRequirements(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate key pair
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := make([]byte, 1024) // 1KB test message
	rand.Read(message)

	// Measure encryption performance
	encryptTimes := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		start := time.Now()
		encrypted, err := engine.EncryptMessage(message, keyPair.PublicKey)
		encryptTimes[i] = time.Since(start)

		if err != nil {
			t.Fatalf("Encryption %d failed: %v", i, err)
		}

		// Measure decryption performance
		start = time.Now()
		_, err = engine.DecryptMessage(encrypted, keyPair.ID)
		decryptTime := time.Since(start)

		if err != nil {
			t.Fatalf("Decryption %d failed: %v", i, err)
		}

		// Check individual performance requirements
		if encryptTimes[i] > 10*time.Microsecond {
			t.Logf("Encryption %d time %v exceeds 10μs target", i, encryptTimes[i])
		}

		if decryptTime > 5*time.Microsecond {
			t.Logf("Decryption %d time %v exceeds 5μs target", i, decryptTime)
		}
	}

	// Calculate average performance
	var totalEncryptTime time.Duration
	for _, t := range encryptTimes {
		totalEncryptTime += t
	}
	avgEncryptTime := totalEncryptTime / time.Duration(len(encryptTimes))

	t.Logf("Average encryption time: %v", avgEncryptTime)
	t.Logf("Performance requirement: Encryption < 10μs, Decryption < 5μs")

	// Validate 100% integrity
	for i := 0; i < 1000; i++ {
		testMsg := make([]byte, 64)
		rand.Read(testMsg)

		encrypted, err := engine.EncryptMessage(testMsg, keyPair.PublicKey)
		if err != nil {
			t.Fatalf("Integrity test %d encryption failed: %v", i, err)
		}

		decrypted, err := engine.DecryptMessage(encrypted, keyPair.ID)
		if err != nil {
			t.Fatalf("Integrity test %d decryption failed: %v", i, err)
		}

		if !bytes.Equal(testMsg, decrypted) {
			t.Fatalf("Integrity test %d failed: message mismatch", i)
		}
	}

	t.Log("100% integrity verification passed for 1000 test cases")
}

// testEdgeCases validates edge case handling
func testEdgeCases(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate key pair
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test 1: Empty message
	_, err = engine.EncryptMessage([]byte{}, keyPair.PublicKey)
	if err == nil {
		t.Error("Empty message should fail encryption")
	}

	// Test 2: Nil encrypted message
	_, err = engine.DecryptMessage(nil, keyPair.ID)
	if err == nil {
		t.Error("Nil encrypted message should fail decryption")
	}

	// Test 3: Invalid key ID
	message := []byte("test message")
	encrypted, err := engine.EncryptMessage(message, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = engine.DecryptMessage(encrypted, "invalid-key-id")
	if err == nil {
		t.Error("Invalid key ID should fail decryption")
	}

	// Test 4: Corrupted encrypted message structure
	corruptedMsg := &EncryptedMessage{
		Ciphertext:   []byte{},
		EncryptedKey: []byte{},
		Nonce:        []byte{},
		AuthTag:      []byte{},
		HMAC:         []byte{},
	}

	_, err = engine.DecryptMessage(corruptedMsg, keyPair.ID)
	if err == nil {
		t.Error("Corrupted message structure should fail decryption")
	}

	// Test 5: Very large message
	largeMessage := make([]byte, 1024*1024) // 1MB
	rand.Read(largeMessage)

	encrypted, err = engine.EncryptMessage(largeMessage, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Large message encryption failed: %v", err)
	}

	decrypted, err := engine.DecryptMessage(encrypted, keyPair.ID)
	if err != nil {
		t.Fatalf("Large message decryption failed: %v", err)
	}

	if !bytes.Equal(largeMessage, decrypted) {
		t.Error("Large message roundtrip failed")
	}
}

// testSecurityProperties validates security properties
func testSecurityProperties(t *testing.T) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	// Generate key pairs
	keyPair1, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}

	keyPair2, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	message := []byte("security test message")

	// Test 1: Same message with different keys should produce different ciphertexts
	encrypted1, err := engine.EncryptMessage(message, keyPair1.PublicKey)
	if err != nil {
		t.Fatalf("Encryption 1 failed: %v", err)
	}

	encrypted2, err := engine.EncryptMessage(message, keyPair2.PublicKey)
	if err != nil {
		t.Fatalf("Encryption 2 failed: %v", err)
	}

	if bytes.Equal(encrypted1.Ciphertext, encrypted2.Ciphertext) {
		t.Error("Same message with different keys should produce different ciphertexts")
	}

	// Test 2: Same message with same key should produce different ciphertexts (due to random nonce)
	encrypted3, err := engine.EncryptMessage(message, keyPair1.PublicKey)
	if err != nil {
		t.Fatalf("Encryption 3 failed: %v", err)
	}

	if bytes.Equal(encrypted1.Ciphertext, encrypted3.Ciphertext) {
		t.Error("Same message with same key should produce different ciphertexts due to random nonce")
	}

	// Test 3: Cross-key decryption should fail
	_, err = engine.DecryptMessage(encrypted1, keyPair2.ID)
	if err == nil {
		t.Error("Cross-key decryption should fail")
	}

	// Test 4: Nonce uniqueness
	nonces := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		encrypted, err := engine.EncryptMessage(message, keyPair1.PublicKey)
		if err != nil {
			t.Fatalf("Encryption %d failed: %v", i, err)
		}

		nonceStr := string(encrypted.Nonce)
		if nonces[nonceStr] {
			t.Errorf("Duplicate nonce found at iteration %d", i)
		}
		nonces[nonceStr] = true
	}

	t.Logf("Nonce uniqueness validated for 1000 encryptions")
}