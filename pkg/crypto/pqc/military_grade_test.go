package pqc

import (
	"bytes"
	"testing"
	"time"
)

// TestMilitaryGradePQCEngine tests the military-grade PQC engine
func TestMilitaryGradePQCEngine(t *testing.T) {
	// Create military-grade PQC engine
	config := &PQCConfig{
		EnableHSM:         false,
		KeyRotationPeriod: 24 * time.Hour,
		EnableMetrics:     true,
		MaxConcurrentOps:  1000,
	}

	engine, err := NewPQCEngine(config)
	if err != nil {
		t.Fatalf("Failed to create military-grade PQC engine: %v", err)
	}
	defer engine.Close()

	// Verify military-grade components are initialized
	if engine.secureRandom == nil {
		t.Error("Secure random generator not initialized")
	}
	if engine.secureMemory == nil {
		t.Error("Secure memory manager not initialized")
	}
	if engine.secureKeystore == nil {
		t.Error("Secure keystore not initialized")
	}
	if engine.sideChannelProt == nil {
		t.Error("Side-channel protection not initialized")
	}
	if engine.auditLogger == nil {
		t.Error("Security audit logger not initialized")
	}

	// Test enhanced security features
	if !engine.constantTimeOps {
		t.Error("Constant-time operations not enabled")
	}
	if !engine.forwardSecrecy {
		t.Error("Forward secrecy not enabled")
	}

	t.Log("Military-grade PQC engine initialized successfully")
}

// TestSecureRandomGeneration tests the secure random number generator
func TestSecureRandomGeneration(t *testing.T) {
	secureRand, err := NewSecureRandom(nil)
	if err != nil {
		t.Fatalf("Failed to create secure random generator: %v", err)
	}
	defer secureRand.Zeroize()

	// Test random generation
	data1 := make([]byte, 32)
	data2 := make([]byte, 32)

	if _, err := secureRand.Read(data1); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	if _, err := secureRand.Read(data2); err != nil {
		t.Fatalf("Failed to generate second random data: %v", err)
	}

	// Verify randomness (data should be different)
	if bytes.Equal(data1, data2) {
		t.Error("Generated random data is identical - poor randomness")
	}

	// Test statistics
	stats := secureRand.GetStats()
	if stats["reseed_counter"].(uint64) == 0 {
		t.Error("Reseed counter should be > 0")
	}

	t.Log("Secure random generation test passed")
}

// TestSecureMemoryManagement tests secure memory allocation and protection
func TestSecureMemoryManagement(t *testing.T) {
	secMem := GetSecureMemory()

	// Test secure allocation
	data, err := secMem.SecureAlloc(1024)
	if err != nil {
		t.Fatalf("Failed to allocate secure memory: %v", err)
	}

	// Write test data
	testData := []byte("Military-grade secret data")
	copy(data[:len(testData)], testData)

	// Test memory protection
	if err := secMem.SetProtection(data, ProtectionReadOnly); err != nil {
		t.Errorf("Failed to set memory protection: %v", err)
	}

	// Test secure zeroization
	secMem.SecureZeroize(data)

	// Verify data is zeroed
	for i, b := range data[:len(testData)] {
		if b != 0 {
			t.Errorf("Memory not properly zeroed at index %d: got %d", i, b)
		}
	}

	// Test secure free
	if err := secMem.SecureFree(data); err != nil {
		t.Errorf("Failed to free secure memory: %v", err)
	}

	// Test statistics
	stats := secMem.GetStats()
	if stats["alloc_count"].(uint64) == 0 {
		t.Error("Allocation count should be > 0")
	}

	t.Log("Secure memory management test passed")
}

// TestSideChannelProtection tests side-channel attack protection
func TestSideChannelProtection(t *testing.T) {
	scp, err := NewSideChannelProtection(nil)
	if err != nil {
		t.Fatalf("Failed to create side-channel protection: %v", err)
	}
	defer scp.Cleanup()

	// Test constant-time operations
	data1 := []byte("secret data 1")
	data2 := []byte("secret data 2")
	data3 := []byte("secret data 1") // Same as data1

	// Test constant-time comparison
	if scp.ConstantTimeCompare(data1, data2) {
		t.Error("Constant-time compare should return false for different data")
	}

	if !scp.ConstantTimeCompare(data1, data3) {
		t.Error("Constant-time compare should return true for identical data")
	}

	// Test constant-time selection
	condition := 1
	selected := scp.ConstantTimeSelect(condition, data1, data2)
	if !bytes.Equal(selected, data1) {
		t.Errorf("Constant-time select failed: expected %q, got %q", string(data1), string(selected))
	}

	// Test masked operation
	result := scp.MaskedOperation(func(data []byte) []byte {
		// Simple XOR operation
		output := make([]byte, len(data))
		for i, b := range data {
			output[i] = b ^ 0xAA
		}
		return output
	}, data1)

	if len(result) != len(data1) {
		t.Error("Masked operation result length mismatch")
	}

	// Test statistics
	stats := scp.GetProtectionStats()
	if stats["operation_count"].(uint64) == 0 {
		t.Error("Operation count should be > 0")
	}

	t.Log("Side-channel protection test passed")
}

// TestSecureKeystore tests the secure keystore functionality
func TestSecureKeystore(t *testing.T) {
	keystore, err := NewSecureKeystore(nil)
	if err != nil {
		t.Fatalf("Failed to create secure keystore: %v", err)
	}
	defer keystore.Cleanup()

	// Test key storage
	keyID := "test-key-001"
	keyMaterial := []byte("super-secret-key-material-32-bytes")
	expiresAt := time.Now().Add(24 * time.Hour)

	err = keystore.StoreKey(keyID, KeyTypeAES, KeyUsageEncryption|KeyUsageDecryption,
		keyMaterial, expiresAt)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Test key retrieval
	retrievedKey, err := keystore.RetrieveKey(keyID, KeyUsageEncryption)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	if !bytes.Equal(keyMaterial, retrievedKey) {
		t.Errorf("Retrieved key does not match original: expected %x, got %x", keyMaterial, retrievedKey)
	}

	// Test key information
	keyInfo, err := keystore.GetKeyInfo(keyID)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	if keyInfo.Type != KeyTypeAES {
		t.Error("Key type mismatch")
	}

	if keyInfo.Usage&KeyUsageEncryption == 0 {
		t.Error("Key usage mismatch")
	}

	// Test key rotation
	err = keystore.RotateKey(keyID)
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify key changed after rotation
	rotatedKey, err := keystore.RetrieveKey(keyID, KeyUsageEncryption)
	if err != nil {
		t.Fatalf("Failed to retrieve rotated key: %v", err)
	}

	if bytes.Equal(keyMaterial, rotatedKey) {
		t.Error("Key should have changed after rotation")
	}

	// Test key deletion
	err = keystore.DeleteKey(keyID)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	_, err = keystore.RetrieveKey(keyID, KeyUsageEncryption)
	if err == nil {
		t.Error("Key should not be retrievable after deletion")
	}

	// Test statistics
	stats := keystore.GetStats()
	if stats["key_creations"].(uint64) == 0 {
		t.Error("Key creation count should be > 0")
	}

	t.Log("Secure keystore test passed")
}

// TestSecurityAuditLogger tests the security audit logging functionality
func TestSecurityAuditLogger(t *testing.T) {
	auditLogger := NewSecurityAuditLogger(nil)

	// Test event logging
	auditLogger.LogEvent(EventTypeKeyGeneration, SeverityInfo, "test",
		"Test key generation", map[string]interface{}{
			"key_type": "test",
			"key_size": 256,
		})

	auditLogger.LogEvent(EventTypeEncryption, SeverityInfo, "test",
		"Test encryption", map[string]interface{}{
			"message_size": 1024,
		})

	// Test security violation logging
	auditLogger.LogSecurityViolation("Test security violation",
		[]string{"suspicious_activity", "rate_limit_exceeded"},
		"test-user", "test-session", "192.168.1.100")

	// Test event retrieval
	events := auditLogger.GetEvents(10)
	if len(events) < 3 {
		t.Error("Should have at least 3 logged events")
	}

	// Verify event types
	foundKeyGen := false
	foundEncryption := false
	foundViolation := false

	for _, event := range events {
		switch event.EventType {
		case EventTypeKeyGeneration:
			foundKeyGen = true
		case EventTypeEncryption:
			foundEncryption = true
		case EventTypeSecurityViolation:
			foundViolation = true
		}
	}

	if !foundKeyGen {
		t.Error("Key generation event not found")
	}
	if !foundEncryption {
		t.Error("Encryption event not found")
	}
	if !foundViolation {
		t.Error("Security violation event not found")
	}

	// Test statistics
	stats := auditLogger.GetStats()
	if stats["total_events"].(uint64) < 3 {
		t.Error("Total events should be >= 3")
	}

	// Test event export
	startTime := time.Now().Add(-time.Hour)
	endTime := time.Now().Add(time.Hour)

	exportData, err := auditLogger.ExportEvents(startTime, endTime)
	if err != nil {
		t.Fatalf("Failed to export events: %v", err)
	}

	if len(exportData) == 0 {
		t.Error("Exported data should not be empty")
	}

	t.Log("Security audit logger test passed")
}

// TestMilitaryGradeEncryptionDecryption tests end-to-end military-grade encryption
func TestMilitaryGradeEncryptionDecryption(t *testing.T) {
	// Create military-grade PQC engine
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

	// Test message
	originalMessage := []byte("TOP SECRET: Military-grade quantum-safe encryption test message")

	// Encrypt message
	encryptedMsg, err := engine.EncryptMessage(originalMessage, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Verify encrypted message structure
	if len(encryptedMsg.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	if len(encryptedMsg.EncryptedKey) == 0 {
		t.Error("Encrypted key should not be empty")
	}
	if len(encryptedMsg.Nonce) == 0 {
		t.Error("Nonce should not be empty")
	}
	if len(encryptedMsg.HMAC) == 0 {
		t.Error("HMAC should not be empty")
	}

	// Decrypt message
	decryptedMessage, err := engine.DecryptMessage(encryptedMsg, keyPair.ID)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(originalMessage, decryptedMessage) {
		t.Error("Decrypted message does not match original")
	}

	// Test audit events
	events := engine.auditLogger.GetEvents(10)
	foundEncryption := false
	foundDecryption := false

	for _, event := range events {
		if event.EventType == EventTypeEncryption {
			foundEncryption = true
		}
		if event.EventType == EventTypeDecryption {
			foundDecryption = true
		}
	}

	if !foundEncryption {
		t.Error("Encryption event not logged")
	}
	if !foundDecryption {
		t.Error("Decryption event not logged")
	}

	t.Log("Military-grade encryption/decryption test passed")
}

// BenchmarkMilitaryGradeEncryption benchmarks military-grade encryption performance
func BenchmarkMilitaryGradeEncryption(b *testing.B) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		b.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := make([]byte, 1024) // 1KB message
	engine.secureRandom.Read(message)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := engine.EncryptMessage(message, keyPair.PublicKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkMilitaryGradeDecryption benchmarks military-grade decryption performance
func BenchmarkMilitaryGradeDecryption(b *testing.B) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		b.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := make([]byte, 1024) // 1KB message
	engine.secureRandom.Read(message)

	encryptedMsg, err := engine.EncryptMessage(message, keyPair.PublicKey)
	if err != nil {
		b.Fatalf("Failed to encrypt message: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := engine.DecryptMessage(encryptedMsg, keyPair.ID)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
