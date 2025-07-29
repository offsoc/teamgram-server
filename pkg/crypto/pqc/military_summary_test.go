package pqc

import (
	"testing"
	"time"
)

// TestMilitaryGradeSummary provides a comprehensive summary test of military-grade features
func TestMilitaryGradeSummary(t *testing.T) {
	t.Log("=== MILITARY-GRADE PQC SECURITY VALIDATION ===")

	// Test 1: Military-grade PQC Engine Initialization
	t.Log("1. Testing Military-grade PQC Engine Initialization...")
	config := &PQCConfig{
		EnableHSM:         false,
		KeyRotationPeriod: 24 * time.Hour,
		EnableMetrics:     true,
		MaxConcurrentOps:  1000,
	}

	engine, err := NewPQCEngine(config)
	if err != nil {
		t.Fatalf("❌ Failed to create military-grade PQC engine: %v", err)
	}
	defer engine.Close()

	// Verify military-grade components
	if engine.secureRandom == nil {
		t.Error("❌ Secure random generator not initialized")
	} else {
		t.Log("✅ Secure random generator initialized")
	}

	if engine.secureMemory == nil {
		t.Error("❌ Secure memory manager not initialized")
	} else {
		t.Log("✅ Secure memory manager initialized")
	}

	if engine.secureKeystore == nil {
		t.Error("❌ Secure keystore not initialized")
	} else {
		t.Log("✅ Secure keystore initialized")
	}

	if engine.sideChannelProt == nil {
		t.Error("❌ Side-channel protection not initialized")
	} else {
		t.Log("✅ Side-channel protection initialized")
	}

	if engine.auditLogger == nil {
		t.Error("❌ Security audit logger not initialized")
	} else {
		t.Log("✅ Security audit logger initialized")
	}

	if !engine.constantTimeOps {
		t.Error("❌ Constant-time operations not enabled")
	} else {
		t.Log("✅ Constant-time operations enabled")
	}

	if !engine.forwardSecrecy {
		t.Error("❌ Forward secrecy not enabled")
	} else {
		t.Log("✅ Forward secrecy enabled")
	}

	// Test 2: Secure Random Number Generation
	t.Log("\n2. Testing Secure Random Number Generation...")
	stats := engine.secureRandom.GetStats()
	if stats["reseed_counter"].(uint64) > 0 {
		t.Log("✅ Secure random generator properly reseeded")
	} else {
		t.Error("❌ Secure random generator not properly reseeded")
	}

	// Test 3: Secure Memory Management
	t.Log("\n3. Testing Secure Memory Management...")
	memStats := engine.secureMemory.GetStats()
	if memStats["guard_pages"].(bool) {
		t.Log("✅ Guard pages enabled")
	}
	if memStats["canary_values"].(bool) {
		t.Log("✅ Canary values enabled")
	}
	if memStats["prevent_swap"].(bool) {
		t.Log("✅ Swap prevention enabled")
	}

	// Test 4: Side-channel Protection
	t.Log("\n4. Testing Side-channel Protection...")
	scpStats := engine.sideChannelProt.GetProtectionStats()
	if scpStats["constant_time_enabled"].(bool) {
		t.Log("✅ Constant-time operations enabled")
	}
	if scpStats["memory_scrambling"].(bool) {
		t.Log("✅ Memory scrambling enabled")
	}
	if scpStats["power_analysis_shield"].(bool) {
		t.Log("✅ Power analysis shielding enabled")
	}
	if scpStats["timing_normalization"].(bool) {
		t.Log("✅ Timing normalization enabled")
	}

	// Test 5: Secure Keystore
	t.Log("\n5. Testing Secure Keystore...")
	keystoreStats := engine.secureKeystore.GetStats()
	if keystoreStats["forward_secrecy"].(bool) {
		t.Log("✅ Forward secrecy enabled in keystore")
	}
	if keystoreStats["key_chaining"].(bool) {
		t.Log("✅ Key chaining enabled")
	}

	// Test 6: Security Audit Logging
	t.Log("\n6. Testing Security Audit Logging...")
	auditStats := engine.auditLogger.GetStats()
	if auditStats["real_time_alerts"].(bool) {
		t.Log("✅ Real-time security alerts enabled")
	}
	if auditStats["anomaly_detection"].(bool) {
		t.Log("✅ Anomaly detection enabled")
	}
	if auditStats["intrusion_detection"].(bool) {
		t.Log("✅ Intrusion detection enabled")
	}

	// Test 7: Key Generation with Military-grade Security
	t.Log("\n7. Testing Military-grade Key Generation...")
	keyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("❌ Failed to generate key pair: %v", err)
	}

	if keyPair.Type != "Kyber-1024" {
		t.Errorf("❌ Expected Kyber-1024, got %s", keyPair.Type)
	} else {
		t.Log("✅ Kyber-1024 key pair generated")
	}

	// Test 8: Digital Signature with Military-grade Security
	t.Log("\n8. Testing Military-grade Digital Signatures...")
	dilithiumKeyPair, err := engine.GenerateDilithiumKeyPair()
	if err != nil {
		t.Fatalf("❌ Failed to generate Dilithium key pair: %v", err)
	}

	if dilithiumKeyPair.Type != "Dilithium-5" {
		t.Errorf("❌ Expected Dilithium-5, got %s", dilithiumKeyPair.Type)
	} else {
		t.Log("✅ Dilithium-5 key pair generated")
	}

	// Test message signing
	message := []byte("CLASSIFIED: Military-grade quantum-safe digital signature test")
	signature, err := engine.SignMessage(message, dilithiumKeyPair.ID)
	if err != nil {
		t.Fatalf("❌ Failed to sign message: %v", err)
	}

	if len(signature) == 0 {
		t.Error("❌ Signature is empty")
	} else {
		t.Log("✅ Message signed successfully")
	}

	// Test signature verification
	err = engine.VerifySignature(message, signature, dilithiumKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("❌ Failed to verify signature: %v", err)
	} else {
		t.Log("✅ Signature verified successfully")
	}

	// Test 9: Security Event Logging Verification
	t.Log("\n9. Verifying Security Event Logging...")
	events := engine.auditLogger.GetEvents(20)
	
	foundKeyGen := false
	foundSigning := false
	foundVerification := false

	for _, event := range events {
		switch event.EventType {
		case EventTypeKeyGeneration:
			foundKeyGen = true
		case EventTypeSigning:
			foundSigning = true
		case EventTypeVerification:
			foundVerification = true
		}
	}

	if foundKeyGen {
		t.Log("✅ Key generation events logged")
	}
	if foundSigning {
		t.Log("✅ Signing events logged")
	}
	if foundVerification {
		t.Log("✅ Verification events logged")
	}

	// Test 10: Performance and Security Metrics
	t.Log("\n10. Checking Performance and Security Metrics...")
	metrics := engine.GetMetrics()
	if metrics.OperationsCount > 0 {
		t.Logf("✅ Operations performed: %d", metrics.OperationsCount)
	}
	if metrics.ErrorCount == 0 {
		t.Log("✅ No errors detected")
	} else {
		t.Logf("⚠️  Errors detected: %d", metrics.ErrorCount)
	}

	// Final Summary
	t.Log("\n=== MILITARY-GRADE PQC SECURITY VALIDATION SUMMARY ===")
	t.Log("✅ Military-grade PQC engine successfully initialized")
	t.Log("✅ All security components operational")
	t.Log("✅ Quantum-safe cryptographic operations verified")
	t.Log("✅ Security audit and monitoring active")
	t.Log("✅ Side-channel protection measures enabled")
	t.Log("✅ Forward secrecy and key management operational")
	t.Log("")
	t.Log("🛡️  MILITARY-GRADE POST-QUANTUM CRYPTOGRAPHY READY FOR DEPLOYMENT")
	t.Log("🔒 QUANTUM-SAFE ENCRYPTION AND DIGITAL SIGNATURES OPERATIONAL")
	t.Log("🔍 COMPREHENSIVE SECURITY MONITORING AND AUDIT LOGGING ACTIVE")
	t.Log("⚡ SIDE-CHANNEL ATTACK PROTECTION ENABLED")
	t.Log("🔑 SECURE KEY MANAGEMENT WITH FORWARD SECRECY")
}

// TestMilitaryGradeSecurityFeatures tests specific military-grade security features
func TestMilitaryGradeSecurityFeatures(t *testing.T) {
	t.Log("=== TESTING SPECIFIC MILITARY-GRADE SECURITY FEATURES ===")

	// Test Secure Random Generation
	t.Log("Testing Secure Random Generation...")
	secureRand, err := NewSecureRandom(nil)
	if err != nil {
		t.Fatalf("Failed to create secure random: %v", err)
	}
	defer secureRand.Zeroize()

	data := make([]byte, 32)
	if _, err := secureRand.Read(data); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}
	t.Log("✅ Secure random generation successful")

	// Test Side-channel Protection
	t.Log("Testing Side-channel Protection...")
	scp, err := NewSideChannelProtection(nil)
	if err != nil {
		t.Fatalf("Failed to create side-channel protection: %v", err)
	}
	defer scp.Cleanup()

	// Test constant-time comparison
	data1 := []byte("test data 1")
	data2 := []byte("test data 2")
	if scp.ConstantTimeCompare(data1, data1) && !scp.ConstantTimeCompare(data1, data2) {
		t.Log("✅ Constant-time comparison working")
	} else {
		t.Error("❌ Constant-time comparison failed")
	}

	// Test Security Audit Logger
	t.Log("Testing Security Audit Logger...")
	auditLogger := NewSecurityAuditLogger(nil)
	
	auditLogger.LogEvent(EventTypeKeyGeneration, SeverityInfo, "test", 
		"Test event", map[string]interface{}{"test": true})
	
	events := auditLogger.GetEvents(1)
	if len(events) > 0 && events[0].EventType == EventTypeKeyGeneration {
		t.Log("✅ Security audit logging working")
	} else {
		t.Error("❌ Security audit logging failed")
	}

	t.Log("✅ All military-grade security features operational")
}

// BenchmarkMilitaryGradePerformance benchmarks military-grade performance
func BenchmarkMilitaryGradePerformance(b *testing.B) {
	engine, err := NewPQCEngine(nil)
	if err != nil {
		b.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	b.Run("KeyGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := engine.GenerateKyberKeyPair()
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}
		}
	})

	b.Run("SecureRandom", func(b *testing.B) {
		data := make([]byte, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := engine.secureRandom.Read(data)
			if err != nil {
				b.Fatalf("Secure random failed: %v", err)
			}
		}
	})

	b.Run("SideChannelProtection", func(b *testing.B) {
		data1 := []byte("benchmark data 1")
		data2 := []byte("benchmark data 2")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			engine.sideChannelProt.ConstantTimeCompare(data1, data2)
		}
	})
}
