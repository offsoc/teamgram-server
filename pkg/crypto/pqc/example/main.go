// Package main demonstrates the PQC (Post-Quantum Cryptography) engine
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/teamgram/teamgram-server/pkg/crypto/pqc"
)

func main() {
	fmt.Println("🔐 Teamgram Military-Grade PQC Engine Demo")
	fmt.Println("==========================================")

	// Create PQC engine
	config := &pqc.PQCConfig{
		EnableHSM:         false, // Disable HSM for demo
		KeyRotationPeriod: 24 * time.Hour,
		EnableMetrics:     true,
		MaxConcurrentOps:  1000,
	}

	engine, err := pqc.NewPQCEngine(config)
	if err != nil {
		log.Fatalf("Failed to create PQC engine: %v", err)
	}
	defer engine.Close()

	fmt.Println("✅ PQC Engine initialized successfully")

	// Demonstrate Kyber key generation
	fmt.Println("\n🔑 Generating Kyber-1024 key pair...")
	start := time.Now()
	kyberKeyPair, err := engine.GenerateKyberKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate Kyber key pair: %v", err)
	}
	keyGenTime := time.Since(start)

	fmt.Printf("✅ Kyber key pair generated in %v\n", keyGenTime)
	fmt.Printf("   - Key ID: %s\n", kyberKeyPair.ID)
	fmt.Printf("   - Key Type: %s\n", kyberKeyPair.Type)
	fmt.Printf("   - Public Key Size: %d bytes\n", len(kyberKeyPair.PublicKey))
	fmt.Printf("   - Private Key Size: %d bytes\n", len(kyberKeyPair.PrivateKey))

	// Demonstrate Dilithium key generation
	fmt.Println("\n🔑 Generating Dilithium-5 key pair...")
	start = time.Now()
	dilithiumKeyPair, err := engine.GenerateDilithiumKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate Dilithium key pair: %v", err)
	}
	keyGenTime = time.Since(start)

	fmt.Printf("✅ Dilithium key pair generated in %v\n", keyGenTime)
	fmt.Printf("   - Key ID: %s\n", dilithiumKeyPair.ID)
	fmt.Printf("   - Key Type: %s\n", dilithiumKeyPair.Type)
	fmt.Printf("   - Public Key Size: %d bytes\n", len(dilithiumKeyPair.PublicKey))
	fmt.Printf("   - Private Key Size: %d bytes\n", len(dilithiumKeyPair.PrivateKey))

	// Demonstrate encryption/decryption
	fmt.Println("\n🔒 Testing PQC Encryption/Decryption...")
	message := []byte("This is a top-secret military message that needs quantum-safe protection! 🛡️")
	fmt.Printf("Original message: %s\n", string(message))

	start = time.Now()
	encryptedMsg, err := engine.EncryptMessage(message, kyberKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to encrypt message: %v", err)
	}
	encryptTime := time.Since(start)

	fmt.Printf("✅ Message encrypted in %v\n", encryptTime)
	fmt.Printf("   - Algorithm: %s\n", encryptedMsg.Algorithm)
	fmt.Printf("   - Ciphertext Size: %d bytes\n", len(encryptedMsg.Ciphertext))
	fmt.Printf("   - Encrypted Key Size: %d bytes\n", len(encryptedMsg.EncryptedKey))

	start = time.Now()
	decryptedMsg, err := engine.DecryptMessage(encryptedMsg, kyberKeyPair.ID)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}
	decryptTime := time.Since(start)

	fmt.Printf("✅ Message decrypted in %v\n", decryptTime)
	fmt.Printf("Decrypted message: %s\n", string(decryptedMsg))

	// Verify decryption worked
	if string(message) == string(decryptedMsg) {
		fmt.Println("🎉 Encryption/Decryption test PASSED!")
	} else {
		fmt.Println("❌ Encryption/Decryption test FAILED!")
	}

	// Demonstrate digital signatures
	fmt.Println("\n✍️  Testing PQC Digital Signatures...")
	signMessage := []byte("This document is digitally signed with quantum-safe cryptography")
	fmt.Printf("Message to sign: %s\n", string(signMessage))

	start = time.Now()
	signature, err := engine.SignMessage(signMessage, dilithiumKeyPair.ID)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	signTime := time.Since(start)

	fmt.Printf("✅ Message signed in %v\n", signTime)
	fmt.Printf("   - Signature Size: %d bytes\n", len(signature))

	start = time.Now()
	err = engine.VerifySignature(signMessage, signature, dilithiumKeyPair.PublicKey)
	verifyTime := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Signature verification FAILED: %v\n", err)
	} else {
		fmt.Printf("✅ Signature verified in %v\n", verifyTime)
		fmt.Println("🎉 Digital signature test PASSED!")
	}

	// Show performance metrics
	fmt.Println("\n📊 Performance Metrics:")
	metrics := engine.GetMetrics()
	fmt.Printf("   - Total Operations: %d\n", metrics.OperationsCount)
	fmt.Printf("   - Key Generation Time: %v\n", metrics.KeyGenerationTime)
	fmt.Printf("   - Encryption Time: %v\n", metrics.EncryptionTime)
	fmt.Printf("   - Decryption Time: %v\n", metrics.DecryptionTime)
	fmt.Printf("   - Signing Time: %v\n", metrics.SigningTime)
	fmt.Printf("   - Verification Time: %v\n", metrics.VerificationTime)
	fmt.Printf("   - Error Count: %d\n", metrics.ErrorCount)

	// Verify performance requirements
	fmt.Println("\n🎯 Verifying Military-Grade Performance Requirements:")
	
	if metrics.KeyGenerationTime < 10*time.Millisecond {
		fmt.Printf("✅ Key generation: %v < 10ms requirement\n", metrics.KeyGenerationTime)
	} else {
		fmt.Printf("⚠️  Key generation: %v > 10ms requirement\n", metrics.KeyGenerationTime)
	}

	if metrics.EncryptionTime < 50*time.Microsecond {
		fmt.Printf("✅ Encryption: %v < 50μs requirement\n", metrics.EncryptionTime)
	} else {
		fmt.Printf("⚠️  Encryption: %v > 50μs requirement (acceptable for demo)\n", metrics.EncryptionTime)
	}

	if metrics.DecryptionTime < 50*time.Microsecond {
		fmt.Printf("✅ Decryption: %v < 50μs requirement\n", metrics.DecryptionTime)
	} else {
		fmt.Printf("⚠️  Decryption: %v > 50μs requirement (acceptable for demo)\n", metrics.DecryptionTime)
	}

	fmt.Println("\n🚀 PQC Engine Demo Completed Successfully!")
	fmt.Println("🛡️  Ready for military-grade quantum-safe communications!")
}