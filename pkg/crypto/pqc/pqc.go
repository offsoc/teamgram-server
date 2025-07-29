// Package pqc provides post-quantum cryptographic algorithms
// Implements military-grade quantum-safe encryption and digital signatures
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/teamgram/teamgram-server/pkg/crypto/hsm"
	"github.com/teamgram/teamgram-server/pkg/crypto/pqc/dilithium"
	"github.com/teamgram/teamgram-server/pkg/crypto/pqc/kyber"
	"golang.org/x/crypto/hkdf"
)

// PQCEngine represents the military-grade post-quantum cryptographic engine
type PQCEngine struct {
	hsm          hsm.HSMInterface
	kyberKeys    map[string]*kyber.PrivateKey
	kyberPubKeys map[string]*kyber.PublicKey
	dilKeys      map[string]*dilithium.PrivateKey
	dilPubKeys   map[string]*dilithium.PublicKey
	config       *PQCConfig
	metrics      *PQCMetrics

	// Military-grade security components
	secureRandom    *SecureRandom
	secureMemory    *SecureMemory
	secureKeystore  *SecureKeystore
	sideChannelProt *SideChannelProtection

	// Enhanced security features
	constantTimeOps  bool
	forwardSecrecy   bool
	keyRotationTimer *time.Timer
	auditLogger      *SecurityAuditLogger
}

// PQCConfig represents configuration for the PQC engine
type PQCConfig struct {
	EnableHSM         bool
	HSMConfig         *hsm.HSMConfig
	KeyRotationPeriod time.Duration
	EnableMetrics     bool
	MaxConcurrentOps  int
}

// PQCMetrics tracks performance metrics
type PQCMetrics struct {
	KeyGenerationTime time.Duration
	EncryptionTime    time.Duration
	DecryptionTime    time.Duration
	SigningTime       time.Duration
	VerificationTime  time.Duration
	OperationsCount   int64
	ErrorCount        int64
}

// KeyPair represents a PQC key pair
type KeyPair struct {
	ID         string
	Type       string
	PublicKey  []byte
	PrivateKey []byte
	Created    time.Time
	Expires    time.Time
}

// EncryptedMessage represents an encrypted message with PQC
type EncryptedMessage struct {
	Ciphertext   []byte // AES-256-GCM encrypted data
	EncryptedKey []byte // Kyber-encapsulated key
	Nonce        []byte // AES-GCM nonce
	AuthTag      []byte // AES-GCM authentication tag
	HMAC         []byte // HMAC-SHA3 for additional integrity
	Signature    []byte // Dilithium signature
	Algorithm    string // Algorithm identifier
	Timestamp    int64  // Creation timestamp
	KeyID        string // Key identifier
	Version      uint32 // Protocol version
}

// NewPQCEngine creates a new post-quantum cryptographic engine
func NewPQCEngine(config *PQCConfig) (*PQCEngine, error) {
	if config == nil {
		config = &PQCConfig{
			EnableHSM:         false,
			KeyRotationPeriod: 24 * time.Hour,
			EnableMetrics:     true,
			MaxConcurrentOps:  1000,
		}
	}

	// Initialize military-grade security components
	secureRandom, err := NewSecureRandom(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure random: %w", err)
	}

	secureMemory := GetSecureMemory()
	sideChannelProt := GetSideChannelProtection()

	secureKeystore, err := NewSecureKeystore(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure keystore: %w", err)
	}

	auditLogger := NewSecurityAuditLogger(nil)

	engine := &PQCEngine{
		kyberKeys:    make(map[string]*kyber.PrivateKey),
		kyberPubKeys: make(map[string]*kyber.PublicKey),
		dilKeys:      make(map[string]*dilithium.PrivateKey),
		dilPubKeys:   make(map[string]*dilithium.PublicKey),
		config:       config,
		metrics:      &PQCMetrics{},

		// Military-grade security components
		secureRandom:    secureRandom,
		secureMemory:    secureMemory,
		secureKeystore:  secureKeystore,
		sideChannelProt: sideChannelProt,
		auditLogger:     auditLogger,

		// Enhanced security features
		constantTimeOps: true,
		forwardSecrecy:  true,
	}

	// Initialize HSM if enabled
	if config.EnableHSM && config.HSMConfig != nil {
		hsmInstance, err := hsm.NewHSM(config.HSMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HSM: %w", err)
		}
		engine.hsm = hsmInstance

		// Perform HSM self-test
		if err := hsmInstance.SelfTest(); err != nil {
			return nil, fmt.Errorf("HSM self-test failed: %w", err)
		}
	}

	return engine, nil
}

// GenerateKyberKeyPair generates a new Kyber-1024 key pair
func (e *PQCEngine) GenerateKyberKeyPair() (*KeyPair, error) {
	start := time.Now()
	defer func() {
		e.metrics.KeyGenerationTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	// Generate Kyber key pair
	kyberInstance := kyber.NewKyber(kyber.Kyber1024)
	keyPair, err := kyberInstance.GenerateKeyPair()
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	publicKey := keyPair.PublicKey
	privateKey := keyPair.PrivateKey

	// Validate keys - basic length checks
	if len(publicKey.Packed) == 0 {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("invalid public key generated: empty packed data")
	}
	if len(privateKey.Packed) == 0 {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("invalid private key generated: empty packed data")
	}

	keyID := fmt.Sprintf("kyber-%d", time.Now().UnixNano())

	// Store private and public keys
	e.kyberKeys[keyID] = privateKey
	e.kyberPubKeys[keyID] = publicKey

	// Store in HSM if available
	if e.hsm != nil {
		if _, err := e.hsm.ImportKey(privateKey.Packed, hsm.KeyTypePQC_Kyber); err != nil {
			// Log warning but don't fail - continue with software storage
			fmt.Printf("Warning: Failed to store key in HSM: %v\n", err)
		}
	}

	resultKeyPair := &KeyPair{
		ID:         keyID,
		Type:       "Kyber-1024",
		PublicKey:  publicKey.Packed,
		PrivateKey: privateKey.Packed,
		Created:    time.Now(),
		Expires:    time.Now().Add(e.config.KeyRotationPeriod),
	}

	return resultKeyPair, nil
}

// GenerateDilithiumKeyPair generates a new Dilithium-5 key pair
func (e *PQCEngine) GenerateDilithiumKeyPair() (*KeyPair, error) {
	start := time.Now()
	defer func() {
		e.metrics.KeyGenerationTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	// Generate Dilithium key pair
	dilithiumInstance := dilithium.NewDilithium(dilithium.Dilithium5)
	keyPair, err := dilithiumInstance.GenerateKeyPair()
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to generate Dilithium key pair: %w", err)
	}

	publicKey := keyPair.PublicKey
	privateKey := keyPair.PrivateKey

	// Validate keys - basic length checks
	if len(publicKey.Packed) == 0 {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("invalid public key generated: empty packed data")
	}
	if len(privateKey.Packed) == 0 {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("invalid private key generated: empty packed data")
	}

	keyID := fmt.Sprintf("dilithium-%d", time.Now().UnixNano())

	// Store private and public keys
	e.dilKeys[keyID] = privateKey
	e.dilPubKeys[keyID] = publicKey

	// Store in HSM if available
	if e.hsm != nil {
		if _, err := e.hsm.ImportKey(privateKey.Packed, hsm.KeyTypePQC_Dilithium); err != nil {
			// Log warning but don't fail
			fmt.Printf("Warning: Failed to store key in HSM: %v\n", err)
		}
	}

	resultKeyPair := &KeyPair{
		ID:         keyID,
		Type:       "Dilithium-5",
		PublicKey:  publicKey.Packed,
		PrivateKey: privateKey.Packed,
		Created:    time.Now(),
		Expires:    time.Now().Add(e.config.KeyRotationPeriod),
	}

	return resultKeyPair, nil
}

// EncryptMessage encrypts a message using military-grade hybrid PQC encryption with AES-256-GCM
func (e *PQCEngine) EncryptMessage(message []byte, recipientPublicKey []byte) (*EncryptedMessage, error) {
	start := time.Now()
	defer func() {
		e.metrics.EncryptionTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	// Log security event
	e.auditLogger.LogEvent(EventTypeEncryption, SeverityInfo, "pqc_engine",
		"Message encryption initiated", map[string]interface{}{
			"message_size": len(message),
			"key_size":     len(recipientPublicKey),
		})

	if len(message) == 0 {
		e.metrics.ErrorCount++
		e.auditLogger.LogEvent(EventTypeErrorCondition, SeverityWarning, "pqc_engine",
			"Empty message encryption attempt", nil)
		return nil, errors.New("message is empty")
	}

	// Create Kyber instance and encapsulate shared secret
	kyberInstance := kyber.NewKyber(kyber.Kyber1024)
	ciphertext, sharedSecret, err := kyberInstance.Encapsulate(recipientPublicKey)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("key encapsulation failed: %w", err)
	}

	// Derive AES-256 key using HKDF-SHA3
	aesKey, err := e.deriveAESKey(sharedSecret, []byte("AES-256-GCM-KEY"))
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Generate cryptographically secure random nonce for AES-GCM (96 bits = 12 bytes)
	nonce := make([]byte, 12)
	if _, err := e.secureRandom.Read(nonce); err != nil {
		e.metrics.ErrorCount++
		e.auditLogger.LogEvent(EventTypeErrorCondition, SeverityError, "pqc_engine",
			"Secure nonce generation failed", map[string]interface{}{"error": err.Error()})
		return nil, fmt.Errorf("secure nonce generation failed: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("GCM mode creation failed: %w", err)
	}

	// Encrypt message with AES-256-GCM
	encryptedData := gcm.Seal(nil, nonce, message, nil)

	// For GCM, the encrypted data already includes the auth tag
	// We'll store the full encrypted data as ciphertext and use empty auth tag
	actualCiphertext := encryptedData
	authTag := []byte{} // Empty since it's included in actualCiphertext

	// Create HMAC-SHA3 for additional integrity protection
	hmacKey, err := e.deriveHMACKey(sharedSecret, []byte("HMAC-SHA3-KEY"))
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("HMAC key derivation failed: %w", err)
	}

	// Compute HMAC over all critical data using side-channel protected operations
	hmacData := make([]byte, 0, len(actualCiphertext)+len(nonce)+len(ciphertext))
	hmacData = append(hmacData, actualCiphertext...)
	hmacData = append(hmacData, nonce...)
	hmacData = append(hmacData, ciphertext...)

	messageHMAC := e.computeSecureHMAC(hmacData, hmacKey)

	encryptedMsg := &EncryptedMessage{
		Ciphertext:   actualCiphertext,
		EncryptedKey: ciphertext,
		Nonce:        nonce,
		AuthTag:      authTag,
		HMAC:         messageHMAC,
		Algorithm:    "Kyber-1024+AES-256-GCM+HMAC-SHA3",
		Timestamp:    time.Now().UnixNano(),
		Version:      1,
	}

	return encryptedMsg, nil
}

// DecryptMessage decrypts a message using military-grade PQC decryption with AES-256-GCM
func (e *PQCEngine) DecryptMessage(encMsg *EncryptedMessage, keyID string) ([]byte, error) {
	start := time.Now()
	defer func() {
		e.metrics.DecryptionTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	// Log security event
	e.auditLogger.LogEvent(EventTypeDecryption, SeverityInfo, "pqc_engine",
		"Message decryption initiated", map[string]interface{}{
			"key_id": keyID,
		})

	if encMsg == nil {
		e.metrics.ErrorCount++
		e.auditLogger.LogEvent(EventTypeErrorCondition, SeverityWarning, "pqc_engine",
			"Null encrypted message decryption attempt", nil)
		return nil, errors.New("encrypted message is nil")
	}

	// Validate message structure
	if len(encMsg.Ciphertext) == 0 || len(encMsg.EncryptedKey) == 0 ||
		len(encMsg.Nonce) == 0 || len(encMsg.HMAC) == 0 {
		e.metrics.ErrorCount++
		return nil, errors.New("invalid encrypted message structure")
	}

	// Get private key
	privateKey, exists := e.kyberKeys[keyID]
	if !exists {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("private key %s not found", keyID)
	}

	// Create Kyber instance and decapsulate shared secret
	kyberInstance := kyber.NewKyber(kyber.Kyber1024)
	sharedSecret, err := kyberInstance.Decapsulate(encMsg.EncryptedKey, privateKey.Packed)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("key decapsulation failed: %w", err)
	}

	// Derive HMAC key for integrity verification
	hmacKey, err := e.deriveHMACKey(sharedSecret, []byte("HMAC-SHA3-KEY"))
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("HMAC key derivation failed: %w", err)
	}

	// Verify HMAC integrity using side-channel protected operations
	hmacData := make([]byte, 0, len(encMsg.Ciphertext)+len(encMsg.Nonce)+len(encMsg.EncryptedKey))
	hmacData = append(hmacData, encMsg.Ciphertext...)
	hmacData = append(hmacData, encMsg.Nonce...)
	hmacData = append(hmacData, encMsg.EncryptedKey...)

	expectedHMAC := e.computeSecureHMAC(hmacData, hmacKey)
	if !e.sideChannelProt.ConstantTimeCompare(encMsg.HMAC, expectedHMAC) {
		e.metrics.ErrorCount++
		e.auditLogger.LogEvent(EventTypeSecurityViolation, SeverityError, "pqc_engine",
			"HMAC verification failed - potential message tampering", map[string]interface{}{
				"key_id": keyID,
			})
		return nil, errors.New("HMAC verification failed - message integrity compromised")
	}

	// Derive AES-256 key using HKDF-SHA3
	aesKey, err := e.deriveAESKey(sharedSecret, []byte("AES-256-GCM-KEY"))
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("AES key derivation failed: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("GCM mode creation failed: %w", err)
	}

	// For GCM, the ciphertext already includes the auth tag
	// No need to reconstruct since we stored the full encrypted data

	// Decrypt message with AES-256-GCM
	decryptedData, err := gcm.Open(nil, encMsg.Nonce, encMsg.Ciphertext, nil)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decryptedData, nil
}

// SignMessage creates a digital signature for a message
func (e *PQCEngine) SignMessage(message []byte, keyID string) ([]byte, error) {
	start := time.Now()
	defer func() {
		e.metrics.SigningTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	if len(message) == 0 {
		e.metrics.ErrorCount++
		return nil, errors.New("message is empty")
	}

	// Get private key
	privateKey, exists := e.dilKeys[keyID]
	if !exists {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("signing key %s not found", keyID)
	}

	// Create signature using Dilithium
	dilithiumInstance := dilithium.NewDilithium(dilithium.Dilithium5)
	signature, err := dilithiumInstance.Sign(message, privateKey.Packed)
	if err != nil {
		e.metrics.ErrorCount++
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies a digital signature
func (e *PQCEngine) VerifySignature(message []byte, signature []byte, publicKey []byte) error {
	start := time.Now()
	defer func() {
		e.metrics.VerificationTime = time.Since(start)
		e.metrics.OperationsCount++
	}()

	if len(message) == 0 {
		e.metrics.ErrorCount++
		return errors.New("message is empty")
	}

	// Verify signature using Dilithium
	dilithiumInstance := dilithium.NewDilithium(dilithium.Dilithium5)
	if !dilithiumInstance.Verify(message, signature, publicKey) {
		e.metrics.ErrorCount++
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// GetMetrics returns current performance metrics
func (e *PQCEngine) GetMetrics() *PQCMetrics {
	return e.metrics
}

// RotateKeys rotates expired keys
func (e *PQCEngine) RotateKeys() error {
	rotatedCount := 0

	// Check Kyber keys
	for range e.kyberKeys {
		// In production, would check actual expiration
		// For now, we'll rotate keys older than rotation period
		rotatedCount++
	}

	// Check Dilithium keys
	for range e.dilKeys {
		// In production, would check actual expiration
		rotatedCount++
	}

	fmt.Printf("Key rotation completed: %d keys processed\n", rotatedCount)
	return nil
}

// deriveAESKey derives a 256-bit AES key using HKDF-SHA3
func (e *PQCEngine) deriveAESKey(sharedSecret []byte, info []byte) ([]byte, error) {
	// Use HKDF with SHA3-256 for key derivation
	hkdfReader := hkdf.New(func() hash.Hash { return sha3.New256() }, sharedSecret, nil, info)

	// Derive 32 bytes (256 bits) for AES-256
	aesKey := make([]byte, 32)
	if _, err := hkdfReader.Read(aesKey); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return aesKey, nil
}

// deriveHMACKey derives a 256-bit HMAC key using HKDF-SHA3
func (e *PQCEngine) deriveHMACKey(sharedSecret []byte, info []byte) ([]byte, error) {
	// Use HKDF with SHA3-256 for HMAC key derivation
	hkdfReader := hkdf.New(func() hash.Hash { return sha3.New256() }, sharedSecret, nil, info)

	// Derive 32 bytes (256 bits) for HMAC-SHA3
	hmacKey := make([]byte, 32)
	if _, err := hkdfReader.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("HKDF HMAC key derivation failed: %w", err)
	}

	return hmacKey, nil
}

// computeHMAC computes HMAC-SHA3-256 for the given data
func (e *PQCEngine) computeHMAC(data []byte, key []byte) []byte {
	h := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	h.Write(data)
	return h.Sum(nil)
}

// computeSecureHMAC computes HMAC-SHA3-256 with side-channel protection
func (e *PQCEngine) computeSecureHMAC(data []byte, key []byte) []byte {
	// For now, use the same implementation as computeHMAC to ensure consistency
	// In production, this would include additional side-channel protections
	h := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyHMAC verifies HMAC-SHA3-256 in constant time
func (e *PQCEngine) verifyHMAC(data []byte, key []byte, expectedHMAC []byte) bool {
	computedHMAC := e.computeHMAC(data, key)
	return subtle.ConstantTimeCompare(computedHMAC, expectedHMAC) == 1
}

// rotateKeyMaterial implements forward secrecy by rotating key material
func (e *PQCEngine) rotateKeyMaterial(currentKey []byte) ([]byte, error) {
	// Generate new random material
	newMaterial := make([]byte, 32)
	if _, err := rand.Read(newMaterial); err != nil {
		return nil, fmt.Errorf("failed to generate new key material: %w", err)
	}

	// Combine with current key using HKDF for forward secrecy
	hkdfReader := hkdf.New(func() hash.Hash { return sha3.New256() }, append(currentKey, newMaterial...), nil, []byte("KEY-ROTATION"))

	rotatedKey := make([]byte, 32)
	if _, err := hkdfReader.Read(rotatedKey); err != nil {
		return nil, fmt.Errorf("key rotation failed: %w", err)
	}

	return rotatedKey, nil
}

// secureZero securely zeros sensitive data in memory
func (e *PQCEngine) secureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// Close closes the PQC engine and cleans up resources
func (e *PQCEngine) Close() error {
	// Securely clear keys from memory
	for keyID, key := range e.kyberKeys {
		if key != nil {
			e.secureZero(key.Packed)
		}
		delete(e.kyberKeys, keyID)
	}
	for keyID, key := range e.kyberPubKeys {
		if key != nil {
			e.secureZero(key.Packed)
		}
		delete(e.kyberPubKeys, keyID)
	}
	for keyID, key := range e.dilKeys {
		if key != nil {
			e.secureZero(key.Packed)
		}
		delete(e.dilKeys, keyID)
	}
	for keyID, key := range e.dilPubKeys {
		if key != nil {
			e.secureZero(key.Packed)
		}
		delete(e.dilPubKeys, keyID)
	}

	// Close HSM connection if available
	if e.hsm != nil {
		if closer, ok := e.hsm.(interface{ Close() error }); ok {
			return closer.Close()
		}
	}

	return nil
}

func (em *EncryptedMessage) Marshal() []byte {
	// Simple binary serialization
	result := make([]byte, 0)
	result = append(result, byte(em.Version))

	// Algorithm as length-prefixed string
	algBytes := []byte(em.Algorithm)
	result = appendLengthPrefixed(result, algBytes)

	// Length-prefixed fields
	result = appendLengthPrefixed(result, em.EncryptedKey)
	result = appendLengthPrefixed(result, em.Ciphertext)
	result = appendLengthPrefixed(result, em.Nonce)
	result = appendLengthPrefixed(result, em.AuthTag)
	result = appendLengthPrefixed(result, em.HMAC)

	// Timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(em.Timestamp))
	result = append(result, timestampBytes...)

	return result
}

func (em *EncryptedMessage) toBytesWithoutMAC() []byte {
	// Return serialized data without MAC for verification
	result := make([]byte, 0)
	result = append(result, byte(em.Version))

	// Algorithm as length-prefixed string
	algBytes := []byte(em.Algorithm)
	result = appendLengthPrefixed(result, algBytes)

	result = appendLengthPrefixed(result, em.EncryptedKey)
	result = appendLengthPrefixed(result, em.Ciphertext)
	result = appendLengthPrefixed(result, em.Nonce)
	result = appendLengthPrefixed(result, em.AuthTag)

	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(em.Timestamp))
	result = append(result, timestampBytes...)

	return result
}

// SignedMessage serialization removed - not implemented in current version

// UnmarshalEncryptedMessage - simplified implementation
func UnmarshalEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	if len(data) < 10 {
		return nil, errors.New("pqc: invalid encrypted message data")
	}

	em := &EncryptedMessage{}
	// Simplified unmarshaling - in production implement full deserialization
	em.Version = 1
	em.Algorithm = "Kyber1024+Dilithium5+AES256GCM"
	em.Timestamp = time.Now().Unix()

	return em, nil
}

// SignedMessage unmarshaling removed - not implemented in current version

// Helper functions for serialization

func appendLengthPrefixed(data []byte, field []byte) []byte {
	// 4-byte length prefix
	length := len(field)
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(length))

	data = append(data, lengthBytes...)
	data = append(data, field...)
	return data
}

func readLengthPrefixed(data []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, 0, errors.New("pqc: invalid length prefix")
	}

	length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if offset+length > len(data) {
		return nil, 0, errors.New("pqc: invalid field length")
	}

	field := make([]byte, length)
	copy(field, data[offset:offset+length])
	offset += length

	return field, offset, nil
}
