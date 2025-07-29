package hybrid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// HybridCryptoService provides post-quantum cryptography hybrid encryption
type HybridCryptoService struct {
	config        *Config
	classicalKeys map[string]*ClassicalKeyPair
	quantumKeys   map[string]*QuantumKeyPair
	hybridKeys    map[string]*HybridKeyPair
	mutex         sync.RWMutex
	logger        logx.Logger
}

// Config for hybrid crypto service
type Config struct {
	EnableClassicalCrypto bool   `json:"enable_classical_crypto"`
	EnableQuantumCrypto   bool   `json:"enable_quantum_crypto"`
	DefaultKeySize        int    `json:"default_key_size"`
	KeyRotationInterval   int    `json:"key_rotation_interval"` // hours
	QuantumAlgorithm      string `json:"quantum_algorithm"`     // kyber, dilithium, etc.
	ClassicalAlgorithm    string `json:"classical_algorithm"`   // rsa, ecdsa, etc.
	HybridMode            string `json:"hybrid_mode"`           // parallel, sequential, adaptive
}

// ClassicalKeyPair represents a classical cryptographic key pair
type ClassicalKeyPair struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeySize    int       `json:"key_size"`
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IsActive   bool      `json:"is_active"`
}

// QuantumKeyPair represents a post-quantum cryptographic key pair
type QuantumKeyPair struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeySize    int       `json:"key_size"`
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IsActive   bool      `json:"is_active"`
}

// HybridKeyPair represents a hybrid key pair combining classical and quantum keys
type HybridKeyPair struct {
	ID           string            `json:"id"`
	ClassicalKey *ClassicalKeyPair `json:"classical_key"`
	QuantumKey   *QuantumKeyPair   `json:"quantum_key"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	IsActive     bool              `json:"is_active"`
}

// EncryptionRequest represents an encryption request
type EncryptionRequest struct {
	Data      []byte                 `json:"data"`
	KeyID     string                 `json:"key_id"`
	Algorithm EncryptionAlgorithm    `json:"algorithm"`
	Mode      EncryptionMode         `json:"mode"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// EncryptionResult represents encryption results
type EncryptionResult struct {
	EncryptedData   []byte                 `json:"encrypted_data"`
	KeyID           string                 `json:"key_id"`
	Algorithm       EncryptionAlgorithm    `json:"algorithm"`
	Mode            EncryptionMode         `json:"mode"`
	IV              []byte                 `json:"iv,omitempty"`
	AuthTag         []byte                 `json:"auth_tag,omitempty"`
	ClassicalResult *ClassicalResult       `json:"classical_result,omitempty"`
	QuantumResult   *QuantumResult         `json:"quantum_result,omitempty"`
	EncryptedAt     time.Time              `json:"encrypted_at"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// DecryptionRequest represents a decryption request
type DecryptionRequest struct {
	EncryptedData []byte                 `json:"encrypted_data"`
	KeyID         string                 `json:"key_id"`
	Algorithm     EncryptionAlgorithm    `json:"algorithm"`
	Mode          EncryptionMode         `json:"mode"`
	IV            []byte                 `json:"iv,omitempty"`
	AuthTag       []byte                 `json:"auth_tag,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// DecryptionResult represents decryption results
type DecryptionResult struct {
	DecryptedData []byte                 `json:"decrypted_data"`
	KeyID         string                 `json:"key_id"`
	Algorithm     EncryptionAlgorithm    `json:"algorithm"`
	Mode          EncryptionMode         `json:"mode"`
	Verified      bool                   `json:"verified"`
	DecryptedAt   time.Time              `json:"decrypted_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ClassicalResult represents classical encryption results
type ClassicalResult struct {
	Algorithm     string    `json:"algorithm"`
	EncryptedData []byte    `json:"encrypted_data"`
	Signature     []byte    `json:"signature,omitempty"`
	ProcessedAt   time.Time `json:"processed_at"`
}

// QuantumResult represents quantum encryption results
type QuantumResult struct {
	Algorithm     string    `json:"algorithm"`
	EncryptedData []byte    `json:"encrypted_data"`
	Signature     []byte    `json:"signature,omitempty"`
	ProcessedAt   time.Time `json:"processed_at"`
}

// SigningRequest represents a signing request
type SigningRequest struct {
	Data      []byte                 `json:"data"`
	KeyID     string                 `json:"key_id"`
	Algorithm SigningAlgorithm       `json:"algorithm"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// SigningResult represents signing results
type SigningResult struct {
	Signature    []byte                 `json:"signature"`
	KeyID        string                 `json:"key_id"`
	Algorithm    SigningAlgorithm       `json:"algorithm"`
	ClassicalSig []byte                 `json:"classical_signature,omitempty"`
	QuantumSig   []byte                 `json:"quantum_signature,omitempty"`
	SignedAt     time.Time              `json:"signed_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// VerificationRequest represents a verification request
type VerificationRequest struct {
	Data      []byte                 `json:"data"`
	Signature []byte                 `json:"signature"`
	KeyID     string                 `json:"key_id"`
	Algorithm SigningAlgorithm       `json:"algorithm"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// VerificationResult represents verification results
type VerificationResult struct {
	Valid      bool                   `json:"valid"`
	KeyID      string                 `json:"key_id"`
	Algorithm  SigningAlgorithm       `json:"algorithm"`
	VerifiedAt time.Time              `json:"verified_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Enums
type EncryptionAlgorithm string

const (
	EncryptionAlgorithmClassical EncryptionAlgorithm = "classical"
	EncryptionAlgorithmQuantum   EncryptionAlgorithm = "quantum"
	EncryptionAlgorithmHybrid    EncryptionAlgorithm = "hybrid"
)

type EncryptionMode string

const (
	EncryptionModeParallel   EncryptionMode = "parallel"
	EncryptionModeSequential EncryptionMode = "sequential"
	EncryptionModeAdaptive   EncryptionMode = "adaptive"
)

type SigningAlgorithm string

const (
	SigningAlgorithmClassical SigningAlgorithm = "classical"
	SigningAlgorithmQuantum   SigningAlgorithm = "quantum"
	SigningAlgorithmHybrid    SigningAlgorithm = "hybrid"
)

// NewHybridCryptoService creates a new hybrid crypto service
func NewHybridCryptoService(config *Config) *HybridCryptoService {
	if config == nil {
		config = DefaultConfig()
	}

	service := &HybridCryptoService{
		config:        config,
		classicalKeys: make(map[string]*ClassicalKeyPair),
		quantumKeys:   make(map[string]*QuantumKeyPair),
		hybridKeys:    make(map[string]*HybridKeyPair),
		logger:        logx.WithContext(context.Background()),
	}

	// Generate default key pairs
	service.initializeDefaultKeys()

	return service
}

// DefaultConfig returns default hybrid crypto configuration
func DefaultConfig() *Config {
	return &Config{
		EnableClassicalCrypto: true,
		EnableQuantumCrypto:   true,
		DefaultKeySize:        2048,
		KeyRotationInterval:   24 * 7, // 1 week
		QuantumAlgorithm:      "kyber",
		ClassicalAlgorithm:    "rsa",
		HybridMode:            "parallel",
	}
}

// GenerateHybridKeyPair generates a new hybrid key pair
func (hcs *HybridCryptoService) GenerateHybridKeyPair(ctx context.Context, keyID string) (*HybridKeyPair, error) {
	// Generate classical key pair
	classicalKey, err := hcs.generateClassicalKeyPair(keyID + "_classical")
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate quantum key pair
	quantumKey, err := hcs.generateQuantumKeyPair(keyID + "_quantum")
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum key: %w", err)
	}

	// Create hybrid key pair
	hybridKey := &HybridKeyPair{
		ID:           keyID,
		ClassicalKey: classicalKey,
		QuantumKey:   quantumKey,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(hcs.config.KeyRotationInterval) * time.Hour),
		IsActive:     true,
	}

	// Store keys
	hcs.mutex.Lock()
	hcs.classicalKeys[classicalKey.ID] = classicalKey
	hcs.quantumKeys[quantumKey.ID] = quantumKey
	hcs.hybridKeys[hybridKey.ID] = hybridKey
	hcs.mutex.Unlock()

	hcs.logger.Infof("Generated hybrid key pair: %s", keyID)
	return hybridKey, nil
}

// Encrypt encrypts data using hybrid cryptography
func (hcs *HybridCryptoService) Encrypt(ctx context.Context, request *EncryptionRequest) (*EncryptionResult, error) {
	hybridKey, err := hcs.getHybridKey(request.KeyID)
	if err != nil {
		return nil, err
	}

	result := &EncryptionResult{
		KeyID:       request.KeyID,
		Algorithm:   request.Algorithm,
		Mode:        request.Mode,
		EncryptedAt: time.Now(),
		Metadata:    request.Metadata,
	}

	switch request.Mode {
	case EncryptionModeParallel:
		err = hcs.encryptParallel(request.Data, hybridKey, result)
	case EncryptionModeSequential:
		err = hcs.encryptSequential(request.Data, hybridKey, result)
	case EncryptionModeAdaptive:
		err = hcs.encryptAdaptive(request.Data, hybridKey, result)
	default:
		return nil, fmt.Errorf("unsupported encryption mode: %s", request.Mode)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Decrypt decrypts data using hybrid cryptography
func (hcs *HybridCryptoService) Decrypt(ctx context.Context, request *DecryptionRequest) (*DecryptionResult, error) {
	hybridKey, err := hcs.getHybridKey(request.KeyID)
	if err != nil {
		return nil, err
	}

	result := &DecryptionResult{
		KeyID:       request.KeyID,
		Algorithm:   request.Algorithm,
		Mode:        request.Mode,
		DecryptedAt: time.Now(),
		Metadata:    request.Metadata,
	}

	switch request.Mode {
	case EncryptionModeParallel:
		err = hcs.decryptParallel(request.EncryptedData, hybridKey, result)
	case EncryptionModeSequential:
		err = hcs.decryptSequential(request.EncryptedData, hybridKey, result)
	case EncryptionModeAdaptive:
		err = hcs.decryptAdaptive(request.EncryptedData, hybridKey, result)
	default:
		return nil, fmt.Errorf("unsupported decryption mode: %s", request.Mode)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Sign signs data using hybrid cryptography
func (hcs *HybridCryptoService) Sign(ctx context.Context, request *SigningRequest) (*SigningResult, error) {
	hybridKey, err := hcs.getHybridKey(request.KeyID)
	if err != nil {
		return nil, err
	}

	result := &SigningResult{
		KeyID:     request.KeyID,
		Algorithm: request.Algorithm,
		SignedAt:  time.Now(),
		Metadata:  request.Metadata,
	}

	// Sign with classical algorithm
	if hcs.config.EnableClassicalCrypto {
		classicalSig, err := hcs.signClassical(request.Data, hybridKey.ClassicalKey)
		if err != nil {
			return nil, fmt.Errorf("classical signing failed: %w", err)
		}
		result.ClassicalSig = classicalSig
	}

	// Sign with quantum algorithm
	if hcs.config.EnableQuantumCrypto {
		quantumSig, err := hcs.signQuantum(request.Data, hybridKey.QuantumKey)
		if err != nil {
			return nil, fmt.Errorf("quantum signing failed: %w", err)
		}
		result.QuantumSig = quantumSig
	}

	// Combine signatures
	result.Signature = hcs.combineSignatures(result.ClassicalSig, result.QuantumSig)

	return result, nil
}

// Verify verifies a signature using hybrid cryptography
func (hcs *HybridCryptoService) Verify(ctx context.Context, request *VerificationRequest) (*VerificationResult, error) {
	hybridKey, err := hcs.getHybridKey(request.KeyID)
	if err != nil {
		return nil, err
	}

	result := &VerificationResult{
		KeyID:      request.KeyID,
		Algorithm:  request.Algorithm,
		VerifiedAt: time.Now(),
		Metadata:   request.Metadata,
	}

	// Extract individual signatures
	classicalSig, quantumSig := hcs.extractSignatures(request.Signature)

	// Verify classical signature
	classicalValid := true
	if hcs.config.EnableClassicalCrypto && len(classicalSig) > 0 {
		classicalValid = hcs.verifyClassical(request.Data, classicalSig, hybridKey.ClassicalKey)
	}

	// Verify quantum signature
	quantumValid := true
	if hcs.config.EnableQuantumCrypto && len(quantumSig) > 0 {
		quantumValid = hcs.verifyQuantum(request.Data, quantumSig, hybridKey.QuantumKey)
	}

	// Both signatures must be valid for hybrid verification to pass
	result.Valid = classicalValid && quantumValid

	return result, nil
}

// Helper methods

func (hcs *HybridCryptoService) generateClassicalKeyPair(keyID string) (*ClassicalKeyPair, error) {
	// Generate RSA key pair (mock implementation)
	_, err := rsa.GenerateKey(rand.Reader, hcs.config.DefaultKeySize)
	if err != nil {
		return nil, err
	}

	keyPair := &ClassicalKeyPair{
		ID:         keyID,
		Algorithm:  hcs.config.ClassicalAlgorithm,
		KeySize:    hcs.config.DefaultKeySize,
		PublicKey:  []byte("mock_classical_public_key"),
		PrivateKey: []byte("mock_classical_private_key"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Duration(hcs.config.KeyRotationInterval) * time.Hour),
		IsActive:   true,
	}

	return keyPair, nil
}

func (hcs *HybridCryptoService) generateQuantumKeyPair(keyID string) (*QuantumKeyPair, error) {
	// Generate quantum-resistant key pair (mock implementation)
	keyPair := &QuantumKeyPair{
		ID:         keyID,
		Algorithm:  hcs.config.QuantumAlgorithm,
		KeySize:    hcs.config.DefaultKeySize,
		PublicKey:  []byte("mock_quantum_public_key"),
		PrivateKey: []byte("mock_quantum_private_key"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Duration(hcs.config.KeyRotationInterval) * time.Hour),
		IsActive:   true,
	}

	return keyPair, nil
}

func (hcs *HybridCryptoService) getHybridKey(keyID string) (*HybridKeyPair, error) {
	hcs.mutex.RLock()
	defer hcs.mutex.RUnlock()

	key, exists := hcs.hybridKeys[keyID]
	if !exists {
		return nil, fmt.Errorf("hybrid key %s not found", keyID)
	}

	if !key.IsActive {
		return nil, fmt.Errorf("hybrid key %s is not active", keyID)
	}

	if time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("hybrid key %s has expired", keyID)
	}

	return key, nil
}

func (hcs *HybridCryptoService) encryptParallel(data []byte, key *HybridKeyPair, result *EncryptionResult) error {
	// Encrypt with both algorithms in parallel
	classicalData := hcs.encryptClassical(data, key.ClassicalKey)
	quantumData := hcs.encryptQuantum(data, key.QuantumKey)

	// Combine encrypted data
	result.EncryptedData = hcs.combineEncryptedData(classicalData, quantumData)
	result.ClassicalResult = &ClassicalResult{
		Algorithm:     key.ClassicalKey.Algorithm,
		EncryptedData: classicalData,
		ProcessedAt:   time.Now(),
	}
	result.QuantumResult = &QuantumResult{
		Algorithm:     key.QuantumKey.Algorithm,
		EncryptedData: quantumData,
		ProcessedAt:   time.Now(),
	}

	return nil
}

func (hcs *HybridCryptoService) encryptSequential(data []byte, key *HybridKeyPair, result *EncryptionResult) error {
	// Encrypt with classical first, then quantum
	classicalData := hcs.encryptClassical(data, key.ClassicalKey)
	quantumData := hcs.encryptQuantum(classicalData, key.QuantumKey)

	result.EncryptedData = quantumData
	return nil
}

func (hcs *HybridCryptoService) encryptAdaptive(data []byte, key *HybridKeyPair, result *EncryptionResult) error {
	// Choose encryption method based on data characteristics
	if len(data) > 1024 {
		return hcs.encryptParallel(data, key, result)
	} else {
		return hcs.encryptSequential(data, key, result)
	}
}

func (hcs *HybridCryptoService) decryptParallel(encryptedData []byte, key *HybridKeyPair, result *DecryptionResult) error {
	// Extract and decrypt both parts
	classicalData, quantumData := hcs.extractEncryptedData(encryptedData)

	classicalDecrypted := hcs.decryptClassical(classicalData, key.ClassicalKey)
	quantumDecrypted := hcs.decryptQuantum(quantumData, key.QuantumKey)

	// Verify both decryptions match
	if string(classicalDecrypted) == string(quantumDecrypted) {
		result.DecryptedData = classicalDecrypted
		result.Verified = true
	} else {
		result.Verified = false
	}

	return nil
}

func (hcs *HybridCryptoService) decryptSequential(encryptedData []byte, key *HybridKeyPair, result *DecryptionResult) error {
	// Decrypt quantum first, then classical
	quantumDecrypted := hcs.decryptQuantum(encryptedData, key.QuantumKey)
	classicalDecrypted := hcs.decryptClassical(quantumDecrypted, key.ClassicalKey)

	result.DecryptedData = classicalDecrypted
	result.Verified = true
	return nil
}

func (hcs *HybridCryptoService) decryptAdaptive(encryptedData []byte, key *HybridKeyPair, result *DecryptionResult) error {
	// Try parallel first, fall back to sequential
	err := hcs.decryptParallel(encryptedData, key, result)
	if err != nil || !result.Verified {
		return hcs.decryptSequential(encryptedData, key, result)
	}
	return nil
}

// Mock encryption/decryption methods
func (hcs *HybridCryptoService) encryptClassical(data []byte, key *ClassicalKeyPair) []byte {
	// Mock classical encryption
	hash := sha256.Sum256(append(data, key.PublicKey...))
	return hash[:]
}

func (hcs *HybridCryptoService) encryptQuantum(data []byte, key *QuantumKeyPair) []byte {
	// Mock quantum encryption
	hash := sha256.Sum256(append(data, key.PublicKey...))
	return hash[:]
}

func (hcs *HybridCryptoService) decryptClassical(encryptedData []byte, key *ClassicalKeyPair) []byte {
	// Mock classical decryption
	return []byte("decrypted_classical_data")
}

func (hcs *HybridCryptoService) decryptQuantum(encryptedData []byte, key *QuantumKeyPair) []byte {
	// Mock quantum decryption
	return []byte("decrypted_quantum_data")
}

func (hcs *HybridCryptoService) signClassical(data []byte, key *ClassicalKeyPair) ([]byte, error) {
	// Mock classical signing
	hash := sha256.Sum256(append(data, key.PrivateKey...))
	return hash[:], nil
}

func (hcs *HybridCryptoService) signQuantum(data []byte, key *QuantumKeyPair) ([]byte, error) {
	// Mock quantum signing
	hash := sha256.Sum256(append(data, key.PrivateKey...))
	return hash[:], nil
}

func (hcs *HybridCryptoService) verifyClassical(data, signature []byte, key *ClassicalKeyPair) bool {
	// Mock classical verification
	expectedSig, _ := hcs.signClassical(data, key)
	return string(signature) == string(expectedSig)
}

func (hcs *HybridCryptoService) verifyQuantum(data, signature []byte, key *QuantumKeyPair) bool {
	// Mock quantum verification
	expectedSig, _ := hcs.signQuantum(data, key)
	return string(signature) == string(expectedSig)
}

func (hcs *HybridCryptoService) combineEncryptedData(classical, quantum []byte) []byte {
	// Simple combination - in production, this would be more sophisticated
	combined := make([]byte, len(classical)+len(quantum)+4)
	copy(combined[0:4], []byte{byte(len(classical) >> 8), byte(len(classical)), 0, 0})
	copy(combined[4:4+len(classical)], classical)
	copy(combined[4+len(classical):], quantum)
	return combined
}

func (hcs *HybridCryptoService) extractEncryptedData(combined []byte) (classical, quantum []byte) {
	if len(combined) < 4 {
		return nil, nil
	}
	classicalLen := int(combined[0])<<8 | int(combined[1])
	if len(combined) < 4+classicalLen {
		return nil, nil
	}
	classical = combined[4 : 4+classicalLen]
	quantum = combined[4+classicalLen:]
	return
}

func (hcs *HybridCryptoService) combineSignatures(classical, quantum []byte) []byte {
	return hcs.combineEncryptedData(classical, quantum)
}

func (hcs *HybridCryptoService) extractSignatures(combined []byte) (classical, quantum []byte) {
	return hcs.extractEncryptedData(combined)
}

func (hcs *HybridCryptoService) initializeDefaultKeys() {
	// Generate default hybrid key pair
	_, err := hcs.GenerateHybridKeyPair(context.Background(), "default")
	if err != nil {
		hcs.logger.Errorf("Failed to generate default hybrid key: %v", err)
	} else {
		hcs.logger.Infof("Generated default hybrid key pair")
	}
}

// GetHybridKey gets a hybrid key by ID
func (hcs *HybridCryptoService) GetHybridKey(keyID string) (*HybridKeyPair, error) {
	return hcs.getHybridKey(keyID)
}

// ListHybridKeys lists all hybrid keys
func (hcs *HybridCryptoService) ListHybridKeys() []*HybridKeyPair {
	hcs.mutex.RLock()
	defer hcs.mutex.RUnlock()

	keys := make([]*HybridKeyPair, 0, len(hcs.hybridKeys))
	for _, key := range hcs.hybridKeys {
		keys = append(keys, key)
	}

	return keys
}

// RotateKeys rotates expired keys
func (hcs *HybridCryptoService) RotateKeys(ctx context.Context) error {
	hcs.mutex.Lock()
	defer hcs.mutex.Unlock()

	now := time.Now()
	rotatedCount := 0

	for keyID, key := range hcs.hybridKeys {
		if now.After(key.ExpiresAt) {
			// Generate new key pair
			newKey, err := hcs.GenerateHybridKeyPair(ctx, keyID+"_rotated")
			if err != nil {
				hcs.logger.Errorf("Failed to rotate key %s: %v", keyID, err)
				continue
			}

			// Deactivate old key
			key.IsActive = false

			// Replace with new key
			hcs.hybridKeys[keyID] = newKey
			rotatedCount++
		}
	}

	hcs.logger.Infof("Rotated %d hybrid keys", rotatedCount)
	return nil
}
