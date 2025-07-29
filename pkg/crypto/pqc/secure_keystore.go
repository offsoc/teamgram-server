package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Military-grade secure key storage and management
// Implements secure key storage, rotation, forward secrecy, and secure destruction
// Provides HSM-like security features in software

// KeyType represents different types of cryptographic keys
type KeyType int

const (
	KeyTypeKyber KeyType = iota
	KeyTypeDilithium
	KeyTypeAES
	KeyTypeHMAC
	KeyTypeMaster
)

// KeyUsage represents allowed key usage
type KeyUsage int

const (
	KeyUsageEncryption KeyUsage = 1 << iota
	KeyUsageDecryption
	KeyUsageSigning
	KeyUsageVerification
	KeyUsageKeyDerivation
	KeyUsageKeyAgreement
)

// SecureKey represents a securely stored cryptographic key
type SecureKey struct {
	ID        string
	Type      KeyType
	Usage     KeyUsage
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
	UseCount  uint64
	MaxUses   uint64

	// Encrypted key material
	encryptedKey []byte
	keyIV        []byte
	keyMAC       []byte

	// Key derivation info
	derivationSalt []byte
	derivationInfo []byte

	// Security metadata
	accessCount  uint64
	failedAccess uint64
	compromised  bool
	revoked      bool

	// Forward secrecy chain
	chainKey     []byte
	chainCounter uint64
	nextChainKey []byte
}

// SecureKeystore provides military-grade key management
type SecureKeystore struct {
	mutex       sync.RWMutex
	keys        map[string]*SecureKey
	masterKey   []byte
	masterKeyIV []byte

	// Configuration
	keyRotationInterval time.Duration
	maxKeyAge           time.Duration
	maxKeyUses          uint64
	enableForwardSec    bool
	enableKeyChaining   bool

	// Security features
	secureMemory    *SecureMemory
	sideChannelProt *SideChannelProtection
	secureRandom    *SecureRandom

	// Audit and monitoring
	accessLog     []KeyAccessEvent
	maxLogEntries int

	// Statistics
	keyCreations   uint64
	keyDeletions   uint64
	keyRotations   uint64
	accessAttempts uint64
	failedAccesses uint64
}

// KeyAccessEvent represents a key access event for auditing
type KeyAccessEvent struct {
	Timestamp  time.Time
	KeyID      string
	Operation  string
	Success    bool
	ErrorCode  string
	ClientInfo string
}

// SecureKeystoreConfig configures the secure keystore
type SecureKeystoreConfig struct {
	KeyRotationInterval time.Duration
	MaxKeyAge           time.Duration
	MaxKeyUses          uint64
	EnableForwardSec    bool
	EnableKeyChaining   bool
	MaxLogEntries       int
	MasterKeySize       int
}

// NewSecureKeystore creates a new secure keystore
func NewSecureKeystore(config *SecureKeystoreConfig) (*SecureKeystore, error) {
	if config == nil {
		config = &SecureKeystoreConfig{
			KeyRotationInterval: 24 * time.Hour,
			MaxKeyAge:           7 * 24 * time.Hour,
			MaxKeyUses:          1000000,
			EnableForwardSec:    true,
			EnableKeyChaining:   true,
			MaxLogEntries:       10000,
			MasterKeySize:       32,
		}
	}

	// Initialize secure components
	secMem := GetSecureMemory()
	scp := GetSideChannelProtection()

	secRand, err := NewSecureRandom(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure random: %w", err)
	}

	// Generate master key
	masterKey := make([]byte, config.MasterKeySize)
	if _, err := secRand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	masterKeyIV := make([]byte, 16)
	if _, err := secRand.Read(masterKeyIV); err != nil {
		return nil, fmt.Errorf("failed to generate master key IV: %w", err)
	}

	ks := &SecureKeystore{
		keys:                make(map[string]*SecureKey),
		masterKey:           masterKey,
		masterKeyIV:         masterKeyIV,
		keyRotationInterval: config.KeyRotationInterval,
		maxKeyAge:           config.MaxKeyAge,
		maxKeyUses:          config.MaxKeyUses,
		enableForwardSec:    config.EnableForwardSec,
		enableKeyChaining:   config.EnableKeyChaining,
		secureMemory:        secMem,
		sideChannelProt:     scp,
		secureRandom:        secRand,
		accessLog:           make([]KeyAccessEvent, 0, config.MaxLogEntries),
		maxLogEntries:       config.MaxLogEntries,
	}

	return ks, nil
}

// StoreKey securely stores a cryptographic key
func (ks *SecureKeystore) StoreKey(id string, keyType KeyType, usage KeyUsage, keyMaterial []byte, expiresAt time.Time) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Check if key already exists
	if _, exists := ks.keys[id]; exists {
		ks.logAccess(id, "store", false, "key_already_exists", "")
		return fmt.Errorf("key with ID %s already exists", id)
	}

	// Validate key material
	if len(keyMaterial) == 0 {
		return fmt.Errorf("empty key material")
	}

	// Encrypt key material
	encryptedKey, keyIV, keyMAC, err := ks.encryptKeyMaterial(keyMaterial)
	if err != nil {
		ks.logAccess(id, "store", false, "encryption_failed", "")
		return fmt.Errorf("failed to encrypt key material: %w", err)
	}

	// Generate derivation salt
	derivationSalt := make([]byte, 32)
	if _, err := ks.secureRandom.Read(derivationSalt); err != nil {
		return fmt.Errorf("failed to generate derivation salt: %w", err)
	}

	// Initialize forward secrecy chain if enabled
	var chainKey, nextChainKey []byte
	if ks.enableForwardSec {
		chainKey = make([]byte, 32)
		nextChainKey = make([]byte, 32)
		if _, err := ks.secureRandom.Read(chainKey); err != nil {
			return fmt.Errorf("failed to generate chain key: %w", err)
		}
		if _, err := ks.secureRandom.Read(nextChainKey); err != nil {
			return fmt.Errorf("failed to generate next chain key: %w", err)
		}
	}

	// Create secure key
	key := &SecureKey{
		ID:             id,
		Type:           keyType,
		Usage:          usage,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
		MaxUses:        ks.maxKeyUses,
		encryptedKey:   encryptedKey,
		keyIV:          keyIV,
		keyMAC:         keyMAC,
		derivationSalt: derivationSalt,
		chainKey:       chainKey,
		nextChainKey:   nextChainKey,
	}

	// Store key
	ks.keys[id] = key
	ks.keyCreations++

	// Securely clear original key material
	ks.sideChannelProt.ConstantTimeZeroize(keyMaterial)

	ks.logAccess(id, "store", true, "", "")
	return nil
}

// RetrieveKey securely retrieves and decrypts a key
func (ks *SecureKeystore) RetrieveKey(id string, usage KeyUsage) ([]byte, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	key, exists := ks.keys[id]
	if !exists {
		ks.logAccess(id, "retrieve", false, "key_not_found", "")
		ks.failedAccesses++
		return nil, fmt.Errorf("key not found: %s", id)
	}

	// Check key validity
	if err := ks.validateKeyAccess(key, usage); err != nil {
		ks.logAccess(id, "retrieve", false, "validation_failed", "")
		key.failedAccess++
		ks.failedAccesses++
		return nil, err
	}

	// Decrypt key material
	keyMaterial, err := ks.decryptKeyMaterial(key.encryptedKey, key.keyIV, key.keyMAC)
	if err != nil {
		ks.logAccess(id, "retrieve", false, "decryption_failed", "")
		key.failedAccess++
		ks.failedAccesses++
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Update key usage statistics
	key.LastUsed = time.Now()
	key.UseCount++
	key.accessCount++
	ks.accessAttempts++

	// Perform forward secrecy key rotation if enabled
	if ks.enableForwardSec && key.chainKey != nil {
		if err := ks.rotateChainKey(key); err != nil {
			// Log but don't fail the operation
			ks.logAccess(id, "chain_rotation", false, "rotation_failed", "")
		}
	}

	ks.logAccess(id, "retrieve", true, "", "")
	return keyMaterial, nil
}

// RotateKey rotates a key for forward secrecy
func (ks *SecureKeystore) RotateKey(id string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	key, exists := ks.keys[id]
	if !exists {
		return fmt.Errorf("key not found: %s", id)
	}

	// Generate new key material
	oldKeyMaterial, err := ks.decryptKeyMaterial(key.encryptedKey, key.keyIV, key.keyMAC)
	if err != nil {
		return fmt.Errorf("failed to decrypt old key: %w", err)
	}

	// Derive new key material using KDF
	newKeyMaterial, err := ks.deriveNewKey(oldKeyMaterial, key.derivationSalt)
	if err != nil {
		ks.sideChannelProt.ConstantTimeZeroize(oldKeyMaterial)
		return fmt.Errorf("failed to derive new key: %w", err)
	}

	// Encrypt new key material
	encryptedKey, keyIV, keyMAC, err := ks.encryptKeyMaterial(newKeyMaterial)
	if err != nil {
		ks.sideChannelProt.ConstantTimeZeroize(oldKeyMaterial)
		ks.sideChannelProt.ConstantTimeZeroize(newKeyMaterial)
		return fmt.Errorf("failed to encrypt new key: %w", err)
	}

	// Update key
	key.encryptedKey = encryptedKey
	key.keyIV = keyIV
	key.keyMAC = keyMAC
	key.UseCount = 0
	key.LastUsed = time.Now()

	// Generate new derivation salt
	if _, err := ks.secureRandom.Read(key.derivationSalt); err != nil {
		return fmt.Errorf("failed to generate new derivation salt: %w", err)
	}

	// Securely clear old key material
	ks.sideChannelProt.ConstantTimeZeroize(oldKeyMaterial)
	ks.sideChannelProt.ConstantTimeZeroize(newKeyMaterial)

	ks.keyRotations++
	ks.logAccess(id, "rotate", true, "", "")
	return nil
}

// DeleteKey securely deletes a key
func (ks *SecureKeystore) DeleteKey(id string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	key, exists := ks.keys[id]
	if !exists {
		return fmt.Errorf("key not found: %s", id)
	}

	// Securely zero key material
	ks.sideChannelProt.ConstantTimeZeroize(key.encryptedKey)
	ks.sideChannelProt.ConstantTimeZeroize(key.keyIV)
	ks.sideChannelProt.ConstantTimeZeroize(key.keyMAC)
	ks.sideChannelProt.ConstantTimeZeroize(key.derivationSalt)
	if key.chainKey != nil {
		ks.sideChannelProt.ConstantTimeZeroize(key.chainKey)
	}
	if key.nextChainKey != nil {
		ks.sideChannelProt.ConstantTimeZeroize(key.nextChainKey)
	}

	// Remove from keystore
	delete(ks.keys, id)
	ks.keyDeletions++

	ks.logAccess(id, "delete", true, "", "")
	return nil
}

// encryptKeyMaterial encrypts key material using the master key
func (ks *SecureKeystore) encryptKeyMaterial(keyMaterial []byte) ([]byte, []byte, []byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate random IV (12 bytes for GCM)
	iv := make([]byte, 12)
	if _, err := ks.secureRandom.Read(iv); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt using AES-GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedKey := gcm.Seal(nil, iv, keyMaterial, nil)

	// Split ciphertext and MAC
	if len(encryptedKey) < gcm.Overhead() {
		return nil, nil, nil, fmt.Errorf("encrypted data too short")
	}

	ciphertext := encryptedKey[:len(encryptedKey)-gcm.Overhead()]
	mac := encryptedKey[len(encryptedKey)-gcm.Overhead():]

	return ciphertext, iv, mac, nil
}

// decryptKeyMaterial decrypts key material using the master key
func (ks *SecureKeystore) decryptKeyMaterial(encryptedKey, iv, mac []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Reconstruct full ciphertext
	fullCiphertext := append(encryptedKey, mac...)

	// Decrypt
	keyMaterial, err := gcm.Open(nil, iv, fullCiphertext, nil)
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}

// validateKeyAccess validates key access permissions and constraints
func (ks *SecureKeystore) validateKeyAccess(key *SecureKey, usage KeyUsage) error {
	// Check if key is revoked or compromised
	if key.revoked {
		return fmt.Errorf("key is revoked")
	}
	if key.compromised {
		return fmt.Errorf("key is compromised")
	}

	// Check expiration
	if time.Now().After(key.ExpiresAt) {
		return fmt.Errorf("key has expired")
	}

	// Check usage permissions
	if key.Usage&usage == 0 {
		return fmt.Errorf("key usage not permitted")
	}

	// Check use count limit
	if key.UseCount >= key.MaxUses {
		return fmt.Errorf("key use count exceeded")
	}

	// Check key age
	if time.Since(key.CreatedAt) > ks.maxKeyAge {
		return fmt.Errorf("key is too old")
	}

	return nil
}

// deriveNewKey derives a new key from existing key material
func (ks *SecureKeystore) deriveNewKey(oldKey, salt []byte) ([]byte, error) {
	// Use HKDF-like key derivation
	hasher := sha3.New256()
	hasher.Write(oldKey)
	hasher.Write(salt)
	hasher.Write([]byte("key_rotation"))

	return hasher.Sum(nil), nil
}

// rotateChainKey rotates the forward secrecy chain key
func (ks *SecureKeystore) rotateChainKey(key *SecureKey) error {
	if key.chainKey == nil {
		return fmt.Errorf("no chain key available")
	}

	// Derive next chain key
	hasher := sha3.New256()
	hasher.Write(key.chainKey)
	hasher.Write(key.nextChainKey)

	counter := make([]byte, 8)
	binary.LittleEndian.PutUint64(counter, key.chainCounter)
	hasher.Write(counter)

	newChainKey := hasher.Sum(nil)

	// Update chain
	ks.sideChannelProt.ConstantTimeZeroize(key.chainKey)
	key.chainKey = key.nextChainKey
	key.nextChainKey = newChainKey[:32]
	key.chainCounter++

	return nil
}

// logAccess logs a key access event
func (ks *SecureKeystore) logAccess(keyID, operation string, success bool, errorCode, clientInfo string) {
	event := KeyAccessEvent{
		Timestamp:  time.Now(),
		KeyID:      keyID,
		Operation:  operation,
		Success:    success,
		ErrorCode:  errorCode,
		ClientInfo: clientInfo,
	}

	// Add to log (circular buffer)
	if len(ks.accessLog) >= ks.maxLogEntries {
		copy(ks.accessLog, ks.accessLog[1:])
		ks.accessLog = ks.accessLog[:ks.maxLogEntries-1]
	}

	ks.accessLog = append(ks.accessLog, event)
}

// GetKeyInfo returns information about a key without revealing key material
func (ks *SecureKeystore) GetKeyInfo(id string) (*SecureKey, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	key, exists := ks.keys[id]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", id)
	}

	// Return copy without sensitive data
	info := &SecureKey{
		ID:           key.ID,
		Type:         key.Type,
		Usage:        key.Usage,
		CreatedAt:    key.CreatedAt,
		ExpiresAt:    key.ExpiresAt,
		LastUsed:     key.LastUsed,
		UseCount:     key.UseCount,
		MaxUses:      key.MaxUses,
		accessCount:  key.accessCount,
		failedAccess: key.failedAccess,
		compromised:  key.compromised,
		revoked:      key.revoked,
		chainCounter: key.chainCounter,
	}

	return info, nil
}

// GetStats returns keystore statistics
func (ks *SecureKeystore) GetStats() map[string]interface{} {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	return map[string]interface{}{
		"total_keys":        len(ks.keys),
		"key_creations":     ks.keyCreations,
		"key_deletions":     ks.keyDeletions,
		"key_rotations":     ks.keyRotations,
		"access_attempts":   ks.accessAttempts,
		"failed_accesses":   ks.failedAccesses,
		"log_entries":       len(ks.accessLog),
		"forward_secrecy":   ks.enableForwardSec,
		"key_chaining":      ks.enableKeyChaining,
		"rotation_interval": ks.keyRotationInterval,
		"max_key_age":       ks.maxKeyAge,
	}
}

// Cleanup securely cleans up the keystore
func (ks *SecureKeystore) Cleanup() error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Securely delete all keys
	for id := range ks.keys {
		if err := ks.DeleteKey(id); err != nil {
			return fmt.Errorf("failed to delete key %s: %w", id, err)
		}
	}

	// Clear master key
	ks.sideChannelProt.ConstantTimeZeroize(ks.masterKey)
	ks.sideChannelProt.ConstantTimeZeroize(ks.masterKeyIV)

	// Clear access log
	ks.accessLog = nil

	return nil
}
