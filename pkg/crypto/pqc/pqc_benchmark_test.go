// Package pqc provides comprehensive benchmarks for PQC engine
// to validate performance requirements: encryption < 10μs, decryption < 5μs
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// BenchmarkAESGCMEncryption benchmarks AES-256-GCM encryption
func BenchmarkAESGCMEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	message := make([]byte, 1024)
	rand.Read(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("GCM mode creation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gcm.Seal(nil, nonce, message, nil)
	}
}

// BenchmarkAESGCMDecryption benchmarks AES-256-GCM decryption
func BenchmarkAESGCMDecryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	message := make([]byte, 1024)
	rand.Read(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("GCM mode creation failed: %v", err)
	}

	ciphertext := gcm.Seal(nil, nonce, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkHKDFSHA3KeyDerivation benchmarks HKDF-SHA3 key derivation
func BenchmarkHKDFSHA3KeyDerivation(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)

	info := []byte("AES-256-GCM-KEY")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hkdf := hkdf.New(sha3.New256, secret, nil, info)
		key := make([]byte, 32)
		hkdf.Read(key)
	}
}

// BenchmarkHMACSHA3Computation benchmarks HMAC-SHA3 computation
func BenchmarkHMACSHA3Computation(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha3.New256, key)
		h.Write(data)
		_ = h.Sum(nil)
	}
}

// BenchmarkMessageSizes benchmarks different message sizes
func BenchmarkMessageSizes(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("GCM mode creation failed: %v", err)
	}

	sizes := []int{16, 64, 256, 1024, 4096, 16384, 65536}

	for _, size := range sizes {
		message := make([]byte, size)
		rand.Read(message)

		b.Run(fmt.Sprintf("Encrypt_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = gcm.Seal(nil, nonce, message, nil)
			}
		})

		ciphertext := gcm.Seal(nil, nonce, message, nil)

		b.Run(fmt.Sprintf("Decrypt_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := gcm.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkConcurrentOperations benchmarks concurrent encryption/decryption
func BenchmarkConcurrentOperations(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	message := make([]byte, 1024)
	rand.Read(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("GCM mode creation failed: %v", err)
	}

	b.Run("ConcurrentEncryption", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = gcm.Seal(nil, nonce, message, nil)
			}
		})
	})

	ciphertext := gcm.Seal(nil, nonce, message, nil)

	b.Run("ConcurrentDecryption", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := gcm.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	})
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	message := make([]byte, 1024)
	rand.Read(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("GCM mode creation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext := gcm.Seal(nil, nonce, message, nil)
		_, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}