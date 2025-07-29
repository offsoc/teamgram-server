// Copyright 2024 Teamgram Authors
//  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: teamgramio (teamgram.io@gmail.com)

package kdf

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

// HKDF derives keys using HKDF-SHA256
func HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PBKDF2 derives keys using PBKDF2
func PBKDF2(password, salt []byte, iterations, keyLength int) []byte {
	// Simplified PBKDF2 implementation
	key := make([]byte, keyLength)
	for i := 0; i < iterations; i++ {
		hash := sha256.Sum256(append(password, salt...))
		copy(key, hash[:])
	}
	return key
}
