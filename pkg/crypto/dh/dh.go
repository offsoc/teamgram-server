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

package dh

import (
	"crypto/rand"
	"math/big"
)

// DHKeyPair represents a Diffie-Hellman key pair
type DHKeyPair struct {
	PrivateKey *big.Int
	PublicKey  *big.Int
	P          *big.Int
	G          *big.Int
}

// GenerateKeyPair generates a new DH key pair
func GenerateKeyPair() (*DHKeyPair, error) {
	// Use a standard 2048-bit prime
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	g := big.NewInt(2)

	// Generate private key
	privateKey, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}

	// Calculate public key: g^privateKey mod p
	publicKey := new(big.Int).Exp(g, privateKey, p)

	return &DHKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		P:          p,
		G:          g,
	}, nil
}

// ComputeSharedSecret computes the shared secret
func (kp *DHKeyPair) ComputeSharedSecret(otherPublicKey *big.Int) *big.Int {
	return new(big.Int).Exp(otherPublicKey, kp.PrivateKey, kp.P)
}
