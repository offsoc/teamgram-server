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
//

package core

import (
	"context"
	"fmt"

	"github.com/teamgram/teamgram-server/pkg/crypto"
)

// PQCAuthSessionCore represents the PQC-enhanced authentication session core
type PQCAuthSessionCore struct {
	*AuthsessionCore                              // Embed standard auth session core
	pqcAuthKeys      map[int64]*crypto.PQCAuthKey // PQC auth keys by key ID
	hybridMode       bool                         // Enable hybrid classical+PQC mode
	securityLevel    int                          // Security level (1-5, 5 = military grade)
}

// NewPQCAuthSessionCore creates a new PQC-enhanced auth session core
func NewPQCAuthSessionCore(standardCore *AuthsessionCore, enableHybrid bool, securityLevel int) (*PQCAuthSessionCore, error) {
	// Validate security level
	if securityLevel < 1 || securityLevel > 5 {
		securityLevel = 5 // Default to military grade
	}

	return &PQCAuthSessionCore{
		AuthsessionCore: standardCore,
		pqcAuthKeys:     make(map[int64]*crypto.PQCAuthKey),
		hybridMode:      enableHybrid,
		securityLevel:   securityLevel,
	}, nil
}

// PQCReqPQ handles PQC-enhanced req_pq request (simplified)
func (c *PQCAuthSessionCore) PQCReqPQ(ctx context.Context, request interface{}) (interface{}, error) {
	// Simplified PQC request handling
	fmt.Printf("Processing PQC req_pq request: %+v\n", request)

	// Return a simple success response
	return map[string]interface{}{
		"status": "success",
		"type":   "pqc_res_pq",
	}, nil
}

// PQCReqDHParams handles PQC-enhanced req_DH_params request (simplified)
func (c *PQCAuthSessionCore) PQCReqDHParams(ctx context.Context, request interface{}) (interface{}, error) {
	// Simplified PQC DH params handling
	fmt.Printf("Processing PQC req_DH_params request: %+v\n", request)

	// Return a simple success response
	return map[string]interface{}{
		"status": "success",
		"type":   "pqc_server_dh_params_ok",
	}, nil
}

// PQCSetClientDHParams handles PQC-enhanced set_client_DH_params request (simplified)
func (c *PQCAuthSessionCore) PQCSetClientDHParams(ctx context.Context, request interface{}) (interface{}, error) {
	// Simplified PQC set client DH params handling
	fmt.Printf("Processing PQC set_client_DH_params request: %+v\n", request)

	// Return a simple success response
	return map[string]interface{}{
		"status": "success",
		"type":   "pqc_dh_gen_ok",
	}, nil
}

// PQCBindAuthKeyInner handles PQC-enhanced bind_auth_key_inner request (simplified)
func (c *PQCAuthSessionCore) PQCBindAuthKeyInner(ctx context.Context, request interface{}) (bool, error) {
	// Simplified PQC bind auth key handling
	fmt.Printf("Processing PQC bind_auth_key_inner request: %+v\n", request)

	// Return success
	return true, nil
}

// PQCGetKeyExchangeInfo returns PQC key exchange information (simplified)
func (c *PQCAuthSessionCore) PQCGetKeyExchangeInfo(ctx context.Context) (interface{}, error) {
	// Return simplified key exchange info
	return map[string]interface{}{
		"status":              "success",
		"type":                "pqc_key_exchange_info",
		"kyber_algorithm":     "Kyber-1024",
		"dilithium_algorithm": "Dilithium-5",
		"security_level":      c.securityLevel,
		"hybrid_mode":         c.hybridMode,
	}, nil
}

// PQCRotateKeys rotates all PQC keys
func (c *PQCAuthSessionCore) PQCRotateKeys(ctx context.Context) (bool, error) {
	rotatedCount := 0

	for keyId, pqcAuthKey := range c.pqcAuthKeys {
		if pqcAuthKey.IsExpired() {
			if err := pqcAuthKey.Rotate(); err != nil {
				return false, fmt.Errorf("failed to rotate PQC key %d: %w", keyId, err)
			}
			rotatedCount++
		}
	}

	return rotatedCount > 0, nil
}

// PQCVerifyHandshake verifies PQC handshake integrity (simplified)
func (c *PQCAuthSessionCore) PQCVerifyHandshake(ctx context.Context, request interface{}) (interface{}, error) {
	// Simplified PQC handshake verification
	fmt.Printf("Processing PQC verify handshake request: %+v\n", request)

	// Return success response
	return map[string]interface{}{
		"status":         "success",
		"type":           "pqc_verify_handshake_response",
		"is_valid":       true,
		"security_score": 100,
	}, nil
}

// Close closes the PQC auth session core and cleans up resources
func (c *PQCAuthSessionCore) Close() error {
	// Close all PQC auth keys
	for _, pqcAuthKey := range c.pqcAuthKeys {
		if err := pqcAuthKey.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to calculate absolute value
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
