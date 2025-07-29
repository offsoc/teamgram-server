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

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// E2EManager manages end-to-end encryption
type E2EManager struct {
	config    *E2EConfig
	sessions  map[string]*E2ESession
	mutex     sync.RWMutex
	logger    logx.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	isRunning bool
}

// E2EConfig represents E2E configuration
type E2EConfig struct {
	Algorithm       string        `json:"algorithm"`
	KeySize         int           `json:"key_size"`
	SessionTimeout  time.Duration `json:"session_timeout"`
	EnablePFS       bool          `json:"enable_pfs"` // Perfect Forward Secrecy
	EnableDTLS      bool          `json:"enable_dtls"`
	EnableSRTP      bool          `json:"enable_srtp"`
	VerifyFingerprint bool        `json:"verify_fingerprint"`
}

// E2ESession represents an E2E session
type E2ESession struct {
	ID                string            `json:"id"`
	CallID            int64             `json:"call_id"`
	UserID            int64             `json:"user_id"`
	PeerID            int64             `json:"peer_id"`
	LocalKey          []byte            `json:"-"`
	RemoteKey         []byte            `json:"-"`
	SharedSecret      []byte            `json:"-"`
	LocalFingerprint  string            `json:"local_fingerprint"`
	RemoteFingerprint string            `json:"remote_fingerprint"`
	Algorithm         string            `json:"algorithm"`
	State             E2EState          `json:"state"`
	CreatedAt         time.Time         `json:"created_at"`
	LastActivity      time.Time         `json:"last_activity"`
	ExpiresAt         time.Time         `json:"expires_at"`
	Metadata          map[string]string `json:"metadata"`
	mutex             sync.RWMutex
}

// E2EState represents the state of an E2E session
type E2EState string

const (
	E2EStateInitializing E2EState = "initializing"
	E2EStateKeyExchange  E2EState = "key_exchange"
	E2EStateEstablished  E2EState = "established"
	E2EStateExpired      E2EState = "expired"
	E2EStateClosed       E2EState = "closed"
	E2EStateFailed       E2EState = "failed"
)

// NewE2EManager creates a new E2E manager
func NewE2EManager(config *E2EConfig) (*E2EManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &E2EManager{
		config:   config,
		sessions: make(map[string]*E2ESession),
		logger:   logx.WithContext(ctx),
		ctx:      ctx,
		cancel:   cancel,
	}

	return manager, nil
}

// DefaultE2EConfig returns default E2E configuration
func DefaultE2EConfig() *E2EConfig {
	return &E2EConfig{
		Algorithm:         "AES-256-GCM",
		KeySize:           32, // 256 bits
		SessionTimeout:    30 * time.Minute,
		EnablePFS:         true,
		EnableDTLS:        true,
		EnableSRTP:        true,
		VerifyFingerprint: true,
	}
}

// Start starts the E2E manager
func (m *E2EManager) Start() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.isRunning {
		return errors.New("E2E manager is already running")
	}

	m.logger.Info("Starting E2E manager...")

	// Start session cleanup routine
	go m.sessionCleanupRoutine()

	m.isRunning = true
	m.logger.Info("E2E manager started successfully")

	return nil
}

// Stop stops the E2E manager
func (m *E2EManager) Stop() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isRunning {
		return nil
	}

	m.logger.Info("Stopping E2E manager...")
	m.cancel()

	// Close all sessions
	for _, session := range m.sessions {
		session.Close()
	}

	m.isRunning = false
	m.logger.Info("E2E manager stopped")

	return nil
}

// CreateSession creates a new E2E session
func (m *E2EManager) CreateSession(callID int64, userID, peerID int64) (*E2ESession, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	sessionID := m.generateSessionID(callID, userID, peerID)

	if _, exists := m.sessions[sessionID]; exists {
		return nil, fmt.Errorf("E2E session with ID %s already exists", sessionID)
	}

	// Generate local key
	localKey := make([]byte, m.config.KeySize)
	if _, err := rand.Read(localKey); err != nil {
		return nil, fmt.Errorf("failed to generate local key: %w", err)
	}

	// Generate local fingerprint
	localFingerprint := m.generateFingerprint(localKey)

	session := &E2ESession{
		ID:                sessionID,
		CallID:            callID,
		UserID:            userID,
		PeerID:            peerID,
		LocalKey:          localKey,
		LocalFingerprint:  localFingerprint,
		Algorithm:         m.config.Algorithm,
		State:             E2EStateInitializing,
		CreatedAt:         time.Now(),
		LastActivity:      time.Now(),
		ExpiresAt:         time.Now().Add(m.config.SessionTimeout),
		Metadata:          make(map[string]string),
	}

	m.sessions[sessionID] = session
	m.logger.Infof("Created E2E session: %s", sessionID)

	return session, nil
}

// GetSession gets an E2E session by ID
func (m *E2EManager) GetSession(sessionID string) (*E2ESession, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("E2E session with ID %s not found", sessionID)
	}

	return session, nil
}

// CloseSession closes an E2E session
func (m *E2EManager) CloseSession(sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("E2E session with ID %s not found", sessionID)
	}

	session.Close()
	delete(m.sessions, sessionID)
	m.logger.Infof("Closed E2E session: %s", sessionID)

	return nil
}

// ExchangeKeys performs key exchange for an E2E session
func (m *E2EManager) ExchangeKeys(sessionID string, remoteKey []byte) error {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	return session.ExchangeKeys(remoteKey)
}

// Private methods

func (m *E2EManager) generateSessionID(callID int64, userID, peerID int64) string {
	data := fmt.Sprintf("%d:%d:%d:%d", callID, userID, peerID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter ID
}

func (m *E2EManager) generateFingerprint(key []byte) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

func (m *E2EManager) sessionCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

func (m *E2EManager) cleanupExpiredSessions() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	for sessionID, session := range m.sessions {
		session.mutex.RLock()
		if session.State == E2EStateExpired || session.State == E2EStateClosed || now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
		session.mutex.RUnlock()
	}

	for _, sessionID := range expiredSessions {
		if session, exists := m.sessions[sessionID]; exists {
			session.Close()
			delete(m.sessions, sessionID)
		}
	}

	if len(expiredSessions) > 0 {
		m.logger.Infof("Cleaned up %d expired E2E sessions", len(expiredSessions))
	}
}

// E2ESession methods

// ExchangeKeys performs key exchange with remote peer
func (s *E2ESession) ExchangeKeys(remoteKey []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.State != E2EStateInitializing && s.State != E2EStateKeyExchange {
		return fmt.Errorf("invalid state for key exchange: %s", s.State)
	}

	s.RemoteKey = make([]byte, len(remoteKey))
	copy(s.RemoteKey, remoteKey)

	// Generate remote fingerprint
	s.RemoteFingerprint = s.generateFingerprint(remoteKey)

	// Generate shared secret using ECDH or similar
	s.SharedSecret = s.generateSharedSecret(s.LocalKey, s.RemoteKey)

	s.State = E2EStateEstablished
	s.LastActivity = time.Now()

	return nil
}

// Close closes the E2E session
func (s *E2ESession) Close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.State = E2EStateClosed

	// Clear sensitive data
	if s.LocalKey != nil {
		for i := range s.LocalKey {
			s.LocalKey[i] = 0
		}
		s.LocalKey = nil
	}

	if s.RemoteKey != nil {
		for i := range s.RemoteKey {
			s.RemoteKey[i] = 0
		}
		s.RemoteKey = nil
	}

	if s.SharedSecret != nil {
		for i := range s.SharedSecret {
			s.SharedSecret[i] = 0
		}
		s.SharedSecret = nil
	}
}

// GetState returns the current state of the session
func (s *E2ESession) GetState() E2EState {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.State
}

// IsEstablished returns true if the session is established
func (s *E2ESession) IsEstablished() bool {
	return s.GetState() == E2EStateEstablished
}

// Private session methods

func (s *E2ESession) generateFingerprint(key []byte) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

func (s *E2ESession) generateSharedSecret(localKey, remoteKey []byte) []byte {
	// Simplified shared secret generation
	// In a real implementation, this would use proper ECDH
	combined := append(localKey, remoteKey...)
	hash := sha256.Sum256(combined)
	return hash[:]
}
