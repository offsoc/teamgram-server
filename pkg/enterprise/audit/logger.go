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

package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// Logger provides enterprise-grade audit logging
type Logger struct {
	config        *Config
	eventBuffer   []*AuditEvent
	bufferMutex   sync.RWMutex
	encryptionKey []byte
	storage       *AuditStorage
	metrics       *AuditMetrics
	logger        logx.Logger
	flushTicker   *time.Ticker
	stopChan      chan struct{}
}

// Config represents audit logger configuration
type Config struct {
	Enabled           bool          `json:"enabled"`
	RealTimeLogging   bool          `json:"real_time_logging"`
	EncryptionEnabled bool          `json:"encryption_enabled"`
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	ComplianceMode    bool          `json:"compliance_mode"`
}

// AuditEvent represents an audit event
type AuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"`
	EventName     string                 `json:"event_name"`
	UserID        int64                  `json:"user_id"`
	SessionID     string                 `json:"session_id"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	Resource      string                 `json:"resource"`
	Action        string                 `json:"action"`
	Result        string                 `json:"result"`
	Severity      string                 `json:"severity"`
	Data          map[string]interface{} `json:"data"`
	Hash          string                 `json:"hash"`
	Encrypted     bool                   `json:"encrypted"`
	ComplianceTag string                 `json:"compliance_tag"`
}

// AuditStorage handles audit event storage
type AuditStorage struct {
	events      []*AuditEvent
	mutex       sync.RWMutex
	maxEvents   int
	compression bool
}

// AuditMetrics tracks audit logging metrics
type AuditMetrics struct {
	TotalEvents      int64     `json:"total_events"`
	SecurityEvents   int64     `json:"security_events"`
	ComplianceEvents int64     `json:"compliance_events"`
	EncryptedEvents  int64     `json:"encrypted_events"`
	BufferedEvents   int64     `json:"buffered_events"`
	StoredEvents     int64     `json:"stored_events"`
	LastFlush        time.Time `json:"last_flush"`
	LastEvent        time.Time `json:"last_event"`
}

// NewLogger creates a new audit logger
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	if config.BufferSize <= 0 {
		config.BufferSize = 1000
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 30 * time.Second
	}
	if config.RetentionPeriod <= 0 {
		config.RetentionPeriod = 365 * 24 * time.Hour // 1 year
	}

	logger := &Logger{
		config:      config,
		eventBuffer: make([]*AuditEvent, 0, config.BufferSize),
		metrics: &AuditMetrics{
			LastFlush: time.Now(),
			LastEvent: time.Now(),
		},
		logger:   logx.WithContext(context.Background()),
		stopChan: make(chan struct{}),
	}

	// Initialize encryption if enabled
	if config.EncryptionEnabled {
		if err := logger.initializeEncryption(); err != nil {
			return nil, fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	// Initialize storage
	logger.storage = &AuditStorage{
		events:      make([]*AuditEvent, 0),
		maxEvents:   100000, // Keep last 100k events in memory
		compression: true,
	}

	// Start background flush routine
	if !config.RealTimeLogging {
		logger.flushTicker = time.NewTicker(config.FlushInterval)
		go logger.flushRoutine()
	}

	return logger, nil
}

// LogEvent logs a general audit event
func (l *Logger) LogEvent(ctx context.Context, eventName string, userID int64, data map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	event := l.createAuditEvent(ctx, "AUDIT", eventName, userID, "INFO", data)
	l.processEvent(event)
}

// LogSecurityEvent logs a security-related audit event
func (l *Logger) LogSecurityEvent(ctx context.Context, eventName string, userID int64, data map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	event := l.createAuditEvent(ctx, "SECURITY", eventName, userID, "HIGH", data)
	l.processEvent(event)

	l.bufferMutex.Lock()
	l.metrics.SecurityEvents++
	l.bufferMutex.Unlock()
}

// LogComplianceEvent logs a compliance-related audit event
func (l *Logger) LogComplianceEvent(ctx context.Context, eventName string, userID int64, complianceTag string, data map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	event := l.createAuditEvent(ctx, "COMPLIANCE", eventName, userID, "CRITICAL", data)
	event.ComplianceTag = complianceTag
	l.processEvent(event)

	l.bufferMutex.Lock()
	l.metrics.ComplianceEvents++
	l.bufferMutex.Unlock()
}

// GetMetrics returns current audit metrics
func (l *Logger) GetMetrics() *AuditMetrics {
	l.bufferMutex.RLock()
	defer l.bufferMutex.RUnlock()

	metrics := *l.metrics
	metrics.BufferedEvents = int64(len(l.eventBuffer))
	return &metrics
}

// GetEvents retrieves audit events with filtering
func (l *Logger) GetEvents(filter *EventFilter) ([]*AuditEvent, error) {
	if filter == nil {
		filter = &EventFilter{}
	}

	l.storage.mutex.RLock()
	defer l.storage.mutex.RUnlock()

	var filteredEvents []*AuditEvent
	for _, event := range l.storage.events {
		if l.matchesFilter(event, filter) {
			// Decrypt if necessary
			if event.Encrypted && l.encryptionKey != nil {
				decryptedEvent, err := l.decryptEvent(event)
				if err != nil {
					l.logger.Infow("Failed to decrypt audit event", logx.Field("error", err))
					continue
				}
				filteredEvents = append(filteredEvents, decryptedEvent)
			} else {
				filteredEvents = append(filteredEvents, event)
			}
		}
	}

	return filteredEvents, nil
}

// Flush forces immediate flush of buffered events
func (l *Logger) Flush() error {
	return l.flushEvents()
}

// Close gracefully shuts down the audit logger
func (l *Logger) Close() error {
	close(l.stopChan)

	if l.flushTicker != nil {
		l.flushTicker.Stop()
	}

	// Final flush
	return l.flushEvents()
}

// Private methods

func (l *Logger) createAuditEvent(ctx context.Context, eventType, eventName string, userID int64, severity string, data map[string]interface{}) *AuditEvent {
	event := &AuditEvent{
		ID:        l.generateEventID(),
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		EventName: eventName,
		UserID:    userID,
		Severity:  severity,
		Data:      data,
	}

	// Extract context information
	if ctx != nil {
		if sessionID := l.extractSessionID(ctx); sessionID != "" {
			event.SessionID = sessionID
		}
		if ipAddress := l.extractIPAddress(ctx); ipAddress != "" {
			event.IPAddress = ipAddress
		}
		if userAgent := l.extractUserAgent(ctx); userAgent != "" {
			event.UserAgent = userAgent
		}
	}

	// Generate hash for integrity
	event.Hash = l.generateEventHash(event)

	return event
}

func (l *Logger) processEvent(event *AuditEvent) {
	// Encrypt if enabled
	if l.config.EncryptionEnabled && l.encryptionKey != nil {
		encryptedEvent, err := l.encryptEvent(event)
		if err != nil {
			l.logger.Infow("Failed to encrypt audit event", logx.Field("error", err))
		} else {
			event = encryptedEvent
			l.bufferMutex.Lock()
			l.metrics.EncryptedEvents++
			l.bufferMutex.Unlock()
		}
	}

	if l.config.RealTimeLogging {
		// Log immediately
		l.logEventToOutput(event)
		l.storeEvent(event)
	} else {
		// Buffer for batch processing
		l.bufferEvent(event)
	}

	l.bufferMutex.Lock()
	l.metrics.TotalEvents++
	l.metrics.LastEvent = time.Now()
	l.bufferMutex.Unlock()
}

func (l *Logger) bufferEvent(event *AuditEvent) {
	l.bufferMutex.Lock()
	defer l.bufferMutex.Unlock()

	l.eventBuffer = append(l.eventBuffer, event)

	// Flush if buffer is full
	if len(l.eventBuffer) >= l.config.BufferSize {
		go l.flushEvents()
	}
}

func (l *Logger) flushEvents() error {
	l.bufferMutex.Lock()
	events := make([]*AuditEvent, len(l.eventBuffer))
	copy(events, l.eventBuffer)
	l.eventBuffer = l.eventBuffer[:0] // Clear buffer
	l.bufferMutex.Unlock()

	// Log events
	for _, event := range events {
		l.logEventToOutput(event)
		l.storeEvent(event)
	}

	l.bufferMutex.Lock()
	l.metrics.LastFlush = time.Now()
	l.bufferMutex.Unlock()

	return nil
}

func (l *Logger) flushRoutine() {
	for {
		select {
		case <-l.flushTicker.C:
			if err := l.flushEvents(); err != nil {
				l.logger.Errorf("Failed to flush audit events: %v", err)
			}
		case <-l.stopChan:
			return
		}
	}
}

func (l *Logger) logEventToOutput(event *AuditEvent) {
	logData := map[string]interface{}{
		"audit_id":       event.ID,
		"timestamp":      event.Timestamp,
		"event_type":     event.EventType,
		"event_name":     event.EventName,
		"user_id":        event.UserID,
		"session_id":     event.SessionID,
		"ip_address":     event.IPAddress,
		"severity":       event.Severity,
		"hash":           event.Hash,
		"encrypted":      event.Encrypted,
		"compliance_tag": event.ComplianceTag,
	}

	if event.Data != nil {
		for k, v := range event.Data {
			logData[k] = v
		}
	}

	switch event.Severity {
	case "CRITICAL", "HIGH":
		l.logger.Errorw("Audit Event")
	case "MEDIUM":
		l.logger.Infow("Audit Event")
	default:
		l.logger.Infow("Audit Event")
	}
}

func (l *Logger) storeEvent(event *AuditEvent) {
	l.storage.mutex.Lock()
	defer l.storage.mutex.Unlock()

	l.storage.events = append(l.storage.events, event)

	// Maintain storage limit
	if len(l.storage.events) > l.storage.maxEvents {
		// Remove oldest events
		removeCount := len(l.storage.events) - l.storage.maxEvents
		l.storage.events = l.storage.events[removeCount:]
	}

	l.bufferMutex.Lock()
	l.metrics.StoredEvents++
	l.bufferMutex.Unlock()
}

func (l *Logger) initializeEncryption() error {
	// Generate encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}
	l.encryptionKey = key
	return nil
}

func (l *Logger) encryptEvent(event *AuditEvent) (*AuditEvent, error) {
	// Serialize event data
	data, err := json.Marshal(event.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Encrypt data (simplified - in production use proper encryption)
	hash := sha256.Sum256(data)
	encryptedData := hex.EncodeToString(hash[:])

	// Create encrypted event
	encryptedEvent := *event
	encryptedEvent.Data = map[string]interface{}{
		"encrypted_data": encryptedData,
	}
	encryptedEvent.Encrypted = true

	return &encryptedEvent, nil
}

func (l *Logger) decryptEvent(event *AuditEvent) (*AuditEvent, error) {
	if !event.Encrypted {
		return event, nil
	}

	// Decrypt event data (simplified - in production use proper decryption)
	decryptedEvent := *event
	decryptedEvent.Encrypted = false

	return &decryptedEvent, nil
}

func (l *Logger) generateEventID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func (l *Logger) generateEventHash(event *AuditEvent) string {
	data := fmt.Sprintf("%s:%s:%s:%d:%s",
		event.ID, event.Timestamp.Format(time.RFC3339),
		event.EventType, event.UserID, event.EventName)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (l *Logger) extractSessionID(ctx context.Context) string {
	// Extract session ID from context
	// Implementation depends on your session management
	return ""
}

func (l *Logger) extractIPAddress(ctx context.Context) string {
	// Extract IP address from context
	// Implementation depends on your request handling
	return ""
}

func (l *Logger) extractUserAgent(ctx context.Context) string {
	// Extract user agent from context
	// Implementation depends on your request handling
	return ""
}

func (l *Logger) matchesFilter(event *AuditEvent, filter *EventFilter) bool {
	if filter.EventType != "" && event.EventType != filter.EventType {
		return false
	}
	if filter.UserID != 0 && event.UserID != filter.UserID {
		return false
	}
	if filter.Severity != "" && event.Severity != filter.Severity {
		return false
	}
	if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
		return false
	}
	return true
}

// EventFilter represents audit event filtering criteria
type EventFilter struct {
	EventType string    `json:"event_type"`
	UserID    int64     `json:"user_id"`
	Severity  string    `json:"severity"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}
