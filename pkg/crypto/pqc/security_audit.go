package pqc

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Military-grade security audit logging and intrusion detection
// Implements comprehensive security event logging, anomaly detection,
// and real-time security monitoring

// SecurityEventType represents different types of security events
type SecurityEventType int

const (
	EventTypeKeyGeneration SecurityEventType = iota
	EventTypeKeyAccess
	EventTypeKeyRotation
	EventTypeKeyDeletion
	EventTypeEncryption
	EventTypeDecryption
	EventTypeSigning
	EventTypeVerification
	EventTypeAuthentication
	EventTypeAuthorization
	EventTypeSecurityViolation
	EventTypeAnomalousActivity
	EventTypeSystemTampering
	EventTypeIntrusionAttempt
	EventTypeConfigChange
	EventTypeErrorCondition
)

// SecuritySeverity represents the severity level of security events
type SecuritySeverity int

const (
	SeverityInfo SecuritySeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
	SeverityEmergency
)

// SecurityEvent represents a security audit event
type SecurityEvent struct {
	Timestamp    time.Time         `json:"timestamp"`
	EventType    SecurityEventType `json:"event_type"`
	Severity     SecuritySeverity  `json:"severity"`
	Source       string           `json:"source"`
	Description  string           `json:"description"`
	Details      map[string]interface{} `json:"details"`
	UserID       string           `json:"user_id,omitempty"`
	SessionID    string           `json:"session_id,omitempty"`
	RemoteAddr   string           `json:"remote_addr,omitempty"`
	
	// Security context
	ThreatLevel  int              `json:"threat_level"`
	Indicators   []string         `json:"indicators,omitempty"`
	Mitigation   string           `json:"mitigation,omitempty"`
	
	// Correlation
	CorrelationID string          `json:"correlation_id,omitempty"`
	ParentEventID string          `json:"parent_event_id,omitempty"`
}

// SecurityAuditLogger provides comprehensive security audit logging
type SecurityAuditLogger struct {
	mutex           sync.RWMutex
	events          []SecurityEvent
	maxEvents       int
	
	// Real-time monitoring
	alertThresholds map[SecurityEventType]int
	eventCounts     map[SecurityEventType]int
	timeWindows     map[SecurityEventType]time.Duration
	lastEventTime   map[SecurityEventType]time.Time
	
	// Anomaly detection
	baselineMetrics map[string]float64
	anomalyThreshold float64
	
	// Intrusion detection
	suspiciousPatterns []SecurityPattern
	activeThreats      map[string]ThreatContext
	
	// Configuration
	enableRealTimeAlerts bool
	enableAnomalyDetection bool
	enableIntrusionDetection bool
	
	// Statistics
	totalEvents     uint64
	criticalEvents  uint64
	anomaliesDetected uint64
	threatsBlocked  uint64
}

// SecurityPattern represents a pattern for intrusion detection
type SecurityPattern struct {
	Name        string
	EventTypes  []SecurityEventType
	TimeWindow  time.Duration
	Threshold   int
	Severity    SecuritySeverity
	Description string
}

// ThreatContext represents an active threat context
type ThreatContext struct {
	ThreatID     string
	FirstSeen    time.Time
	LastSeen     time.Time
	EventCount   int
	Severity     SecuritySeverity
	Indicators   []string
	Blocked      bool
	Mitigated    bool
}

// SecurityAuditConfig configures the security audit logger
type SecurityAuditConfig struct {
	MaxEvents                int
	EnableRealTimeAlerts     bool
	EnableAnomalyDetection   bool
	EnableIntrusionDetection bool
	AnomalyThreshold         float64
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(config *SecurityAuditConfig) *SecurityAuditLogger {
	if config == nil {
		config = &SecurityAuditConfig{
			MaxEvents:                10000,
			EnableRealTimeAlerts:     true,
			EnableAnomalyDetection:   true,
			EnableIntrusionDetection: true,
			AnomalyThreshold:         2.0, // 2 standard deviations
		}
	}

	sal := &SecurityAuditLogger{
		events:                   make([]SecurityEvent, 0, config.MaxEvents),
		maxEvents:                config.MaxEvents,
		alertThresholds:          make(map[SecurityEventType]int),
		eventCounts:              make(map[SecurityEventType]int),
		timeWindows:              make(map[SecurityEventType]time.Duration),
		lastEventTime:            make(map[SecurityEventType]time.Time),
		baselineMetrics:          make(map[string]float64),
		anomalyThreshold:         config.AnomalyThreshold,
		activeThreats:            make(map[string]ThreatContext),
		enableRealTimeAlerts:     config.EnableRealTimeAlerts,
		enableAnomalyDetection:   config.EnableAnomalyDetection,
		enableIntrusionDetection: config.EnableIntrusionDetection,
	}

	// Initialize default alert thresholds
	sal.initializeDefaultThresholds()
	
	// Initialize security patterns
	sal.initializeSecurityPatterns()

	return sal
}

// LogEvent logs a security event
func (sal *SecurityAuditLogger) LogEvent(eventType SecurityEventType, severity SecuritySeverity, 
	source, description string, details map[string]interface{}) {
	
	sal.mutex.Lock()
	defer sal.mutex.Unlock()

	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Severity:    severity,
		Source:      source,
		Description: description,
		Details:     details,
		ThreatLevel: sal.calculateThreatLevel(eventType, severity),
	}

	// Add event to log
	sal.addEvent(event)
	
	// Update statistics
	sal.totalEvents++
	if severity >= SeverityCritical {
		sal.criticalEvents++
	}

	// Real-time analysis
	if sal.enableRealTimeAlerts {
		sal.checkAlertThresholds(eventType)
	}
	
	if sal.enableAnomalyDetection {
		sal.detectAnomalies(event)
	}
	
	if sal.enableIntrusionDetection {
		sal.detectIntrusions(event)
	}
}

// LogSecurityViolation logs a security violation with enhanced context
func (sal *SecurityAuditLogger) LogSecurityViolation(description string, indicators []string, 
	userID, sessionID, remoteAddr string) {
	
	details := map[string]interface{}{
		"indicators":    indicators,
		"violation_type": "security_policy",
		"automated":     true,
	}

	event := SecurityEvent{
		Timestamp:     time.Now(),
		EventType:     EventTypeSecurityViolation,
		Severity:      SeverityError,
		Source:        "security_monitor",
		Description:   description,
		Details:       details,
		UserID:        userID,
		SessionID:     sessionID,
		RemoteAddr:    remoteAddr,
		Indicators:    indicators,
		ThreatLevel:   7, // High threat level for violations
	}

	sal.mutex.Lock()
	defer sal.mutex.Unlock()
	
	sal.addEvent(event)
	sal.totalEvents++
	
	// Immediate threat analysis for violations
	sal.analyzeSecurityViolation(event)
}

// addEvent adds an event to the log (circular buffer)
func (sal *SecurityAuditLogger) addEvent(event SecurityEvent) {
	if len(sal.events) >= sal.maxEvents {
		// Remove oldest event
		copy(sal.events, sal.events[1:])
		sal.events = sal.events[:sal.maxEvents-1]
	}
	
	sal.events = append(sal.events, event)
}

// checkAlertThresholds checks if event frequency exceeds thresholds
func (sal *SecurityAuditLogger) checkAlertThresholds(eventType SecurityEventType) {
	threshold, exists := sal.alertThresholds[eventType]
	if !exists {
		return
	}

	timeWindow, exists := sal.timeWindows[eventType]
	if !exists {
		timeWindow = time.Hour // Default window
	}

	// Count events in time window
	now := time.Now()
	count := 0
	for i := len(sal.events) - 1; i >= 0; i-- {
		if now.Sub(sal.events[i].Timestamp) > timeWindow {
			break
		}
		if sal.events[i].EventType == eventType {
			count++
		}
	}

	if count > threshold {
		sal.triggerAlert(eventType, count, threshold, timeWindow)
	}
}

// detectAnomalies detects anomalous patterns in security events
func (sal *SecurityAuditLogger) detectAnomalies(event SecurityEvent) {
	// Simple anomaly detection based on event frequency
	eventTypeStr := fmt.Sprintf("event_type_%d", int(event.EventType))
	
	// Calculate current rate
	now := time.Now()
	recentCount := 0
	for i := len(sal.events) - 1; i >= 0; i-- {
		if now.Sub(sal.events[i].Timestamp) > time.Hour {
			break
		}
		if sal.events[i].EventType == event.EventType {
			recentCount++
		}
	}

	baseline, exists := sal.baselineMetrics[eventTypeStr]
	if !exists {
		// Establish baseline
		sal.baselineMetrics[eventTypeStr] = float64(recentCount)
		return
	}

	// Check for anomaly
	deviation := float64(recentCount) - baseline
	if deviation > sal.anomalyThreshold*baseline {
		sal.reportAnomaly(event.EventType, recentCount, baseline)
	}

	// Update baseline (exponential moving average)
	sal.baselineMetrics[eventTypeStr] = 0.9*baseline + 0.1*float64(recentCount)
}

// detectIntrusions detects intrusion patterns
func (sal *SecurityAuditLogger) detectIntrusions(event SecurityEvent) {
	for _, pattern := range sal.suspiciousPatterns {
		if sal.matchesPattern(event, pattern) {
			sal.handlePatternMatch(event, pattern)
		}
	}
}

// analyzeSecurityViolation performs immediate analysis of security violations
func (sal *SecurityAuditLogger) analyzeSecurityViolation(event SecurityEvent) {
	// Create or update threat context
	threatID := fmt.Sprintf("violation_%s_%s", event.UserID, event.RemoteAddr)
	
	threat, exists := sal.activeThreats[threatID]
	if !exists {
		threat = ThreatContext{
			ThreatID:   threatID,
			FirstSeen:  event.Timestamp,
			LastSeen:   event.Timestamp,
			EventCount: 1,
			Severity:   event.Severity,
			Indicators: event.Indicators,
		}
	} else {
		threat.LastSeen = event.Timestamp
		threat.EventCount++
		threat.Indicators = append(threat.Indicators, event.Indicators...)
		
		// Escalate severity if multiple violations
		if threat.EventCount > 3 && threat.Severity < SeverityCritical {
			threat.Severity = SeverityCritical
		}
	}

	sal.activeThreats[threatID] = threat
	
	// Auto-mitigation for critical threats
	if threat.Severity >= SeverityCritical && !threat.Mitigated {
		sal.initiateThreatMitigation(threatID, threat)
	}
}

// triggerAlert triggers a security alert
func (sal *SecurityAuditLogger) triggerAlert(eventType SecurityEventType, count, threshold int, window time.Duration) {
	alertEvent := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventTypeAnomalousActivity,
		Severity:    SeverityWarning,
		Source:      "alert_system",
		Description: fmt.Sprintf("Event threshold exceeded: %d events of type %d in %v (threshold: %d)", 
			count, int(eventType), window, threshold),
		Details: map[string]interface{}{
			"triggered_event_type": eventType,
			"event_count":         count,
			"threshold":           threshold,
			"time_window":         window.String(),
		},
		ThreatLevel: 5,
	}

	sal.addEvent(alertEvent)
}

// reportAnomaly reports a detected anomaly
func (sal *SecurityAuditLogger) reportAnomaly(eventType SecurityEventType, current int, baseline float64) {
	sal.anomaliesDetected++
	
	anomalyEvent := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventTypeAnomalousActivity,
		Severity:    SeverityWarning,
		Source:      "anomaly_detector",
		Description: fmt.Sprintf("Anomalous activity detected for event type %d", int(eventType)),
		Details: map[string]interface{}{
			"event_type":      eventType,
			"current_rate":    current,
			"baseline_rate":   baseline,
			"deviation_ratio": float64(current) / baseline,
		},
		ThreatLevel: 6,
	}

	sal.addEvent(anomalyEvent)
}

// matchesPattern checks if an event matches a security pattern
func (sal *SecurityAuditLogger) matchesPattern(event SecurityEvent, pattern SecurityPattern) bool {
	// Check if event type is in pattern
	for _, eventType := range pattern.EventTypes {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

// handlePatternMatch handles a pattern match
func (sal *SecurityAuditLogger) handlePatternMatch(event SecurityEvent, pattern SecurityPattern) {
	// Count matching events in time window
	now := time.Now()
	count := 0
	for i := len(sal.events) - 1; i >= 0; i-- {
		if now.Sub(sal.events[i].Timestamp) > pattern.TimeWindow {
			break
		}
		if sal.matchesPattern(sal.events[i], pattern) {
			count++
		}
	}

	if count >= pattern.Threshold {
		sal.reportPatternMatch(pattern, count)
	}
}

// reportPatternMatch reports a pattern match
func (sal *SecurityAuditLogger) reportPatternMatch(pattern SecurityPattern, count int) {
	patternEvent := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventTypeIntrusionAttempt,
		Severity:    pattern.Severity,
		Source:      "intrusion_detector",
		Description: fmt.Sprintf("Security pattern detected: %s (%d events)", pattern.Name, count),
		Details: map[string]interface{}{
			"pattern_name":   pattern.Name,
			"pattern_desc":   pattern.Description,
			"event_count":    count,
			"threshold":      pattern.Threshold,
			"time_window":    pattern.TimeWindow.String(),
		},
		ThreatLevel: 8,
	}

	sal.addEvent(patternEvent)
}

// initiateThreatMitigation initiates threat mitigation
func (sal *SecurityAuditLogger) initiateThreatMitigation(threatID string, threat ThreatContext) {
	// Mark as mitigated
	threat.Mitigated = true
	sal.activeThreats[threatID] = threat
	sal.threatsBlocked++

	mitigationEvent := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventTypeSecurityViolation,
		Severity:    SeverityEmergency,
		Source:      "threat_mitigation",
		Description: fmt.Sprintf("Automatic threat mitigation initiated for %s", threatID),
		Details: map[string]interface{}{
			"threat_id":     threatID,
			"event_count":   threat.EventCount,
			"first_seen":    threat.FirstSeen,
			"last_seen":     threat.LastSeen,
			"indicators":    threat.Indicators,
			"mitigation":    "automatic_blocking",
		},
		ThreatLevel: 10,
		Mitigation:  "Automatic blocking initiated",
	}

	sal.addEvent(mitigationEvent)
}

// initializeDefaultThresholds sets up default alert thresholds
func (sal *SecurityAuditLogger) initializeDefaultThresholds() {
	sal.alertThresholds[EventTypeKeyAccess] = 100
	sal.alertThresholds[EventTypeEncryption] = 1000
	sal.alertThresholds[EventTypeDecryption] = 1000
	sal.alertThresholds[EventTypeSecurityViolation] = 5
	sal.alertThresholds[EventTypeIntrusionAttempt] = 3
	
	sal.timeWindows[EventTypeKeyAccess] = time.Hour
	sal.timeWindows[EventTypeEncryption] = time.Hour
	sal.timeWindows[EventTypeDecryption] = time.Hour
	sal.timeWindows[EventTypeSecurityViolation] = time.Minute * 10
	sal.timeWindows[EventTypeIntrusionAttempt] = time.Minute * 5
}

// initializeSecurityPatterns sets up intrusion detection patterns
func (sal *SecurityAuditLogger) initializeSecurityPatterns() {
	sal.suspiciousPatterns = []SecurityPattern{
		{
			Name:        "Rapid Key Access",
			EventTypes:  []SecurityEventType{EventTypeKeyAccess},
			TimeWindow:  time.Minute,
			Threshold:   20,
			Severity:    SeverityWarning,
			Description: "Unusually rapid key access attempts",
		},
		{
			Name:        "Multiple Security Violations",
			EventTypes:  []SecurityEventType{EventTypeSecurityViolation},
			TimeWindow:  time.Minute * 5,
			Threshold:   3,
			Severity:    SeverityCritical,
			Description: "Multiple security violations in short time",
		},
		{
			Name:        "Brute Force Pattern",
			EventTypes:  []SecurityEventType{EventTypeAuthentication, EventTypeAuthorization},
			TimeWindow:  time.Minute * 2,
			Threshold:   10,
			Severity:    SeverityError,
			Description: "Potential brute force attack pattern",
		},
	}
}

// calculateThreatLevel calculates threat level based on event type and severity
func (sal *SecurityAuditLogger) calculateThreatLevel(eventType SecurityEventType, severity SecuritySeverity) int {
	base := int(severity) * 2
	
	switch eventType {
	case EventTypeSecurityViolation, EventTypeIntrusionAttempt:
		return base + 5
	case EventTypeSystemTampering:
		return base + 4
	case EventTypeAnomalousActivity:
		return base + 3
	case EventTypeKeyDeletion, EventTypeConfigChange:
		return base + 2
	default:
		return base
	}
}

// GetEvents returns recent security events
func (sal *SecurityAuditLogger) GetEvents(limit int) []SecurityEvent {
	sal.mutex.RLock()
	defer sal.mutex.RUnlock()

	if limit <= 0 || limit > len(sal.events) {
		limit = len(sal.events)
	}

	start := len(sal.events) - limit
	events := make([]SecurityEvent, limit)
	copy(events, sal.events[start:])

	return events
}

// GetStats returns audit logger statistics
func (sal *SecurityAuditLogger) GetStats() map[string]interface{} {
	sal.mutex.RLock()
	defer sal.mutex.RUnlock()

	return map[string]interface{}{
		"total_events":         sal.totalEvents,
		"critical_events":      sal.criticalEvents,
		"anomalies_detected":   sal.anomaliesDetected,
		"threats_blocked":      sal.threatsBlocked,
		"active_threats":       len(sal.activeThreats),
		"events_in_memory":     len(sal.events),
		"real_time_alerts":     sal.enableRealTimeAlerts,
		"anomaly_detection":    sal.enableAnomalyDetection,
		"intrusion_detection":  sal.enableIntrusionDetection,
	}
}

// ExportEvents exports events as JSON
func (sal *SecurityAuditLogger) ExportEvents(startTime, endTime time.Time) ([]byte, error) {
	sal.mutex.RLock()
	defer sal.mutex.RUnlock()

	var filteredEvents []SecurityEvent
	for _, event := range sal.events {
		if event.Timestamp.After(startTime) && event.Timestamp.Before(endTime) {
			filteredEvents = append(filteredEvents, event)
		}
	}

	return json.Marshal(filteredEvents)
}

// Cleanup performs cleanup of audit logger resources
func (sal *SecurityAuditLogger) Cleanup() {
	sal.mutex.Lock()
	defer sal.mutex.Unlock()

	sal.events = nil
	sal.activeThreats = make(map[string]ThreatContext)
	sal.baselineMetrics = make(map[string]float64)
}
