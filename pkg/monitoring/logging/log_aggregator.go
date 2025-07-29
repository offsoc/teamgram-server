package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// LogAggregator provides centralized log aggregation and analysis
type LogAggregator struct {
	config     *Config
	logs       []*LogEntry
	processors map[string]LogProcessor
	exporters  map[string]LogExporter
	patterns   map[string]*LogPattern
	alerts     map[string]*LogAlert
	mutex      sync.RWMutex
	logger     logx.Logger
}

// Config for log aggregator
type Config struct {
	EnableStructuredLogging bool   `json:"enable_structured_logging"`
	EnableLogParsing        bool   `json:"enable_log_parsing"`
	EnableAnomalyDetection  bool   `json:"enable_anomaly_detection"`
	EnableAlerts            bool   `json:"enable_alerts"`
	MaxLogEntries           int    `json:"max_log_entries"`
	RetentionPeriod         int    `json:"retention_period"`    // hours
	ProcessingInterval      int    `json:"processing_interval"` // seconds
	ExportInterval          int    `json:"export_interval"`     // seconds
	LogLevel                string `json:"log_level"`
}

// LogEntry represents a log entry
type LogEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Service   string                 `json:"service"`
	Host      string                 `json:"host"`
	Fields    map[string]interface{} `json:"fields"`
	Tags      []string               `json:"tags"`
	TraceID   string                 `json:"trace_id,omitempty"`
	SpanID    string                 `json:"span_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	Metadata  map[string]string      `json:"metadata"`
}

// LogProcessor interface for log processing
type LogProcessor interface {
	GetName() string
	GetType() ProcessorType
	Process(ctx context.Context, entry *LogEntry) (*LogEntry, error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// LogExporter interface for log export
type LogExporter interface {
	GetName() string
	GetType() ExporterType
	Export(ctx context.Context, entries []*LogEntry) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// LogPattern represents a log pattern for parsing
type LogPattern struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Pattern     string            `json:"pattern"`
	Fields      []string          `json:"fields"`
	Source      string            `json:"source"`
	Description string            `json:"description"`
	Examples    []string          `json:"examples"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	IsActive    bool              `json:"is_active"`
}

// LogAlert represents a log-based alert
type LogAlert struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Query         LogQuery          `json:"query"`
	Condition     AlertCondition    `json:"condition"`
	Threshold     float64           `json:"threshold"`
	Window        time.Duration     `json:"window"`
	Severity      AlertSeverity     `json:"severity"`
	Actions       []AlertAction     `json:"actions"`
	Metadata      map[string]string `json:"metadata"`
	CreatedAt     time.Time         `json:"created_at"`
	IsActive      bool              `json:"is_active"`
	LastTriggered *time.Time        `json:"last_triggered,omitempty"`
}

// LogQuery represents a log query
type LogQuery struct {
	Level     LogLevel               `json:"level,omitempty"`
	Source    string                 `json:"source,omitempty"`
	Service   string                 `json:"service,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Limit     int                    `json:"limit"`
}

// LogQueryResult represents query results
type LogQueryResult struct {
	Entries      []*LogEntry            `json:"entries"`
	TotalCount   int64                  `json:"total_count"`
	QueryTime    time.Duration          `json:"query_time"`
	Aggregations map[string]interface{} `json:"aggregations"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AlertCondition represents an alert condition
type AlertCondition struct {
	Type     ConditionType `json:"type"`
	Operator string        `json:"operator"` // gt, lt, eq, contains
	Field    string        `json:"field"`
	Value    interface{}   `json:"value"`
}

// AlertAction represents an alert action
type AlertAction struct {
	Type       ActionType        `json:"type"`
	Target     string            `json:"target"`
	Parameters map[string]string `json:"parameters"`
}

// LogStatistics represents log statistics
type LogStatistics struct {
	TotalLogs     int64              `json:"total_logs"`
	LogsByLevel   map[LogLevel]int64 `json:"logs_by_level"`
	LogsBySource  map[string]int64   `json:"logs_by_source"`
	LogsByService map[string]int64   `json:"logs_by_service"`
	ErrorRate     float64            `json:"error_rate"`
	TopErrors     []ErrorSummary     `json:"top_errors"`
	TimeRange     TimeRange          `json:"time_range"`
	LastUpdated   time.Time          `json:"last_updated"`
}

// ErrorSummary represents an error summary
type ErrorSummary struct {
	Message   string    `json:"message"`
	Count     int64     `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	FirstSeen time.Time `json:"first_seen"`
	Sources   []string  `json:"sources"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Enums
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

type ProcessorType string

const (
	ProcessorTypeParser      ProcessorType = "parser"
	ProcessorTypeEnricher    ProcessorType = "enricher"
	ProcessorTypeFilter      ProcessorType = "filter"
	ProcessorTypeTransformer ProcessorType = "transformer"
)

type ExporterType string

const (
	ExporterTypeElasticsearch ExporterType = "elasticsearch"
	ExporterTypeSplunk        ExporterType = "splunk"
	ExporterTypeFluentd       ExporterType = "fluentd"
	ExporterTypeKafka         ExporterType = "kafka"
	ExporterTypeFile          ExporterType = "file"
)

type ConditionType string

const (
	ConditionTypeCount   ConditionType = "count"
	ConditionTypeRate    ConditionType = "rate"
	ConditionTypePattern ConditionType = "pattern"
	ConditionTypeAnomaly ConditionType = "anomaly"
)

type ActionType string

const (
	ActionTypeEmail     ActionType = "email"
	ActionTypeSlack     ActionType = "slack"
	ActionTypeWebhook   ActionType = "webhook"
	ActionTypePagerDuty ActionType = "pagerduty"
)

type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// NewLogAggregator creates a new log aggregator
func NewLogAggregator(config *Config) *LogAggregator {
	if config == nil {
		config = DefaultConfig()
	}

	aggregator := &LogAggregator{
		config:     config,
		logs:       make([]*LogEntry, 0),
		processors: make(map[string]LogProcessor),
		exporters:  make(map[string]LogExporter),
		patterns:   make(map[string]*LogPattern),
		alerts:     make(map[string]*LogAlert),
		logger:     logx.WithContext(context.Background()),
	}

	// Initialize default patterns and alerts
	aggregator.initializeDefaults()

	return aggregator
}

// DefaultConfig returns default log aggregator configuration
func DefaultConfig() *Config {
	return &Config{
		EnableStructuredLogging: true,
		EnableLogParsing:        true,
		EnableAnomalyDetection:  true,
		EnableAlerts:            true,
		MaxLogEntries:           100000,
		RetentionPeriod:         24, // 24 hours
		ProcessingInterval:      5,  // 5 seconds
		ExportInterval:          60, // 1 minute
		LogLevel:                "info",
	}
}

// StartAggregation starts log aggregation
func (la *LogAggregator) StartAggregation(ctx context.Context) error {
	// Start all processors
	for name, processor := range la.processors {
		err := processor.Start(ctx)
		if err != nil {
			la.logger.Errorf("Failed to start processor %s: %v", name, err)
		}
	}

	// Start all exporters
	for name, exporter := range la.exporters {
		err := exporter.Start(ctx)
		if err != nil {
			la.logger.Errorf("Failed to start exporter %s: %v", name, err)
		}
	}

	// Start processing loop
	go la.processingLoop(ctx)

	// Start export loop
	go la.exportLoop(ctx)

	// Start alert monitoring
	if la.config.EnableAlerts {
		go la.alertLoop(ctx)
	}

	la.logger.Infof("Started log aggregation")
	return nil
}

// StopAggregation stops log aggregation
func (la *LogAggregator) StopAggregation(ctx context.Context) error {
	// Stop all processors
	for name, processor := range la.processors {
		err := processor.Stop(ctx)
		if err != nil {
			la.logger.Errorf("Failed to stop processor %s: %v", name, err)
		}
	}

	// Stop all exporters
	for name, exporter := range la.exporters {
		err := exporter.Stop(ctx)
		if err != nil {
			la.logger.Errorf("Failed to stop exporter %s: %v", name, err)
		}
	}

	la.logger.Infof("Stopped log aggregation")
	return nil
}

// IngestLog ingests a log entry
func (la *LogAggregator) IngestLog(entry *LogEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	if entry.ID == "" {
		entry.ID = la.generateLogID()
	}

	// Process the log entry
	processedEntry := entry
	for _, processor := range la.processors {
		var err error
		processedEntry, err = processor.Process(context.Background(), processedEntry)
		if err != nil {
			la.logger.Errorf("Failed to process log with %s: %v", processor.GetName(), err)
			continue
		}
	}

	la.mutex.Lock()
	defer la.mutex.Unlock()

	// Check log limit
	if len(la.logs) >= la.config.MaxLogEntries {
		la.evictOldLogs()
	}

	la.logs = append(la.logs, processedEntry)
	return nil
}

// QueryLogs queries log entries
func (la *LogAggregator) QueryLogs(ctx context.Context, query *LogQuery) (*LogQueryResult, error) {
	start := time.Now()

	la.mutex.RLock()
	defer la.mutex.RUnlock()

	var matchedLogs []*LogEntry
	for _, entry := range la.logs {
		if la.matchesQuery(entry, query) {
			matchedLogs = append(matchedLogs, entry)
		}
	}

	// Apply limit
	if query.Limit > 0 && len(matchedLogs) > query.Limit {
		matchedLogs = matchedLogs[:query.Limit]
	}

	result := &LogQueryResult{
		Entries:      matchedLogs,
		TotalCount:   int64(len(matchedLogs)),
		QueryTime:    time.Since(start),
		Aggregations: make(map[string]interface{}),
		Metadata:     make(map[string]interface{}),
	}

	return result, nil
}

// GetLogStatistics gets log statistics
func (la *LogAggregator) GetLogStatistics(timeRange TimeRange) (*LogStatistics, error) {
	la.mutex.RLock()
	defer la.mutex.RUnlock()

	stats := &LogStatistics{
		LogsByLevel:   make(map[LogLevel]int64),
		LogsBySource:  make(map[string]int64),
		LogsByService: make(map[string]int64),
		TopErrors:     make([]ErrorSummary, 0),
		TimeRange:     timeRange,
		LastUpdated:   time.Now(),
	}

	totalLogs := int64(0)
	errorCount := int64(0)
	errorMessages := make(map[string]*ErrorSummary)

	for _, entry := range la.logs {
		// Check time range
		if !timeRange.Start.IsZero() && entry.Timestamp.Before(timeRange.Start) {
			continue
		}
		if !timeRange.End.IsZero() && entry.Timestamp.After(timeRange.End) {
			continue
		}

		totalLogs++
		stats.LogsByLevel[entry.Level]++
		stats.LogsBySource[entry.Source]++
		stats.LogsByService[entry.Service]++

		// Track errors
		if entry.Level == LogLevelError || entry.Level == LogLevelFatal {
			errorCount++

			if summary, exists := errorMessages[entry.Message]; exists {
				summary.Count++
				if entry.Timestamp.After(summary.LastSeen) {
					summary.LastSeen = entry.Timestamp
				}
				if entry.Timestamp.Before(summary.FirstSeen) {
					summary.FirstSeen = entry.Timestamp
				}
			} else {
				errorMessages[entry.Message] = &ErrorSummary{
					Message:   entry.Message,
					Count:     1,
					LastSeen:  entry.Timestamp,
					FirstSeen: entry.Timestamp,
					Sources:   []string{entry.Source},
				}
			}
		}
	}

	stats.TotalLogs = totalLogs
	if totalLogs > 0 {
		stats.ErrorRate = float64(errorCount) / float64(totalLogs)
	}

	// Convert error map to slice and sort by count
	for _, summary := range errorMessages {
		stats.TopErrors = append(stats.TopErrors, *summary)
	}

	return stats, nil
}

// RegisterProcessor registers a log processor
func (la *LogAggregator) RegisterProcessor(processor LogProcessor) error {
	la.mutex.Lock()
	defer la.mutex.Unlock()

	la.processors[processor.GetName()] = processor
	la.logger.Infof("Registered log processor: %s (%s)", processor.GetName(), processor.GetType())
	return nil
}

// RegisterExporter registers a log exporter
func (la *LogAggregator) RegisterExporter(exporter LogExporter) error {
	la.mutex.Lock()
	defer la.mutex.Unlock()

	la.exporters[exporter.GetName()] = exporter
	la.logger.Infof("Registered log exporter: %s (%s)", exporter.GetName(), exporter.GetType())
	return nil
}

// Helper methods

func (la *LogAggregator) processingLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(la.config.ProcessingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			la.processLogs(ctx)
		}
	}
}

func (la *LogAggregator) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(la.config.ExportInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			la.exportLogs(ctx)
		}
	}
}

func (la *LogAggregator) alertLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check alerts every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			la.checkAlerts(ctx)
		}
	}
}

func (la *LogAggregator) processLogs(ctx context.Context) {
	// Clean up old logs
	la.cleanupOldLogs()

	// Perform anomaly detection if enabled
	if la.config.EnableAnomalyDetection {
		la.detectAnomalies()
	}
}

func (la *LogAggregator) exportLogs(ctx context.Context) {
	la.mutex.RLock()
	logs := make([]*LogEntry, len(la.logs))
	copy(logs, la.logs)
	la.mutex.RUnlock()

	for name, exporter := range la.exporters {
		err := exporter.Export(ctx, logs)
		if err != nil {
			la.logger.Errorf("Failed to export logs to %s: %v", name, err)
		}
	}
}

func (la *LogAggregator) checkAlerts(ctx context.Context) {
	for _, alert := range la.alerts {
		if !alert.IsActive {
			continue
		}

		triggered := la.evaluateAlert(alert)
		if triggered {
			la.triggerAlert(alert)
		}
	}
}

func (la *LogAggregator) generateLogID() string {
	return fmt.Sprintf("log_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
}

func (la *LogAggregator) matchesQuery(entry *LogEntry, query *LogQuery) bool {
	// Check level
	if query.Level != "" && entry.Level != query.Level {
		return false
	}

	// Check source
	if query.Source != "" && entry.Source != query.Source {
		return false
	}

	// Check service
	if query.Service != "" && entry.Service != query.Service {
		return false
	}

	// Check message
	if query.Message != "" && entry.Message != query.Message {
		return false
	}

	// Check time range
	if !query.StartTime.IsZero() && entry.Timestamp.Before(query.StartTime) {
		return false
	}
	if !query.EndTime.IsZero() && entry.Timestamp.After(query.EndTime) {
		return false
	}

	// Check tags
	for _, tag := range query.Tags {
		found := false
		for _, entryTag := range entry.Tags {
			if entryTag == tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (la *LogAggregator) evictOldLogs() {
	// Remove oldest logs when limit is reached
	if len(la.logs) < la.config.MaxLogEntries {
		return
	}

	// Remove 10% of oldest logs
	removeCount := la.config.MaxLogEntries / 10
	if removeCount > 0 {
		la.logs = la.logs[removeCount:]
	}
}

func (la *LogAggregator) cleanupOldLogs() {
	la.mutex.Lock()
	defer la.mutex.Unlock()

	cutoff := time.Now().Add(-time.Duration(la.config.RetentionPeriod) * time.Hour)

	var filteredLogs []*LogEntry
	for _, entry := range la.logs {
		if entry.Timestamp.After(cutoff) {
			filteredLogs = append(filteredLogs, entry)
		}
	}

	la.logs = filteredLogs
}

func (la *LogAggregator) detectAnomalies() {
	// Simple anomaly detection - look for error rate spikes
	recentLogs := la.getRecentLogs(time.Hour)
	if len(recentLogs) < 100 {
		return
	}

	errorCount := 0
	for _, entry := range recentLogs {
		if entry.Level == LogLevelError || entry.Level == LogLevelFatal {
			errorCount++
		}
	}

	errorRate := float64(errorCount) / float64(len(recentLogs))
	if errorRate > 0.1 { // 10% error rate threshold
		la.logger.Errorf("Anomaly detected: high error rate %.2f%%", errorRate*100)
	}
}

func (la *LogAggregator) getRecentLogs(duration time.Duration) []*LogEntry {
	cutoff := time.Now().Add(-duration)
	var recentLogs []*LogEntry

	for _, entry := range la.logs {
		if entry.Timestamp.After(cutoff) {
			recentLogs = append(recentLogs, entry)
		}
	}

	return recentLogs
}

func (la *LogAggregator) evaluateAlert(alert *LogAlert) bool {
	// Simple alert evaluation
	query := &alert.Query
	query.StartTime = time.Now().Add(-alert.Window)
	query.EndTime = time.Now()

	result, err := la.QueryLogs(context.Background(), query)
	if err != nil {
		return false
	}

	switch alert.Condition.Type {
	case ConditionTypeCount:
		return float64(result.TotalCount) > alert.Threshold
	case ConditionTypeRate:
		windowLogs := la.getRecentLogs(alert.Window)
		if len(windowLogs) == 0 {
			return false
		}
		rate := float64(result.TotalCount) / float64(len(windowLogs))
		return rate > alert.Threshold
	default:
		return false
	}
}

func (la *LogAggregator) triggerAlert(alert *LogAlert) {
	now := time.Now()
	alert.LastTriggered = &now

	la.logger.Errorf("Alert triggered: %s (%s)", alert.Name, alert.Severity)

	// Execute alert actions
	for _, action := range alert.Actions {
		la.executeAlertAction(action, alert)
	}
}

func (la *LogAggregator) executeAlertAction(action AlertAction, alert *LogAlert) {
	switch action.Type {
	case ActionTypeEmail:
		la.logger.Infof("Sending email alert: %s", alert.Name)
	case ActionTypeSlack:
		la.logger.Infof("Sending Slack alert: %s", alert.Name)
	case ActionTypeWebhook:
		la.logger.Infof("Sending webhook alert: %s", alert.Name)
	default:
		la.logger.Errorf("Unknown alert action type: %s", action.Type)
	}
}

func (la *LogAggregator) initializeDefaults() {
	// Default log patterns
	patterns := []*LogPattern{
		{
			ID:          "nginx_access",
			Name:        "Nginx Access Log",
			Pattern:     `^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+)`,
			Fields:      []string{"ip", "timestamp", "method", "url", "protocol", "status", "size"},
			Source:      "nginx",
			Description: "Standard Nginx access log format",
			CreatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, pattern := range patterns {
		la.patterns[pattern.ID] = pattern
	}

	// Default alerts
	alerts := []*LogAlert{
		{
			ID:          "high_error_rate",
			Name:        "High Error Rate",
			Description: "Alert when error rate exceeds threshold",
			Query: LogQuery{
				Level: LogLevelError,
			},
			Condition: AlertCondition{
				Type:     ConditionTypeRate,
				Operator: "gt",
				Field:    "level",
				Value:    "error",
			},
			Threshold: 0.05, // 5%
			Window:    5 * time.Minute,
			Severity:  AlertSeverityHigh,
			Actions: []AlertAction{
				{Type: ActionTypeEmail, Target: "admin@example.com"},
			},
			CreatedAt: time.Now(),
			IsActive:  true,
		},
	}

	for _, alert := range alerts {
		la.alerts[alert.ID] = alert
	}
}

// Mock implementations for demonstration

// JSONLogProcessor processes JSON logs
type JSONLogProcessor struct {
	name string
}

func (p *JSONLogProcessor) GetName() string        { return p.name }
func (p *JSONLogProcessor) GetType() ProcessorType { return ProcessorTypeParser }

func (p *JSONLogProcessor) Process(ctx context.Context, entry *LogEntry) (*LogEntry, error) {
	// Try to parse message as JSON
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(entry.Message), &jsonData)
	if err == nil {
		// Merge JSON fields into entry fields
		if entry.Fields == nil {
			entry.Fields = make(map[string]interface{})
		}
		for key, value := range jsonData {
			entry.Fields[key] = value
		}
	}

	return entry, nil
}

func (p *JSONLogProcessor) Start(ctx context.Context) error { return nil }
func (p *JSONLogProcessor) Stop(ctx context.Context) error  { return nil }
