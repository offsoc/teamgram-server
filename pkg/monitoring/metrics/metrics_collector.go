package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// MetricsCollector provides comprehensive metrics collection
type MetricsCollector struct {
	config    *Config
	metrics   map[string]*Metric
	collectors map[string]Collector
	exporters map[string]Exporter
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for metrics collector
type Config struct {
	EnableSystemMetrics    bool   `json:"enable_system_metrics"`
	EnableApplicationMetrics bool `json:"enable_application_metrics"`
	EnableCustomMetrics    bool   `json:"enable_custom_metrics"`
	CollectionInterval     int    `json:"collection_interval"`     // seconds
	RetentionPeriod        int    `json:"retention_period"`        // hours
	MaxMetrics             int    `json:"max_metrics"`
	ExportInterval         int    `json:"export_interval"`         // seconds
	EnableAggregation      bool   `json:"enable_aggregation"`
}

// Metric represents a metric
type Metric struct {
	Name        string            `json:"name"`
	Type        MetricType        `json:"type"`
	Value       interface{}       `json:"value"`
	Unit        string            `json:"unit"`
	Labels      map[string]string `json:"labels"`
	Timestamp   time.Time         `json:"timestamp"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Metadata    map[string]string `json:"metadata"`
}

// Collector interface for metric collection
type Collector interface {
	GetName() string
	GetType() CollectorType
	Collect(ctx context.Context) ([]*Metric, error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Exporter interface for metric export
type Exporter interface {
	GetName() string
	GetType() ExporterType
	Export(ctx context.Context, metrics []*Metric) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// MetricSample represents a metric sample
type MetricSample struct {
	Metric    *Metric   `json:"metric"`
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// AggregatedMetric represents an aggregated metric
type AggregatedMetric struct {
	Name      string            `json:"name"`
	Type      MetricType        `json:"type"`
	Labels    map[string]string `json:"labels"`
	Count     int64             `json:"count"`
	Sum       float64           `json:"sum"`
	Min       float64           `json:"min"`
	Max       float64           `json:"max"`
	Average   float64           `json:"average"`
	Percentiles map[string]float64 `json:"percentiles"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
}

// MetricsQuery represents a metrics query
type MetricsQuery struct {
	MetricName string            `json:"metric_name"`
	Labels     map[string]string `json:"labels"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Aggregation string           `json:"aggregation"` // sum, avg, min, max, count
	GroupBy    []string          `json:"group_by"`
	Limit      int               `json:"limit"`
}

// MetricsQueryResult represents query results
type MetricsQueryResult struct {
	Metrics     []*Metric          `json:"metrics"`
	Aggregated  []*AggregatedMetric `json:"aggregated"`
	TotalCount  int64              `json:"total_count"`
	QueryTime   time.Duration      `json:"query_time"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums
type MetricType string
const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

type CollectorType string
const (
	CollectorTypeSystem      CollectorType = "system"
	CollectorTypeApplication CollectorType = "application"
	CollectorTypeCustom      CollectorType = "custom"
	CollectorTypeNetwork     CollectorType = "network"
	CollectorTypeDatabase    CollectorType = "database"
)

type ExporterType string
const (
	ExporterTypePrometheus ExporterType = "prometheus"
	ExporterTypeInfluxDB   ExporterType = "influxdb"
	ExporterTypeElastic    ExporterType = "elasticsearch"
	ExporterTypeCloudWatch ExporterType = "cloudwatch"
	ExporterTypeCustom     ExporterType = "custom"
)

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(config *Config) *MetricsCollector {
	if config == nil {
		config = DefaultConfig()
	}

	collector := &MetricsCollector{
		config:     config,
		metrics:    make(map[string]*Metric),
		collectors: make(map[string]Collector),
		exporters:  make(map[string]Exporter),
		logger:     logx.WithContext(context.Background()),
	}

	// Initialize default collectors
	collector.initializeDefaultCollectors()

	return collector
}

// DefaultConfig returns default metrics collector configuration
func DefaultConfig() *Config {
	return &Config{
		EnableSystemMetrics:      true,
		EnableApplicationMetrics: true,
		EnableCustomMetrics:      true,
		CollectionInterval:       15,   // 15 seconds
		RetentionPeriod:          24,   // 24 hours
		MaxMetrics:               10000,
		ExportInterval:           60,   // 1 minute
		EnableAggregation:        true,
	}
}

// StartCollection starts metric collection
func (mc *MetricsCollector) StartCollection(ctx context.Context) error {
	// Start all collectors
	for name, collector := range mc.collectors {
		err := collector.Start(ctx)
		if err != nil {
			mc.logger.Errorf("Failed to start collector %s: %v", name, err)
		}
	}

	// Start collection loop
	go mc.collectionLoop(ctx)

	// Start export loop
	go mc.exportLoop(ctx)

	mc.logger.Infof("Started metrics collection")
	return nil
}

// StopCollection stops metric collection
func (mc *MetricsCollector) StopCollection(ctx context.Context) error {
	// Stop all collectors
	for name, collector := range mc.collectors {
		err := collector.Stop(ctx)
		if err != nil {
			mc.logger.Errorf("Failed to stop collector %s: %v", name, err)
		}
	}

	// Stop all exporters
	for name, exporter := range mc.exporters {
		err := exporter.Stop(ctx)
		if err != nil {
			mc.logger.Errorf("Failed to stop exporter %s: %v", name, err)
		}
	}

	mc.logger.Infof("Stopped metrics collection")
	return nil
}

// RecordMetric records a custom metric
func (mc *MetricsCollector) RecordMetric(metric *Metric) error {
	if !mc.config.EnableCustomMetrics {
		return fmt.Errorf("custom metrics are disabled")
	}

	metric.Timestamp = time.Now()
	
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// Check metrics limit
	if len(mc.metrics) >= mc.config.MaxMetrics {
		mc.evictOldMetrics()
	}

	key := mc.generateMetricKey(metric)
	mc.metrics[key] = metric

	return nil
}

// QueryMetrics queries metrics
func (mc *MetricsCollector) QueryMetrics(ctx context.Context, query *MetricsQuery) (*MetricsQueryResult, error) {
	start := time.Now()

	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	var matchedMetrics []*Metric
	for _, metric := range mc.metrics {
		if mc.matchesQuery(metric, query) {
			matchedMetrics = append(matchedMetrics, metric)
		}
	}

	// Apply limit
	if query.Limit > 0 && len(matchedMetrics) > query.Limit {
		matchedMetrics = matchedMetrics[:query.Limit]
	}

	result := &MetricsQueryResult{
		Metrics:    matchedMetrics,
		TotalCount: int64(len(matchedMetrics)),
		QueryTime:  time.Since(start),
		Metadata:   make(map[string]interface{}),
	}

	// Apply aggregation if requested
	if query.Aggregation != "" && mc.config.EnableAggregation {
		aggregated := mc.aggregateMetrics(matchedMetrics, query)
		result.Aggregated = aggregated
	}

	return result, nil
}

// GetMetricsSummary gets a summary of all metrics
func (mc *MetricsCollector) GetMetricsSummary() map[string]interface{} {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	summary := make(map[string]interface{})
	
	totalMetrics := len(mc.metrics)
	metricsByType := make(map[MetricType]int)
	metricsBySource := make(map[string]int)

	for _, metric := range mc.metrics {
		metricsByType[metric.Type]++
		metricsBySource[metric.Source]++
	}

	summary["total_metrics"] = totalMetrics
	summary["metrics_by_type"] = metricsByType
	summary["metrics_by_source"] = metricsBySource
	summary["collection_interval"] = mc.config.CollectionInterval
	summary["retention_period"] = mc.config.RetentionPeriod

	return summary
}

// RegisterCollector registers a metric collector
func (mc *MetricsCollector) RegisterCollector(collector Collector) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.collectors[collector.GetName()] = collector
	mc.logger.Infof("Registered metrics collector: %s (%s)", collector.GetName(), collector.GetType())
	return nil
}

// RegisterExporter registers a metric exporter
func (mc *MetricsCollector) RegisterExporter(exporter Exporter) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.exporters[exporter.GetName()] = exporter
	mc.logger.Infof("Registered metrics exporter: %s (%s)", exporter.GetName(), exporter.GetType())
	return nil
}

// Helper methods

func (mc *MetricsCollector) collectionLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(mc.config.CollectionInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mc.collectMetrics(ctx)
		}
	}
}

func (mc *MetricsCollector) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(mc.config.ExportInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mc.exportMetrics(ctx)
		}
	}
}

func (mc *MetricsCollector) collectMetrics(ctx context.Context) {
	for name, collector := range mc.collectors {
		metrics, err := collector.Collect(ctx)
		if err != nil {
			mc.logger.Errorf("Failed to collect metrics from %s: %v", name, err)
			continue
		}

		mc.mutex.Lock()
		for _, metric := range metrics {
			key := mc.generateMetricKey(metric)
			mc.metrics[key] = metric
		}
		mc.mutex.Unlock()
	}

	// Clean up old metrics
	mc.cleanupOldMetrics()
}

func (mc *MetricsCollector) exportMetrics(ctx context.Context) {
	mc.mutex.RLock()
	metrics := make([]*Metric, 0, len(mc.metrics))
	for _, metric := range mc.metrics {
		metrics = append(metrics, metric)
	}
	mc.mutex.RUnlock()

	for name, exporter := range mc.exporters {
		err := exporter.Export(ctx, metrics)
		if err != nil {
			mc.logger.Errorf("Failed to export metrics to %s: %v", name, err)
		}
	}
}

func (mc *MetricsCollector) generateMetricKey(metric *Metric) string {
	return fmt.Sprintf("%s_%s_%d", metric.Name, metric.Source, metric.Timestamp.Unix())
}

func (mc *MetricsCollector) matchesQuery(metric *Metric, query *MetricsQuery) bool {
	// Check metric name
	if query.MetricName != "" && metric.Name != query.MetricName {
		return false
	}

	// Check time range
	if !query.StartTime.IsZero() && metric.Timestamp.Before(query.StartTime) {
		return false
	}
	if !query.EndTime.IsZero() && metric.Timestamp.After(query.EndTime) {
		return false
	}

	// Check labels
	for key, value := range query.Labels {
		if metricValue, exists := metric.Labels[key]; !exists || metricValue != value {
			return false
		}
	}

	return true
}

func (mc *MetricsCollector) aggregateMetrics(metrics []*Metric, query *MetricsQuery) []*AggregatedMetric {
	// Group metrics by labels
	groups := make(map[string][]*Metric)
	
	for _, metric := range metrics {
		groupKey := mc.generateGroupKey(metric, query.GroupBy)
		groups[groupKey] = append(groups[groupKey], metric)
	}

	// Aggregate each group
	var aggregated []*AggregatedMetric
	for _, group := range groups {
		agg := mc.aggregateGroup(group, query.Aggregation)
		aggregated = append(aggregated, agg)
	}

	return aggregated
}

func (mc *MetricsCollector) generateGroupKey(metric *Metric, groupBy []string) string {
	if len(groupBy) == 0 {
		return "default"
	}

	key := ""
	for _, field := range groupBy {
		if value, exists := metric.Labels[field]; exists {
			key += field + "=" + value + ","
		}
	}

	return key
}

func (mc *MetricsCollector) aggregateGroup(metrics []*Metric, aggregation string) *AggregatedMetric {
	if len(metrics) == 0 {
		return nil
	}

	agg := &AggregatedMetric{
		Name:        metrics[0].Name,
		Type:        metrics[0].Type,
		Labels:      metrics[0].Labels,
		Count:       int64(len(metrics)),
		StartTime:   metrics[0].Timestamp,
		EndTime:     metrics[0].Timestamp,
		Percentiles: make(map[string]float64),
	}

	values := make([]float64, 0, len(metrics))
	sum := 0.0

	for _, metric := range metrics {
		value := mc.extractNumericValue(metric.Value)
		values = append(values, value)
		sum += value

		if metric.Timestamp.Before(agg.StartTime) {
			agg.StartTime = metric.Timestamp
		}
		if metric.Timestamp.After(agg.EndTime) {
			agg.EndTime = metric.Timestamp
		}
	}

	agg.Sum = sum
	agg.Average = sum / float64(len(values))

	if len(values) > 0 {
		agg.Min = values[0]
		agg.Max = values[0]
		
		for _, value := range values {
			if value < agg.Min {
				agg.Min = value
			}
			if value > agg.Max {
				agg.Max = value
			}
		}
	}

	return agg
}

func (mc *MetricsCollector) extractNumericValue(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case int32:
		return float64(v)
	default:
		return 0.0
	}
}

func (mc *MetricsCollector) evictOldMetrics() {
	// Simple eviction - remove oldest metrics
	if len(mc.metrics) < mc.config.MaxMetrics {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	for key, metric := range mc.metrics {
		if oldestKey == "" || metric.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = metric.Timestamp
		}
	}

	if oldestKey != "" {
		delete(mc.metrics, oldestKey)
	}
}

func (mc *MetricsCollector) cleanupOldMetrics() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	cutoff := time.Now().Add(-time.Duration(mc.config.RetentionPeriod) * time.Hour)
	
	for key, metric := range mc.metrics {
		if metric.Timestamp.Before(cutoff) {
			delete(mc.metrics, key)
		}
	}
}

func (mc *MetricsCollector) initializeDefaultCollectors() {
	// System metrics collector
	if mc.config.EnableSystemMetrics {
		systemCollector := &SystemMetricsCollector{
			name: "system_metrics",
		}
		mc.collectors[systemCollector.GetName()] = systemCollector
	}

	// Application metrics collector
	if mc.config.EnableApplicationMetrics {
		appCollector := &ApplicationMetricsCollector{
			name: "application_metrics",
		}
		mc.collectors[appCollector.GetName()] = appCollector
	}
}

// Mock implementations for demonstration

// SystemMetricsCollector collects system metrics
type SystemMetricsCollector struct {
	name string
}

func (c *SystemMetricsCollector) GetName() string { return c.name }
func (c *SystemMetricsCollector) GetType() CollectorType { return CollectorTypeSystem }

func (c *SystemMetricsCollector) Collect(ctx context.Context) ([]*Metric, error) {
	metrics := []*Metric{
		{
			Name:        "cpu_usage",
			Type:        MetricTypeGauge,
			Value:       float64(time.Now().Unix() % 100),
			Unit:        "percent",
			Labels:      map[string]string{"host": "localhost"},
			Timestamp:   time.Now(),
			Description: "CPU usage percentage",
			Source:      "system",
		},
		{
			Name:        "memory_usage",
			Type:        MetricTypeGauge,
			Value:       float64(time.Now().Unix() % 80),
			Unit:        "percent",
			Labels:      map[string]string{"host": "localhost"},
			Timestamp:   time.Now(),
			Description: "Memory usage percentage",
			Source:      "system",
		},
	}

	return metrics, nil
}

func (c *SystemMetricsCollector) Start(ctx context.Context) error { return nil }
func (c *SystemMetricsCollector) Stop(ctx context.Context) error { return nil }

// ApplicationMetricsCollector collects application metrics
type ApplicationMetricsCollector struct {
	name string
}

func (c *ApplicationMetricsCollector) GetName() string { return c.name }
func (c *ApplicationMetricsCollector) GetType() CollectorType { return CollectorTypeApplication }

func (c *ApplicationMetricsCollector) Collect(ctx context.Context) ([]*Metric, error) {
	metrics := []*Metric{
		{
			Name:        "request_count",
			Type:        MetricTypeCounter,
			Value:       int64(time.Now().Unix() % 1000),
			Unit:        "requests",
			Labels:      map[string]string{"service": "teamgram", "method": "GET"},
			Timestamp:   time.Now(),
			Description: "Total number of requests",
			Source:      "application",
		},
		{
			Name:        "response_time",
			Type:        MetricTypeHistogram,
			Value:       float64(time.Now().Unix()%500 + 50),
			Unit:        "milliseconds",
			Labels:      map[string]string{"service": "teamgram", "endpoint": "/api/messages"},
			Timestamp:   time.Now(),
			Description: "Response time in milliseconds",
			Source:      "application",
		},
	}

	return metrics, nil
}

func (c *ApplicationMetricsCollector) Start(ctx context.Context) error { return nil }
func (c *ApplicationMetricsCollector) Stop(ctx context.Context) error { return nil }
