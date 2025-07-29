package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// DistributedTracer provides distributed tracing capabilities
type DistributedTracer struct {
	config    *Config
	traces    map[string]*Trace
	spans     map[string]*Span
	exporters map[string]TraceExporter
	samplers  map[string]Sampler
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for distributed tracer
type Config struct {
	ServiceName        string  `json:"service_name"`
	ServiceVersion     string  `json:"service_version"`
	SamplingRate       float64 `json:"sampling_rate"`
	MaxTraces          int     `json:"max_traces"`
	MaxSpansPerTrace   int     `json:"max_spans_per_trace"`
	TraceTimeout       int     `json:"trace_timeout"`       // seconds
	ExportInterval     int     `json:"export_interval"`     // seconds
	EnableProfiling    bool    `json:"enable_profiling"`
	EnableMetrics      bool    `json:"enable_metrics"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
}

// Trace represents a distributed trace
type Trace struct {
	TraceID     string            `json:"trace_id"`
	SpanCount   int               `json:"span_count"`
	RootSpan    *Span             `json:"root_span"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     *time.Time        `json:"end_time,omitempty"`
	Duration    time.Duration     `json:"duration"`
	Status      TraceStatus       `json:"status"`
	Tags        map[string]string `json:"tags"`
	Baggage     map[string]string `json:"baggage"`
	Metadata    map[string]string `json:"metadata"`
}

// Span represents a span within a trace
type Span struct {
	SpanID       string            `json:"span_id"`
	TraceID      string            `json:"trace_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	OperationName string           `json:"operation_name"`
	ServiceName  string            `json:"service_name"`
	StartTime    time.Time         `json:"start_time"`
	EndTime      *time.Time        `json:"end_time,omitempty"`
	Duration     time.Duration     `json:"duration"`
	Status       SpanStatus        `json:"status"`
	Kind         SpanKind          `json:"kind"`
	Tags         map[string]string `json:"tags"`
	Logs         []SpanLog         `json:"logs"`
	Events       []SpanEvent       `json:"events"`
	Links        []SpanLink        `json:"links"`
	Attributes   map[string]interface{} `json:"attributes"`
	Resource     Resource          `json:"resource"`
	Metadata     map[string]string `json:"metadata"`
}

// SpanLog represents a log entry within a span
type SpanLog struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
}

// SpanEvent represents an event within a span
type SpanEvent struct {
	Name       string                 `json:"name"`
	Timestamp  time.Time              `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
}

// SpanLink represents a link to another span
type SpanLink struct {
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	Type       LinkType               `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Resource represents a resource
type Resource struct {
	ServiceName    string            `json:"service_name"`
	ServiceVersion string            `json:"service_version"`
	HostName       string            `json:"host_name"`
	Attributes     map[string]string `json:"attributes"`
}

// TraceExporter interface for trace export
type TraceExporter interface {
	GetName() string
	GetType() ExporterType
	Export(ctx context.Context, traces []*Trace) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Sampler interface for trace sampling
type Sampler interface {
	GetName() string
	ShouldSample(ctx context.Context, traceID string, spanName string, attributes map[string]interface{}) SamplingResult
}

// SamplingResult represents a sampling decision
type SamplingResult struct {
	Decision   SamplingDecision      `json:"decision"`
	Attributes map[string]interface{} `json:"attributes"`
	TraceState string                `json:"trace_state"`
}

// TraceContext represents trace context for propagation
type TraceContext struct {
	TraceID      string            `json:"trace_id"`
	SpanID       string            `json:"span_id"`
	TraceFlags   byte              `json:"trace_flags"`
	TraceState   string            `json:"trace_state"`
	Baggage      map[string]string `json:"baggage"`
}

// SpanBuilder helps build spans
type SpanBuilder struct {
	tracer        *DistributedTracer
	operationName string
	parentSpan    *Span
	startTime     time.Time
	tags          map[string]string
	attributes    map[string]interface{}
	kind          SpanKind
}

// Enums
type TraceStatus string
const (
	TraceStatusActive    TraceStatus = "active"
	TraceStatusCompleted TraceStatus = "completed"
	TraceStatusError     TraceStatus = "error"
	TraceStatusTimeout   TraceStatus = "timeout"
)

type SpanStatus string
const (
	SpanStatusUnset SpanStatus = "unset"
	SpanStatusOk    SpanStatus = "ok"
	SpanStatusError SpanStatus = "error"
)

type SpanKind string
const (
	SpanKindInternal SpanKind = "internal"
	SpanKindServer   SpanKind = "server"
	SpanKindClient   SpanKind = "client"
	SpanKindProducer SpanKind = "producer"
	SpanKindConsumer SpanKind = "consumer"
)

type LinkType string
const (
	LinkTypeChild  LinkType = "child"
	LinkTypeParent LinkType = "parent"
	LinkTypeFollows LinkType = "follows"
)

type ExporterType string
const (
	ExporterTypeJaeger     ExporterType = "jaeger"
	ExporterTypeZipkin     ExporterType = "zipkin"
	ExporterTypeOTLP       ExporterType = "otlp"
	ExporterTypeConsole    ExporterType = "console"
	ExporterTypePrometheus ExporterType = "prometheus"
)

type SamplingDecision string
const (
	SamplingDecisionDrop   SamplingDecision = "drop"
	SamplingDecisionRecord SamplingDecision = "record"
	SamplingDecisionSample SamplingDecision = "sample"
)

// NewDistributedTracer creates a new distributed tracer
func NewDistributedTracer(config *Config) *DistributedTracer {
	if config == nil {
		config = DefaultConfig()
	}

	tracer := &DistributedTracer{
		config:    config,
		traces:    make(map[string]*Trace),
		spans:     make(map[string]*Span),
		exporters: make(map[string]TraceExporter),
		samplers:  make(map[string]Sampler),
		logger:    logx.WithContext(context.Background()),
	}

	// Initialize default samplers
	tracer.initializeDefaultSamplers()

	return tracer
}

// DefaultConfig returns default distributed tracer configuration
func DefaultConfig() *Config {
	return &Config{
		ServiceName:        "teamgram",
		ServiceVersion:     "1.0.0",
		SamplingRate:       0.1,  // 10%
		MaxTraces:          10000,
		MaxSpansPerTrace:   1000,
		TraceTimeout:       300,  // 5 minutes
		ExportInterval:     30,   // 30 seconds
		EnableProfiling:    true,
		EnableMetrics:      true,
		ResourceAttributes: make(map[string]string),
	}
}

// StartSpan starts a new span
func (dt *DistributedTracer) StartSpan(ctx context.Context, operationName string) (*Span, context.Context) {
	builder := dt.NewSpanBuilder(operationName)
	
	// Extract parent span from context
	if parentSpan := dt.SpanFromContext(ctx); parentSpan != nil {
		builder = builder.WithParent(parentSpan)
	}

	span := builder.Start()
	newCtx := dt.ContextWithSpan(ctx, span)
	
	return span, newCtx
}

// NewSpanBuilder creates a new span builder
func (dt *DistributedTracer) NewSpanBuilder(operationName string) *SpanBuilder {
	return &SpanBuilder{
		tracer:        dt,
		operationName: operationName,
		startTime:     time.Now(),
		tags:          make(map[string]string),
		attributes:    make(map[string]interface{}),
		kind:          SpanKindInternal,
	}
}

// WithParent sets the parent span
func (sb *SpanBuilder) WithParent(parent *Span) *SpanBuilder {
	sb.parentSpan = parent
	return sb
}

// WithTag adds a tag
func (sb *SpanBuilder) WithTag(key, value string) *SpanBuilder {
	sb.tags[key] = value
	return sb
}

// WithAttribute adds an attribute
func (sb *SpanBuilder) WithAttribute(key string, value interface{}) *SpanBuilder {
	sb.attributes[key] = value
	return sb
}

// WithKind sets the span kind
func (sb *SpanBuilder) WithKind(kind SpanKind) *SpanBuilder {
	sb.kind = kind
	return sb
}

// WithStartTime sets the start time
func (sb *SpanBuilder) WithStartTime(startTime time.Time) *SpanBuilder {
	sb.startTime = startTime
	return sb
}

// Start creates and starts the span
func (sb *SpanBuilder) Start() *Span {
	spanID := sb.tracer.generateSpanID()
	traceID := spanID // Use span ID as trace ID for root spans
	
	if sb.parentSpan != nil {
		traceID = sb.parentSpan.TraceID
	}

	// Check sampling decision
	samplingResult := sb.tracer.shouldSample(traceID, sb.operationName, sb.attributes)
	if samplingResult.Decision == SamplingDecisionDrop {
		return nil // Return no-op span
	}

	span := &Span{
		SpanID:        spanID,
		TraceID:       traceID,
		OperationName: sb.operationName,
		ServiceName:   sb.tracer.config.ServiceName,
		StartTime:     sb.startTime,
		Status:        SpanStatusUnset,
		Kind:          sb.kind,
		Tags:          sb.tags,
		Logs:          make([]SpanLog, 0),
		Events:        make([]SpanEvent, 0),
		Links:         make([]SpanLink, 0),
		Attributes:    sb.attributes,
		Resource: Resource{
			ServiceName:    sb.tracer.config.ServiceName,
			ServiceVersion: sb.tracer.config.ServiceVersion,
			Attributes:     sb.tracer.config.ResourceAttributes,
		},
		Metadata: make(map[string]string),
	}

	if sb.parentSpan != nil {
		span.ParentSpanID = sb.parentSpan.SpanID
	}

	// Store span
	sb.tracer.mutex.Lock()
	sb.tracer.spans[spanID] = span
	
	// Create or update trace
	if trace, exists := sb.tracer.traces[traceID]; exists {
		trace.SpanCount++
	} else {
		trace := &Trace{
			TraceID:   traceID,
			SpanCount: 1,
			RootSpan:  span,
			StartTime: sb.startTime,
			Status:    TraceStatusActive,
			Tags:      make(map[string]string),
			Baggage:   make(map[string]string),
			Metadata:  make(map[string]string),
		}
		sb.tracer.traces[traceID] = trace
	}
	sb.tracer.mutex.Unlock()

	sb.tracer.logger.Debugf("Started span: %s (trace: %s)", span.OperationName, span.TraceID)
	return span
}

// FinishSpan finishes a span
func (dt *DistributedTracer) FinishSpan(span *Span) {
	if span == nil {
		return
	}

	endTime := time.Now()
	span.EndTime = &endTime
	span.Duration = endTime.Sub(span.StartTime)

	if span.Status == SpanStatusUnset {
		span.Status = SpanStatusOk
	}

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	// Update trace
	if trace, exists := dt.traces[span.TraceID]; exists {
		// Check if all spans in trace are finished
		allFinished := true
		for _, s := range dt.spans {
			if s.TraceID == span.TraceID && s.EndTime == nil {
				allFinished = false
				break
			}
		}

		if allFinished {
			trace.EndTime = &endTime
			trace.Duration = endTime.Sub(trace.StartTime)
			trace.Status = TraceStatusCompleted
		}
	}

	dt.logger.Debugf("Finished span: %s (duration: %v)", span.OperationName, span.Duration)
}

// AddEvent adds an event to a span
func (dt *DistributedTracer) AddEvent(span *Span, name string, attributes map[string]interface{}) {
	if span == nil {
		return
	}

	event := SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attributes,
	}

	span.Events = append(span.Events, event)
}

// AddLog adds a log to a span
func (dt *DistributedTracer) AddLog(span *Span, level, message string, fields map[string]interface{}) {
	if span == nil {
		return
	}

	log := SpanLog{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Fields:    fields,
	}

	span.Logs = append(span.Logs, log)
}

// SetSpanStatus sets the status of a span
func (dt *DistributedTracer) SetSpanStatus(span *Span, status SpanStatus) {
	if span == nil {
		return
	}

	span.Status = status
}

// SetSpanError marks a span as error
func (dt *DistributedTracer) SetSpanError(span *Span, err error) {
	if span == nil {
		return
	}

	span.Status = SpanStatusError
	span.Attributes["error"] = true
	span.Attributes["error.message"] = err.Error()
	
	dt.AddEvent(span, "error", map[string]interface{}{
		"error.message": err.Error(),
		"error.type":    fmt.Sprintf("%T", err),
	})
}

// SpanFromContext extracts span from context
func (dt *DistributedTracer) SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value("span").(*Span); ok {
		return span
	}
	return nil
}

// ContextWithSpan adds span to context
func (dt *DistributedTracer) ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, "span", span)
}

// InjectTraceContext injects trace context into headers
func (dt *DistributedTracer) InjectTraceContext(span *Span, headers map[string]string) {
	if span == nil {
		return
	}

	// W3C Trace Context format
	headers["traceparent"] = fmt.Sprintf("00-%s-%s-01", span.TraceID, span.SpanID)
	
	// Add baggage if present
	if trace, exists := dt.traces[span.TraceID]; exists && len(trace.Baggage) > 0 {
		baggage := ""
		for key, value := range trace.Baggage {
			if baggage != "" {
				baggage += ","
			}
			baggage += fmt.Sprintf("%s=%s", key, value)
		}
		headers["baggage"] = baggage
	}
}

// ExtractTraceContext extracts trace context from headers
func (dt *DistributedTracer) ExtractTraceContext(headers map[string]string) *TraceContext {
	traceparent := headers["traceparent"]
	if traceparent == "" {
		return nil
	}

	// Parse W3C Trace Context format: version-traceId-spanId-flags
	// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
	if len(traceparent) != 55 {
		return nil
	}

	traceID := traceparent[3:35]
	spanID := traceparent[36:52]
	
	context := &TraceContext{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: 1,
		Baggage:    make(map[string]string),
	}

	// Parse baggage
	if baggage := headers["baggage"]; baggage != "" {
		// Simple baggage parsing
		context.Baggage["baggage"] = baggage
	}

	return context
}

// StartExport starts trace export
func (dt *DistributedTracer) StartExport(ctx context.Context) error {
	// Start all exporters
	for name, exporter := range dt.exporters {
		err := exporter.Start(ctx)
		if err != nil {
			dt.logger.Errorf("Failed to start exporter %s: %v", name, err)
		}
	}

	// Start export loop
	go dt.exportLoop(ctx)

	dt.logger.Infof("Started trace export")
	return nil
}

// StopExport stops trace export
func (dt *DistributedTracer) StopExport(ctx context.Context) error {
	// Stop all exporters
	for name, exporter := range dt.exporters {
		err := exporter.Stop(ctx)
		if err != nil {
			dt.logger.Errorf("Failed to stop exporter %s: %v", name, err)
		}
	}

	dt.logger.Infof("Stopped trace export")
	return nil
}

// RegisterExporter registers a trace exporter
func (dt *DistributedTracer) RegisterExporter(exporter TraceExporter) error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	dt.exporters[exporter.GetName()] = exporter
	dt.logger.Infof("Registered trace exporter: %s (%s)", exporter.GetName(), exporter.GetType())
	return nil
}

// Helper methods

func (dt *DistributedTracer) generateSpanID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (dt *DistributedTracer) shouldSample(traceID, spanName string, attributes map[string]interface{}) SamplingResult {
	// Use first available sampler
	for _, sampler := range dt.samplers {
		return sampler.ShouldSample(context.Background(), traceID, spanName, attributes)
	}

	// Default sampling based on rate
	decision := SamplingDecisionDrop
	if dt.config.SamplingRate > 0 {
		// Simple hash-based sampling
		hash := 0
		for _, b := range []byte(traceID) {
			hash = hash*31 + int(b)
		}
		if float64(hash%100)/100.0 < dt.config.SamplingRate {
			decision = SamplingDecisionSample
		}
	}

	return SamplingResult{
		Decision:   decision,
		Attributes: make(map[string]interface{}),
	}
}

func (dt *DistributedTracer) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(dt.config.ExportInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dt.exportTraces(ctx)
		}
	}
}

func (dt *DistributedTracer) exportTraces(ctx context.Context) {
	dt.mutex.RLock()
	traces := make([]*Trace, 0, len(dt.traces))
	for _, trace := range dt.traces {
		if trace.Status == TraceStatusCompleted {
			traces = append(traces, trace)
		}
	}
	dt.mutex.RUnlock()

	if len(traces) == 0 {
		return
	}

	for name, exporter := range dt.exporters {
		err := exporter.Export(ctx, traces)
		if err != nil {
			dt.logger.Errorf("Failed to export traces to %s: %v", name, err)
		}
	}

	// Clean up exported traces
	dt.mutex.Lock()
	for _, trace := range traces {
		delete(dt.traces, trace.TraceID)
		// Also clean up spans
		for spanID, span := range dt.spans {
			if span.TraceID == trace.TraceID {
				delete(dt.spans, spanID)
			}
		}
	}
	dt.mutex.Unlock()
}

func (dt *DistributedTracer) initializeDefaultSamplers() {
	// Probability sampler
	probSampler := &ProbabilitySampler{
		name:        "probability",
		probability: dt.config.SamplingRate,
	}
	dt.samplers[probSampler.GetName()] = probSampler
}

// GetTraceStatistics gets trace statistics
func (dt *DistributedTracer) GetTraceStatistics() map[string]interface{} {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	stats := make(map[string]interface{})
	
	totalTraces := len(dt.traces)
	totalSpans := len(dt.spans)
	activeTraces := 0
	
	for _, trace := range dt.traces {
		if trace.Status == TraceStatusActive {
			activeTraces++
		}
	}

	stats["total_traces"] = totalTraces
	stats["active_traces"] = activeTraces
	stats["total_spans"] = totalSpans
	stats["sampling_rate"] = dt.config.SamplingRate

	return stats
}

// Mock implementations for demonstration

// ProbabilitySampler implements probability-based sampling
type ProbabilitySampler struct {
	name        string
	probability float64
}

func (s *ProbabilitySampler) GetName() string { return s.name }

func (s *ProbabilitySampler) ShouldSample(ctx context.Context, traceID string, spanName string, attributes map[string]interface{}) SamplingResult {
	// Simple hash-based sampling
	hash := 0
	for _, b := range []byte(traceID) {
		hash = hash*31 + int(b)
	}
	
	decision := SamplingDecisionDrop
	if float64(hash%100)/100.0 < s.probability {
		decision = SamplingDecisionSample
	}

	return SamplingResult{
		Decision:   decision,
		Attributes: make(map[string]interface{}),
	}
}
