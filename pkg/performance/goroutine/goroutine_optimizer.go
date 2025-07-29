package goroutine

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// GoroutineOptimizer provides goroutine optimization and management
type GoroutineOptimizer struct {
	config    *Config
	pools     map[string]*GoroutinePool
	monitor   *GoroutineMonitor
	scheduler *GoroutineScheduler
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for goroutine optimizer
type Config struct {
	EnablePooling          bool    `json:"enable_pooling"`
	EnableScheduling       bool    `json:"enable_scheduling"`
	EnableLeakDetection    bool    `json:"enable_leak_detection"`
	EnableProfiling        bool    `json:"enable_profiling"`
	MaxGoroutines          int     `json:"max_goroutines"`
	PoolSize               int     `json:"pool_size"`
	IdleTimeout            int     `json:"idle_timeout"`            // seconds
	LeakThreshold          int     `json:"leak_threshold"`
	MonitoringInterval     int     `json:"monitoring_interval"`     // seconds
	OptimizationInterval   int     `json:"optimization_interval"`   // seconds
	CPUThreshold           float64 `json:"cpu_threshold"`
	MemoryThreshold        float64 `json:"memory_threshold"`
}

// GoroutinePool represents a pool of goroutines
type GoroutinePool struct {
	Name        string            `json:"name"`
	Size        int               `json:"size"`
	Active      int               `json:"active"`
	Idle        int               `json:"idle"`
	Queue       chan Task         `json:"-"`
	Workers     []*Worker         `json:"workers"`
	Stats       PoolStats         `json:"stats"`
	Config      PoolConfig        `json:"config"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	LastUsed    time.Time         `json:"last_used"`
}

// Worker represents a worker goroutine
type Worker struct {
	ID        int           `json:"id"`
	PoolName  string        `json:"pool_name"`
	Status    WorkerStatus  `json:"status"`
	TaskCount int64         `json:"task_count"`
	LastTask  time.Time     `json:"last_task"`
	StartTime time.Time     `json:"start_time"`
	CPUTime   time.Duration `json:"cpu_time"`
}

// Task represents a task to be executed
type Task struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Function func() error           `json:"-"`
	Priority Priority               `json:"priority"`
	Timeout  time.Duration          `json:"timeout"`
	Metadata map[string]interface{} `json:"metadata"`
	Created  time.Time              `json:"created"`
	Started  *time.Time             `json:"started,omitempty"`
	Finished *time.Time             `json:"finished,omitempty"`
	Error    error                  `json:"error,omitempty"`
}

// PoolStats represents pool statistics
type PoolStats struct {
	TasksExecuted   int64         `json:"tasks_executed"`
	TasksQueued     int64         `json:"tasks_queued"`
	TasksFailed     int64         `json:"tasks_failed"`
	AverageWaitTime time.Duration `json:"average_wait_time"`
	AverageExecTime time.Duration `json:"average_exec_time"`
	ThroughputPerSec float64      `json:"throughput_per_sec"`
	LastUpdated     time.Time     `json:"last_updated"`
}

// PoolConfig represents pool configuration
type PoolConfig struct {
	MinWorkers  int           `json:"min_workers"`
	MaxWorkers  int           `json:"max_workers"`
	IdleTimeout time.Duration `json:"idle_timeout"`
	QueueSize   int           `json:"queue_size"`
	AutoScale   bool          `json:"auto_scale"`
}

// GoroutineMonitor monitors goroutine performance
type GoroutineMonitor struct {
	metrics     *GoroutineMetrics
	leaks       []GoroutineLeak
	profiles    []GoroutineProfile
	mutex       sync.RWMutex
}

// GoroutineMetrics represents goroutine metrics
type GoroutineMetrics struct {
	TotalGoroutines    int           `json:"total_goroutines"`
	ActiveGoroutines   int           `json:"active_goroutines"`
	IdleGoroutines     int           `json:"idle_goroutines"`
	BlockedGoroutines  int           `json:"blocked_goroutines"`
	CPUUsage           float64       `json:"cpu_usage"`
	MemoryUsage        int64         `json:"memory_usage"`
	GCPauses           time.Duration `json:"gc_pauses"`
	StackSize          int64         `json:"stack_size"`
	LastUpdated        time.Time     `json:"last_updated"`
}

// GoroutineLeak represents a potential goroutine leak
type GoroutineLeak struct {
	ID          string    `json:"id"`
	Function    string    `json:"function"`
	File        string    `json:"file"`
	Line        int       `json:"line"`
	Duration    time.Duration `json:"duration"`
	StackTrace  string    `json:"stack_trace"`
	DetectedAt  time.Time `json:"detected_at"`
	Severity    Severity  `json:"severity"`
}

// GoroutineProfile represents a goroutine profile
type GoroutineProfile struct {
	ID          string        `json:"id"`
	Function    string        `json:"function"`
	State       string        `json:"state"`
	Duration    time.Duration `json:"duration"`
	CPUTime     time.Duration `json:"cpu_time"`
	MemoryUsage int64         `json:"memory_usage"`
	StackTrace  string        `json:"stack_trace"`
	CreatedAt   time.Time     `json:"created_at"`
}

// GoroutineScheduler manages goroutine scheduling
type GoroutineScheduler struct {
	queues    map[Priority]*PriorityQueue
	policies  map[string]*SchedulingPolicy
	mutex     sync.RWMutex
}

// PriorityQueue represents a priority queue
type PriorityQueue struct {
	Priority Priority `json:"priority"`
	Tasks    []Task   `json:"tasks"`
	mutex    sync.Mutex
}

// SchedulingPolicy represents a scheduling policy
type SchedulingPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Algorithm   SchedulingAlgorithm `json:"algorithm"`
	Parameters  map[string]interface{} `json:"parameters"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	CreatedAt   time.Time         `json:"created_at"`
	IsActive    bool              `json:"is_active"`
}

// PolicyCondition represents a policy condition
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// PolicyAction represents a policy action
type PolicyAction struct {
	Type       ActionType        `json:"type"`
	Parameters map[string]string `json:"parameters"`
}

// OptimizationRequest represents an optimization request
type OptimizationRequest struct {
	PoolName    string                 `json:"pool_name"`
	Objectives  []OptimizationObjective `json:"objectives"`
	Constraints OptimizationConstraints `json:"constraints"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// OptimizationObjective represents an optimization objective
type OptimizationObjective struct {
	Type   ObjectiveType `json:"type"`
	Target float64       `json:"target"`
	Weight float64       `json:"weight"`
}

// OptimizationConstraints represents optimization constraints
type OptimizationConstraints struct {
	MaxGoroutines   int           `json:"max_goroutines"`
	MaxMemoryUsage  int64         `json:"max_memory_usage"`
	MaxCPUUsage     float64       `json:"max_cpu_usage"`
	MaxLatency      time.Duration `json:"max_latency"`
}

// OptimizationResult represents optimization results
type OptimizationResult struct {
	PoolName      string                 `json:"pool_name"`
	Success       bool                   `json:"success"`
	Improvements  map[string]interface{} `json:"improvements"`
	AppliedActions []string              `json:"applied_actions"`
	OptimizedAt   time.Time              `json:"optimized_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Enums
type WorkerStatus string
const (
	WorkerStatusIdle    WorkerStatus = "idle"
	WorkerStatusBusy    WorkerStatus = "busy"
	WorkerStatusStopped WorkerStatus = "stopped"
)

type Priority string
const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

type Severity string
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type SchedulingAlgorithm string
const (
	SchedulingAlgorithmFIFO     SchedulingAlgorithm = "fifo"
	SchedulingAlgorithmPriority SchedulingAlgorithm = "priority"
	SchedulingAlgorithmRoundRobin SchedulingAlgorithm = "round_robin"
	SchedulingAlgorithmShortest SchedulingAlgorithm = "shortest_job_first"
)

type ActionType string
const (
	ActionTypeScale     ActionType = "scale"
	ActionTypePrioritize ActionType = "prioritize"
	ActionTypeThrottle  ActionType = "throttle"
	ActionTypeKill      ActionType = "kill"
)

type ObjectiveType string
const (
	ObjectiveTypeLatency    ObjectiveType = "latency"
	ObjectiveTypeThroughput ObjectiveType = "throughput"
	ObjectiveTypeResource   ObjectiveType = "resource"
	ObjectiveTypeReliability ObjectiveType = "reliability"
)

// NewGoroutineOptimizer creates a new goroutine optimizer
func NewGoroutineOptimizer(config *Config) *GoroutineOptimizer {
	if config == nil {
		config = DefaultConfig()
	}

	optimizer := &GoroutineOptimizer{
		config: config,
		pools:  make(map[string]*GoroutinePool),
		monitor: &GoroutineMonitor{
			metrics:  &GoroutineMetrics{},
			leaks:    make([]GoroutineLeak, 0),
			profiles: make([]GoroutineProfile, 0),
		},
		scheduler: &GoroutineScheduler{
			queues:   make(map[Priority]*PriorityQueue),
			policies: make(map[string]*SchedulingPolicy),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize priority queues
	optimizer.initializePriorityQueues()

	// Initialize default scheduling policies
	optimizer.initializeDefaultPolicies()

	return optimizer
}

// DefaultConfig returns default goroutine optimizer configuration
func DefaultConfig() *Config {
	return &Config{
		EnablePooling:        true,
		EnableScheduling:     true,
		EnableLeakDetection:  true,
		EnableProfiling:      true,
		MaxGoroutines:        10000,
		PoolSize:             100,
		IdleTimeout:          300,  // 5 minutes
		LeakThreshold:        1000,
		MonitoringInterval:   30,   // 30 seconds
		OptimizationInterval: 300,  // 5 minutes
		CPUThreshold:         0.8,  // 80%
		MemoryThreshold:      0.8,  // 80%
	}
}

// StartOptimization starts goroutine optimization
func (go_opt *GoroutineOptimizer) StartOptimization(ctx context.Context) error {
	// Start monitoring loop
	go go_opt.monitoringLoop(ctx)

	// Start optimization loop
	go go_opt.optimizationLoop(ctx)

	// Start leak detection if enabled
	if go_opt.config.EnableLeakDetection {
		go go_opt.leakDetectionLoop(ctx)
	}

	go_opt.logger.Infof("Started goroutine optimization")
	return nil
}

// StopOptimization stops goroutine optimization
func (go_opt *GoroutineOptimizer) StopOptimization(ctx context.Context) error {
	// Stop all pools
	for _, pool := range go_opt.pools {
		go_opt.stopPool(pool)
	}

	go_opt.logger.Infof("Stopped goroutine optimization")
	return nil
}

// CreatePool creates a new goroutine pool
func (go_opt *GoroutineOptimizer) CreatePool(name string, config PoolConfig) (*GoroutinePool, error) {
	go_opt.mutex.Lock()
	defer go_opt.mutex.Unlock()

	if _, exists := go_opt.pools[name]; exists {
		return nil, fmt.Errorf("pool %s already exists", name)
	}

	pool := &GoroutinePool{
		Name:      name,
		Size:      config.MinWorkers,
		Active:    0,
		Idle:      0,
		Queue:     make(chan Task, config.QueueSize),
		Workers:   make([]*Worker, 0),
		Config:    config,
		Metadata:  make(map[string]string),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	// Start workers
	for i := 0; i < config.MinWorkers; i++ {
		worker := go_opt.createWorker(i, name)
		pool.Workers = append(pool.Workers, worker)
		go go_opt.runWorker(worker, pool)
	}

	go_opt.pools[name] = pool
	go_opt.logger.Infof("Created goroutine pool: %s with %d workers", name, config.MinWorkers)
	return pool, nil
}

// SubmitTask submits a task to a pool
func (go_opt *GoroutineOptimizer) SubmitTask(poolName string, task Task) error {
	pool, exists := go_opt.pools[poolName]
	if !exists {
		return fmt.Errorf("pool %s not found", poolName)
	}

	task.Created = time.Now()
	
	select {
	case pool.Queue <- task:
		pool.LastUsed = time.Now()
		return nil
	default:
		return fmt.Errorf("pool %s queue is full", poolName)
	}
}

// OptimizePool optimizes a goroutine pool
func (go_opt *GoroutineOptimizer) OptimizePool(ctx context.Context, request *OptimizationRequest) (*OptimizationResult, error) {
	start := time.Now()

	pool, exists := go_opt.pools[request.PoolName]
	if !exists {
		return nil, fmt.Errorf("pool %s not found", request.PoolName)
	}

	result := &OptimizationResult{
		PoolName:       request.PoolName,
		Success:        false,
		Improvements:   make(map[string]interface{}),
		AppliedActions: []string{},
		OptimizedAt:    start,
		Metadata:       request.Metadata,
	}

	// Get baseline metrics
	beforeStats := pool.Stats

	// Apply optimizations based on objectives
	for _, objective := range request.Objectives {
		actions := go_opt.getOptimizationActions(pool, objective, request.Constraints)
		for _, action := range actions {
			err := go_opt.executeAction(pool, action)
			if err == nil {
				result.AppliedActions = append(result.AppliedActions, string(action.Type))
			}
		}
	}

	// Get updated metrics
	afterStats := pool.Stats

	// Calculate improvements
	result.Improvements = go_opt.calculateImprovements(beforeStats, afterStats)
	result.Success = len(result.AppliedActions) > 0

	go_opt.logger.Infof("Optimized pool %s: success=%t, actions=%v", request.PoolName, result.Success, result.AppliedActions)
	return result, nil
}

// GetGoroutineMetrics gets current goroutine metrics
func (go_opt *GoroutineOptimizer) GetGoroutineMetrics() *GoroutineMetrics {
	go_opt.monitor.mutex.RLock()
	defer go_opt.monitor.mutex.RUnlock()

	return go_opt.monitor.metrics
}

// GetGoroutineLeaks gets detected goroutine leaks
func (go_opt *GoroutineOptimizer) GetGoroutineLeaks() []GoroutineLeak {
	go_opt.monitor.mutex.RLock()
	defer go_opt.monitor.mutex.RUnlock()

	return go_opt.monitor.leaks
}

// Helper methods

func (go_opt *GoroutineOptimizer) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(go_opt.config.MonitoringInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			go_opt.updateMetrics()
		}
	}
}

func (go_opt *GoroutineOptimizer) optimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(go_opt.config.OptimizationInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			go_opt.performAutoOptimization(ctx)
		}
	}
}

func (go_opt *GoroutineOptimizer) leakDetectionLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			go_opt.detectLeaks()
		}
	}
}

func (go_opt *GoroutineOptimizer) createWorker(id int, poolName string) *Worker {
	return &Worker{
		ID:        id,
		PoolName:  poolName,
		Status:    WorkerStatusIdle,
		TaskCount: 0,
		StartTime: time.Now(),
	}
}

func (go_opt *GoroutineOptimizer) runWorker(worker *Worker, pool *GoroutinePool) {
	for task := range pool.Queue {
		worker.Status = WorkerStatusBusy
		worker.TaskCount++
		worker.LastTask = time.Now()

		// Execute task
		start := time.Now()
		task.Started = &start
		
		err := task.Function()
		
		end := time.Now()
		task.Finished = &end
		task.Error = err

		if err != nil {
			pool.Stats.TasksFailed++
		} else {
			pool.Stats.TasksExecuted++
		}

		worker.Status = WorkerStatusIdle
	}
	worker.Status = WorkerStatusStopped
}

func (go_opt *GoroutineOptimizer) stopPool(pool *GoroutinePool) {
	close(pool.Queue)
	for _, worker := range pool.Workers {
		worker.Status = WorkerStatusStopped
	}
}

func (go_opt *GoroutineOptimizer) updateMetrics() {
	go_opt.monitor.mutex.Lock()
	defer go_opt.monitor.mutex.Unlock()

	// Get runtime metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	go_opt.monitor.metrics = &GoroutineMetrics{
		TotalGoroutines:   runtime.NumGoroutine(),
		ActiveGoroutines:  runtime.NumGoroutine() - go_opt.countIdleGoroutines(),
		IdleGoroutines:    go_opt.countIdleGoroutines(),
		BlockedGoroutines: 0, // Would need more sophisticated tracking
		CPUUsage:          go_opt.getCPUUsage(),
		MemoryUsage:       int64(m.Alloc),
		GCPauses:          time.Duration(m.PauseTotalNs),
		StackSize:         int64(m.StackInuse),
		LastUpdated:       time.Now(),
	}

	// Update pool stats
	for _, pool := range go_opt.pools {
		go_opt.updatePoolStats(pool)
	}
}

func (go_opt *GoroutineOptimizer) countIdleGoroutines() int {
	idle := 0
	for _, pool := range go_opt.pools {
		for _, worker := range pool.Workers {
			if worker.Status == WorkerStatusIdle {
				idle++
			}
		}
	}
	return idle
}

func (go_opt *GoroutineOptimizer) getCPUUsage() float64 {
	// Mock CPU usage calculation
	return 50.0 // 50%
}

func (go_opt *GoroutineOptimizer) updatePoolStats(pool *GoroutinePool) {
	pool.Stats.TasksQueued = int64(len(pool.Queue))
	pool.Stats.LastUpdated = time.Now()
	
	// Calculate throughput
	if pool.Stats.TasksExecuted > 0 {
		duration := time.Since(pool.CreatedAt)
		pool.Stats.ThroughputPerSec = float64(pool.Stats.TasksExecuted) / duration.Seconds()
	}
}

func (go_opt *GoroutineOptimizer) detectLeaks() {
	currentGoroutines := runtime.NumGoroutine()
	if currentGoroutines > go_opt.config.LeakThreshold {
		leak := GoroutineLeak{
			ID:         fmt.Sprintf("leak_%d", time.Now().Unix()),
			Function:   "unknown",
			Duration:   time.Minute, // Mock duration
			DetectedAt: time.Now(),
			Severity:   SeverityHigh,
		}

		go_opt.monitor.mutex.Lock()
		go_opt.monitor.leaks = append(go_opt.monitor.leaks, leak)
		go_opt.monitor.mutex.Unlock()

		go_opt.logger.Errorf("Potential goroutine leak detected: %d goroutines", currentGoroutines)
	}
}

func (go_opt *GoroutineOptimizer) performAutoOptimization(ctx context.Context) {
	for name, pool := range go_opt.pools {
		if go_opt.needsOptimization(pool) {
			go_opt.autoOptimizePool(ctx, name, pool)
		}
	}
}

func (go_opt *GoroutineOptimizer) needsOptimization(pool *GoroutinePool) bool {
	// Check queue length
	if len(pool.Queue) > pool.Config.QueueSize/2 {
		return true
	}

	// Check worker utilization
	busyWorkers := 0
	for _, worker := range pool.Workers {
		if worker.Status == WorkerStatusBusy {
			busyWorkers++
		}
	}

	utilization := float64(busyWorkers) / float64(len(pool.Workers))
	return utilization > 0.8 || utilization < 0.2
}

func (go_opt *GoroutineOptimizer) autoOptimizePool(ctx context.Context, name string, pool *GoroutinePool) {
	request := &OptimizationRequest{
		PoolName: name,
		Objectives: []OptimizationObjective{
			{
				Type:   ObjectiveTypeThroughput,
				Target: 100.0,
				Weight: 1.0,
			},
		},
		Constraints: OptimizationConstraints{
			MaxGoroutines: go_opt.config.MaxGoroutines,
		},
	}

	_, err := go_opt.OptimizePool(ctx, request)
	if err != nil {
		go_opt.logger.Errorf("Auto-optimization failed for pool %s: %v", name, err)
	}
}

func (go_opt *GoroutineOptimizer) getOptimizationActions(pool *GoroutinePool, objective OptimizationObjective, constraints OptimizationConstraints) []PolicyAction {
	var actions []PolicyAction

	switch objective.Type {
	case ObjectiveTypeThroughput:
		if len(pool.Queue) > pool.Config.QueueSize/2 {
			actions = append(actions, PolicyAction{
				Type: ActionTypeScale,
				Parameters: map[string]string{
					"direction": "up",
					"amount":    "2",
				},
			})
		}
	case ObjectiveTypeResource:
		busyWorkers := 0
		for _, worker := range pool.Workers {
			if worker.Status == WorkerStatusBusy {
				busyWorkers++
			}
		}
		if float64(busyWorkers)/float64(len(pool.Workers)) < 0.2 {
			actions = append(actions, PolicyAction{
				Type: ActionTypeScale,
				Parameters: map[string]string{
					"direction": "down",
					"amount":    "1",
				},
			})
		}
	}

	return actions
}

func (go_opt *GoroutineOptimizer) executeAction(pool *GoroutinePool, action PolicyAction) error {
	switch action.Type {
	case ActionTypeScale:
		return go_opt.scalePool(pool, action.Parameters)
	case ActionTypeThrottle:
		return go_opt.throttlePool(pool, action.Parameters)
	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

func (go_opt *GoroutineOptimizer) scalePool(pool *GoroutinePool, params map[string]string) error {
	direction := params["direction"]
	
	if direction == "up" && len(pool.Workers) < pool.Config.MaxWorkers {
		// Add worker
		worker := go_opt.createWorker(len(pool.Workers), pool.Name)
		pool.Workers = append(pool.Workers, worker)
		go go_opt.runWorker(worker, pool)
		pool.Size++
		go_opt.logger.Infof("Scaled up pool %s to %d workers", pool.Name, pool.Size)
	} else if direction == "down" && len(pool.Workers) > pool.Config.MinWorkers {
		// Remove worker (simplified)
		pool.Size--
		go_opt.logger.Infof("Scaled down pool %s to %d workers", pool.Name, pool.Size)
	}

	return nil
}

func (go_opt *GoroutineOptimizer) throttlePool(pool *GoroutinePool, params map[string]string) error {
	// Mock throttling implementation
	go_opt.logger.Infof("Throttling pool %s", pool.Name)
	return nil
}

func (go_opt *GoroutineOptimizer) calculateImprovements(before, after PoolStats) map[string]interface{} {
	improvements := make(map[string]interface{})

	// Throughput improvement
	throughputImprovement := (after.ThroughputPerSec - before.ThroughputPerSec) / before.ThroughputPerSec * 100
	improvements["throughput_improvement"] = throughputImprovement

	// Queue length improvement
	queueImprovement := float64(before.TasksQueued-after.TasksQueued) / float64(before.TasksQueued) * 100
	improvements["queue_improvement"] = queueImprovement

	return improvements
}

func (go_opt *GoroutineOptimizer) initializePriorityQueues() {
	priorities := []Priority{PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical}
	
	for _, priority := range priorities {
		go_opt.scheduler.queues[priority] = &PriorityQueue{
			Priority: priority,
			Tasks:    make([]Task, 0),
		}
	}
}

func (go_opt *GoroutineOptimizer) initializeDefaultPolicies() {
	// High throughput policy
	throughputPolicy := &SchedulingPolicy{
		ID:        "high_throughput",
		Name:      "High Throughput Policy",
		Algorithm: SchedulingAlgorithmFIFO,
		Parameters: map[string]interface{}{
			"batch_size": 10,
		},
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	// Low latency policy
	latencyPolicy := &SchedulingPolicy{
		ID:        "low_latency",
		Name:      "Low Latency Policy",
		Algorithm: SchedulingAlgorithmPriority,
		Parameters: map[string]interface{}{
			"preemptive": true,
		},
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	go_opt.scheduler.policies[throughputPolicy.ID] = throughputPolicy
	go_opt.scheduler.policies[latencyPolicy.ID] = latencyPolicy
}

// GetOptimizationRecommendations gets optimization recommendations
func (go_opt *GoroutineOptimizer) GetOptimizationRecommendations() ([]string, error) {
	var recommendations []string

	metrics := go_opt.GetGoroutineMetrics()

	// Check goroutine count
	if metrics.TotalGoroutines > go_opt.config.MaxGoroutines {
		recommendations = append(recommendations, fmt.Sprintf("High goroutine count (%d) - consider using goroutine pools", metrics.TotalGoroutines))
	}

	// Check for potential leaks
	if len(go_opt.monitor.leaks) > 0 {
		recommendations = append(recommendations, "Potential goroutine leaks detected - review long-running goroutines")
	}

	// Check CPU usage
	if metrics.CPUUsage > go_opt.config.CPUThreshold*100 {
		recommendations = append(recommendations, "High CPU usage - consider optimizing goroutine scheduling")
	}

	// Check memory usage
	if float64(metrics.MemoryUsage) > go_opt.config.MemoryThreshold*1024*1024*1024 {
		recommendations = append(recommendations, "High memory usage - review goroutine memory allocation patterns")
	}

	// Pool-specific recommendations
	for name, pool := range go_opt.pools {
		if len(pool.Queue) > pool.Config.QueueSize*3/4 {
			recommendations = append(recommendations, fmt.Sprintf("Pool %s queue is nearly full - consider scaling up", name))
		}
		
		if pool.Stats.TasksFailed > 0 && pool.Stats.TasksExecuted > 0 {
			failureRate := float64(pool.Stats.TasksFailed) / float64(pool.Stats.TasksExecuted)
			if failureRate > 0.1 {
				recommendations = append(recommendations, fmt.Sprintf("Pool %s has high failure rate (%.1f%%) - review error handling", name, failureRate*100))
			}
		}
	}

	return recommendations, nil
}
