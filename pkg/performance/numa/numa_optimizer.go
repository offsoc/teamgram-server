package numa

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// NUMAOptimizer provides NUMA (Non-Uniform Memory Access) optimization
type NUMAOptimizer struct {
	config    *Config
	topology  *NUMATopology
	policies  map[string]*NUMAPolicy
	monitor   *NUMAMonitor
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for NUMA optimizer
type Config struct {
	EnableNUMAOptimization bool    `json:"enable_numa_optimization"`
	EnableMemoryBinding    bool    `json:"enable_memory_binding"`
	EnableCPUAffinity      bool    `json:"enable_cpu_affinity"`
	EnableAutoBalancing    bool    `json:"enable_auto_balancing"`
	BalancingThreshold     float64 `json:"balancing_threshold"`
	MonitoringInterval     int     `json:"monitoring_interval"`     // seconds
	OptimizationInterval   int     `json:"optimization_interval"`   // seconds
}

// NUMATopology represents NUMA topology
type NUMATopology struct {
	Nodes     []NUMANode    `json:"nodes"`
	NodeCount int           `json:"node_count"`
	CPUCount  int           `json:"cpu_count"`
	Memory    MemoryInfo    `json:"memory"`
	Distances [][]int       `json:"distances"`
	LastUpdated time.Time   `json:"last_updated"`
}

// NUMANode represents a NUMA node
type NUMANode struct {
	ID        int           `json:"id"`
	CPUs      []int         `json:"cpus"`
	Memory    NodeMemory    `json:"memory"`
	Load      NodeLoad      `json:"load"`
	Processes []ProcessInfo `json:"processes"`
	Status    NodeStatus    `json:"status"`
}

// NodeMemory represents node memory information
type NodeMemory struct {
	Total     int64   `json:"total"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Usage     float64 `json:"usage"`
}

// NodeLoad represents node load information
type NodeLoad struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	ProcessCount int    `json:"process_count"`
	ThreadCount  int    `json:"thread_count"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	CPUUsage  float64 `json:"cpu_usage"`
	MemoryUsage int64 `json:"memory_usage"`
	NodeID    int    `json:"node_id"`
}

// MemoryInfo represents memory information
type MemoryInfo struct {
	Total     int64   `json:"total"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Usage     float64 `json:"usage"`
}

// NUMAPolicy represents a NUMA policy
type NUMAPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        PolicyType        `json:"type"`
	Scope       PolicyScope       `json:"scope"`
	Rules       []PolicyRule      `json:"rules"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	IsActive    bool              `json:"is_active"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
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

// NUMAMonitor monitors NUMA performance
type NUMAMonitor struct {
	metrics map[int]*NodeMetrics
	mutex   sync.RWMutex
}

// NodeMetrics represents node metrics
type NodeMetrics struct {
	NodeID      int           `json:"node_id"`
	CPUMetrics  CPUMetrics    `json:"cpu_metrics"`
	MemoryMetrics MemoryMetrics `json:"memory_metrics"`
	NetworkMetrics NetworkMetrics `json:"network_metrics"`
	LastUpdated time.Time     `json:"last_updated"`
}

// CPUMetrics represents CPU metrics
type CPUMetrics struct {
	Usage       float64 `json:"usage"`
	LoadAverage float64 `json:"load_average"`
	ContextSwitches int64 `json:"context_switches"`
	Interrupts  int64   `json:"interrupts"`
}

// MemoryMetrics represents memory metrics
type MemoryMetrics struct {
	Usage       float64 `json:"usage"`
	Bandwidth   float64 `json:"bandwidth"`
	Latency     float64 `json:"latency"`
	PageFaults  int64   `json:"page_faults"`
}

// NetworkMetrics represents network metrics
type NetworkMetrics struct {
	Bandwidth   float64 `json:"bandwidth"`
	Latency     float64 `json:"latency"`
	PacketRate  float64 `json:"packet_rate"`
}

// OptimizationRequest represents an optimization request
type OptimizationRequest struct {
	ProcessID   int                    `json:"process_id"`
	ProcessName string                 `json:"process_name"`
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
	MaxCPUUsage    float64 `json:"max_cpu_usage"`
	MaxMemoryUsage float64 `json:"max_memory_usage"`
	PreferredNodes []int   `json:"preferred_nodes"`
	AvoidNodes     []int   `json:"avoid_nodes"`
}

// OptimizationResult represents optimization results
type OptimizationResult struct {
	ProcessID     int                    `json:"process_id"`
	Success       bool                   `json:"success"`
	AssignedNode  int                    `json:"assigned_node"`
	CPUAffinity   []int                  `json:"cpu_affinity"`
	Improvements  map[string]interface{} `json:"improvements"`
	AppliedActions []string              `json:"applied_actions"`
	OptimizedAt   time.Time              `json:"optimized_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Enums
type PolicyType string
const (
	PolicyTypeMemoryBinding PolicyType = "memory_binding"
	PolicyTypeCPUAffinity   PolicyType = "cpu_affinity"
	PolicyTypeLoadBalancing PolicyType = "load_balancing"
	PolicyTypeAutoMigration PolicyType = "auto_migration"
)

type PolicyScope string
const (
	PolicyScopeGlobal  PolicyScope = "global"
	PolicyScopeProcess PolicyScope = "process"
	PolicyScopeThread  PolicyScope = "thread"
	PolicyScopeMemory  PolicyScope = "memory"
)

type ActionType string
const (
	ActionTypeBind     ActionType = "bind"
	ActionTypeMigrate  ActionType = "migrate"
	ActionTypeBalance  ActionType = "balance"
	ActionTypeOptimize ActionType = "optimize"
)

type NodeStatus string
const (
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
	NodeStatusBusy    NodeStatus = "busy"
	NodeStatusIdle    NodeStatus = "idle"
)

type ObjectiveType string
const (
	ObjectiveTypeLatency    ObjectiveType = "latency"
	ObjectiveTypeThroughput ObjectiveType = "throughput"
	ObjectiveTypeMemoryBandwidth ObjectiveType = "memory_bandwidth"
	ObjectiveTypeLoadBalance ObjectiveType = "load_balance"
)

// NewNUMAOptimizer creates a new NUMA optimizer
func NewNUMAOptimizer(config *Config) *NUMAOptimizer {
	if config == nil {
		config = DefaultConfig()
	}

	optimizer := &NUMAOptimizer{
		config:   config,
		topology: &NUMATopology{},
		policies: make(map[string]*NUMAPolicy),
		monitor: &NUMAMonitor{
			metrics: make(map[int]*NodeMetrics),
		},
		logger: logx.WithContext(context.Background()),
	}

	// Initialize NUMA topology
	optimizer.initializeTopology()

	// Initialize default policies
	optimizer.initializeDefaultPolicies()

	return optimizer
}

// DefaultConfig returns default NUMA optimizer configuration
func DefaultConfig() *Config {
	return &Config{
		EnableNUMAOptimization: true,
		EnableMemoryBinding:    true,
		EnableCPUAffinity:      true,
		EnableAutoBalancing:    true,
		BalancingThreshold:     0.8,  // 80%
		MonitoringInterval:     30,   // 30 seconds
		OptimizationInterval:   300,  // 5 minutes
	}
}

// StartOptimization starts NUMA optimization
func (no *NUMAOptimizer) StartOptimization(ctx context.Context) error {
	if !no.config.EnableNUMAOptimization {
		return fmt.Errorf("NUMA optimization is disabled")
	}

	// Start monitoring loop
	go no.monitoringLoop(ctx)

	// Start optimization loop
	go no.optimizationLoop(ctx)

	no.logger.Infof("Started NUMA optimization")
	return nil
}

// StopOptimization stops NUMA optimization
func (no *NUMAOptimizer) StopOptimization(ctx context.Context) error {
	no.logger.Infof("Stopped NUMA optimization")
	return nil
}

// OptimizeProcess optimizes a process for NUMA
func (no *NUMAOptimizer) OptimizeProcess(ctx context.Context, request *OptimizationRequest) (*OptimizationResult, error) {
	start := time.Now()

	result := &OptimizationResult{
		ProcessID:      request.ProcessID,
		Success:        false,
		AppliedActions: []string{},
		OptimizedAt:    start,
		Metadata:       request.Metadata,
	}

	// Find optimal NUMA node
	optimalNode := no.findOptimalNode(request)
	if optimalNode == -1 {
		return result, fmt.Errorf("no optimal NUMA node found")
	}

	result.AssignedNode = optimalNode

	// Apply CPU affinity if enabled
	if no.config.EnableCPUAffinity {
		cpuAffinity := no.getCPUAffinity(optimalNode)
		result.CPUAffinity = cpuAffinity
		result.AppliedActions = append(result.AppliedActions, "cpu_affinity")
	}

	// Apply memory binding if enabled
	if no.config.EnableMemoryBinding {
		err := no.bindMemory(request.ProcessID, optimalNode)
		if err == nil {
			result.AppliedActions = append(result.AppliedActions, "memory_binding")
		}
	}

	result.Success = len(result.AppliedActions) > 0
	result.Improvements = no.calculateImprovements(request.ProcessID, optimalNode)

	no.logger.Infof("Optimized process %d for NUMA: node=%d, actions=%v", request.ProcessID, optimalNode, result.AppliedActions)
	return result, nil
}

// GetNUMATopology gets NUMA topology information
func (no *NUMAOptimizer) GetNUMATopology() *NUMATopology {
	no.mutex.RLock()
	defer no.mutex.RUnlock()

	return no.topology
}

// GetNodeMetrics gets metrics for a specific NUMA node
func (no *NUMAOptimizer) GetNodeMetrics(nodeID int) (*NodeMetrics, error) {
	no.monitor.mutex.RLock()
	defer no.monitor.mutex.RUnlock()

	metrics, exists := no.monitor.metrics[nodeID]
	if !exists {
		return nil, fmt.Errorf("metrics not found for NUMA node %d", nodeID)
	}

	return metrics, nil
}

// Helper methods

func (no *NUMAOptimizer) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(no.config.MonitoringInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			no.updateMetrics()
		}
	}
}

func (no *NUMAOptimizer) optimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(no.config.OptimizationInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			no.performAutoOptimization(ctx)
		}
	}
}

func (no *NUMAOptimizer) initializeTopology() {
	// Mock NUMA topology initialization
	no.topology = &NUMATopology{
		Nodes: []NUMANode{
			{
				ID:   0,
				CPUs: []int{0, 1, 2, 3},
				Memory: NodeMemory{
					Total:     8 * 1024 * 1024 * 1024, // 8GB
					Used:      2 * 1024 * 1024 * 1024, // 2GB
					Available: 6 * 1024 * 1024 * 1024, // 6GB
					Usage:     0.25,
				},
				Load: NodeLoad{
					CPUUsage:     30.0,
					MemoryUsage:  25.0,
					ProcessCount: 10,
					ThreadCount:  50,
				},
				Status: NodeStatusOnline,
			},
			{
				ID:   1,
				CPUs: []int{4, 5, 6, 7},
				Memory: NodeMemory{
					Total:     8 * 1024 * 1024 * 1024, // 8GB
					Used:      3 * 1024 * 1024 * 1024, // 3GB
					Available: 5 * 1024 * 1024 * 1024, // 5GB
					Usage:     0.375,
				},
				Load: NodeLoad{
					CPUUsage:     45.0,
					MemoryUsage:  37.5,
					ProcessCount: 15,
					ThreadCount:  75,
				},
				Status: NodeStatusOnline,
			},
		},
		NodeCount: 2,
		CPUCount:  8,
		Memory: MemoryInfo{
			Total:     16 * 1024 * 1024 * 1024, // 16GB
			Used:      5 * 1024 * 1024 * 1024,  // 5GB
			Available: 11 * 1024 * 1024 * 1024, // 11GB
			Usage:     0.3125,
		},
		Distances: [][]int{
			{10, 20},
			{20, 10},
		},
		LastUpdated: time.Now(),
	}
}

func (no *NUMAOptimizer) initializeDefaultPolicies() {
	// CPU-intensive workload policy
	cpuPolicy := &NUMAPolicy{
		ID:          "cpu_intensive",
		Name:        "CPU Intensive Policy",
		Description: "Optimized for CPU-intensive workloads",
		Type:        PolicyTypeCPUAffinity,
		Scope:       PolicyScopeProcess,
		Rules: []PolicyRule{
			{
				ID:        "cpu_affinity_rule",
				Name:      "CPU Affinity Rule",
				Condition: "cpu_usage > 80",
				Action:    "bind_to_node",
				Priority:  1,
			},
		},
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	// Memory-intensive workload policy
	memoryPolicy := &NUMAPolicy{
		ID:          "memory_intensive",
		Name:        "Memory Intensive Policy",
		Description: "Optimized for memory-intensive workloads",
		Type:        PolicyTypeMemoryBinding,
		Scope:       PolicyScopeProcess,
		Rules: []PolicyRule{
			{
				ID:        "memory_binding_rule",
				Name:      "Memory Binding Rule",
				Condition: "memory_usage > 1GB",
				Action:    "bind_memory_to_node",
				Priority:  1,
			},
		},
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	no.policies[cpuPolicy.ID] = cpuPolicy
	no.policies[memoryPolicy.ID] = memoryPolicy
}

func (no *NUMAOptimizer) findOptimalNode(request *OptimizationRequest) int {
	bestNode := -1
	bestScore := 0.0

	for _, node := range no.topology.Nodes {
		if node.Status != NodeStatusOnline {
			continue
		}

		// Check constraints
		if no.violatesConstraints(node.ID, request.Constraints) {
			continue
		}

		// Calculate node score
		score := no.calculateNodeScore(node, request.Objectives)
		if score > bestScore {
			bestScore = score
			bestNode = node.ID
		}
	}

	return bestNode
}

func (no *NUMAOptimizer) violatesConstraints(nodeID int, constraints OptimizationConstraints) bool {
	// Check if node is in avoid list
	for _, avoidNode := range constraints.AvoidNodes {
		if nodeID == avoidNode {
			return true
		}
	}

	// Check resource constraints
	if nodeID < len(no.topology.Nodes) {
		node := no.topology.Nodes[nodeID]
		if node.Load.CPUUsage > constraints.MaxCPUUsage {
			return true
		}
		if node.Load.MemoryUsage > constraints.MaxMemoryUsage {
			return true
		}
	}

	return false
}

func (no *NUMAOptimizer) calculateNodeScore(node NUMANode, objectives []OptimizationObjective) float64 {
	score := 0.0

	for _, objective := range objectives {
		switch objective.Type {
		case ObjectiveTypeLatency:
			// Lower CPU usage = better latency
			latencyScore := (100.0 - node.Load.CPUUsage) / 100.0
			score += latencyScore * objective.Weight
		case ObjectiveTypeThroughput:
			// More available CPU = better throughput
			throughputScore := (100.0 - node.Load.CPUUsage) / 100.0
			score += throughputScore * objective.Weight
		case ObjectiveTypeMemoryBandwidth:
			// More available memory = better bandwidth
			memoryScore := (100.0 - node.Load.MemoryUsage) / 100.0
			score += memoryScore * objective.Weight
		case ObjectiveTypeLoadBalance:
			// Lower load = better balance
			balanceScore := (100.0 - (node.Load.CPUUsage+node.Load.MemoryUsage)/2.0) / 100.0
			score += balanceScore * objective.Weight
		}
	}

	return score
}

func (no *NUMAOptimizer) getCPUAffinity(nodeID int) []int {
	if nodeID < len(no.topology.Nodes) {
		return no.topology.Nodes[nodeID].CPUs
	}
	return []int{}
}

func (no *NUMAOptimizer) bindMemory(processID, nodeID int) error {
	// Mock memory binding implementation
	no.logger.Infof("Binding memory for process %d to NUMA node %d", processID, nodeID)
	return nil
}

func (no *NUMAOptimizer) calculateImprovements(processID, nodeID int) map[string]interface{} {
	improvements := make(map[string]interface{})
	
	// Mock improvement calculations
	improvements["latency_improvement"] = 15.0  // 15% improvement
	improvements["throughput_improvement"] = 20.0 // 20% improvement
	improvements["memory_bandwidth_improvement"] = 10.0 // 10% improvement

	return improvements
}

func (no *NUMAOptimizer) updateMetrics() {
	no.monitor.mutex.Lock()
	defer no.monitor.mutex.Unlock()

	for _, node := range no.topology.Nodes {
		metrics := &NodeMetrics{
			NodeID: node.ID,
			CPUMetrics: CPUMetrics{
				Usage:           node.Load.CPUUsage,
				LoadAverage:     node.Load.CPUUsage / 100.0,
				ContextSwitches: 1000,
				Interrupts:      500,
			},
			MemoryMetrics: MemoryMetrics{
				Usage:      node.Load.MemoryUsage,
				Bandwidth:  1000.0, // MB/s
				Latency:    100.0,  // ns
				PageFaults: 50,
			},
			NetworkMetrics: NetworkMetrics{
				Bandwidth:  100.0, // MB/s
				Latency:    1.0,   // ms
				PacketRate: 1000.0, // packets/s
			},
			LastUpdated: time.Now(),
		}

		no.monitor.metrics[node.ID] = metrics
	}
}

func (no *NUMAOptimizer) performAutoOptimization(ctx context.Context) {
	if !no.config.EnableAutoBalancing {
		return
	}

	// Check for load imbalance
	imbalance := no.detectLoadImbalance()
	if imbalance > no.config.BalancingThreshold {
		no.rebalanceLoad(ctx)
	}
}

func (no *NUMAOptimizer) detectLoadImbalance() float64 {
	if len(no.topology.Nodes) < 2 {
		return 0.0
	}

	var loads []float64
	for _, node := range no.topology.Nodes {
		loads = append(loads, (node.Load.CPUUsage+node.Load.MemoryUsage)/2.0)
	}

	// Calculate coefficient of variation
	mean := 0.0
	for _, load := range loads {
		mean += load
	}
	mean /= float64(len(loads))

	variance := 0.0
	for _, load := range loads {
		diff := load - mean
		variance += diff * diff
	}
	variance /= float64(len(loads))

	if mean == 0 {
		return 0.0
	}

	return variance / (mean * mean) // Coefficient of variation squared
}

func (no *NUMAOptimizer) rebalanceLoad(ctx context.Context) {
	no.logger.Infof("Performing NUMA load rebalancing")
	
	// Mock load rebalancing implementation
	// In a real implementation, this would migrate processes between nodes
}

// GetOptimizationRecommendations gets optimization recommendations
func (no *NUMAOptimizer) GetOptimizationRecommendations() ([]string, error) {
	var recommendations []string

	// Check load imbalance
	imbalance := no.detectLoadImbalance()
	if imbalance > no.config.BalancingThreshold {
		recommendations = append(recommendations, "Consider enabling auto-balancing to distribute load across NUMA nodes")
	}

	// Check individual node utilization
	for _, node := range no.topology.Nodes {
		if node.Load.CPUUsage > 90.0 {
			recommendations = append(recommendations, fmt.Sprintf("NUMA node %d has high CPU usage (%.1f%%) - consider migrating processes", node.ID, node.Load.CPUUsage))
		}
		if node.Load.MemoryUsage > 90.0 {
			recommendations = append(recommendations, fmt.Sprintf("NUMA node %d has high memory usage (%.1f%%) - consider memory optimization", node.ID, node.Load.MemoryUsage))
		}
	}

	// Check memory binding
	if !no.config.EnableMemoryBinding {
		recommendations = append(recommendations, "Consider enabling memory binding for better NUMA performance")
	}

	// Check CPU affinity
	if !no.config.EnableCPUAffinity {
		recommendations = append(recommendations, "Consider enabling CPU affinity for better NUMA performance")
	}

	return recommendations, nil
}
