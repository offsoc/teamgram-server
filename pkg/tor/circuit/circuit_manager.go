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

package circuit

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// CircuitManager manages Tor circuits with multi-hop routing and circuit reuse
type CircuitManager struct {
	mutex           sync.RWMutex
	config          *CircuitConfig
	circuits        map[string]*Circuit
	circuitPool     *CircuitPool
	nodeDirectory   *NodeDirectory
	pathSelector    *PathSelector
	streamManager   *StreamManager
	metrics         *CircuitMetrics
	logger          logx.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
}

// CircuitConfig configuration for circuit management
type CircuitConfig struct {
	MaxCircuits          int           `json:"max_circuits"`
	MinCircuits          int           `json:"min_circuits"`
	CircuitBuildTimeout  time.Duration `json:"circuit_build_timeout"`
	CircuitIdleTimeout   time.Duration `json:"circuit_idle_timeout"`
	MaxStreamsPerCircuit int           `json:"max_streams_per_circuit"`
	PathLength           int           `json:"path_length"`
	EnableCircuitReuse   bool          `json:"enable_circuit_reuse"`
	EnableLoadBalancing  bool          `json:"enable_load_balancing"`
	PreemptiveBuilding   bool          `json:"preemptive_building"`
	CircuitPurpose       []string      `json:"circuit_purpose"`
}

// Circuit represents a Tor circuit with multi-hop routing
type Circuit struct {
	ID              string        `json:"id"`
	Path            []*Node       `json:"path"`
	State           CircuitState  `json:"state"`
	Purpose         string        `json:"purpose"`
	CreatedAt       time.Time     `json:"created_at"`
	LastUsed        time.Time     `json:"last_used"`
	StreamCount     int           `json:"stream_count"`
	MaxStreams      int           `json:"max_streams"`
	BytesRead       int64         `json:"bytes_read"`
	BytesWritten    int64         `json:"bytes_written"`
	BuildTime       time.Duration `json:"build_time"`
	IsReady         bool          `json:"is_ready"`
	IsReusable      bool          `json:"is_reusable"`
	Priority        int           `json:"priority"`
	conn            net.Conn      `json:"-"`
	streams         map[int]*Stream `json:"-"`
	mutex           sync.RWMutex  `json:"-"`
}

// Node represents a Tor relay node
type Node struct {
	Fingerprint     string    `json:"fingerprint"`
	Nickname        string    `json:"nickname"`
	Address         string    `json:"address"`
	Port            int       `json:"port"`
	Country         string    `json:"country"`
	Bandwidth       int64     `json:"bandwidth"`
	Flags           []string  `json:"flags"`
	IsExit          bool      `json:"is_exit"`
	IsGuard         bool      `json:"is_guard"`
	IsStable        bool      `json:"is_stable"`
	IsFast          bool      `json:"is_fast"`
	LastSeen        time.Time `json:"last_seen"`
	Latency         time.Duration `json:"latency"`
	SuccessRate     float64   `json:"success_rate"`
}

// Stream represents a data stream within a circuit
type Stream struct {
	ID          int           `json:"id"`
	CircuitID   string        `json:"circuit_id"`
	Target      string        `json:"target"`
	Port        int           `json:"port"`
	State       StreamState   `json:"state"`
	CreatedAt   time.Time     `json:"created_at"`
	BytesRead   int64         `json:"bytes_read"`
	BytesWritten int64        `json:"bytes_written"`
	conn        net.Conn      `json:"-"`
}

// CircuitState represents the state of a circuit
type CircuitState int

const (
	CircuitStateBuilding CircuitState = iota
	CircuitStateReady
	CircuitStateFailed
	CircuitStateClosed
	CircuitStateExtending
)

// StreamState represents the state of a stream
type StreamState int

const (
	StreamStateNew StreamState = iota
	StreamStateConnecting
	StreamStateConnected
	StreamStateFailed
	StreamStateClosed
)

// CircuitPool manages a pool of reusable circuits
type CircuitPool struct {
	mutex           sync.RWMutex
	availableCircuits map[string][]*Circuit
	busyCircuits    map[string]*Circuit
	maxPoolSize     int
	logger          logx.Logger
}

// NodeDirectory maintains information about Tor relay nodes
type NodeDirectory struct {
	mutex       sync.RWMutex
	nodes       map[string]*Node
	guardNodes  []*Node
	middleNodes []*Node
	exitNodes   []*Node
	lastUpdated time.Time
	logger      logx.Logger
}

// PathSelector selects optimal paths for circuits
type PathSelector struct {
	nodeDirectory *NodeDirectory
	config        *CircuitConfig
	logger        logx.Logger
}

// StreamManager manages streams within circuits
type StreamManager struct {
	mutex   sync.RWMutex
	streams map[int]*Stream
	nextID  int
	logger  logx.Logger
}

// CircuitMetrics tracks circuit performance
type CircuitMetrics struct {
	TotalCircuits     int64         `json:"total_circuits"`
	ActiveCircuits    int64         `json:"active_circuits"`
	FailedCircuits    int64         `json:"failed_circuits"`
	AvgBuildTime      time.Duration `json:"avg_build_time"`
	MaxBuildTime      time.Duration `json:"max_build_time"`
	MinBuildTime      time.Duration `json:"min_build_time"`
	CircuitReuse      int64         `json:"circuit_reuse"`
	StreamCount       int64         `json:"stream_count"`
	TotalBytes        int64         `json:"total_bytes"`
	LastUpdated       time.Time     `json:"last_updated"`
}

// NewCircuitManager creates a new circuit manager
func NewCircuitManager(config *CircuitConfig) (*CircuitManager, error) {
	if config == nil {
		config = DefaultCircuitConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &CircuitManager{
		config:   config,
		circuits: make(map[string]*Circuit),
		metrics: &CircuitMetrics{
			MinBuildTime: time.Hour, // Initialize to high value
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	manager.circuitPool = NewCircuitPool(config.MaxCircuits)
	manager.nodeDirectory = NewNodeDirectory()
	manager.pathSelector = NewPathSelector(manager.nodeDirectory, config)
	manager.streamManager = NewStreamManager()
	
	return manager, nil
}

// Start starts the circuit manager
func (cm *CircuitManager) Start() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if cm.isRunning {
		return fmt.Errorf("circuit manager is already running")
	}
	
	cm.logger.Info("Starting circuit manager...")
	
	// Update node directory
	if err := cm.nodeDirectory.Update(); err != nil {
		cm.logger.Errorf("Failed to update node directory: %v", err)
	}
	
	// Pre-build circuits if enabled
	if cm.config.PreemptiveBuilding {
		go cm.preemptiveBuildingLoop()
	}
	
	// Start circuit maintenance
	go cm.maintenanceLoop()
	
	// Start metrics collection
	go cm.metricsLoop()
	
	cm.isRunning = true
	cm.logger.Info("Circuit manager started successfully")
	
	return nil
}

// CreateCircuit creates a new circuit with multi-hop routing
func (cm *CircuitManager) CreateCircuit(purpose string) (*Circuit, error) {
	start := time.Now()
	
	// Check if we can reuse an existing circuit
	if cm.config.EnableCircuitReuse {
		if circuit := cm.circuitPool.GetAvailableCircuit(purpose); circuit != nil {
			cm.logger.Infof("Reusing existing circuit %s for purpose %s", circuit.ID, purpose)
			return circuit, nil
		}
	}
	
	// Select path for new circuit
	path, err := cm.pathSelector.SelectPath(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to select path: %w", err)
	}
	
	// Create circuit
	circuit := &Circuit{
		ID:         generateCircuitID(),
		Path:       path,
		State:      CircuitStateBuilding,
		Purpose:    purpose,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		MaxStreams: cm.config.MaxStreamsPerCircuit,
		IsReusable: cm.config.EnableCircuitReuse,
		streams:    make(map[int]*Stream),
	}
	
	// Build circuit
	if err := cm.buildCircuit(circuit); err != nil {
		circuit.State = CircuitStateFailed
		cm.updateMetrics(false, time.Since(start))
		return nil, fmt.Errorf("failed to build circuit: %w", err)
	}
	
	circuit.State = CircuitStateReady
	circuit.IsReady = true
	circuit.BuildTime = time.Since(start)
	
	// Store circuit
	cm.mutex.Lock()
	cm.circuits[circuit.ID] = circuit
	cm.mutex.Unlock()
	
	// Add to pool if reusable
	if circuit.IsReusable {
		cm.circuitPool.AddCircuit(circuit)
	}
	
	cm.updateMetrics(true, circuit.BuildTime)
	cm.logger.Infof("Created circuit %s with %d hops in %v", circuit.ID, len(circuit.Path), circuit.BuildTime)
	
	return circuit, nil
}

// GetCircuit retrieves a circuit by ID
func (cm *CircuitManager) GetCircuit(circuitID string) (*Circuit, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	circuit, exists := cm.circuits[circuitID]
	return circuit, exists
}

// CreateStream creates a new stream within a circuit
func (cm *CircuitManager) CreateStream(circuit *Circuit, target string, port int) (*Stream, error) {
	if !circuit.IsReady {
		return nil, fmt.Errorf("circuit %s is not ready", circuit.ID)
	}
	
	circuit.mutex.Lock()
	defer circuit.mutex.Unlock()
	
	if circuit.StreamCount >= circuit.MaxStreams {
		return nil, fmt.Errorf("circuit %s has reached maximum streams", circuit.ID)
	}
	
	stream := &Stream{
		ID:        cm.streamManager.GetNextID(),
		CircuitID: circuit.ID,
		Target:    target,
		Port:      port,
		State:     StreamStateNew,
		CreatedAt: time.Now(),
	}
	
	// Establish stream connection
	if err := cm.establishStream(circuit, stream); err != nil {
		return nil, fmt.Errorf("failed to establish stream: %w", err)
	}
	
	circuit.streams[stream.ID] = stream
	circuit.StreamCount++
	circuit.LastUsed = time.Now()
	
	cm.streamManager.AddStream(stream)
	
	return stream, nil
}

// buildCircuit builds a circuit through multiple hops
func (cm *CircuitManager) buildCircuit(circuit *Circuit) error {
	if len(circuit.Path) == 0 {
		return fmt.Errorf("empty circuit path")
	}
	
	// Connect to guard node (first hop)
	guardNode := circuit.Path[0]
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", guardNode.Address, guardNode.Port), 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to guard node %s: %w", guardNode.Nickname, err)
	}
	
	circuit.conn = conn
	
	// Extend circuit through each hop
	for i := 1; i < len(circuit.Path); i++ {
		circuit.State = CircuitStateExtending
		node := circuit.Path[i]
		
		if err := cm.extendCircuit(circuit, node); err != nil {
			conn.Close()
			return fmt.Errorf("failed to extend circuit to %s: %w", node.Nickname, err)
		}
		
		cm.logger.Debugf("Extended circuit %s to hop %d (%s)", circuit.ID, i+1, node.Nickname)
	}
	
	return nil
}

// extendCircuit extends a circuit to the next hop
func (cm *CircuitManager) extendCircuit(circuit *Circuit, node *Node) error {
	// Simulate circuit extension (in real implementation, this would use Tor protocol)
	time.Sleep(100 * time.Millisecond) // Simulate network delay
	
	// Verify node is reachable
	testConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node.Address, node.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("node %s is not reachable: %w", node.Nickname, err)
	}
	testConn.Close()
	
	return nil
}

// establishStream establishes a stream within a circuit
func (cm *CircuitManager) establishStream(circuit *Circuit, stream *Stream) error {
	// Simulate stream establishment
	stream.State = StreamStateConnecting
	
	// In real implementation, this would send RELAY_BEGIN cell
	time.Sleep(50 * time.Millisecond)
	
	stream.State = StreamStateConnected
	return nil
}

// DefaultCircuitConfig returns default circuit configuration
func DefaultCircuitConfig() *CircuitConfig {
	return &CircuitConfig{
		MaxCircuits:          10,
		MinCircuits:          3,
		CircuitBuildTimeout:  60 * time.Second,
		CircuitIdleTimeout:   10 * time.Minute,
		MaxStreamsPerCircuit: 10,
		PathLength:           3,
		EnableCircuitReuse:   true,
		EnableLoadBalancing:  true,
		PreemptiveBuilding:   true,
		CircuitPurpose:       []string{"general", "exit", "internal"},
	}
}

// Helper functions

func generateCircuitID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("circuit_%x", bytes)
}

func (cm *CircuitManager) preemptiveBuildingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cm.ensureMinimumCircuits()
		case <-cm.ctx.Done():
			return
		}
	}
}

func (cm *CircuitManager) ensureMinimumCircuits() {
	cm.mutex.RLock()
	activeCount := len(cm.circuits)
	cm.mutex.RUnlock()
	
	if activeCount < cm.config.MinCircuits {
		needed := cm.config.MinCircuits - activeCount
		for i := 0; i < needed; i++ {
			go func() {
				_, err := cm.CreateCircuit("general")
				if err != nil {
					cm.logger.Errorf("Failed to create preemptive circuit: %v", err)
				}
			}()
		}
	}
}

func (cm *CircuitManager) maintenanceLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cm.cleanupIdleCircuits()
		case <-cm.ctx.Done():
			return
		}
	}
}

func (cm *CircuitManager) cleanupIdleCircuits() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	now := time.Now()
	for id, circuit := range cm.circuits {
		if now.Sub(circuit.LastUsed) > cm.config.CircuitIdleTimeout {
			circuit.State = CircuitStateClosed
			if circuit.conn != nil {
				circuit.conn.Close()
			}
			delete(cm.circuits, id)
			cm.logger.Debugf("Cleaned up idle circuit %s", id)
		}
	}
}

func (cm *CircuitManager) metricsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cm.updateCircuitMetrics()
		case <-cm.ctx.Done():
			return
		}
	}
}

func (cm *CircuitManager) updateCircuitMetrics() {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	cm.metrics.ActiveCircuits = int64(len(cm.circuits))
	cm.metrics.LastUpdated = time.Now()
	
	// Calculate total bytes
	var totalBytes int64
	for _, circuit := range cm.circuits {
		totalBytes += circuit.BytesRead + circuit.BytesWritten
	}
	cm.metrics.TotalBytes = totalBytes
}

func (cm *CircuitManager) updateMetrics(success bool, buildTime time.Duration) {
	cm.metrics.TotalCircuits++

	if success {
		if buildTime > cm.metrics.MaxBuildTime {
			cm.metrics.MaxBuildTime = buildTime
		}
		if buildTime < cm.metrics.MinBuildTime {
			cm.metrics.MinBuildTime = buildTime
		}
		cm.metrics.AvgBuildTime = (cm.metrics.AvgBuildTime + buildTime) / 2
	} else {
		cm.metrics.FailedCircuits++
	}
}

// NewCircuitPool creates a new circuit pool
func NewCircuitPool(maxSize int) *CircuitPool {
	return &CircuitPool{
		availableCircuits: make(map[string][]*Circuit),
		busyCircuits:     make(map[string]*Circuit),
		maxPoolSize:      maxSize,
		logger:           logx.WithContext(context.Background()),
	}
}

// GetAvailableCircuit gets an available circuit for the given purpose
func (cp *CircuitPool) GetAvailableCircuit(purpose string) *Circuit {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	circuits, exists := cp.availableCircuits[purpose]
	if !exists || len(circuits) == 0 {
		return nil
	}

	// Get the first available circuit
	circuit := circuits[0]
	cp.availableCircuits[purpose] = circuits[1:]
	cp.busyCircuits[circuit.ID] = circuit

	return circuit
}

// AddCircuit adds a circuit to the pool
func (cp *CircuitPool) AddCircuit(circuit *Circuit) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if len(cp.availableCircuits[circuit.Purpose]) >= cp.maxPoolSize {
		return // Pool is full
	}

	cp.availableCircuits[circuit.Purpose] = append(cp.availableCircuits[circuit.Purpose], circuit)
}

// NewNodeDirectory creates a new node directory
func NewNodeDirectory() *NodeDirectory {
	return &NodeDirectory{
		nodes:       make(map[string]*Node),
		guardNodes:  make([]*Node, 0),
		middleNodes: make([]*Node, 0),
		exitNodes:   make([]*Node, 0),
		logger:      logx.WithContext(context.Background()),
	}
}

// Update updates the node directory with current relay information
func (nd *NodeDirectory) Update() error {
	nd.mutex.Lock()
	defer nd.mutex.Unlock()

	// Simulate loading node information (in real implementation, this would fetch from Tor directory)
	sampleNodes := []*Node{
		{
			Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Nickname:    "GuardNode1",
			Address:     "198.96.155.3",
			Port:        9001,
			Country:     "US",
			Bandwidth:   1000000,
			Flags:       []string{"Guard", "Stable", "Fast"},
			IsGuard:     true,
			IsExit:      false,
			IsStable:    true,
			IsFast:      true,
			LastSeen:    time.Now(),
			SuccessRate: 0.99,
		},
		{
			Fingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			Nickname:    "MiddleNode1",
			Address:     "176.10.104.240",
			Port:        9001,
			Country:     "DE",
			Bandwidth:   2000000,
			Flags:       []string{"Stable", "Fast"},
			IsGuard:     false,
			IsExit:      false,
			IsStable:    true,
			IsFast:      true,
			LastSeen:    time.Now(),
			SuccessRate: 0.98,
		},
		{
			Fingerprint: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			Nickname:    "ExitNode1",
			Address:     "185.220.101.32",
			Port:        9001,
			Country:     "NL",
			Bandwidth:   1500000,
			Flags:       []string{"Exit", "Stable", "Fast"},
			IsGuard:     false,
			IsExit:      true,
			IsStable:    true,
			IsFast:      true,
			LastSeen:    time.Now(),
			SuccessRate: 0.97,
		},
	}

	// Clear existing nodes
	nd.nodes = make(map[string]*Node)
	nd.guardNodes = nd.guardNodes[:0]
	nd.middleNodes = nd.middleNodes[:0]
	nd.exitNodes = nd.exitNodes[:0]

	// Add sample nodes
	for _, node := range sampleNodes {
		nd.nodes[node.Fingerprint] = node

		if node.IsGuard {
			nd.guardNodes = append(nd.guardNodes, node)
		} else if node.IsExit {
			nd.exitNodes = append(nd.exitNodes, node)
		} else {
			nd.middleNodes = append(nd.middleNodes, node)
		}
	}

	nd.lastUpdated = time.Now()
	nd.logger.Infof("Updated node directory: %d guards, %d middle, %d exit nodes",
		len(nd.guardNodes), len(nd.middleNodes), len(nd.exitNodes))

	return nil
}

// NewPathSelector creates a new path selector
func NewPathSelector(nodeDirectory *NodeDirectory, config *CircuitConfig) *PathSelector {
	return &PathSelector{
		nodeDirectory: nodeDirectory,
		config:        config,
		logger:        logx.WithContext(context.Background()),
	}
}

// SelectPath selects an optimal path for a circuit
func (ps *PathSelector) SelectPath(purpose string) ([]*Node, error) {
	ps.nodeDirectory.mutex.RLock()
	defer ps.nodeDirectory.mutex.RUnlock()

	if len(ps.nodeDirectory.guardNodes) == 0 || len(ps.nodeDirectory.exitNodes) == 0 {
		return nil, fmt.Errorf("insufficient nodes available")
	}

	path := make([]*Node, 0, ps.config.PathLength)

	// Select guard node (first hop)
	guardNode := ps.selectBestNode(ps.nodeDirectory.guardNodes)
	if guardNode == nil {
		return nil, fmt.Errorf("no suitable guard node found")
	}
	path = append(path, guardNode)

	// Select middle nodes
	for i := 1; i < ps.config.PathLength-1; i++ {
		middleNode := ps.selectBestNode(ps.nodeDirectory.middleNodes)
		if middleNode == nil {
			return nil, fmt.Errorf("no suitable middle node found")
		}
		path = append(path, middleNode)
	}

	// Select exit node (last hop)
	exitNode := ps.selectBestNode(ps.nodeDirectory.exitNodes)
	if exitNode == nil {
		return nil, fmt.Errorf("no suitable exit node found")
	}
	path = append(path, exitNode)

	ps.logger.Debugf("Selected path for %s: %s -> %s -> %s",
		purpose, guardNode.Nickname, path[1].Nickname, exitNode.Nickname)

	return path, nil
}

// selectBestNode selects the best node from a list based on performance metrics
func (ps *PathSelector) selectBestNode(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}

	// Simple selection based on success rate and bandwidth
	var bestNode *Node
	var bestScore float64

	for _, node := range nodes {
		// Calculate score based on success rate and bandwidth
		score := node.SuccessRate * (float64(node.Bandwidth) / 1000000.0)

		if bestNode == nil || score > bestScore {
			bestNode = node
			bestScore = score
		}
	}

	return bestNode
}

// NewStreamManager creates a new stream manager
func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams: make(map[int]*Stream),
		nextID:  1,
		logger:  logx.WithContext(context.Background()),
	}
}

// GetNextID returns the next available stream ID
func (sm *StreamManager) GetNextID() int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	id := sm.nextID
	sm.nextID++
	return id
}

// AddStream adds a stream to the manager
func (sm *StreamManager) AddStream(stream *Stream) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.streams[stream.ID] = stream
}
