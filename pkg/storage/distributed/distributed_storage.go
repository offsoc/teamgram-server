package distributed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// DistributedStorage provides distributed storage capabilities
type DistributedStorage struct {
	config      *Config
	nodes       map[string]*StorageNode
	shards      map[string]*Shard
	replicas    map[string][]*Replica
	metadata    map[string]*FileMetadata
	mutex       sync.RWMutex
	logger      logx.Logger
}

// Config for distributed storage
type Config struct {
	ReplicationFactor    int    `json:"replication_factor"`
	ShardSize           int64  `json:"shard_size"`           // bytes
	ConsistencyLevel    string `json:"consistency_level"`   // strong, eventual, weak
	CompressionEnabled  bool   `json:"compression_enabled"`
	EncryptionEnabled   bool   `json:"encryption_enabled"`
	ErasureCoding       bool   `json:"erasure_coding"`
	AutoRebalancing     bool   `json:"auto_rebalancing"`
	HealthCheckInterval int    `json:"health_check_interval"` // seconds
}

// StorageNode represents a storage node in the cluster
type StorageNode struct {
	ID          string            `json:"id"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Status      NodeStatus        `json:"status"`
	Capacity    int64             `json:"capacity"`    // bytes
	Used        int64             `json:"used"`        // bytes
	Available   int64             `json:"available"`   // bytes
	Load        float64           `json:"load"`        // 0.0 to 1.0
	Latency     time.Duration     `json:"latency"`
	Shards      []string          `json:"shards"`
	Metadata    map[string]string `json:"metadata"`
	LastSeen    time.Time         `json:"last_seen"`
	CreatedAt   time.Time         `json:"created_at"`
}

// Shard represents a data shard
type Shard struct {
	ID          string            `json:"id"`
	FileID      string            `json:"file_id"`
	Index       int               `json:"index"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"`
	Data        []byte            `json:"data"`
	Compressed  bool              `json:"compressed"`
	Encrypted   bool              `json:"encrypted"`
	Nodes       []string          `json:"nodes"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Replica represents a shard replica
type Replica struct {
	ID        string    `json:"id"`
	ShardID   string    `json:"shard_id"`
	NodeID    string    `json:"node_id"`
	Status    ReplicaStatus `json:"status"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileMetadata represents file metadata
type FileMetadata struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Size        int64             `json:"size"`
	MimeType    string            `json:"mime_type"`
	Checksum    string            `json:"checksum"`
	ShardCount  int               `json:"shard_count"`
	Shards      []string          `json:"shards"`
	Compressed  bool              `json:"compressed"`
	Encrypted   bool              `json:"encrypted"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	AccessedAt  time.Time         `json:"accessed_at"`
}

// StoreRequest represents a store request
type StoreRequest struct {
	FileID      string            `json:"file_id"`
	FileName    string            `json:"file_name"`
	Data        []byte            `json:"data"`
	MimeType    string            `json:"mime_type"`
	Compress    bool              `json:"compress"`
	Encrypt     bool              `json:"encrypt"`
	Metadata    map[string]string `json:"metadata"`
}

// StoreResult represents store results
type StoreResult struct {
	FileID      string            `json:"file_id"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"`
	ShardCount  int               `json:"shard_count"`
	Nodes       []string          `json:"nodes"`
	StoredAt    time.Time         `json:"stored_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RetrieveRequest represents a retrieve request
type RetrieveRequest struct {
	FileID      string            `json:"file_id"`
	Metadata    map[string]string `json:"metadata"`
}

// RetrieveResult represents retrieve results
type RetrieveResult struct {
	FileID      string            `json:"file_id"`
	FileName    string            `json:"file_name"`
	Data        []byte            `json:"data"`
	Size        int64             `json:"size"`
	MimeType    string            `json:"mime_type"`
	Checksum    string            `json:"checksum"`
	RetrievedAt time.Time         `json:"retrieved_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums
type NodeStatus string
const (
	NodeStatusOnline     NodeStatus = "online"
	NodeStatusOffline    NodeStatus = "offline"
	NodeStatusMaintenance NodeStatus = "maintenance"
	NodeStatusFailed     NodeStatus = "failed"
)

type ReplicaStatus string
const (
	ReplicaStatusActive   ReplicaStatus = "active"
	ReplicaStatusStale    ReplicaStatus = "stale"
	ReplicaStatusCorrupted ReplicaStatus = "corrupted"
	ReplicaStatusMissing  ReplicaStatus = "missing"
)

// NewDistributedStorage creates a new distributed storage service
func NewDistributedStorage(config *Config) *DistributedStorage {
	if config == nil {
		config = DefaultConfig()
	}

	storage := &DistributedStorage{
		config:   config,
		nodes:    make(map[string]*StorageNode),
		shards:   make(map[string]*Shard),
		replicas: make(map[string][]*Replica),
		metadata: make(map[string]*FileMetadata),
		logger:   logx.WithContext(context.Background()),
	}

	// Initialize default nodes
	storage.initializeDefaultNodes()

	return storage
}

// DefaultConfig returns default distributed storage configuration
func DefaultConfig() *Config {
	return &Config{
		ReplicationFactor:    3,
		ShardSize:           64 * 1024 * 1024, // 64MB
		ConsistencyLevel:    "eventual",
		CompressionEnabled:  true,
		EncryptionEnabled:   true,
		ErasureCoding:       false,
		AutoRebalancing:     true,
		HealthCheckInterval: 30,
	}
}

// Store stores data in the distributed storage
func (ds *DistributedStorage) Store(ctx context.Context, request *StoreRequest) (*StoreResult, error) {
	start := time.Now()

	// Generate file ID if not provided
	if request.FileID == "" {
		request.FileID = ds.generateFileID(request.FileName, request.Data)
	}

	// Calculate checksum
	checksum := ds.calculateChecksum(request.Data)

	// Create file metadata
	metadata := &FileMetadata{
		ID:         request.FileID,
		Name:       request.FileName,
		Size:       int64(len(request.Data)),
		MimeType:   request.MimeType,
		Checksum:   checksum,
		Compressed: request.Compress,
		Encrypted:  request.Encrypt,
		Metadata:   request.Metadata,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		AccessedAt: time.Now(),
	}

	// Process data (compression, encryption)
	processedData := ds.processData(request.Data, request.Compress, request.Encrypt)

	// Create shards
	shards := ds.createShards(request.FileID, processedData)
	metadata.ShardCount = len(shards)
	metadata.Shards = make([]string, len(shards))

	// Store shards across nodes
	var storedNodes []string
	for i, shard := range shards {
		metadata.Shards[i] = shard.ID
		
		// Select nodes for this shard
		nodes, err := ds.selectNodes(shard)
		if err != nil {
			return nil, fmt.Errorf("failed to select nodes for shard %s: %w", shard.ID, err)
		}

		// Store shard on selected nodes
		err = ds.storeShard(shard, nodes)
		if err != nil {
			return nil, fmt.Errorf("failed to store shard %s: %w", shard.ID, err)
		}

		storedNodes = append(storedNodes, nodes...)
	}

	// Store metadata
	ds.mutex.Lock()
	ds.metadata[request.FileID] = metadata
	ds.mutex.Unlock()

	result := &StoreResult{
		FileID:     request.FileID,
		Size:       metadata.Size,
		Checksum:   checksum,
		ShardCount: len(shards),
		Nodes:      ds.uniqueStrings(storedNodes),
		StoredAt:   start,
		Metadata:   make(map[string]interface{}),
	}

	ds.logger.Infof("Stored file %s (%d bytes) across %d nodes", request.FileID, metadata.Size, len(result.Nodes))
	return result, nil
}

// Retrieve retrieves data from distributed storage
func (ds *DistributedStorage) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResult, error) {
	start := time.Now()

	// Get file metadata
	ds.mutex.RLock()
	metadata, exists := ds.metadata[request.FileID]
	ds.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("file %s not found", request.FileID)
	}

	// Retrieve shards
	var shardData [][]byte
	for _, shardID := range metadata.Shards {
		data, err := ds.retrieveShard(shardID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve shard %s: %w", shardID, err)
		}
		shardData = append(shardData, data)
	}

	// Reconstruct file data
	reconstructedData := ds.reconstructData(shardData)

	// Process data (decompression, decryption)
	finalData := ds.unprocessData(reconstructedData, metadata.Compressed, metadata.Encrypted)

	// Verify checksum
	if ds.calculateChecksum(finalData) != metadata.Checksum {
		return nil, fmt.Errorf("checksum verification failed for file %s", request.FileID)
	}

	// Update access time
	ds.mutex.Lock()
	metadata.AccessedAt = time.Now()
	ds.mutex.Unlock()

	result := &RetrieveResult{
		FileID:      request.FileID,
		FileName:    metadata.Name,
		Data:        finalData,
		Size:        metadata.Size,
		MimeType:    metadata.MimeType,
		Checksum:    metadata.Checksum,
		RetrievedAt: start,
		Metadata:    make(map[string]interface{}),
	}

	ds.logger.Infof("Retrieved file %s (%d bytes)", request.FileID, metadata.Size)
	return result, nil
}

// Delete deletes data from distributed storage
func (ds *DistributedStorage) Delete(ctx context.Context, fileID string) error {
	// Get file metadata
	ds.mutex.RLock()
	metadata, exists := ds.metadata[fileID]
	ds.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("file %s not found", fileID)
	}

	// Delete shards
	for _, shardID := range metadata.Shards {
		err := ds.deleteShard(shardID)
		if err != nil {
			ds.logger.Errorf("Failed to delete shard %s: %v", shardID, err)
		}
	}

	// Delete metadata
	ds.mutex.Lock()
	delete(ds.metadata, fileID)
	ds.mutex.Unlock()

	ds.logger.Infof("Deleted file %s", fileID)
	return nil
}

// Helper methods

func (ds *DistributedStorage) generateFileID(fileName string, data []byte) string {
	hash := sha256.Sum256([]byte(fileName + string(data) + fmt.Sprintf("%d", time.Now().Unix())))
	return hex.EncodeToString(hash[:])
}

func (ds *DistributedStorage) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (ds *DistributedStorage) processData(data []byte, compress, encrypt bool) []byte {
	result := data

	// Mock compression
	if compress {
		result = ds.compressData(result)
	}

	// Mock encryption
	if encrypt {
		result = ds.encryptData(result)
	}

	return result
}

func (ds *DistributedStorage) unprocessData(data []byte, compressed, encrypted bool) []byte {
	result := data

	// Mock decryption
	if encrypted {
		result = ds.decryptData(result)
	}

	// Mock decompression
	if compressed {
		result = ds.decompressData(result)
	}

	return result
}

func (ds *DistributedStorage) compressData(data []byte) []byte {
	// Mock compression - in production, use actual compression
	return data
}

func (ds *DistributedStorage) decompressData(data []byte) []byte {
	// Mock decompression - in production, use actual decompression
	return data
}

func (ds *DistributedStorage) encryptData(data []byte) []byte {
	// Mock encryption - in production, use actual encryption
	return data
}

func (ds *DistributedStorage) decryptData(data []byte) []byte {
	// Mock decryption - in production, use actual decryption
	return data
}

func (ds *DistributedStorage) createShards(fileID string, data []byte) []*Shard {
	var shards []*Shard
	shardSize := ds.config.ShardSize
	
	for i := int64(0); i < int64(len(data)); i += shardSize {
		end := i + shardSize
		if end > int64(len(data)) {
			end = int64(len(data))
		}

		shardData := data[i:end]
		shard := &Shard{
			ID:        fmt.Sprintf("%s_shard_%d", fileID, len(shards)),
			FileID:    fileID,
			Index:     len(shards),
			Size:      int64(len(shardData)),
			Checksum:  ds.calculateChecksum(shardData),
			Data:      shardData,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		shards = append(shards, shard)
	}

	return shards
}

func (ds *DistributedStorage) selectNodes(shard *Shard) ([]string, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	var availableNodes []*StorageNode
	for _, node := range ds.nodes {
		if node.Status == NodeStatusOnline && node.Available >= shard.Size {
			availableNodes = append(availableNodes, node)
		}
	}

	if len(availableNodes) < ds.config.ReplicationFactor {
		return nil, fmt.Errorf("insufficient available nodes: need %d, have %d", ds.config.ReplicationFactor, len(availableNodes))
	}

	// Select nodes with lowest load
	selectedNodes := make([]string, ds.config.ReplicationFactor)
	for i := 0; i < ds.config.ReplicationFactor && i < len(availableNodes); i++ {
		selectedNodes[i] = availableNodes[i].ID
	}

	return selectedNodes, nil
}

func (ds *DistributedStorage) storeShard(shard *Shard, nodeIDs []string) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// Store shard
	ds.shards[shard.ID] = shard
	shard.Nodes = nodeIDs

	// Create replicas
	var replicas []*Replica
	for _, nodeID := range nodeIDs {
		replica := &Replica{
			ID:        fmt.Sprintf("%s_replica_%s", shard.ID, nodeID),
			ShardID:   shard.ID,
			NodeID:    nodeID,
			Status:    ReplicaStatusActive,
			Checksum:  shard.Checksum,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		replicas = append(replicas, replica)

		// Update node usage
		if node, exists := ds.nodes[nodeID]; exists {
			node.Used += shard.Size
			node.Available = node.Capacity - node.Used
			node.Shards = append(node.Shards, shard.ID)
		}
	}

	ds.replicas[shard.ID] = replicas
	return nil
}

func (ds *DistributedStorage) retrieveShard(shardID string) ([]byte, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	shard, exists := ds.shards[shardID]
	if !exists {
		return nil, fmt.Errorf("shard %s not found", shardID)
	}

	// In production, this would retrieve from actual storage nodes
	return shard.Data, nil
}

func (ds *DistributedStorage) deleteShard(shardID string) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	shard, exists := ds.shards[shardID]
	if !exists {
		return fmt.Errorf("shard %s not found", shardID)
	}

	// Update node usage
	for _, nodeID := range shard.Nodes {
		if node, exists := ds.nodes[nodeID]; exists {
			node.Used -= shard.Size
			node.Available = node.Capacity - node.Used
			
			// Remove shard from node
			for i, id := range node.Shards {
				if id == shardID {
					node.Shards = append(node.Shards[:i], node.Shards[i+1:]...)
					break
				}
			}
		}
	}

	// Delete shard and replicas
	delete(ds.shards, shardID)
	delete(ds.replicas, shardID)

	return nil
}

func (ds *DistributedStorage) reconstructData(shardData [][]byte) []byte {
	var result []byte
	for _, data := range shardData {
		result = append(result, data...)
	}
	return result
}

func (ds *DistributedStorage) uniqueStrings(strings []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, str := range strings {
		if !keys[str] {
			keys[str] = true
			result = append(result, str)
		}
	}
	
	return result
}

func (ds *DistributedStorage) initializeDefaultNodes() {
	// Create default storage nodes
	nodes := []*StorageNode{
		{
			ID:        "node_1",
			Address:   "192.168.1.10",
			Port:      8080,
			Status:    NodeStatusOnline,
			Capacity:  1024 * 1024 * 1024 * 100, // 100GB
			Used:      0,
			Available: 1024 * 1024 * 1024 * 100,
			Load:      0.0,
			Latency:   10 * time.Millisecond,
			Shards:    []string{},
			LastSeen:  time.Now(),
			CreatedAt: time.Now(),
		},
		{
			ID:        "node_2",
			Address:   "192.168.1.11",
			Port:      8080,
			Status:    NodeStatusOnline,
			Capacity:  1024 * 1024 * 1024 * 100, // 100GB
			Used:      0,
			Available: 1024 * 1024 * 1024 * 100,
			Load:      0.0,
			Latency:   12 * time.Millisecond,
			Shards:    []string{},
			LastSeen:  time.Now(),
			CreatedAt: time.Now(),
		},
		{
			ID:        "node_3",
			Address:   "192.168.1.12",
			Port:      8080,
			Status:    NodeStatusOnline,
			Capacity:  1024 * 1024 * 1024 * 100, // 100GB
			Used:      0,
			Available: 1024 * 1024 * 1024 * 100,
			Load:      0.0,
			Latency:   15 * time.Millisecond,
			Shards:    []string{},
			LastSeen:  time.Now(),
			CreatedAt: time.Now(),
		},
	}

	for _, node := range nodes {
		ds.nodes[node.ID] = node
	}
}

// GetFileMetadata gets file metadata
func (ds *DistributedStorage) GetFileMetadata(fileID string) (*FileMetadata, error) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	metadata, exists := ds.metadata[fileID]
	if !exists {
		return nil, fmt.Errorf("file %s not found", fileID)
	}

	return metadata, nil
}

// ListFiles lists all files
func (ds *DistributedStorage) ListFiles() []*FileMetadata {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	files := make([]*FileMetadata, 0, len(ds.metadata))
	for _, metadata := range ds.metadata {
		files = append(files, metadata)
	}

	return files
}

// GetStorageStats gets storage statistics
func (ds *DistributedStorage) GetStorageStats() map[string]interface{} {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	stats := make(map[string]interface{})
	
	totalCapacity := int64(0)
	totalUsed := int64(0)
	onlineNodes := 0
	
	for _, node := range ds.nodes {
		totalCapacity += node.Capacity
		totalUsed += node.Used
		if node.Status == NodeStatusOnline {
			onlineNodes++
		}
	}

	stats["total_capacity"] = totalCapacity
	stats["total_used"] = totalUsed
	stats["total_available"] = totalCapacity - totalUsed
	stats["utilization"] = float64(totalUsed) / float64(totalCapacity)
	stats["total_nodes"] = len(ds.nodes)
	stats["online_nodes"] = onlineNodes
	stats["total_files"] = len(ds.metadata)
	stats["total_shards"] = len(ds.shards)

	return stats
}
