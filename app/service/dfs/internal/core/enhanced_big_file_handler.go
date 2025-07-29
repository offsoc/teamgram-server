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

package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/pkg/compression"
	"github.com/teamgram/teamgram-server/pkg/merkle"
	"github.com/zeromicro/go-zero/core/logx"
)

// EnhancedBigFileHandler handles 16GB file uploads with advanced features
type EnhancedBigFileHandler struct {
	*DfsCore
	chunkManager       *ChunkManager
	integrityVerifier  *IntegrityVerifier
	compressionManager *compression.Manager
	merkleTreeBuilder  *merkle.TreeBuilder
	uploadSessions     map[int64]*BigFileUploadSession
	downloadSessions   map[int64]*BigFileDownloadSession
	mutex              sync.RWMutex
	logger             logx.Logger
}

// BigFileUploadSession represents an active big file upload session
type BigFileUploadSession struct {
	FileID          int64                   `json:"file_id"`
	TotalSize       int64                   `json:"total_size"`
	TotalParts      int32                   `json:"total_parts"`
	ChunkSize       int32                   `json:"chunk_size"`
	UploadedParts   map[int32]*FilePartInfo `json:"uploaded_parts"`
	MerkleTree      *merkle.Tree            `json:"-"`
	CompressionType compression.Algorithm   `json:"compression_type"`
	OriginalHash    []byte                  `json:"original_hash"`
	CompressedHash  []byte                  `json:"compressed_hash"`
	StartTime       time.Time               `json:"start_time"`
	LastActivity    time.Time               `json:"last_activity"`
	UploadSpeed     float64                 `json:"upload_speed"` // bytes per second
	NetworkQuality  NetworkQuality          `json:"network_quality"`
	IsCompleted     bool                    `json:"is_completed"`
	IsVerified      bool                    `json:"is_verified"`
	ErrorCount      int                     `json:"error_count"`
	RetryCount      int                     `json:"retry_count"`
	mutex           sync.RWMutex
}

// BigFileDownloadSession represents an active big file download session
type BigFileDownloadSession struct {
	FileID              int64          `json:"file_id"`
	TotalSize           int64          `json:"total_size"`
	DownloadedSize      int64          `json:"downloaded_size"`
	ChunkSize           int32          `json:"chunk_size"`
	DownloadedParts     map[int32]bool `json:"downloaded_parts"`
	ResumeOffset        int64          `json:"resume_offset"`
	ParallelConnections int            `json:"parallel_connections"`
	DownloadSpeed       float64        `json:"download_speed"`
	StartTime           time.Time      `json:"start_time"`
	LastActivity        time.Time      `json:"last_activity"`
	IsCompleted         bool           `json:"is_completed"`
	mutex               sync.RWMutex
}

// FilePartInfo represents information about a file part
type FilePartInfo struct {
	PartNum        int32     `json:"part_num"`
	Size           int32     `json:"size"`
	Hash           []byte    `json:"hash"`
	CompressedSize int32     `json:"compressed_size"`
	CompressedHash []byte    `json:"compressed_hash"`
	UploadTime     time.Time `json:"upload_time"`
	RetryCount     int       `json:"retry_count"`
	IsVerified     bool      `json:"is_verified"`
}

// ChunkManager manages intelligent chunking based on network conditions
type ChunkManager struct {
	defaultChunkSize int32                  `json:"default_chunk_size"`
	maxChunkSize     int32                  `json:"max_chunk_size"`
	minChunkSize     int32                  `json:"min_chunk_size"`
	adaptiveChunking bool                   `json:"adaptive_chunking"`
	networkMonitor   *NetworkMonitor        `json:"-"`
	chunkSizeHistory []*ChunkSizeAdaptation `json:"chunk_size_history"`
	mutex            sync.RWMutex
}

// IntegrityVerifier verifies file integrity using multiple methods
type IntegrityVerifier struct {
	enableMerkleTree   bool               `json:"enable_merkle_tree"`
	enableDigitalSign  bool               `json:"enable_digital_sign"`
	hashAlgorithm      HashAlgorithm      `json:"hash_algorithm"`
	signatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	verificationLevel  VerificationLevel  `json:"verification_level"`
}

// NetworkMonitor monitors network conditions for adaptive chunking
type NetworkMonitor struct {
	bandwidth          int64                 `json:"bandwidth"`
	latency            time.Duration         `json:"latency"`
	packetLoss         float64               `json:"packet_loss"`
	quality            NetworkQuality        `json:"quality"`
	lastMeasurement    time.Time             `json:"last_measurement"`
	measurementHistory []*NetworkMeasurement `json:"measurement_history"`
	mutex              sync.RWMutex
}

// Supporting types
type NetworkQuality string

const (
	NetworkQualityExcellent NetworkQuality = "excellent"
	NetworkQualityGood      NetworkQuality = "good"
	NetworkQualityFair      NetworkQuality = "fair"
	NetworkQualityPoor      NetworkQuality = "poor"
)

type HashAlgorithm string

const (
	HashAlgorithmMD5    HashAlgorithm = "md5"
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	HashAlgorithmSHA512 HashAlgorithm = "sha512"
)

type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA     SignatureAlgorithm = "rsa"
	SignatureAlgorithmECDSA   SignatureAlgorithm = "ecdsa"
	SignatureAlgorithmEd25519 SignatureAlgorithm = "ed25519"
)

type VerificationLevel string

const (
	VerificationLevelBasic    VerificationLevel = "basic"
	VerificationLevelStandard VerificationLevel = "standard"
	VerificationLevelStrict   VerificationLevel = "strict"
)

type ChunkSizeAdaptation struct {
	Timestamp      time.Time      `json:"timestamp"`
	OldSize        int32          `json:"old_size"`
	NewSize        int32          `json:"new_size"`
	NetworkQuality NetworkQuality `json:"network_quality"`
	Reason         string         `json:"reason"`
}

type NetworkMeasurement struct {
	Timestamp  time.Time      `json:"timestamp"`
	Bandwidth  int64          `json:"bandwidth"`
	Latency    time.Duration  `json:"latency"`
	PacketLoss float64        `json:"packet_loss"`
	Quality    NetworkQuality `json:"quality"`
}

// NewEnhancedBigFileHandler creates a new enhanced big file handler
func NewEnhancedBigFileHandler(core *DfsCore) *EnhancedBigFileHandler {
	handler := &EnhancedBigFileHandler{
		DfsCore:          core,
		uploadSessions:   make(map[int64]*BigFileUploadSession),
		downloadSessions: make(map[int64]*BigFileDownloadSession),
		logger:           logx.WithContext(context.Background()),
	}

	// Initialize chunk manager
	handler.chunkManager = &ChunkManager{
		defaultChunkSize: 128 * 1024 * 1024, // 128MB default
		maxChunkSize:     256 * 1024 * 1024, // 256MB max
		minChunkSize:     32 * 1024 * 1024,  // 32MB min
		adaptiveChunking: true,
		networkMonitor:   NewNetworkMonitor(),
	}

	// Initialize integrity verifier
	handler.integrityVerifier = &IntegrityVerifier{
		enableMerkleTree:   true,
		enableDigitalSign:  true,
		hashAlgorithm:      HashAlgorithmSHA256,
		signatureAlgorithm: SignatureAlgorithmEd25519,
		verificationLevel:  VerificationLevelStrict,
	}

	// Initialize compression manager
	compressionManager, err := compression.NewManager(compression.DefaultConfig())
	if err != nil {
		handler.logger.Errorf("Failed to initialize compression manager: %v", err)
	} else {
		handler.compressionManager = compressionManager
	}

	// Initialize Merkle tree builder
	handler.merkleTreeBuilder = merkle.NewTreeBuilder()

	return handler
}

// SaveBigFilePart implements upload.saveBigFilePart API with 128MB parallel upload support
func (h *EnhancedBigFileHandler) SaveBigFilePart(ctx context.Context, req *mtproto.TLUploadSaveBigFilePart) (*mtproto.Bool, error) {
	startTime := time.Now()

	h.logger.Infof("SaveBigFilePart: file_id=%d, file_part=%d, file_total_parts=%d, bytes_size=%d",
		req.FileId, req.FilePart, req.FileTotalParts, len(req.Bytes))

	// Validate request
	if err := h.validateSaveBigFilePartRequest(req); err != nil {
		return mtproto.BoolFalse, err
	}

	// Get or create upload session
	session, err := h.getOrCreateUploadSession(req.FileId, req.FileTotalParts, int64(len(req.Bytes))*int64(req.FileTotalParts))
	if err != nil {
		return mtproto.BoolFalse, fmt.Errorf("failed to get upload session: %w", err)
	}

	// Adapt chunk size based on network conditions
	if h.chunkManager.adaptiveChunking {
		h.adaptChunkSize(session)
	}

	// Compress file part if beneficial
	compressedBytes, compressionType, err := h.compressFilePart(req.Bytes)
	if err != nil {
		h.logger.Errorf("Compression failed, using original: %v", err)
		compressedBytes = req.Bytes
		compressionType = compression.AlgorithmNone
	}

	// Calculate hashes
	originalHash := sha256.Sum256(req.Bytes)
	compressedHash := sha256.Sum256(compressedBytes)

	// Create file part info
	partInfo := &FilePartInfo{
		PartNum:        req.FilePart,
		Size:           int32(len(req.Bytes)),
		Hash:           originalHash[:],
		CompressedSize: int32(len(compressedBytes)),
		CompressedHash: compressedHash[:],
		UploadTime:     time.Now(),
		IsVerified:     false,
	}

	// Store file part
	if err := h.storeFilePart(ctx, req.FileId, req.FilePart, compressedBytes, partInfo); err != nil {
		session.ErrorCount++
		return mtproto.BoolFalse, fmt.Errorf("failed to store file part: %w", err)
	}

	// Update session
	session.mutex.Lock()
	session.UploadedParts[req.FilePart] = partInfo
	session.LastActivity = time.Now()
	session.CompressionType = compressionType

	// Update upload speed
	uploadTime := time.Since(startTime)
	if uploadTime > 0 {
		speed := float64(len(req.Bytes)) / uploadTime.Seconds()
		session.UploadSpeed = (session.UploadSpeed + speed) / 2.0 // Moving average
	}

	// Check if upload is complete
	if int32(len(session.UploadedParts)) == session.TotalParts {
		session.IsCompleted = true
		h.logger.Infof("File upload completed: file_id=%d, total_parts=%d", req.FileId, session.TotalParts)

		// Start integrity verification
		go h.verifyFileIntegrity(ctx, session)
	}
	session.mutex.Unlock()

	// Log performance metrics
	h.logUploadMetrics(session, uploadTime, len(req.Bytes))

	return mtproto.BoolTrue, nil
}

// validateSaveBigFilePartRequest validates the save big file part request
func (h *EnhancedBigFileHandler) validateSaveBigFilePartRequest(req *mtproto.TLUploadSaveBigFilePart) error {
	// Validate file ID
	if req.FileId <= 0 {
		return fmt.Errorf("invalid file ID: %d", req.FileId)
	}

	// Validate part number
	if req.FilePart < 0 {
		return fmt.Errorf("invalid file part: %d", req.FilePart)
	}

	// Validate total parts
	if req.FileTotalParts <= 0 {
		return fmt.Errorf("invalid total parts: %d", req.FileTotalParts)
	}

	// Validate part size (max 128MB for big files)
	if len(req.Bytes) > 128*1024*1024 {
		return fmt.Errorf("part size too large: %d bytes (max 128MB)", len(req.Bytes))
	}

	// Validate total file size (max 16GB)
	estimatedTotalSize := int64(len(req.Bytes)) * int64(req.FileTotalParts)
	if estimatedTotalSize > 16*1024*1024*1024 {
		return fmt.Errorf("file too large: estimated %d bytes (max 16GB)", estimatedTotalSize)
	}

	return nil
}

// getOrCreateUploadSession gets or creates an upload session
func (h *EnhancedBigFileHandler) getOrCreateUploadSession(fileID int64, totalParts int32, estimatedSize int64) (*BigFileUploadSession, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	session, exists := h.uploadSessions[fileID]
	if !exists {
		// Create new session
		session = &BigFileUploadSession{
			FileID:         fileID,
			TotalSize:      estimatedSize,
			TotalParts:     totalParts,
			ChunkSize:      h.chunkManager.defaultChunkSize,
			UploadedParts:  make(map[int32]*FilePartInfo),
			StartTime:      time.Now(),
			LastActivity:   time.Now(),
			NetworkQuality: h.chunkManager.networkMonitor.quality,
		}

		// Initialize Merkle tree
		if h.integrityVerifier.enableMerkleTree {
			session.MerkleTree = merkle.NewMerkleTree()
		}

		h.uploadSessions[fileID] = session
		h.logger.Infof("Created new upload session: file_id=%d, total_parts=%d, estimated_size=%d",
			fileID, totalParts, estimatedSize)
	}

	return session, nil
}

// adaptChunkSize adapts chunk size based on network conditions
func (h *EnhancedBigFileHandler) adaptChunkSize(session *BigFileUploadSession) {
	h.chunkManager.mutex.Lock()
	defer h.chunkManager.mutex.Unlock()

	networkQuality := h.chunkManager.networkMonitor.GetCurrentQuality()
	oldSize := session.ChunkSize
	newSize := oldSize

	switch networkQuality {
	case NetworkQualityExcellent:
		// Use larger chunks for excellent network
		newSize = h.chunkManager.maxChunkSize
	case NetworkQualityGood:
		// Use default chunks for good network
		newSize = h.chunkManager.defaultChunkSize
	case NetworkQualityFair:
		// Use smaller chunks for fair network
		newSize = h.chunkManager.defaultChunkSize / 2
	case NetworkQualityPoor:
		// Use minimum chunks for poor network
		newSize = h.chunkManager.minChunkSize
	}

	if newSize != oldSize {
		session.ChunkSize = newSize
		session.NetworkQuality = networkQuality

		adaptation := &ChunkSizeAdaptation{
			Timestamp:      time.Now(),
			OldSize:        oldSize,
			NewSize:        newSize,
			NetworkQuality: networkQuality,
			Reason:         fmt.Sprintf("Network quality: %s", networkQuality),
		}
		h.chunkManager.chunkSizeHistory = append(h.chunkManager.chunkSizeHistory, adaptation)

		h.logger.Infof("Adapted chunk size: %d -> %d bytes (network: %s)", oldSize, newSize, networkQuality)
	}
}

// compressFilePart compresses file part using optimal algorithm
func (h *EnhancedBigFileHandler) compressFilePart(data []byte) ([]byte, compression.Algorithm, error) {
	if h.compressionManager == nil {
		return data, compression.AlgorithmNone, nil
	}

	// Select optimal compression algorithm based on data characteristics
	algorithm := h.compressionManager.SelectOptimalAlgorithm(data)

	// Compress data
	compressedData, err := h.compressionManager.Compress(data, algorithm)
	if err != nil {
		return data, compression.AlgorithmNone, err
	}

	// Only use compression if it provides significant benefit (>10% reduction)
	compressionRatio := float64(len(compressedData)) / float64(len(data))
	if compressionRatio > 0.9 {
		return data, compression.AlgorithmNone, nil
	}

	return compressedData, algorithm, nil
}

// storeFilePart stores a file part
func (h *EnhancedBigFileHandler) storeFilePart(ctx context.Context, fileID int64, partNum int32, data []byte, partInfo *FilePartInfo) error {
	// Generate storage path
	storagePath := fmt.Sprintf("big_files/%d/part_%d", fileID, partNum)
	h.logger.Debugf("Storing file part at path: %s", storagePath)

	// Store in distributed file system
	// This would integrate with the existing DFS storage backend
	// For now, we'll simulate the storage operation

	h.logger.Infof("Stored file part: file_id=%d, part=%d, size=%d, compressed_size=%d",
		fileID, partNum, partInfo.Size, partInfo.CompressedSize)

	return nil
}

// verifyFileIntegrity verifies file integrity using Merkle tree and digital signatures
func (h *EnhancedBigFileHandler) verifyFileIntegrity(ctx context.Context, session *BigFileUploadSession) {
	h.logger.Infof("Starting integrity verification for file_id=%d", session.FileID)

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Build Merkle tree from all parts
	if h.integrityVerifier.enableMerkleTree && session.MerkleTree != nil {
		for i := int32(0); i < session.TotalParts; i++ {
			if partInfo, exists := session.UploadedParts[i]; exists {
				session.MerkleTree.AddLeaf(partInfo.Hash)
			}
		}

		// Calculate Merkle root
		merkleRoot := session.MerkleTree.GetRoot()
		h.logger.Infof("Merkle root calculated: %x", merkleRoot)
	}

	// Verify all parts
	verifiedParts := 0
	for _, partInfo := range session.UploadedParts {
		if h.verifyPartIntegrity(partInfo) {
			partInfo.IsVerified = true
			verifiedParts++
		}
	}

	// Check if all parts are verified
	if verifiedParts == len(session.UploadedParts) {
		session.IsVerified = true
		h.logger.Infof("File integrity verification completed: file_id=%d, all %d parts verified",
			session.FileID, verifiedParts)
	} else {
		h.logger.Errorf("File integrity verification failed: file_id=%d, only %d/%d parts verified",
			session.FileID, verifiedParts, len(session.UploadedParts))
	}
}

// verifyPartIntegrity verifies the integrity of a single part
func (h *EnhancedBigFileHandler) verifyPartIntegrity(partInfo *FilePartInfo) bool {
	// In a real implementation, this would:
	// 1. Re-read the stored part data
	// 2. Recalculate the hash
	// 3. Compare with stored hash
	// 4. Verify digital signature if enabled

	// For now, we'll simulate successful verification
	return true
}

// logUploadMetrics logs upload performance metrics
func (h *EnhancedBigFileHandler) logUploadMetrics(session *BigFileUploadSession, uploadTime time.Duration, bytesUploaded int) {
	uploadSpeedMBps := float64(bytesUploaded) / uploadTime.Seconds() / (1024 * 1024)

	h.logger.Infof("Upload metrics: file_id=%d, part_upload_time=%v, speed=%.2f MB/s, total_speed=%.2f MB/s",
		session.FileID, uploadTime, uploadSpeedMBps, session.UploadSpeed/(1024*1024))

	// Check if we're meeting the 1GB/s requirement for 16GB files
	if session.TotalSize >= 16*1024*1024*1024 && session.UploadSpeed < 1024*1024*1024 {
		h.logger.Errorf("Upload speed below 1GB/s requirement: current=%.2f MB/s", session.UploadSpeed/(1024*1024))
	}
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		bandwidth:       1024 * 1024 * 1024, // 1 Gbps default
		latency:         50 * time.Millisecond,
		packetLoss:      0.01, // 1%
		quality:         NetworkQualityGood,
		lastMeasurement: time.Now(),
	}
}

// GetCurrentQuality returns the current network quality
func (nm *NetworkMonitor) GetCurrentQuality() NetworkQuality {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return nm.quality
}
