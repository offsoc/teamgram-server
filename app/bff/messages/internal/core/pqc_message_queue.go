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
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// PQCMessageQueue handles PQC message processing in a queue
type PQCMessageQueue struct {
	mutex           sync.RWMutex
	encryptionQueue chan *PQCMessageTask
	decryptionQueue chan *PQCMessageTask
	workers         []*PQCMessageWorker
	config          *PQCQueueConfig
	metrics         *PQCQueueMetrics
	logger          logx.Logger
	ctx             context.Context
	cancel          context.CancelFunc
}

// PQCMessageTask represents a message processing task
type PQCMessageTask struct {
	ID          string                 `json:"id"`
	Type        PQCTaskType            `json:"type"`
	MessageID   int64                  `json:"message_id"`
	UserID      int64                  `json:"user_id"`
	PeerID      int64                  `json:"peer_id"`
	PeerType    int32                  `json:"peer_type"`
	Data        []byte                 `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	ProcessedAt time.Time              `json:"processed_at,omitempty"`
	Result      *PQCTaskResult         `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// PQCTaskType represents the type of PQC task
type PQCTaskType string

const (
	TaskTypeEncrypt PQCTaskType = "encrypt"
	TaskTypeDecrypt PQCTaskType = "decrypt"
	TaskTypeVerify  PQCTaskType = "verify"
)

// PQCTaskResult represents the result of a PQC task
type PQCTaskResult struct {
	ProcessedData  []byte                 `json:"processed_data"`
	ContainerHash  string                 `json:"container_hash,omitempty"`
	ProcessingTime time.Duration          `json:"processing_time"`
	IntegrityValid bool                   `json:"integrity_valid"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// PQCQueueConfig configuration for PQC message queue
type PQCQueueConfig struct {
	EncryptionWorkers int           `json:"encryption_workers"`
	DecryptionWorkers int           `json:"decryption_workers"`
	QueueSize         int           `json:"queue_size"`
	ProcessTimeout    time.Duration `json:"process_timeout"`
	RetryAttempts     int           `json:"retry_attempts"`
	RetryDelay        time.Duration `json:"retry_delay"`
	EnableMetrics     bool          `json:"enable_metrics"`
}

// PQCQueueMetrics tracks queue performance
type PQCQueueMetrics struct {
	TotalTasks         int64         `json:"total_tasks"`
	CompletedTasks     int64         `json:"completed_tasks"`
	FailedTasks        int64         `json:"failed_tasks"`
	QueuedTasks        int64         `json:"queued_tasks"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	MaxProcessTime     time.Duration `json:"max_process_time"`
	MinProcessTime     time.Duration `json:"min_process_time"`
	ThroughputPerSec   float64       `json:"throughput_per_sec"`
	LastUpdateTime     time.Time     `json:"last_update_time"`
}

// PQCMessageWorker processes PQC message tasks
type PQCMessageWorker struct {
	ID       int
	queue    *PQCMessageQueue
	taskChan chan *PQCMessageTask
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewPQCMessageQueue creates a new PQC message queue
func NewPQCMessageQueue(config *PQCQueueConfig) *PQCMessageQueue {
	if config == nil {
		config = &PQCQueueConfig{
			EncryptionWorkers: 4,
			DecryptionWorkers: 4,
			QueueSize:         1000,
			ProcessTimeout:    30 * time.Second,
			RetryAttempts:     3,
			RetryDelay:        100 * time.Millisecond,
			EnableMetrics:     true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	queue := &PQCMessageQueue{
		encryptionQueue: make(chan *PQCMessageTask, config.QueueSize),
		decryptionQueue: make(chan *PQCMessageTask, config.QueueSize),
		config:          config,
		metrics: &PQCQueueMetrics{
			MinProcessTime: time.Hour, // Initialize to high value
			LastUpdateTime: time.Now(),
		},
		logger: logx.WithContext(ctx),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start workers
	queue.startWorkers()

	return queue
}

// startWorkers starts the worker goroutines
func (q *PQCMessageQueue) startWorkers() {
	totalWorkers := q.config.EncryptionWorkers + q.config.DecryptionWorkers
	q.workers = make([]*PQCMessageWorker, totalWorkers)

	// Start encryption workers
	for i := 0; i < q.config.EncryptionWorkers; i++ {
		worker := &PQCMessageWorker{
			ID:       i,
			queue:    q,
			taskChan: q.encryptionQueue,
		}
		worker.ctx, worker.cancel = context.WithCancel(q.ctx)
		q.workers[i] = worker
		go worker.run()
	}

	// Start decryption workers
	for i := 0; i < q.config.DecryptionWorkers; i++ {
		workerID := q.config.EncryptionWorkers + i
		worker := &PQCMessageWorker{
			ID:       workerID,
			queue:    q,
			taskChan: q.decryptionQueue,
		}
		worker.ctx, worker.cancel = context.WithCancel(q.ctx)
		q.workers[workerID] = worker
		go worker.run()
	}

	q.logger.Infof("Started %d PQC message workers (%d encryption, %d decryption)",
		totalWorkers, q.config.EncryptionWorkers, q.config.DecryptionWorkers)
}

// EnqueueEncryption enqueues a message for PQC encryption
func (q *PQCMessageQueue) EnqueueEncryption(messageID, userID, peerID int64, peerType int32, data []byte, metadata map[string]interface{}) (*PQCMessageTask, error) {
	task := &PQCMessageTask{
		ID:        fmt.Sprintf("encrypt_%d_%d", messageID, time.Now().UnixNano()),
		Type:      TaskTypeEncrypt,
		MessageID: messageID,
		UserID:    userID,
		PeerID:    peerID,
		PeerType:  peerType,
		Data:      data,
		Metadata:  metadata,
		Priority:  1,
		CreatedAt: time.Now(),
	}

	select {
	case q.encryptionQueue <- task:
		q.updateMetrics(1, 0, 0, 1)
		return task, nil
	case <-q.ctx.Done():
		return nil, fmt.Errorf("queue is shutting down")
	default:
		return nil, fmt.Errorf("encryption queue is full")
	}
}

// EnqueueDecryption enqueues a message for PQC decryption
func (q *PQCMessageQueue) EnqueueDecryption(messageID, userID, peerID int64, peerType int32, containerHash string, metadata map[string]interface{}) (*PQCMessageTask, error) {
	task := &PQCMessageTask{
		ID:        fmt.Sprintf("decrypt_%d_%d", messageID, time.Now().UnixNano()),
		Type:      TaskTypeDecrypt,
		MessageID: messageID,
		UserID:    userID,
		PeerID:    peerID,
		PeerType:  peerType,
		Data:      []byte(containerHash),
		Metadata:  metadata,
		Priority:  1,
		CreatedAt: time.Now(),
	}

	select {
	case q.decryptionQueue <- task:
		q.updateMetrics(1, 0, 0, 1)
		return task, nil
	case <-q.ctx.Done():
		return nil, fmt.Errorf("queue is shutting down")
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("decryption queue timeout")
	}
}

// GetMetrics returns current queue metrics
func (q *PQCMessageQueue) GetMetrics() *PQCQueueMetrics {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	// Calculate current throughput
	now := time.Now()
	timeDiff := now.Sub(q.metrics.LastUpdateTime).Seconds()
	if timeDiff > 0 {
		q.metrics.ThroughputPerSec = float64(q.metrics.CompletedTasks) / timeDiff
	}

	// Return a copy
	metrics := *q.metrics
	return &metrics
}

// Close shuts down the queue and all workers
func (q *PQCMessageQueue) Close() error {
	q.logger.Info("Shutting down PQC message queue...")

	// Cancel context to signal workers to stop
	q.cancel()

	// Close channels
	close(q.encryptionQueue)
	close(q.decryptionQueue)

	// Wait for workers to finish (with timeout)
	done := make(chan struct{})
	go func() {
		for _, worker := range q.workers {
			worker.cancel()
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
		q.logger.Info("All PQC workers stopped gracefully")
	case <-time.After(10 * time.Second):
		q.logger.Infow("Timeout waiting for workers to stop")
	}

	return nil
}

// updateMetrics updates queue metrics
func (q *PQCMessageQueue) updateMetrics(total, completed, failed, queued int64) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.metrics.TotalTasks += total
	q.metrics.CompletedTasks += completed
	q.metrics.FailedTasks += failed
	q.metrics.QueuedTasks += queued
	q.metrics.LastUpdateTime = time.Now()
}

// Worker implementation

// run starts the worker processing loop
func (w *PQCMessageWorker) run() {
	w.queue.logger.Infof("PQC worker %d started", w.ID)
	defer w.queue.logger.Infof("PQC worker %d stopped", w.ID)

	for {
		select {
		case task := <-w.taskChan:
			if task != nil {
				w.processTask(task)
			}
		case <-w.ctx.Done():
			return
		}
	}
}

// processTask processes a single PQC message task
func (w *PQCMessageWorker) processTask(task *PQCMessageTask) {
	start := time.Now()
	task.ProcessedAt = start

	defer func() {
		duration := time.Since(start)
		w.updateTaskMetrics(duration, task.Error == "")
	}()

	// Process task based on type
	switch task.Type {
	case TaskTypeEncrypt:
		w.processEncryption(task)
	case TaskTypeDecrypt:
		w.processDecryption(task)
	case TaskTypeVerify:
		w.processVerification(task)
	default:
		task.Error = fmt.Sprintf("unknown task type: %s", task.Type)
	}
}

// processEncryption processes message encryption
func (w *PQCMessageWorker) processEncryption(task *PQCMessageTask) {
	// Create PQC container
	container, err := CreatePQCMessageContainer(task.MessageID, task.UserID, task.Data, true)
	if err != nil {
		task.Error = fmt.Sprintf("failed to create PQC container: %v", err)
		return
	}

	// Serialize container
	containerData, err := container.SerializeContainer()
	if err != nil {
		task.Error = fmt.Sprintf("failed to serialize container: %v", err)
		return
	}

	// Create result
	task.Result = &PQCTaskResult{
		ProcessedData:  containerData,
		ContainerHash:  fmt.Sprintf("%x", generateNonce(32)), // Simplified hash
		ProcessingTime: time.Since(task.ProcessedAt),
		IntegrityValid: true,
		Metadata: map[string]interface{}{
			"algorithm":      container.PQCAlgorithm,
			"hybrid_mode":    container.HybridMode,
			"container_size": len(containerData),
		},
	}
}

// processDecryption processes message decryption
func (w *PQCMessageWorker) processDecryption(task *PQCMessageTask) {
	containerHash := string(task.Data)

	// Load container (simulated)
	containerData := []byte(`{"message_id":` + fmt.Sprintf("%d", task.MessageID) + `,"encrypted_data":"simulated"}`)

	// Deserialize container
	container, err := DeserializeContainer(containerData)
	if err != nil {
		task.Error = fmt.Sprintf("failed to deserialize container: %v", err)
		return
	}

	// Decrypt message
	decryptedData, err := container.DecryptMessageData()
	if err != nil {
		task.Error = fmt.Sprintf("failed to decrypt message: %v", err)
		return
	}

	// Verify integrity
	err = container.VerifyIntegrity(decryptedData)
	integrityValid := err == nil

	// Create result
	task.Result = &PQCTaskResult{
		ProcessedData:  decryptedData,
		ProcessingTime: time.Since(task.ProcessedAt),
		IntegrityValid: integrityValid,
		Metadata: map[string]interface{}{
			"container_hash": containerHash,
			"algorithm":      container.PQCAlgorithm,
			"decrypted_size": len(decryptedData),
		},
	}

	if !integrityValid {
		task.Error = fmt.Sprintf("integrity verification failed: %v", err)
	}
}

// processVerification processes message verification
func (w *PQCMessageWorker) processVerification(task *PQCMessageTask) {
	// Simulate verification process
	isValid := len(task.Data) > 0

	task.Result = &PQCTaskResult{
		ProcessedData:  task.Data,
		ProcessingTime: time.Since(task.ProcessedAt),
		IntegrityValid: isValid,
		Metadata: map[string]interface{}{
			"verification_type": "dilithium_signature",
			"data_size":         len(task.Data),
		},
	}

	if !isValid {
		task.Error = "verification failed: invalid data"
	}
}

// updateTaskMetrics updates metrics after task processing
func (w *PQCMessageWorker) updateTaskMetrics(duration time.Duration, success bool) {
	w.queue.mutex.Lock()
	defer w.queue.mutex.Unlock()

	if success {
		w.queue.metrics.CompletedTasks++
	} else {
		w.queue.metrics.FailedTasks++
	}

	w.queue.metrics.QueuedTasks--

	// Update processing time metrics
	if duration > w.queue.metrics.MaxProcessTime {
		w.queue.metrics.MaxProcessTime = duration
	}
	if duration < w.queue.metrics.MinProcessTime {
		w.queue.metrics.MinProcessTime = duration
	}

	// Update average processing time (simplified moving average)
	w.queue.metrics.AverageProcessTime = (w.queue.metrics.AverageProcessTime + duration) / 2
}
