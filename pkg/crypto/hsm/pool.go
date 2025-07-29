package hsm

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// NewHSMPool creates a new HSM pool with load balancing and failover
func NewHSMPool(configs []*HSMConfig, poolConfig *PoolConfig) (*HSMPool, error) {
	if len(configs) == 0 {
		return nil, errors.New("at least one HSM configuration is required")
	}
	
	if poolConfig == nil {
		poolConfig = &PoolConfig{
			MaxRetries:          3,
			RetryDelay:          100 * time.Millisecond,
			HealthCheckInterval: 30 * time.Second,
			LoadBalanceStrategy: RoundRobin,
			FailoverEnabled:     true,
			MaxConcurrentOps:    100,
		}
	}
	
	pool := &HSMPool{
		hsms:   make([]*HSM, 0, len(configs)),
		config: poolConfig,
	}
	
	// Initialize HSM instances
	for i, config := range configs {
		hsm, err := NewHSM(config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HSM %d: %w", i, err)
		}
		pool.hsms = append(pool.hsms, hsm)
	}
	
	// Start health checker
	pool.healthChecker = &HealthChecker{
		pool:     pool,
		interval: poolConfig.HealthCheckInterval,
		stopCh:   make(chan struct{}),
	}
	
	go pool.healthChecker.start()
	
	return pool, nil
}

// selectHSM selects an HSM based on the load balancing strategy
func (p *HSMPool) selectHSM() (*HSM, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	if len(p.hsms) == 0 {
		return nil, errors.New("no HSMs available")
	}
	
	switch p.config.LoadBalanceStrategy {
	case RoundRobin:
		return p.selectRoundRobin()
	case LeastLoaded:
		return p.selectLeastLoaded()
	case HealthBased:
		return p.selectHealthBased()
	default:
		return p.selectRoundRobin()
	}
}

// selectRoundRobin implements round-robin load balancing
func (p *HSMPool) selectRoundRobin() (*HSM, error) {
	for i := 0; i < len(p.hsms); i++ {
		index := atomic.AddInt64(&p.currentIndex, 1) % int64(len(p.hsms))
		hsm := p.hsms[index]
		
		if hsm.IsConnected() && hsm.healthStatus {
			return hsm, nil
		}
	}
	
	return nil, errors.New("no healthy HSMs available")
}

// selectLeastLoaded selects the HSM with the lowest operation count
func (p *HSMPool) selectLeastLoaded() (*HSM, error) {
	var selectedHSM *HSM
	var minOps int64 = -1
	
	for _, hsm := range p.hsms {
		if !hsm.IsConnected() || !hsm.healthStatus {
			continue
		}
		
		ops := atomic.LoadInt64(&hsm.operationCount)
		if minOps == -1 || ops < minOps {
			minOps = ops
			selectedHSM = hsm
		}
	}
	
	if selectedHSM == nil {
		return nil, errors.New("no healthy HSMs available")
	}
	
	return selectedHSM, nil
}

// selectHealthBased selects the HSM with the best health metrics
func (p *HSMPool) selectHealthBased() (*HSM, error) {
	var selectedHSM *HSM
	var bestScore float64 = -1
	
	for _, hsm := range p.hsms {
		if !hsm.IsConnected() || !hsm.healthStatus {
			continue
		}
		
		metrics, err := hsm.GetMetrics()
		if err != nil {
			continue
		}
		
		// Calculate health score (availability - error rate)
		score := metrics.Availability - metrics.ErrorRate
		if score > bestScore {
			bestScore = score
			selectedHSM = hsm
		}
	}
	
	if selectedHSM == nil {
		return nil, errors.New("no healthy HSMs available")
	}
	
	return selectedHSM, nil
}

// executeWithRetry executes an operation with retry logic
func (p *HSMPool) executeWithRetry(ctx context.Context, operation func(*HSM) error) error {
	var lastErr error
	
	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		hsm, err := p.selectHSM()
		if err != nil {
			lastErr = err
			continue
		}
		
		err = operation(hsm)
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// If failover is enabled and this isn't the last attempt, try another HSM
		if p.config.FailoverEnabled && attempt < p.config.MaxRetries {
			// Mark HSM as unhealthy temporarily
			hsm.healthStatus = false
			
			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.config.RetryDelay):
			}
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", p.config.MaxRetries+1, lastErr)
}

// GenerateRandom generates random bytes using the pool
func (p *HSMPool) GenerateRandom(ctx context.Context, size int) ([]byte, error) {
	var result []byte
	
	err := p.executeWithRetry(ctx, func(hsm *HSM) error {
		var err error
		result, err = hsm.GenerateRandom(size)
		return err
	})
	
	return result, err
}

// GenerateKey generates a key using the pool
func (p *HSMPool) GenerateKey(ctx context.Context, keyType KeyType, keySize int) (*Key, error) {
	var result *Key
	
	err := p.executeWithRetry(ctx, func(hsm *HSM) error {
		var err error
		result, err = hsm.GenerateKey(keyType, keySize)
		return err
	})
	
	return result, err
}

// GetPoolStatus returns the status of all HSMs in the pool
func (p *HSMPool) GetPoolStatus() ([]*HSMStatus, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	statuses := make([]*HSMStatus, 0, len(p.hsms))
	
	for _, hsm := range p.hsms {
		status, err := hsm.GetStatus()
		if err != nil {
			// Create error status
			status = &HSMStatus{
				IsOnline:   false,
				LastError:  err.Error(),
				ErrorCount: atomic.LoadInt64(&hsm.errorCount),
			}
		}
		statuses = append(statuses, status)
	}
	
	return statuses, nil
}

// GetPoolMetrics returns aggregated metrics for the pool
func (p *HSMPool) GetPoolMetrics() (*HSMMetrics, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	aggregated := &HSMMetrics{
		MinLatency: time.Hour, // Initialize to high value
	}
	
	var totalOps, successOps, failedOps int64
	var totalLatency time.Duration
	var healthyHSMs int
	
	for _, hsm := range p.hsms {
		metrics, err := hsm.GetMetrics()
		if err != nil {
			continue
		}
		
		totalOps += metrics.TotalOperations
		successOps += metrics.SuccessfulOperations
		failedOps += metrics.FailedOperations
		totalLatency += metrics.AverageLatency
		
		if metrics.MaxLatency > aggregated.MaxLatency {
			aggregated.MaxLatency = metrics.MaxLatency
		}
		
		if metrics.MinLatency < aggregated.MinLatency {
			aggregated.MinLatency = metrics.MinLatency
		}
		
		if hsm.IsConnected() && hsm.healthStatus {
			healthyHSMs++
		}
	}
	
	aggregated.TotalOperations = totalOps
	aggregated.SuccessfulOperations = successOps
	aggregated.FailedOperations = failedOps
	
	if len(p.hsms) > 0 {
		aggregated.AverageLatency = totalLatency / time.Duration(len(p.hsms))
	}
	
	if totalOps > 0 {
		aggregated.ErrorRate = float64(failedOps) / float64(totalOps)
		aggregated.OperationsPerSecond = float64(successOps) / time.Since(time.Now().Add(-time.Hour)).Seconds()
	}
	
	if len(p.hsms) > 0 {
		aggregated.Availability = float64(healthyHSMs) / float64(len(p.hsms))
	}
	
	return aggregated, nil
}

// Close shuts down the HSM pool
func (p *HSMPool) Close() error {
	// Stop health checker
	if p.healthChecker != nil {
		p.healthChecker.stop()
	}
	
	// Disconnect all HSMs
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	for _, hsm := range p.hsms {
		hsm.Disconnect()
	}
	
	return nil
}

// start begins the health checking routine
func (hc *HealthChecker) start() {
	if !atomic.CompareAndSwapInt32(&hc.running, 0, 1) {
		return // Already running
	}
	
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hc.stopCh:
			atomic.StoreInt32(&hc.running, 0)
			return
		case <-ticker.C:
			hc.checkHealth()
		}
	}
}

// stop stops the health checking routine
func (hc *HealthChecker) stop() {
	if atomic.LoadInt32(&hc.running) == 1 {
		close(hc.stopCh)
	}
}

// checkHealth performs health checks on all HSMs
func (hc *HealthChecker) checkHealth() {
	hc.pool.mutex.RLock()
	hsms := make([]*HSM, len(hc.pool.hsms))
	copy(hsms, hc.pool.hsms)
	hc.pool.mutex.RUnlock()
	
	for _, hsm := range hsms {
		go func(h *HSM) {
			err := h.SelfTest()
			h.mutex.Lock()
			h.healthStatus = (err == nil)
			h.lastHealthCheck = time.Now()
			if err != nil {
				h.status.LastError = err.Error()
				atomic.AddInt64(&h.status.ErrorCount, 1)
			}
			h.mutex.Unlock()
		}(hsm)
	}
}
