package hsm

import (
	"context"
	"testing"
	"time"
)

// TestHSMPoolCreation tests HSM pool creation
func TestHSMPoolCreation(t *testing.T) {
	t.Logf("=== HSM POOL CREATION TEST ===")
	
	configs := []*HSMConfig{
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-1",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-2",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-3",
		},
	}
	
	poolConfig := &PoolConfig{
		MaxRetries:          3,
		RetryDelay:          100 * time.Millisecond,
		HealthCheckInterval: 5 * time.Second,
		LoadBalanceStrategy: RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    50,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		t.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	// Check pool status
	statuses, err := pool.GetPoolStatus()
	if err != nil {
		t.Fatalf("Failed to get pool status: %v", err)
	}
	
	if len(statuses) != 3 {
		t.Errorf("Expected 3 HSMs in pool, got %d", len(statuses))
	}
	
	onlineCount := 0
	for i, status := range statuses {
		t.Logf("HSM %d: Online=%v, Vendor=%s", i+1, status.IsOnline, status.Vendor)
		if status.IsOnline {
			onlineCount++
		}
	}
	
	if onlineCount != 3 {
		t.Errorf("Expected 3 online HSMs, got %d", onlineCount)
	}
	
	t.Logf("✓ HSM pool created successfully with %d HSMs", len(statuses))
}

// TestHSMPoolLoadBalancing tests load balancing strategies
func TestHSMPoolLoadBalancing(t *testing.T) {
	t.Logf("=== HSM POOL LOAD BALANCING TEST ===")
	
	configs := []*HSMConfig{
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-1",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-2",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-3",
		},
	}
	
	strategies := []LoadBalanceStrategy{RoundRobin, LeastLoaded, HealthBased}
	
	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			poolConfig := &PoolConfig{
				MaxRetries:          3,
				RetryDelay:          50 * time.Millisecond,
				HealthCheckInterval: 10 * time.Second,
				LoadBalanceStrategy: strategy,
				FailoverEnabled:     true,
				MaxConcurrentOps:    50,
			}
			
			pool, err := NewHSMPool(configs, poolConfig)
			if err != nil {
				t.Fatalf("Failed to create HSM pool: %v", err)
			}
			defer pool.Close()
			
			ctx := context.Background()
			
			// Perform multiple operations to test load balancing
			for i := 0; i < 10; i++ {
				_, err := pool.GenerateRandom(ctx, 32)
				if err != nil {
					t.Fatalf("Failed to generate random bytes: %v", err)
				}
			}
			
			// Check that operations were distributed
			metrics, err := pool.GetPoolMetrics()
			if err != nil {
				t.Fatalf("Failed to get pool metrics: %v", err)
			}
			
			if metrics.TotalOperations < 10 {
				t.Errorf("Expected at least 10 operations, got %d", metrics.TotalOperations)
			}
			
			t.Logf("✓ %s strategy: %d operations completed", strategy, metrics.TotalOperations)
		})
	}
}

// TestHSMPoolFailover tests failover functionality
func TestHSMPoolFailover(t *testing.T) {
	t.Logf("=== HSM POOL FAILOVER TEST ===")
	
	configs := []*HSMConfig{
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-1",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-2",
		},
	}
	
	poolConfig := &PoolConfig{
		MaxRetries:          2,
		RetryDelay:          50 * time.Millisecond,
		HealthCheckInterval: 5 * time.Second,
		LoadBalanceStrategy: RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    50,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		t.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Test normal operation
	_, err = pool.GenerateRandom(ctx, 32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	
	// Simulate HSM failure by disconnecting first HSM
	pool.hsms[0].Disconnect()
	pool.hsms[0].healthStatus = false
	
	// Operations should still work with remaining HSMs
	for i := 0; i < 5; i++ {
		_, err = pool.GenerateRandom(ctx, 32)
		if err != nil {
			t.Fatalf("Failed to generate random bytes after failover: %v", err)
		}
	}
	
	// Check pool metrics
	metrics, err := pool.GetPoolMetrics()
	if err != nil {
		t.Fatalf("Failed to get pool metrics: %v", err)
	}
	
	t.Logf("✓ Failover test completed")
	t.Logf("  Total Operations: %d", metrics.TotalOperations)
	t.Logf("  Successful Operations: %d", metrics.SuccessfulOperations)
	t.Logf("  Failed Operations: %d", metrics.FailedOperations)
	t.Logf("  Availability: %.2f%%", metrics.Availability*100)
}

// TestHSMPoolPerformance tests pool performance requirements
func TestHSMPoolPerformance(t *testing.T) {
	t.Logf("=== HSM POOL PERFORMANCE TEST ===")
	
	configs := []*HSMConfig{
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-1",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-2",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-3",
		},
	}
	
	poolConfig := &PoolConfig{
		MaxRetries:          3,
		RetryDelay:          50 * time.Millisecond,
		HealthCheckInterval: 10 * time.Second,
		LoadBalanceStrategy: RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    100,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		t.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Test latency requirement
	t.Run("LatencyRequirement", func(t *testing.T) {
		iterations := 100
		totalDuration := time.Duration(0)
		
		for i := 0; i < iterations; i++ {
			start := time.Now()
			_, err := pool.GenerateRandom(ctx, 32)
			duration := time.Since(start)
			
			if err != nil {
				t.Fatalf("Random generation failed: %v", err)
			}
			
			totalDuration += duration
		}
		
		avgDuration := totalDuration / time.Duration(iterations)
		t.Logf("Average operation latency: %v", avgDuration)
		
		// Requirement: < 1ms
		if avgDuration > time.Millisecond {
			t.Errorf("Average latency too high: %v > 1ms", avgDuration)
		} else {
			t.Logf("✓ Latency requirement met: %v < 1ms", avgDuration)
		}
	})
	
	// Test availability requirement
	t.Run("AvailabilityRequirement", func(t *testing.T) {
		iterations := 1000
		successCount := 0
		
		for i := 0; i < iterations; i++ {
			_, err := pool.GenerateRandom(ctx, 16)
			if err == nil {
				successCount++
			}
		}
		
		availability := float64(successCount) / float64(iterations) * 100
		t.Logf("Pool availability: %.4f%%", availability)
		
		// Requirement: > 99.99%
		if availability < 99.99 {
			t.Errorf("Availability too low: %.4f%% < 99.99%%", availability)
		} else {
			t.Logf("✓ Availability requirement met: %.4f%% > 99.99%%", availability)
		}
	})
	
	// Test concurrent operations
	t.Run("ConcurrentOperations", func(t *testing.T) {
		concurrency := 50
		iterations := 20
		
		done := make(chan error, concurrency)
		
		start := time.Now()
		
		for i := 0; i < concurrency; i++ {
			go func() {
				for j := 0; j < iterations; j++ {
					_, err := pool.GenerateRandom(ctx, 32)
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
		}
		
		// Wait for all goroutines to complete
		for i := 0; i < concurrency; i++ {
			err := <-done
			if err != nil {
				t.Fatalf("Concurrent operation failed: %v", err)
			}
		}
		
		totalDuration := time.Since(start)
		totalOps := concurrency * iterations
		opsPerSecond := float64(totalOps) / totalDuration.Seconds()
		
		t.Logf("Concurrent test completed:")
		t.Logf("  Total operations: %d", totalOps)
		t.Logf("  Total duration: %v", totalDuration)
		t.Logf("  Operations per second: %.2f", opsPerSecond)
		
		// Should handle reasonable throughput
		if opsPerSecond < 100 {
			t.Errorf("Throughput too low: %.2f ops/sec < 100", opsPerSecond)
		} else {
			t.Logf("✓ Throughput requirement met: %.2f ops/sec > 100", opsPerSecond)
		}
	})
	
	// Get final metrics
	metrics, err := pool.GetPoolMetrics()
	if err != nil {
		t.Fatalf("Failed to get final metrics: %v", err)
	}
	
	t.Logf("Final Pool Metrics:")
	t.Logf("  Total Operations: %d", metrics.TotalOperations)
	t.Logf("  Successful Operations: %d", metrics.SuccessfulOperations)
	t.Logf("  Failed Operations: %d", metrics.FailedOperations)
	t.Logf("  Error Rate: %.4f%%", metrics.ErrorRate*100)
	t.Logf("  Availability: %.4f%%", metrics.Availability*100)
	t.Logf("  Average Latency: %v", metrics.AverageLatency)
	t.Logf("  Max Latency: %v", metrics.MaxLatency)
	t.Logf("  Min Latency: %v", metrics.MinLatency)
}

// TestHSMPoolHealthChecking tests health checking functionality
func TestHSMPoolHealthChecking(t *testing.T) {
	t.Logf("=== HSM POOL HEALTH CHECKING TEST ===")
	
	configs := []*HSMConfig{
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-1",
		},
		{
			Vendor:           VendorSimulator,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			Label:            "HSM-2",
		},
	}
	
	poolConfig := &PoolConfig{
		MaxRetries:          2,
		RetryDelay:          50 * time.Millisecond,
		HealthCheckInterval: 1 * time.Second, // Fast health checks for testing
		LoadBalanceStrategy: HealthBased,
		FailoverEnabled:     true,
		MaxConcurrentOps:    50,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		t.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	// Wait for initial health checks
	time.Sleep(2 * time.Second)
	
	// Check that health checker is running
	if pool.healthChecker == nil {
		t.Errorf("Health checker should be initialized")
	}
	
	// All HSMs should be healthy initially
	statuses, err := pool.GetPoolStatus()
	if err != nil {
		t.Fatalf("Failed to get pool status: %v", err)
	}
	
	healthyCount := 0
	for _, status := range statuses {
		if status.IsOnline {
			healthyCount++
		}
	}
	
	if healthyCount != 2 {
		t.Errorf("Expected 2 healthy HSMs, got %d", healthyCount)
	}
	
	t.Logf("✓ Health checking test completed")
	t.Logf("  Healthy HSMs: %d/%d", healthyCount, len(statuses))
}
