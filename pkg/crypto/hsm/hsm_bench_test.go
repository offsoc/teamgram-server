package hsm

import (
	"context"
	"testing"
	"time"
)

// BenchmarkHSMRandomGeneration benchmarks random number generation
func BenchmarkHSMRandomGeneration(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GenerateRandom(32)
		if err != nil {
			b.Fatalf("Failed to generate random: %v", err)
		}
	}
}

// BenchmarkHSMRandomGeneration16 benchmarks 16-byte random generation
func BenchmarkHSMRandomGeneration16(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GenerateRandom(16)
		if err != nil {
			b.Fatalf("Failed to generate random: %v", err)
		}
	}
}

// BenchmarkHSMRandomGeneration256 benchmarks 256-byte random generation
func BenchmarkHSMRandomGeneration256(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GenerateRandom(256)
		if err != nil {
			b.Fatalf("Failed to generate random: %v", err)
		}
	}
}

// BenchmarkHSMRandomGeneration1024 benchmarks 1024-byte random generation
func BenchmarkHSMRandomGeneration1024(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GenerateRandom(1024)
		if err != nil {
			b.Fatalf("Failed to generate random: %v", err)
		}
	}
}

// BenchmarkHSMKeyGeneration benchmarks key generation
func BenchmarkHSMKeyGeneration(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GenerateKey(KeyTypeAES, 256)
		if err != nil {
			b.Fatalf("Failed to generate key: %v", err)
		}
	}
}

// BenchmarkHSMPoolRandomGeneration benchmarks pool random generation
func BenchmarkHSMPoolRandomGeneration(b *testing.B) {
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
		HealthCheckInterval: 30 * time.Second,
		LoadBalanceStrategy: RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    100,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		b.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pool.GenerateRandom(ctx, 32)
		if err != nil {
			b.Fatalf("Failed to generate random: %v", err)
		}
	}
}

// BenchmarkHSMPoolConcurrentRandom benchmarks concurrent random generation
func BenchmarkHSMPoolConcurrentRandom(b *testing.B) {
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
		MaxRetries:          3,
		RetryDelay:          50 * time.Millisecond,
		HealthCheckInterval: 30 * time.Second,
		LoadBalanceStrategy: RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    100,
	}
	
	pool, err := NewHSMPool(configs, poolConfig)
	if err != nil {
		b.Fatalf("Failed to create HSM pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := pool.GenerateRandom(ctx, 32)
			if err != nil {
				b.Fatalf("Failed to generate random: %v", err)
			}
		}
	})
}

// BenchmarkHSMSelfTest benchmarks self-test operations
func BenchmarkHSMSelfTest(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := hsm.SelfTest()
		if err != nil {
			b.Fatalf("Self-test failed: %v", err)
		}
	}
}

// BenchmarkHSMStatus benchmarks status operations
func BenchmarkHSMStatus(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GetStatus()
		if err != nil {
			b.Fatalf("Failed to get status: %v", err)
		}
	}
}

// BenchmarkHSMMetrics benchmarks metrics operations
func BenchmarkHSMMetrics(b *testing.B) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		b.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	// Generate some operations for metrics
	for i := 0; i < 100; i++ {
		hsm.GenerateRandom(32)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hsm.GetMetrics()
		if err != nil {
			b.Fatalf("Failed to get metrics: %v", err)
		}
	}
}

// TestHSMLatencyRequirements tests that HSM operations meet latency requirements
func TestHSMLatencyRequirements(t *testing.T) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		t.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	// Test random generation latency
	start := time.Now()
	_, err = hsm.GenerateRandom(32)
	latency := time.Since(start)
	
	if err != nil {
		t.Fatalf("Random generation failed: %v", err)
	}
	
	// Requirement: < 1ms
	if latency > time.Millisecond {
		t.Errorf("Random generation latency too high: %v > 1ms", latency)
	}
	
	t.Logf("Random generation latency: %v", latency)
}

// TestHSMThroughputRequirements tests HSM throughput requirements
func TestHSMThroughputRequirements(t *testing.T) {
	config := &HSMConfig{
		Vendor:           VendorSimulator,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
	}
	
	hsm, err := NewHSM(config)
	if err != nil {
		t.Fatalf("Failed to create HSM: %v", err)
	}
	defer hsm.Disconnect()
	
	// Test throughput over 1 second
	start := time.Now()
	operations := 0
	
	for time.Since(start) < time.Second {
		_, err := hsm.GenerateRandom(32)
		if err != nil {
			t.Fatalf("Random generation failed: %v", err)
		}
		operations++
	}
	
	duration := time.Since(start)
	opsPerSecond := float64(operations) / duration.Seconds()
	
	t.Logf("Throughput: %.2f operations/second", opsPerSecond)
	
	// Should achieve reasonable throughput
	if opsPerSecond < 1000 {
		t.Errorf("Throughput too low: %.2f ops/sec < 1000", opsPerSecond)
	}
}
