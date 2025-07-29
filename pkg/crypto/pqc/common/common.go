// Package common provides common utilities for post-quantum cryptography
package common

import (
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// Memory barrier to prevent compiler reordering
func MemoryBarrier() {
	runtime.Gosched()
}

// SecureZero securely zeros memory using compiler barriers and multiple passes
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	
	// First pass: zero with volatile writes
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) = 0
	}
	
	// Memory barrier
	MemoryBarrier()
	
	// Second pass: overwrite with 0xFF
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) = 0xFF
	}
	
	// Memory barrier
	MemoryBarrier()
	
	// Final pass: zero again
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) = 0
	}
	
	// Final memory barrier
	MemoryBarrier()
}

// GetNanoTime returns current time in nanoseconds for benchmarking
func GetNanoTime() int64 {
	return time.Now().UnixNano()
}

// AtomicCounter provides thread-safe counter for performance monitoring
type AtomicCounter struct {
	value int64
}

// NewAtomicCounter creates a new atomic counter
func NewAtomicCounter() *AtomicCounter {
	return &AtomicCounter{}
}

// Increment atomically increments the counter
func (c *AtomicCounter) Increment() {
	atomic.AddInt64(&c.value, 1)
}

// Get atomically gets the counter value
func (c *AtomicCounter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

// Reset atomically resets the counter to zero
func (c *AtomicCounter) Reset() {
	atomic.StoreInt64(&c.value, 0)
}

// Add atomically adds a value to the counter
func (c *AtomicCounter) Add(delta int64) {
	atomic.AddInt64(&c.value, delta)
}

// CPU feature detection
var (
	hasAVX2Flag     bool
	hasAVX512Flag   bool
	hasAESNIFlag    bool
	hasPCLMULQDQFlag bool
	cpuFeaturesInitialized bool
)

func init() {
	detectCPUFeatures()
}

// detectCPUFeatures detects CPU features for hardware acceleration
func detectCPUFeatures() {
	// This is a simplified implementation
	// In production, we would use assembly or cgo to call CPUID
	// For now, we'll use runtime.GOARCH and runtime.GOOS to make educated guesses
	
	switch runtime.GOARCH {
	case "amd64":
		// Most modern x86-64 CPUs support these features
		hasAVX2Flag = true
		hasAVX512Flag = false // More conservative, as not all modern CPUs have AVX-512
		hasAESNIFlag = true
		hasPCLMULQDQFlag = true
	case "arm64":
		// Most modern ARM64 CPUs support NEON and crypto extensions
		hasAVX2Flag = false // ARM doesn't have AVX2, but has NEON
		hasAVX512Flag = false
		hasAESNIFlag = true // ARM crypto extensions
		hasPCLMULQDQFlag = true
	default:
		// Conservative defaults for other architectures
		hasAVX2Flag = false
		hasAVX512Flag = false
		hasAESNIFlag = false
		hasPCLMULQDQFlag = false
	}
	
	cpuFeaturesInitialized = true
}

// HasAVX2 returns true if the CPU supports AVX2 instructions
func HasAVX2() bool {
	return hasAVX2Flag
}

// HasAVX512 returns true if the CPU supports AVX-512 instructions
func HasAVX512() bool {
	return hasAVX512Flag
}

// HasAESNI returns true if the CPU supports AES-NI instructions
func HasAESNI() bool {
	return hasAESNIFlag
}

// HasPCLMULQDQ returns true if the CPU supports PCLMULQDQ instructions
func HasPCLMULQDQ() bool {
	return hasPCLMULQDQFlag
}

// GetOptimalWorkerCount returns the optimal number of workers for parallel processing
func GetOptimalWorkerCount() int {
	// Use number of CPU cores, but cap at reasonable limit
	cores := runtime.NumCPU()
	if cores > 16 {
		return 16
	}
	if cores < 2 {
		return 2
	}
	return cores
}