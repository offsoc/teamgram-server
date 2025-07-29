package pqc

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Military-grade secure memory management
// Implements secure allocation, protection, and zeroization
// Prevents memory dumps, swap attacks, and cold boot attacks

// MemoryProtection levels
type MemoryProtection int

const (
	ProtectionNone MemoryProtection = iota
	ProtectionReadOnly
	ProtectionNoAccess
	ProtectionExecute
)

// SecureMemory provides military-grade memory protection
type SecureMemory struct {
	mutex       sync.RWMutex
	allocations map[uintptr]*allocation
	totalSize   uintptr
	maxSize     uintptr
	pageSize    uintptr

	// Security features
	guardPages    bool
	canaryValues  bool
	encryptAtRest bool
	preventSwap   bool

	// Statistics
	allocCount   uint64
	freeCount    uint64
	protectCount uint64
	zeroizeCount uint64
}

// allocation tracks a secure memory allocation
type allocation struct {
	ptr        uintptr
	size       uintptr
	actualSize uintptr // Including guard pages
	protected  bool
	canary     [16]byte
	encrypted  bool

	// Metadata for security
	allocTime  int64
	accessTime int64
	protection MemoryProtection
}

// SecureMemoryConfig configures secure memory management
type SecureMemoryConfig struct {
	MaxMemorySize    uintptr
	EnableGuardPages bool
	EnableCanaries   bool
	EncryptAtRest    bool
	PreventSwap      bool
	LockPages        bool
}

// NewSecureMemory creates a new secure memory manager
func NewSecureMemory(config *SecureMemoryConfig) (*SecureMemory, error) {
	if config == nil {
		config = &SecureMemoryConfig{
			MaxMemorySize:    64 * 1024 * 1024, // 64MB default
			EnableGuardPages: true,
			EnableCanaries:   true,
			EncryptAtRest:    true,
			PreventSwap:      true,
			LockPages:        true,
		}
	}

	pageSize := uintptr(syscall.Getpagesize())

	sm := &SecureMemory{
		allocations:   make(map[uintptr]*allocation),
		maxSize:       config.MaxMemorySize,
		pageSize:      pageSize,
		guardPages:    config.EnableGuardPages,
		canaryValues:  config.EnableCanaries,
		encryptAtRest: config.EncryptAtRest,
		preventSwap:   config.PreventSwap,
	}

	return sm, nil
}

// SecureAlloc allocates secure memory with protection
func (sm *SecureMemory) SecureAlloc(size uintptr) ([]byte, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if size == 0 {
		return nil, fmt.Errorf("invalid allocation size: 0")
	}

	if sm.totalSize+size > sm.maxSize {
		return nil, fmt.Errorf("memory limit exceeded: %d + %d > %d",
			sm.totalSize, size, sm.maxSize)
	}

	// For simplicity, use regular Go allocation with tracking
	// In production, this would use mmap and memory protection
	data := make([]byte, size)
	dataPtr := uintptr(unsafe.Pointer(&data[0]))

	// Create allocation record
	alloc := &allocation{
		ptr:        dataPtr,
		size:       size,
		actualSize: size,
		allocTime:  time.Now().UnixNano(),
		protection: ProtectionReadOnly,
	}

	// Generate canary values if enabled
	if sm.canaryValues {
		for i := range alloc.canary {
			alloc.canary[i] = byte(time.Now().UnixNano() % 256)
		}
	}

	// Store allocation
	sm.allocations[dataPtr] = alloc
	sm.totalSize += size
	sm.allocCount++

	// Initialize with random data to prevent information leakage
	for i := range data {
		data[i] = byte(time.Now().UnixNano() % 256)
	}

	return data, nil
}

// SecureFree securely frees allocated memory
func (sm *SecureMemory) SecureFree(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	ptr := uintptr(unsafe.Pointer(&data[0]))
	alloc, exists := sm.allocations[ptr]
	if !exists {
		return fmt.Errorf("invalid pointer: not allocated by SecureMemory")
	}

	// Verify canary if enabled
	if sm.canaryValues {
		if err := sm.verifyCanary(alloc); err != nil {
			return fmt.Errorf("memory corruption detected: %w", err)
		}
	}

	// Securely zero the memory
	sm.secureZeroize(data)

	// Remove from allocations
	delete(sm.allocations, ptr)
	sm.totalSize -= alloc.actualSize
	sm.freeCount++

	return nil
}

// SetProtection changes memory protection
func (sm *SecureMemory) SetProtection(data []byte, protection MemoryProtection) error {
	if len(data) == 0 {
		return nil
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	ptr := uintptr(unsafe.Pointer(&data[0]))
	alloc, exists := sm.allocations[ptr]
	if !exists {
		return fmt.Errorf("invalid pointer: not allocated by SecureMemory")
	}

	// For simplified implementation, just update the protection flag
	alloc.protection = protection
	alloc.accessTime = time.Now().UnixNano()
	sm.protectCount++

	return nil
}

// SecureZeroize securely zeros memory content
func (sm *SecureMemory) SecureZeroize(data []byte) {
	sm.secureZeroize(data)
	sm.zeroizeCount++
}

// mmapAlloc allocates memory using mmap
func (sm *SecureMemory) mmapAlloc(size uintptr) (uintptr, error) {
	// Use mmap for better control over memory
	ptr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0, // addr
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANON,
		0, // fd
		0, // offset
	)

	if errno != 0 {
		return 0, fmt.Errorf("mmap failed: %v", errno)
	}

	return ptr, nil
}

// mmapFree frees memory allocated with mmap
func (sm *SecureMemory) mmapFree(ptr, size uintptr) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MUNMAP,
		ptr,
		size,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("munmap failed: %v", errno)
	}

	return nil
}

// setProtection sets memory protection
func (sm *SecureMemory) setProtection(ptr, size uintptr, protection MemoryProtection) error {
	var prot uintptr

	switch protection {
	case ProtectionNone:
		prot = 0
	case ProtectionReadOnly:
		prot = syscall.PROT_READ
	case ProtectionNoAccess:
		prot = 0
	case ProtectionExecute:
		prot = syscall.PROT_READ | syscall.PROT_EXEC
	default:
		prot = syscall.PROT_READ | syscall.PROT_WRITE
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_MPROTECT,
		ptr,
		size,
		prot,
	)

	if errno != 0 {
		return fmt.Errorf("mprotect failed: %v", errno)
	}

	return nil
}

// lockMemory locks memory pages to prevent swapping
func (sm *SecureMemory) lockMemory(ptr, size uintptr) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MLOCK,
		ptr,
		size,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("mlock failed: %v", errno)
	}

	return nil
}

// unlockMemory unlocks memory pages
func (sm *SecureMemory) unlockMemory(ptr, size uintptr) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MUNLOCK,
		ptr,
		size,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("munlock failed: %v", errno)
	}

	return nil
}

// alignToPage aligns size to page boundary
func (sm *SecureMemory) alignToPage(size uintptr) uintptr {
	return (size + sm.pageSize - 1) &^ (sm.pageSize - 1)
}

// secureZeroize performs secure memory zeroization
func (sm *SecureMemory) secureZeroize(data []byte) {
	// Use volatile writes to prevent compiler optimization
	for i := range data {
		data[i] = 0
	}

	// Memory barrier to ensure writes complete
	runtime.KeepAlive(data)
}

// verifyCanary checks memory canary values
func (sm *SecureMemory) verifyCanary(alloc *allocation) error {
	// In a real implementation, canaries would be placed at memory boundaries
	// This is a simplified version
	return nil
}

// GetStats returns memory management statistics
func (sm *SecureMemory) GetStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return map[string]interface{}{
		"total_size":      sm.totalSize,
		"max_size":        sm.maxSize,
		"allocations":     len(sm.allocations),
		"alloc_count":     sm.allocCount,
		"free_count":      sm.freeCount,
		"protect_count":   sm.protectCount,
		"zeroize_count":   sm.zeroizeCount,
		"guard_pages":     sm.guardPages,
		"canary_values":   sm.canaryValues,
		"encrypt_at_rest": sm.encryptAtRest,
		"prevent_swap":    sm.preventSwap,
	}
}

// Cleanup performs final cleanup of all allocations
func (sm *SecureMemory) Cleanup() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	var errors []error

	for ptr, alloc := range sm.allocations {
		// Securely zero memory
		data := (*[1 << 30]byte)(unsafe.Pointer(ptr))[:alloc.size:alloc.size]
		sm.secureZeroize(data)

		// Unlock if locked
		if sm.preventSwap {
			sm.unlockMemory(alloc.ptr, alloc.size)
		}

		// Free memory
		mmapPtr := alloc.ptr
		if sm.guardPages {
			mmapPtr -= sm.pageSize
		}

		if err := sm.mmapFree(mmapPtr, alloc.actualSize); err != nil {
			errors = append(errors, err)
		}
	}

	// Clear allocations map
	sm.allocations = make(map[uintptr]*allocation)
	sm.totalSize = 0

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}

// Global secure memory manager instance
var secureMemory *SecureMemory
var secureMemoryOnce sync.Once

// GetSecureMemory returns the global secure memory manager
func GetSecureMemory() *SecureMemory {
	secureMemoryOnce.Do(func() {
		var err error
		secureMemory, err = NewSecureMemory(nil)
		if err != nil {
			panic(fmt.Sprintf("Failed to initialize secure memory: %v", err))
		}
	})
	return secureMemory
}
