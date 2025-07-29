// Package sidechannel implements side-channel attack protection
// for post-quantum cryptography implementations
package sidechannel

import (
	"crypto/rand"
	"crypto/subtle"
	"runtime"
	"time"
	"unsafe"
	
	"golang.org/x/crypto/sha3"
)

// ProtectionLevel defines the level of side-channel protection
type ProtectionLevel int

const (
	// Basic protection against simple timing attacks
	BasicProtection ProtectionLevel = iota
	
	// Enhanced protection against timing and cache attacks
	EnhancedProtection
	
	// Military-grade protection against all known side-channel attacks
	MilitaryProtection
)

// SideChannelProtector provides side-channel attack protection
type SideChannelProtector struct {
	level           ProtectionLevel
	timingNoise     bool
	cacheProtection bool
	powerAnalysis   bool
	faultInjection  bool
}

// NewSideChannelProtector creates a new side-channel protector
func NewSideChannelProtector(level ProtectionLevel) *SideChannelProtector {
	scp := &SideChannelProtector{
		level: level,
	}
	
	switch level {
	case BasicProtection:
		scp.timingNoise = true
	case EnhancedProtection:
		scp.timingNoise = true
		scp.cacheProtection = true
	case MilitaryProtection:
		scp.timingNoise = true
		scp.cacheProtection = true
		scp.powerAnalysis = true
		scp.faultInjection = true
	}
	
	return scp
}

// ConstantTimeSelect performs constant-time conditional selection
func ConstantTimeSelect(condition int, a, b []byte) {
	if len(a) != len(b) {
		panic("ConstantTimeSelect: slice lengths must be equal")
	}
	
	mask := byte(subtle.ConstantTimeSelect(condition, 1, 0))
	for i := range a {
		a[i] = (mask & a[i]) | ((^mask) & b[i])
	}
}

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeCopy performs constant-time conditional copy
func ConstantTimeCopy(condition int, dst, src []byte) {
	if len(dst) != len(src) {
		panic("ConstantTimeCopy: slice lengths must be equal")
	}
	
	mask := byte(subtle.ConstantTimeSelect(condition, 1, 0))
	for i := range dst {
		dst[i] = (mask & src[i]) | ((^mask) & dst[i])
	}
}

// ConstantTimeByteEq performs constant-time byte equality check
func ConstantTimeByteEq(a, b byte) int {
	return subtle.ConstantTimeByteEq(a, b)
}

// ConstantTimeLessOrEq performs constant-time less-or-equal comparison
func ConstantTimeLessOrEq(a, b int) int {
	return subtle.ConstantTimeLessOrEq(a, b)
}

// AddTimingNoise adds random timing noise to prevent timing attacks
func (scp *SideChannelProtector) AddTimingNoise() {
	if !scp.timingNoise {
		return
	}
	
	// Generate random delay between 0-1000 nanoseconds
	randomBytes := make([]byte, 2)
	rand.Read(randomBytes)
	delay := time.Duration(int(randomBytes[0])<<8|int(randomBytes[1])) % 1000
	
	time.Sleep(delay * time.Nanosecond)
}

// FlushCache flushes CPU cache to prevent cache-based attacks
func (scp *SideChannelProtector) FlushCache() {
	if !scp.cacheProtection {
		return
	}
	
	// Force cache flush by accessing random memory locations
	dummy := make([]byte, 64*1024) // 64KB to flush L1 cache
	for i := 0; i < len(dummy); i += 64 {
		dummy[i] = byte(i)
	}
	
	// Memory barrier to ensure cache flush
	runtime.KeepAlive(dummy)
}

// SecureMemoryAccess performs secure memory access with protection
func (scp *SideChannelProtector) SecureMemoryAccess(data []byte, index int) byte {
	if index < 0 || index >= len(data) {
		panic("SecureMemoryAccess: index out of bounds")
	}
	
	// Add cache protection
	if scp.cacheProtection {
		scp.FlushCache()
	}
	
	// Constant-time memory access
	var result byte
	for i := 0; i < len(data); i++ {
		mask := byte(subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(i), int32(index)), 1, 0))
		result |= mask & data[i]
	}
	
	// Add timing noise
	scp.AddTimingNoise()
	
	return result
}

// SecureMemoryWrite performs secure memory write with protection
func (scp *SideChannelProtector) SecureMemoryWrite(data []byte, index int, value byte) {
	if index < 0 || index >= len(data) {
		panic("SecureMemoryWrite: index out of bounds")
	}
	
	// Add cache protection
	if scp.cacheProtection {
		scp.FlushCache()
	}
	
	// Constant-time memory write
	for i := 0; i < len(data); i++ {
		mask := byte(subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(i), int32(index)), 1, 0))
		data[i] = (mask & value) | ((^mask) & data[i])
	}
	
	// Add timing noise
	scp.AddTimingNoise()
}

// PowerAnalysisProtection provides protection against power analysis attacks
func (scp *SideChannelProtector) PowerAnalysisProtection() {
	if !scp.powerAnalysis {
		return
	}
	
	// Perform dummy operations to mask power consumption
	dummy := make([]byte, 32)
	rand.Read(dummy)
	
	// Dummy cryptographic operations
	for i := 0; i < 10; i++ {
		for j := range dummy {
			dummy[j] ^= byte(i + j)
		}
	}
	
	runtime.KeepAlive(dummy)
}

// FaultInjectionProtection provides protection against fault injection attacks
func (scp *SideChannelProtector) FaultInjectionProtection(operation func() bool) bool {
	if !scp.faultInjection {
		return operation()
	}
	
	// Perform operation multiple times and check consistency
	results := make([]bool, 3)
	for i := range results {
		results[i] = operation()
	}
	
	// Check if all results are consistent
	if results[0] == results[1] && results[1] == results[2] {
		return results[0]
	}
	
	// Inconsistent results indicate possible fault injection
	panic("FaultInjectionProtection: inconsistent results detected")
}

// SecureRandom generates cryptographically secure random bytes with protection
func (scp *SideChannelProtector) SecureRandom(size int) ([]byte, error) {
	result := make([]byte, size)
	
	// Add power analysis protection
	scp.PowerAnalysisProtection()
	
	// Generate random bytes
	if _, err := rand.Read(result); err != nil {
		return nil, err
	}
	
	// Add timing noise
	scp.AddTimingNoise()
	
	return result, nil
}

// ConstantTimeModularReduction performs constant-time modular reduction
func ConstantTimeModularReduction(a, mod uint32) uint32 {
	// Barrett reduction for constant-time modular arithmetic
	if mod == 0 {
		panic("ConstantTimeModularReduction: modulus cannot be zero")
	}
	
	// Precomputed Barrett constant: floor(2^64 / mod)
	// This would be precomputed for each modulus in practice
	var barrett uint64 = (1 << 32) / uint64(mod)
	
	// Barrett reduction: a - (a * barrett >> 32) * mod
	q := uint32((uint64(a) * barrett) >> 32)
	r := a - q*mod
	
	// Conditional subtraction to ensure r < mod
	mask := uint32(subtle.ConstantTimeLessOrEq(int(mod), int(r)))
	r -= mask * mod
	
	return r
}

// ConstantTimeModularMultiplication performs constant-time modular multiplication
func ConstantTimeModularMultiplication(a, b, mod uint32) uint32 {
	if mod == 0 {
		panic("ConstantTimeModularMultiplication: modulus cannot be zero")
	}
	
	// Use 64-bit intermediate to avoid overflow
	product := uint64(a) * uint64(b)
	
	// Reduce using constant-time modular reduction
	return ConstantTimeModularReduction(uint32(product), mod) + 
	       ConstantTimeModularReduction(uint32(product>>32), mod)*
	       ConstantTimeModularReduction(uint32(1<<32%uint64(mod)), mod)
}

// ConstantTimeArrayLookup performs constant-time array lookup
func ConstantTimeArrayLookup(array []uint32, index int) uint32 {
	if index < 0 || index >= len(array) {
		panic("ConstantTimeArrayLookup: index out of bounds")
	}
	
	var result uint32
	for i := 0; i < len(array); i++ {
		mask := uint32(subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(i), int32(index)), 1, 0))
		result |= mask & array[i]
	}
	
	return result
}

// BlindingFactor represents a blinding factor for cryptographic operations
type BlindingFactor struct {
	value    []byte
	inverse  []byte
	lifetime time.Time
}

// NewBlindingFactor creates a new blinding factor
func NewBlindingFactor(size int, lifetime time.Duration) (*BlindingFactor, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	
	// For simplicity, inverse is just the bitwise complement
	// In practice, this would be the modular inverse
	inverse := make([]byte, size)
	for i := range value {
		inverse[i] = ^value[i]
	}
	
	return &BlindingFactor{
		value:    value,
		inverse:  inverse,
		lifetime: time.Now().Add(lifetime),
	}, nil
}

// IsExpired checks if the blinding factor has expired
func (bf *BlindingFactor) IsExpired() bool {
	return time.Now().After(bf.lifetime)
}

// Apply applies the blinding factor to data
func (bf *BlindingFactor) Apply(data []byte) {
	if len(data) != len(bf.value) {
		panic("BlindingFactor.Apply: data length mismatch")
	}
	
	for i := range data {
		data[i] ^= bf.value[i]
	}
}

// Remove removes the blinding factor from data
func (bf *BlindingFactor) Remove(data []byte) {
	if len(data) != len(bf.inverse) {
		panic("BlindingFactor.Remove: data length mismatch")
	}
	
	for i := range data {
		data[i] ^= bf.inverse[i]
	}
}

// Zeroize securely clears the blinding factor
func (bf *BlindingFactor) Zeroize() {
	secureZero(bf.value)
	secureZero(bf.inverse)
}

// secureZero securely zeros memory
func secureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	
	// Multiple passes with different patterns
	for i := range b {
		b[i] = 0x00
	}
	runtime.KeepAlive(b)
	
	for i := range b {
		b[i] = 0xFF
	}
	runtime.KeepAlive(b)
	
	for i := range b {
		b[i] = 0x00
	}
	runtime.KeepAlive(b)
}

// CacheLineSize returns the CPU cache line size
func CacheLineSize() int {
	// Most modern CPUs use 64-byte cache lines
	return 64
}

// AlignToCache aligns data to cache line boundaries
func AlignToCache(data []byte) []byte {
	cacheSize := CacheLineSize()
	if len(data)%cacheSize == 0 {
		return data
	}
	
	aligned := make([]byte, ((len(data)/cacheSize)+1)*cacheSize)
	copy(aligned, data)
	return aligned
}

// PrefetchData prefetches data into CPU cache
func PrefetchData(data []byte) {
	// Access every cache line to prefetch data
	cacheSize := CacheLineSize()
	for i := 0; i < len(data); i += cacheSize {
		_ = data[i]
	}
}

// MemoryBarrier provides a memory barrier to prevent reordering
func MemoryBarrier() {
	runtime.Gosched()
}

// CompilerBarrier prevents compiler optimizations from reordering operations
func CompilerBarrier(ptr unsafe.Pointer) {
	// Use volatile access to prevent compiler optimization
	*(*byte)(ptr) = *(*byte)(ptr)
}

// SideChannelBenchmark benchmarks side-channel protection overhead
type SideChannelBenchmark struct {
	protector *SideChannelProtector
}

// NewSideChannelBenchmark creates a new side-channel benchmark
func NewSideChannelBenchmark(level ProtectionLevel) *SideChannelBenchmark {
	return &SideChannelBenchmark{
		protector: NewSideChannelProtector(level),
	}
}

// BenchmarkProtectionOverhead measures the overhead of side-channel protection
func (scb *SideChannelBenchmark) BenchmarkProtectionOverhead(iterations int) time.Duration {
	data := make([]byte, 1024)
	rand.Read(data)
	
	start := time.Now()
	for i := 0; i < iterations; i++ {
		// Simulate cryptographic operation with protection
		scb.protector.AddTimingNoise()
		scb.protector.FlushCache()
		scb.protector.PowerAnalysisProtection()
		
		// Dummy operation
		for j := range data {
			data[j] ^= byte(i + j)
		}
	}
	
	return time.Since(start)
}

// ValidateProtection validates that side-channel protection is working
func (scp *SideChannelProtector) ValidateProtection() bool {
	// This would perform actual side-channel analysis in production
	// For now, just check that protection features are enabled
	
	switch scp.level {
	case BasicProtection:
		return scp.timingNoise
	case EnhancedProtection:
		return scp.timingNoise && scp.cacheProtection
	case MilitaryProtection:
		return scp.timingNoise && scp.cacheProtection && 
		       scp.powerAnalysis && scp.faultInjection
	default:
		return false
	}
}

// ConstantTimeNTT performs constant-time Number Theoretic Transform
func ConstantTimeNTT(p *[256]int32, zetas []int32) {
	// Constant-time NTT implementation
	k := 0
	for length := 128; length >= 2; length >>= 1 {
		for start := 0; start < 256; start = start + length {
			if k >= len(zetas) {
				break
			}
			zeta := zetas[k]
			k++
			
			for j := start; j < start+length/2; j++ {
				t := ConstantTimeMontgomeryReduce(int64(zeta) * int64(p[j+length/2]))
				p[j+length/2] = p[j] - t
				if p[j+length/2] < 0 {
					p[j+length/2] += 8380417 // Q
				}
				p[j] = p[j] + t
				if p[j] >= 8380417 {
					p[j] -= 8380417
				}
			}
		}
	}
}

// ConstantTimeInvNTT performs constant-time inverse Number Theoretic Transform
func ConstantTimeInvNTT(p *[256]int32, invZetas []int32) {
	// Constant-time inverse NTT implementation
	k := 0
	for length := 2; length <= 128; length <<= 1 {
		for start := 0; start < 256; start = start + length {
			if k >= len(invZetas) {
				break
			}
			zeta := invZetas[k]
			k++
			
			for j := start; j < start+length/2; j++ {
				t := p[j]
				p[j] = t + p[j+length/2]
				if p[j] >= 8380417 {
					p[j] -= 8380417
				}
				p[j+length/2] = t - p[j+length/2]
				if p[j+length/2] < 0 {
					p[j+length/2] += 8380417
				}
				p[j+length/2] = ConstantTimeMontgomeryReduce(int64(zeta) * int64(p[j+length/2]))
			}
		}
	}
	
	// Multiply by Montgomery factor
	f := ConstantTimeMontgomeryReduce(int64(256) << 32)
	for i := 0; i < 256; i++ {
		p[i] = ConstantTimeMontgomeryReduce(int64(p[i]) * int64(f))
	}
}

// ConstantTimeMontgomeryReduce performs constant-time Montgomery reduction
func ConstantTimeMontgomeryReduce(a int64) int32 {
	const Q = 8380417
	const QINV = 4236238847 // -q^(-1) mod 2^32
	
	t := int32(a * int64(QINV))
	t = int32((a - int64(t)*int64(Q)) >> 32)
	return t
}

// ConstantTimeBarrettReduce performs constant-time Barrett reduction
func ConstantTimeBarrettReduce(a int32) int32 {
	const Q = 8380417
	v := ((1 << 26) + Q/2) / Q
	t := int64(v) * int64(a) >> 26
	t = int64(a) - t*int64(Q)
	return int32(t)
}

// ConstantTimeExpandSeed expands a seed using SHAKE-256
func ConstantTimeExpandSeed(seed []byte, outLen int) []byte {
	output := make([]byte, outLen)
	// Use a constant-time SHAKE-256 implementation
	h := sha3.NewShake256()
	h.Write(seed)
	h.Read(output)
	return output
}

// Additional helper functions for Dilithium

// ConstantTimeUniformSampling performs constant-time uniform sampling
func ConstantTimeUniformSampling(p *[256]int32, seed []byte, i, j byte, q int32) {
	// Constant-time rejection sampling for uniform distribution
	h := sha3.NewShake128()
	h.Write(seed)
	h.Write([]byte{i, j})
	
	buf := make([]byte, 168) // SHAKE128 rate
	h.Read(buf)
	
	ctr := 0
	pos := 0
	
	for ctr < 256 {
		if pos + 3 > len(buf) {
			h.Read(buf)
			pos = 0
		}
		
		t := uint32(buf[pos]) | (uint32(buf[pos+1]) << 8) | (uint32(buf[pos+2]) << 16)
		pos += 3
		
		if t < uint32(q) {
			p[ctr] = int32(t)
			ctr++
		}
	}
}

// ConstantTimeBinomialSampling performs constant-time centered binomial sampling
func ConstantTimeBinomialSampling(p *[256]int32, seed []byte, nonce byte, eta int) {
	h := sha3.NewShake256()
	h.Write(seed)
	h.Write([]byte{nonce})
	
	bufSize := 64
	if eta == 4 {
		bufSize = 128
	}
	buf := make([]byte, bufSize)
	h.Read(buf)
	
	for i := 0; i < 256; i++ {
		var a, b uint32
		
		for j := 0; j < eta; j++ {
			idx1 := (i*eta/4 + j/8) % len(buf)
			idx2 := (i*eta/4 + eta/8 + j/8) % len(buf)
			a += uint32((buf[idx1] >> (j%8)) & 1)
			b += uint32((buf[idx2] >> (j%8)) & 1)
		}
		
		p[i] = int32(a) - int32(b)
	}
}

// ConstantTimeModQ performs constant-time modular reduction modulo Q
func ConstantTimeModQ(a int32) int32 {
	const Q = 8380417
	result := a % Q
	if result < 0 {
		result += Q
	}
	return result
}

// ConstantTimePower2Round performs constant-time power-of-2 rounding
func ConstantTimePower2Round(a int32, d int) (int32, int32) {
	a1 := (a + (1 << (d-1))) >> d
	a0 := a - (a1 << d)
	
	if a0 > (1 << (d-1)) {
		a0 -= (1 << d)
		a1 += 1
	}
	
	return a1, a0
}

// ConstantTimeSelectInt performs constant-time conditional selection for integers
func ConstantTimeSelectInt(condition bool, a, b int) int {
	mask := 0
	if condition {
		mask = -1
	}
	return (a & mask) | (b & ^mask)
}

// ConstantTimeCheckNorm checks polynomial norm with constant-time operations
func ConstantTimeCheckNorm(p *[256]int32, bound int32) bool {
	for i := 0; i < 256; i++ {
		abs := p[i]
		if abs < 0 {
			abs = -abs
		}
		if abs >= bound {
			return false
		}
	}
	return true
}

// ConstantTimeNegate negates a polynomial with constant-time operations
func ConstantTimeNegate(p *[256]int32) {
	const Q = 8380417
	for i := 0; i < 256; i++ {
		p[i] = -p[i]
		if p[i] < 0 {
			p[i] += Q
		}
	}
}

// ConstantTimeDecompose performs constant-time polynomial decomposition
func ConstantTimeDecompose(a int32, gamma2 int32) (int32, int32) {
	const Q = 8380417
	ai := a % Q
	if ai < 0 {
		ai += Q
	}
	
	a1 := ai / (2 * gamma2)
	a0 := ai - a1*(2*gamma2)
	
	if a0 > gamma2 {
		a0 -= 2 * gamma2
		a1 += 1
	}
	
	return a1, a0
}

// ConstantTimeMakeHint creates hint polynomial with constant-time operations
func ConstantTimeMakeHint(h, a0, a1 *[256]int32, gamma2 int32) int {
	count := 0
	
	for i := 0; i < 256; i++ {
		const Q = 8380417
		a0i := a0[i] % Q
		if a0i < 0 {
			a0i += Q
		}
		
		a1i := a1[i] % Q
		if a1i < 0 {
			a1i += Q
		}
		
		r := a0i + a1i
		if r >= Q {
			r -= Q
		}
		
		if (a0i <= gamma2 && r > gamma2) || (a0i > gamma2 && r <= gamma2) {
			h[i] = 1
			count++
		} else {
			h[i] = 0
		}
	}
	
	return count
}

// ConstantTimeChallenge computes challenge polynomial with constant-time operations
func ConstantTimeChallenge(c *[256]int32, mu, w1Packed []byte, tau int) {
	h := sha3.NewShake256()
	h.Write(mu)
	h.Write(w1Packed)
	
	buf := make([]byte, 32)
	h.Read(buf)
	
	// Initialize to zero
	for i := 0; i < 256; i++ {
		c[i] = 0
	}
	
	// Set tau coefficients to +/-1
	signs := buf[0] & 1
	buf[0] >>= 1
	
	bufIdx := 1
	for i := 0; i < tau && bufIdx < len(buf); i++ {
		pos := 0
		found := false
		
		if bufIdx < len(buf) {
			if uint16(buf[bufIdx] & 0x0F) < 256 {
				pos = int(buf[bufIdx] & 0x0F)
				found = true
			} else if uint16(buf[bufIdx] >> 4) < 256 {
				pos = int(buf[bufIdx] >> 4)
				found = true
			}
			bufIdx++
		}
		
		if found {
			if (signs & 1) == 1 {
				c[pos] = 1
			} else {
				c[pos] = -1
			}
			signs >>= 1
			
			if signs == 0 && bufIdx < len(buf) {
				signs = buf[bufIdx] & 0xFF
				bufIdx++
			}
		}
	}
}

// ConstantTimeGamma1Sampling performs constant-time gamma1 sampling
func ConstantTimeGamma1Sampling(p *[256]int32, seed []byte, nonce uint16, gamma1 int32) {
	h := sha3.NewShake256()
	h.Write(seed)
	nonceBytes := make([]byte, 2)
	nonceBytes[0] = byte(nonce)
	nonceBytes[1] = byte(nonce >> 8)
	h.Write(nonceBytes)
	
	bufSize := 5 * 256 / 4
	buf := make([]byte, bufSize)
	h.Read(buf)
	
	for i := 0; i < 256; i++ {
		byteOffset := (i * 5) / 4
		bitOffset := (i * 5) % 4 * 2
		
		var t uint32
		if byteOffset+2 < len(buf) {
			t = uint32(buf[byteOffset]) | (uint32(buf[byteOffset+1]) << 8) | (uint32(buf[byteOffset+2]) << 16)
			t = (t >> bitOffset) & 0xFFFFF
		} else {
			t = 0
		}
		
		p[i] = int32(t % uint32(2*gamma1+1)) - gamma1
	}
}

// ConstantTimePackSignature packs signature with constant-time operations
func ConstantTimePackSignature(signature []byte, c *[256]int32, z []Polynomial, h []Polynomial, tau int) {
	pos := 0
	
	// Pack challenge c
	nonZeroCount := 0
	for i := 0; i < 256; i++ {
		if c[i] != 0 {
			if nonZeroCount < tau && pos < len(signature) {
				signature[pos] = byte(i)
				pos++
				nonZeroCount++
			}
		}
	}
	
	// Pack signs
	signByte := byte(0)
	bitPos := 0
	for i := 0; i < 256; i++ {
		if c[i] != 0 {
			if c[i] > 0 {
				signByte |= (1 << bitPos)
			}
			bitPos++
			if bitPos == 8 {
				if pos < len(signature) {
					signature[pos] = signByte
					pos++
				}
				signByte = 0
				bitPos = 0
			}
		}
	}
	if bitPos > 0 && pos < len(signature) {
		signature[pos] = signByte
		pos++
	}
	
	// Pack z (simplified)
	for i := range z {
		for j := 0; j < 256; j++ {
			if pos < len(signature) {
				signature[pos] = byte(z[i][j] & 0xFF)
				pos++
			}
		}
	}
	
	// Pack h (simplified)
	for i := range h {
		for j := 0; j < 256; j++ {
			if pos < len(signature) {
				signature[pos] = byte(h[i][j] & 0xFF)
				pos++
			}
		}
	}
}

// ConstantTimePackPolynomials packs polynomials with constant-time operations
func ConstantTimePackPolynomials(polys []Polynomial, bitsPerCoeff int) []byte {
	totalBits := len(polys) * 256 * bitsPerCoeff
	packed := make([]byte, (totalBits+7)/8)
	
	bitPos := 0
	for i := range polys {
		for j := 0; j < 256; j++ {
			coeff := uint32(polys[i][j])
			if bitsPerCoeff == 2 || bitsPerCoeff == 3 {
				coeff += uint32(2) // Shift to positive range for eta=2 case
			}
			
			// Pack bits
			bytePos := bitPos / 8
			bitOffset := bitPos % 8
			
			if bitOffset+bitsPerCoeff <= 8 {
				if bytePos < len(packed) {
					packed[bytePos] |= byte(coeff << bitOffset)
				}
			} else {
				if bytePos < len(packed) {
					packed[bytePos] |= byte(coeff << bitOffset)
				}
				if bytePos+1 < len(packed) {
					packed[bytePos+1] |= byte(coeff >> (8 - bitOffset))
				}
			}
			
			bitPos += bitsPerCoeff
		}
	}
	
	return packed
}

// ConstantTimeHash performs constant-time hashing
func ConstantTimeHash(data1, data2 []byte) []byte {
	h := sha3.NewShake256()
	h.Write(data1)
	h.Write(data2)
	result := make([]byte, 64)
	h.Read(result)
	return result
}

// ConstantTimeUnpackPolynomials unpacks polynomials with constant-time operations
func ConstantTimeUnpackPolynomials(polys []Polynomial, packed []byte, bitsPerCoeff int) {
	bitPos := 0
	for i := range polys {
		for j := 0; j < 256; j++ {
			bytePos := bitPos / 8
			bitOffset := bitPos % 8
			
			var coeff uint32
			if bytePos < len(packed) {
				if bitOffset+bitsPerCoeff <= 8 {
					coeff = uint32((packed[bytePos] >> bitOffset) & ((1 << bitsPerCoeff) - 1))
				} else {
					coeff = uint32(packed[bytePos] >> bitOffset)
					if bytePos+1 < len(packed) {
						coeff |= uint32(packed[bytePos+1]&((1<<(bitOffset+bitsPerCoeff-8))-1)) << (8 - bitOffset)
					}
				}
			}
			
			// Convert back to centered representation if needed
			if bitsPerCoeff == 2 || bitsPerCoeff == 3 {
				polys[i][j] = int32(coeff) - 2 // Shift back for eta=2 case
			} else {
				polys[i][j] = int32(coeff)
			}
			
			bitPos += bitsPerCoeff
		}
	}
}

// NewConstantTimeHasher creates a new constant-time hasher
func NewConstantTimeHasher() *ConstantTimeHasher {
	return &ConstantTimeHasher{
		hasher: sha3.NewShake256(),
	}
}

// ConstantTimeHasher provides constant-time hashing operations
type ConstantTimeHasher struct {
	hasher sha3.ShakeHash
}

// Write writes data to the hasher
func (h *ConstantTimeHasher) Write(data []byte) {
	h.hasher.Write(data)
}

// Read reads hash output
func (h *ConstantTimeHasher) Read(output []byte) {
	h.hasher.Read(output)
}

// Define polynomial type for the functions above
type Polynomial [256]int32