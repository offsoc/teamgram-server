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

package unit

import (
	"fmt"
	"reflect"
	"testing"
)

// Assert provides assertion utilities
type Assert struct {
	t *testing.T
}

// NewAssert creates a new assert instance
func NewAssert(t *testing.T) *Assert {
	return &Assert{t: t}
}

// Equal asserts that two values are equal
func (a *Assert) Equal(expected, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		a.t.Errorf("Expected %v, got %v", expected, actual)
	}
}

// NotEqual asserts that two values are not equal
func (a *Assert) NotEqual(expected, actual interface{}) {
	if reflect.DeepEqual(expected, actual) {
		a.t.Errorf("Expected %v to not equal %v", expected, actual)
	}
}

// Nil asserts that a value is nil
func (a *Assert) Nil(value interface{}) {
	if value != nil {
		a.t.Errorf("Expected nil, got %v", value)
	}
}

// NotNil asserts that a value is not nil
func (a *Assert) NotNil(value interface{}) {
	if value == nil {
		a.t.Error("Expected non-nil value")
	}
}

// True asserts that a value is true
func (a *Assert) True(value bool) {
	if !value {
		a.t.Error("Expected true, got false")
	}
}

// False asserts that a value is false
func (a *Assert) False(value bool) {
	if value {
		a.t.Error("Expected false, got true")
	}
}

// Error asserts that an error occurred
func (a *Assert) Error(err error) {
	if err == nil {
		a.t.Error("Expected error, got nil")
	}
}

// NoError asserts that no error occurred
func (a *Assert) NoError(err error) {
	if err != nil {
		a.t.Errorf("Expected no error, got %v", err)
	}
}

// Contains asserts that a string contains a substring
func (a *Assert) Contains(str, substr string) {
	if !contains(str, substr) {
		a.t.Errorf("Expected %q to contain %q", str, substr)
	}
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && 
		   (str == substr || 
		    (len(str) > len(substr) && 
		     (str[:len(substr)] == substr || 
		      str[len(str)-len(substr):] == substr ||
		      containsSubstring(str, substr))))
}

func containsSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Mock provides mocking utilities
type Mock struct {
	calls map[string][]interface{}
}

// NewMock creates a new mock
func NewMock() *Mock {
	return &Mock{
		calls: make(map[string][]interface{}),
	}
}

// RecordCall records a method call
func (m *Mock) RecordCall(method string, args ...interface{}) {
	m.calls[method] = append(m.calls[method], args)
}

// GetCalls returns all calls for a method
func (m *Mock) GetCalls(method string) []interface{} {
	return m.calls[method]
}

// CallCount returns the number of calls for a method
func (m *Mock) CallCount(method string) int {
	return len(m.calls[method])
}

// Reset resets all recorded calls
func (m *Mock) Reset() {
	m.calls = make(map[string][]interface{})
}

// Benchmark provides benchmarking utilities
type Benchmark struct {
	name string
}

// NewBenchmark creates a new benchmark
func NewBenchmark(name string) *Benchmark {
	return &Benchmark{name: name}
}

// Run runs a benchmark
func (b *Benchmark) Run(fn func()) {
	fmt.Printf("Running benchmark: %s\n", b.name)
	// In a real implementation, this would measure performance
	fn()
	fmt.Printf("Benchmark %s completed\n", b.name)
}
