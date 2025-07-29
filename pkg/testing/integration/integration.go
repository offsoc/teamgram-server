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

package integration

import (
	"context"
	"fmt"
	"time"
)

// TestSuite represents an integration test suite
type TestSuite struct {
	name  string
	tests []Test
}

// Test represents a single test
type Test struct {
	Name string
	Func func(ctx context.Context) error
}

// NewTestSuite creates a new test suite
func NewTestSuite(name string) *TestSuite {
	return &TestSuite{
		name:  name,
		tests: make([]Test, 0),
	}
}

// AddTest adds a test to the suite
func (ts *TestSuite) AddTest(name string, testFunc func(ctx context.Context) error) {
	ts.tests = append(ts.tests, Test{
		Name: name,
		Func: testFunc,
	})
}

// Run runs all tests in the suite
func (ts *TestSuite) Run(ctx context.Context) error {
	fmt.Printf("Running test suite: %s\n", ts.name)

	for _, test := range ts.tests {
		fmt.Printf("Running test: %s\n", test.Name)
		
		start := time.Now()
		err := test.Func(ctx)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("Test %s FAILED: %v (duration: %v)\n", test.Name, err, duration)
			return err
		}

		fmt.Printf("Test %s PASSED (duration: %v)\n", test.Name, duration)
	}

	fmt.Printf("Test suite %s completed successfully\n", ts.name)
	return nil
}
