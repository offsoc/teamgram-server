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

package formal

import (
	"errors"
	"regexp"
)

// Verifier provides formal verification
type Verifier struct {
	rules map[string]*Rule
}

// Rule represents a verification rule
type Rule struct {
	Name    string
	Pattern string
	regex   *regexp.Regexp
}

// NewVerifier creates a new verifier
func NewVerifier() *Verifier {
	return &Verifier{
		rules: make(map[string]*Rule),
	}
}

// AddRule adds a verification rule
func (v *Verifier) AddRule(name, pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	v.rules[name] = &Rule{
		Name:    name,
		Pattern: pattern,
		regex:   regex,
	}

	return nil
}

// Verify verifies data against a rule
func (v *Verifier) Verify(ruleName string, data string) error {
	rule, exists := v.rules[ruleName]
	if !exists {
		return errors.New("rule not found")
	}

	if !rule.regex.MatchString(data) {
		return errors.New("verification failed")
	}

	return nil
}
