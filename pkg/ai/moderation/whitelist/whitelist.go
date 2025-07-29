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

package whitelist

import (
	"sync"
)

// Manager manages whitelist functionality
type Manager struct {
	whitelist map[string]bool
	mutex     sync.RWMutex
}

// NewManager creates a new whitelist manager
func NewManager() *Manager {
	return &Manager{
		whitelist: make(map[string]bool),
	}
}

// Add adds an item to the whitelist
func (m *Manager) Add(item string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.whitelist[item] = true
}

// Remove removes an item from the whitelist
func (m *Manager) Remove(item string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.whitelist, item)
}

// Contains checks if an item is in the whitelist
func (m *Manager) Contains(item string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.whitelist[item]
}

// GetAll returns all whitelist items
func (m *Manager) GetAll() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	items := make([]string, 0, len(m.whitelist))
	for item := range m.whitelist {
		items = append(items, item)
	}
	return items
}
