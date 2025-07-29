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

package memory

import (
	"runtime"
	"time"
)

// Monitor provides memory monitoring
type Monitor struct {
	usage int64
}

// NewMonitor creates a new memory monitor
func NewMonitor() *Monitor {
	return &Monitor{}
}

// GetUsage returns memory usage in bytes
func (m *Monitor) GetUsage() int64 {
	return m.usage
}

// StartMonitoring starts memory monitoring
func (m *Monitor) StartMonitoring() {
	go func() {
		for {
			m.updateUsage()
			time.Sleep(time.Second)
		}
	}()
}

func (m *Monitor) updateUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.usage = int64(memStats.Alloc)
}
