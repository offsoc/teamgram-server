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

package svc

import (
	"context"

	"github.com/teamgram/teamgram-server/app/bff/video/internal/config"
	"github.com/zeromicro/go-zero/core/logx"
)

// VideoServiceInterface defines the interface for video service
type VideoServiceInterface interface {
	Start() error
	Stop() error
	IsRunning() bool
	GetWebRTCManager() interface{}
	GetE2EEManager() interface{}
	GetSecurityManager() interface{}
}

// ServiceContext represents the service context
type ServiceContext struct {
	Config       *config.Config
	VideoService VideoServiceInterface
	Logger       logx.Logger
}

// NewServiceContext creates a new service context
func NewServiceContext(c *config.Config) *ServiceContext {
	ctx := context.Background()

	svcCtx := &ServiceContext{
		Config: c,
		Logger: logx.WithContext(ctx),
	}

	// Initialize video service
	if err := svcCtx.initVideoService(); err != nil {
		logx.Errorf("Failed to initialize video service: %v", err)
	}

	return svcCtx
}

// initVideoService initializes the video service
func (svc *ServiceContext) initVideoService() error {
	// Create a mock video service for now
	svc.VideoService = &MockVideoService{}
	svc.Logger.Info("Video service initialized successfully")
	return nil
}

// GetVideoService returns the video service
func (svc *ServiceContext) GetVideoService() VideoServiceInterface {
	return svc.VideoService
}

// GetConfig returns the configuration
func (svc *ServiceContext) GetConfig() *config.Config {
	return svc.Config
}

// GetLogger returns the logger
func (svc *ServiceContext) GetLogger() logx.Logger {
	return svc.Logger
}

// MockVideoService is a mock implementation of VideoServiceInterface
type MockVideoService struct {
	running bool
}

// Start starts the mock video service
func (m *MockVideoService) Start() error {
	m.running = true
	return nil
}

// Stop stops the mock video service
func (m *MockVideoService) Stop() error {
	m.running = false
	return nil
}

// IsRunning returns whether the service is running
func (m *MockVideoService) IsRunning() bool {
	return m.running
}

// GetWebRTCManager returns a mock WebRTC manager
func (m *MockVideoService) GetWebRTCManager() interface{} {
	return &MockWebRTCManager{}
}

// GetE2EEManager returns a mock E2EE manager
func (m *MockVideoService) GetE2EEManager() interface{} {
	return &MockE2EEManager{}
}

// GetSecurityManager returns a mock security manager
func (m *MockVideoService) GetSecurityManager() interface{} {
	return &MockSecurityManager{}
}

// Mock managers
type MockWebRTCManager struct{}
type MockE2EEManager struct{}
type MockSecurityManager struct{}
