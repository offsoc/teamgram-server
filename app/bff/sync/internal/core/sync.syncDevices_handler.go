package sync

import (
	"context"
	"errors"
	"sync"
)

type Device struct {
	ID     string
	UserID string
	Data   map[string]interface{}
}

type SyncService struct {
	mu      sync.Mutex
	devices map[string]*Device
}

func NewSyncService() *SyncService {
	return &SyncService{
		devices: make(map[string]*Device),
	}
}

func (s *SyncService) AddDevice(ctx context.Context, device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.devices[device.ID]; exists {
		return errors.New("device already exists")
	}

	s.devices[device.ID] = device
	return nil
}

func (s *SyncService) RemoveDevice(ctx context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.devices[deviceID]; !exists {
		return errors.New("device not found")
	}

	delete(s.devices, deviceID)
	return nil
}

func (s *SyncService) SyncData(ctx context.Context, deviceID string, data map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	device.Data = data
	return nil
}

func (s *SyncService) GetDeviceData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return nil, errors.New("device not found")
	}

	return device.Data, nil
}

func (s *SyncService) SyncAllDevices(ctx context.Context, userID string, data map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, device := range s.devices {
		if device.UserID == userID {
			device.Data = data
		}
	}

	return nil
}
