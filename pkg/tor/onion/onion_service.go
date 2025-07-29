package onion

import (
	"context"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// OnionService manages Tor onion services
type OnionService struct {
	config   *Config
	services map[string]*Service
	mutex    sync.RWMutex
	logger   logx.Logger
}

// Config for onion service
type Config struct {
	MaxServices     int           `json:"max_services"`
	KeyDirectory    string        `json:"key_directory"`
	ServiceTimeout  time.Duration `json:"service_timeout"`
}

// Service represents an onion service
type Service struct {
	ID          string    `json:"id"`
	OnionAddress string   `json:"onion_address"`
	Port        int       `json:"port"`
	TargetPort  int       `json:"target_port"`
	PrivateKey  string    `json:"private_key"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewOnionService creates a new onion service manager
func NewOnionService(config *Config) *OnionService {
	if config == nil {
		config = &Config{
			MaxServices:    5,
			KeyDirectory:   "/tmp/onion_keys",
			ServiceTimeout: time.Minute * 2,
		}
	}

	return &OnionService{
		config:   config,
		services: make(map[string]*Service),
		logger:   logx.WithContext(context.Background()),
	}
}

// CreateService creates a new onion service
func (os *OnionService) CreateService(service *Service) error {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	os.services[service.ID] = service
	os.logger.Infof("Created onion service: %s", service.ID)
	return nil
}

// GetService gets a service by ID
func (os *OnionService) GetService(id string) (*Service, error) {
	os.mutex.RLock()
	defer os.mutex.RUnlock()

	service, exists := os.services[id]
	if !exists {
		return nil, nil
	}

	return service, nil
}

// ListServices lists all services
func (os *OnionService) ListServices() []*Service {
	os.mutex.RLock()
	defer os.mutex.RUnlock()

	services := make([]*Service, 0, len(os.services))
	for _, service := range os.services {
		services = append(services, service)
	}

	return services
}
