package bridge

import (
	"context"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// BridgeManager manages Tor bridges
type BridgeManager struct {
	config   *Config
	bridges  map[string]*Bridge
	mutex    sync.RWMutex
	logger   logx.Logger
}

// Config for bridge manager
type Config struct {
	MaxBridges      int           `json:"max_bridges"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
}

// Bridge represents a Tor bridge
type Bridge struct {
	ID          string    `json:"id"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewBridgeManager creates a new bridge manager
func NewBridgeManager(config *Config) *BridgeManager {
	if config == nil {
		config = &Config{
			MaxBridges:          10,
			HealthCheckInterval: time.Minute * 5,
			ConnectionTimeout:   time.Second * 30,
		}
	}

	return &BridgeManager{
		config:  config,
		bridges: make(map[string]*Bridge),
		logger:  logx.WithContext(context.Background()),
	}
}

// AddBridge adds a new bridge
func (bm *BridgeManager) AddBridge(bridge *Bridge) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.bridges[bridge.ID] = bridge
	bm.logger.Infof("Added bridge: %s", bridge.ID)
	return nil
}

// GetBridge gets a bridge by ID
func (bm *BridgeManager) GetBridge(id string) (*Bridge, error) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	bridge, exists := bm.bridges[id]
	if !exists {
		return nil, nil
	}

	return bridge, nil
}

// ListBridges lists all bridges
func (bm *BridgeManager) ListBridges() []*Bridge {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	bridges := make([]*Bridge, 0, len(bm.bridges))
	for _, bridge := range bm.bridges {
		bridges = append(bridges, bridge)
	}

	return bridges
}
