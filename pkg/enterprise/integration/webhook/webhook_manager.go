package webhook

import (
	"context"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// WebhookManager manages webhook integrations
type WebhookManager struct {
	config    *Config
	webhooks  map[string]*Webhook
	mutex     sync.RWMutex
	logger    logx.Logger
}

// Config for webhook manager
type Config struct {
	MaxRetries      int           `json:"max_retries"`
	RetryInterval   time.Duration `json:"retry_interval"`
	Timeout         time.Duration `json:"timeout"`
	MaxConcurrency  int           `json:"max_concurrency"`
}

// Webhook represents a webhook configuration
type Webhook struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret"`
	Events      []string          `json:"events"`
	Headers     map[string]string `json:"headers"`
	Active      bool              `json:"active"`
	CreatedAt   time.Time         `json:"created_at"`
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(config *Config) *WebhookManager {
	if config == nil {
		config = &Config{
			MaxRetries:     3,
			RetryInterval:  time.Second * 5,
			Timeout:        time.Second * 30,
			MaxConcurrency: 10,
		}
	}

	return &WebhookManager{
		config:   config,
		webhooks: make(map[string]*Webhook),
		logger:   logx.WithContext(context.Background()),
	}
}

// RegisterWebhook registers a new webhook
func (wm *WebhookManager) RegisterWebhook(webhook *Webhook) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.webhooks[webhook.ID] = webhook
	wm.logger.Infof("Registered webhook: %s", webhook.ID)
	return nil
}

// SendEvent sends an event to webhooks
func (wm *WebhookManager) SendEvent(ctx context.Context, event string, data interface{}) error {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	for _, webhook := range wm.webhooks {
		if webhook.Active && wm.shouldSendEvent(webhook, event) {
			go wm.sendWebhook(ctx, webhook, event, data)
		}
	}

	return nil
}

func (wm *WebhookManager) shouldSendEvent(webhook *Webhook, event string) bool {
	for _, e := range webhook.Events {
		if e == event {
			return true
		}
	}
	return false
}

func (wm *WebhookManager) sendWebhook(ctx context.Context, webhook *Webhook, event string, data interface{}) {
	// Mock webhook sending implementation
	wm.logger.Infof("Sending webhook %s for event %s", webhook.ID, event)
}
