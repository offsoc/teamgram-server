package whitelist

// WhitelistManager handles content whitelist management
type WhitelistManager struct {
	config *WhitelistConfig
}

// WhitelistConfig for whitelist manager
type WhitelistConfig struct {
	MaxEntries int `json:"max_entries"`
}

// NewWhitelistManager creates a new whitelist manager
func NewWhitelistManager(config *WhitelistConfig) *WhitelistManager {
	return &WhitelistManager{
		config: config,
	}
}
