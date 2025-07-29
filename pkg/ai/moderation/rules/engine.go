package rules

// Engine handles content moderation rules
type Engine struct {
	config *RulesConfig
}

// RulesConfig for rules engine
type RulesConfig struct {
	MaxRules int `json:"max_rules"`
}

// NewEngine creates a new rules engine
func NewEngine(config *RulesConfig) *Engine {
	return &Engine{
		config: config,
	}
}
