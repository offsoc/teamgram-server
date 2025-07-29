package text

// Moderator handles text content moderation
type Moderator struct {
	config *TextConfig
}

// TextConfig for text moderation
type TextConfig struct {
	MaxLength int `json:"max_length"`
}

// NewModerator creates a new text moderator
func NewModerator(config *TextConfig) *Moderator {
	return &Moderator{
		config: config,
	}
}
