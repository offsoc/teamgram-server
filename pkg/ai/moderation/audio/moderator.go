package audio

// Moderator handles audio content moderation
type Moderator struct {
	config *AudioConfig
}

// AudioConfig for audio moderation
type AudioConfig struct {
	MaxDuration int `json:"max_duration"`
}

// NewModerator creates a new audio moderator
func NewModerator(config *AudioConfig) *Moderator {
	return &Moderator{
		config: config,
	}
}
