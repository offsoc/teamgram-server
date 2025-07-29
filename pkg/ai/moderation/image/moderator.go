package image

// Moderator handles image content moderation
type Moderator struct {
	config *ImageConfig
}

// ImageConfig for image moderation
type ImageConfig struct {
	MaxResolution string `json:"max_resolution"`
}

// NewModerator creates a new image moderator
func NewModerator(config *ImageConfig) *Moderator {
	return &Moderator{
		config: config,
	}
}
