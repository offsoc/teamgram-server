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

package message

import (
	"context"
	"fmt"
	"math"
	"time"
)

// LocationProcessor handles location sharing functionality
type LocationProcessor struct {
	geocoder       *Geocoder
	liveTracker    *LiveLocationTracker
	venueSearcher  *VenueSearcher
	config         *LocationConfig
}

// LocationConfig contains location processing configuration
type LocationConfig struct {
	MaxLiveLocationDuration time.Duration `json:"max_live_location_duration"` // 8 hours
	UpdateInterval          time.Duration `json:"update_interval"`            // 30 seconds
	AccuracyThreshold       float64       `json:"accuracy_threshold"`         // 100 meters
	EnableGeocoding         bool          `json:"enable_geocoding"`
	EnableVenueSearch       bool          `json:"enable_venue_search"`
	MapProvider             string        `json:"map_provider"`               // "google", "osm", etc.
}

// LocationInfo represents location information
type LocationInfo struct {
	Latitude         float64           `json:"latitude"`
	Longitude        float64           `json:"longitude"`
	Accuracy         float64           `json:"accuracy,omitempty"`         // in meters
	Altitude         float64           `json:"altitude,omitempty"`         // in meters
	Heading          float64           `json:"heading,omitempty"`          // in degrees
	Speed            float64           `json:"speed,omitempty"`            // in m/s
	Timestamp        time.Time         `json:"timestamp"`
	Address          *AddressInfo      `json:"address,omitempty"`
	Venue            *VenueInfo        `json:"venue,omitempty"`
	LivePeriod       int               `json:"live_period,omitempty"`      // in seconds
	ProximityRadius  int               `json:"proximity_radius,omitempty"` // in meters
	Attributes       map[string]string `json:"attributes,omitempty"`
}

// AddressInfo represents geocoded address information
type AddressInfo struct {
	FormattedAddress string `json:"formatted_address"`
	Country          string `json:"country,omitempty"`
	CountryCode      string `json:"country_code,omitempty"`
	State            string `json:"state,omitempty"`
	City             string `json:"city,omitempty"`
	District         string `json:"district,omitempty"`
	Street           string `json:"street,omitempty"`
	StreetNumber     string `json:"street_number,omitempty"`
	PostalCode       string `json:"postal_code,omitempty"`
}

// VenueInfo represents venue information
type VenueInfo struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Address      string            `json:"address"`
	FoursquareID string            `json:"foursquare_id,omitempty"`
	FoursquareType string          `json:"foursquare_type,omitempty"`
	GooglePlaceID string           `json:"google_place_id,omitempty"`
	GooglePlaceType string         `json:"google_place_type,omitempty"`
	Category     string            `json:"category,omitempty"`
	Rating       float64           `json:"rating,omitempty"`
	PriceLevel   int               `json:"price_level,omitempty"`
	PhoneNumber  string            `json:"phone_number,omitempty"`
	Website      string            `json:"website,omitempty"`
	Photos       []string          `json:"photos,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

// LiveLocationUpdate represents a live location update
type LiveLocationUpdate struct {
	UserID       int64        `json:"user_id"`
	ChatID       int64        `json:"chat_id"`
	MessageID    int          `json:"message_id"`
	Location     *LocationInfo `json:"location"`
	IsActive     bool         `json:"is_active"`
	ExpiresAt    time.Time    `json:"expires_at"`
	LastUpdate   time.Time    `json:"last_update"`
}

// NewLocationProcessor creates a new location processor
func NewLocationProcessor(config *LocationConfig) *LocationProcessor {
	return &LocationProcessor{
		geocoder:      NewGeocoder(config),
		liveTracker:   NewLiveLocationTracker(config),
		venueSearcher: NewVenueSearcher(config),
		config:        config,
	}
}

// ProcessLocation processes a location message
func (lp *LocationProcessor) ProcessLocation(ctx context.Context, location *LocationInfo) (*LocationInfo, error) {
	// Validate coordinates
	if err := lp.validateCoordinates(location.Latitude, location.Longitude); err != nil {
		return nil, fmt.Errorf("invalid coordinates: %w", err)
	}
	
	// Set timestamp if not provided
	if location.Timestamp.IsZero() {
		location.Timestamp = time.Now()
	}
	
	// Geocode address if enabled and not provided
	if lp.config.EnableGeocoding && location.Address == nil {
		address, err := lp.geocoder.ReverseGeocode(ctx, location.Latitude, location.Longitude)
		if err == nil {
			location.Address = address
		}
	}
	
	// Search for nearby venues if enabled and not provided
	if lp.config.EnableVenueSearch && location.Venue == nil {
		venues, err := lp.venueSearcher.SearchNearby(ctx, location.Latitude, location.Longitude, 100)
		if err == nil && len(venues) > 0 {
			location.Venue = venues[0] // Use closest venue
		}
	}
	
	return location, nil
}

// StartLiveLocation starts live location sharing
func (lp *LocationProcessor) StartLiveLocation(ctx context.Context, userID, chatID int64, messageID int, location *LocationInfo, duration time.Duration) error {
	if duration > lp.config.MaxLiveLocationDuration {
		return fmt.Errorf("live location duration %v exceeds maximum %v", duration, lp.config.MaxLiveLocationDuration)
	}
	
	update := &LiveLocationUpdate{
		UserID:     userID,
		ChatID:     chatID,
		MessageID:  messageID,
		Location:   location,
		IsActive:   true,
		ExpiresAt:  time.Now().Add(duration),
		LastUpdate: time.Now(),
	}
	
	return lp.liveTracker.StartTracking(ctx, update)
}

// UpdateLiveLocation updates live location
func (lp *LocationProcessor) UpdateLiveLocation(ctx context.Context, userID, chatID int64, messageID int, location *LocationInfo) error {
	return lp.liveTracker.UpdateLocation(ctx, userID, chatID, messageID, location)
}

// StopLiveLocation stops live location sharing
func (lp *LocationProcessor) StopLiveLocation(ctx context.Context, userID, chatID int64, messageID int) error {
	return lp.liveTracker.StopTracking(ctx, userID, chatID, messageID)
}

// GetLiveLocations gets active live locations for a chat
func (lp *LocationProcessor) GetLiveLocations(ctx context.Context, chatID int64) ([]*LiveLocationUpdate, error) {
	return lp.liveTracker.GetActiveLiveLocations(ctx, chatID)
}

// SearchVenues searches for venues near a location
func (lp *LocationProcessor) SearchVenues(ctx context.Context, latitude, longitude float64, query string, radius int) ([]*VenueInfo, error) {
	if err := lp.validateCoordinates(latitude, longitude); err != nil {
		return nil, fmt.Errorf("invalid coordinates: %w", err)
	}
	
	if radius <= 0 || radius > 10000 { // Max 10km radius
		radius = 1000 // Default 1km
	}
	
	return lp.venueSearcher.Search(ctx, latitude, longitude, query, radius)
}

// CalculateDistance calculates distance between two coordinates in meters
func (lp *LocationProcessor) CalculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371000 // Earth radius in meters
	
	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180
	
	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	
	return earthRadius * c
}

// validateCoordinates validates latitude and longitude
func (lp *LocationProcessor) validateCoordinates(latitude, longitude float64) error {
	if latitude < -90 || latitude > 90 {
		return fmt.Errorf("latitude %f is out of range [-90, 90]", latitude)
	}
	
	if longitude < -180 || longitude > 180 {
		return fmt.Errorf("longitude %f is out of range [-180, 180]", longitude)
	}
	
	return nil
}

// Geocoder handles address geocoding
type Geocoder struct {
	config *LocationConfig
}

// NewGeocoder creates a new geocoder
func NewGeocoder(config *LocationConfig) *Geocoder {
	return &Geocoder{config: config}
}

// ReverseGeocode converts coordinates to address
func (g *Geocoder) ReverseGeocode(ctx context.Context, latitude, longitude float64) (*AddressInfo, error) {
	// This is a placeholder implementation
	// In production, integrate with Google Maps, OpenStreetMap, or other geocoding services
	return &AddressInfo{
		FormattedAddress: fmt.Sprintf("%.6f, %.6f", latitude, longitude),
		Country:          "Unknown",
		CountryCode:      "XX",
	}, nil
}

// Geocode converts address to coordinates
func (g *Geocoder) Geocode(ctx context.Context, address string) (*LocationInfo, error) {
	// This is a placeholder implementation
	// In production, integrate with geocoding services
	return &LocationInfo{
		Latitude:  0.0,
		Longitude: 0.0,
		Timestamp: time.Now(),
		Address: &AddressInfo{
			FormattedAddress: address,
		},
	}, nil
}

// LiveLocationTracker tracks live location updates
type LiveLocationTracker struct {
	config        *LocationConfig
	activeUpdates map[string]*LiveLocationUpdate // key: userID_chatID_messageID
}

// NewLiveLocationTracker creates a new live location tracker
func NewLiveLocationTracker(config *LocationConfig) *LiveLocationTracker {
	return &LiveLocationTracker{
		config:        config,
		activeUpdates: make(map[string]*LiveLocationUpdate),
	}
}

// StartTracking starts tracking a live location
func (llt *LiveLocationTracker) StartTracking(ctx context.Context, update *LiveLocationUpdate) error {
	key := fmt.Sprintf("%d_%d_%d", update.UserID, update.ChatID, update.MessageID)
	llt.activeUpdates[key] = update
	
	// Start background update routine
	go llt.trackLocation(ctx, key, update)
	
	return nil
}

// UpdateLocation updates a live location
func (llt *LiveLocationTracker) UpdateLocation(ctx context.Context, userID, chatID int64, messageID int, location *LocationInfo) error {
	key := fmt.Sprintf("%d_%d_%d", userID, chatID, messageID)
	
	if update, exists := llt.activeUpdates[key]; exists {
		update.Location = location
		update.LastUpdate = time.Now()
		return nil
	}
	
	return fmt.Errorf("live location not found")
}

// StopTracking stops tracking a live location
func (llt *LiveLocationTracker) StopTracking(ctx context.Context, userID, chatID int64, messageID int) error {
	key := fmt.Sprintf("%d_%d_%d", userID, chatID, messageID)
	
	if update, exists := llt.activeUpdates[key]; exists {
		update.IsActive = false
		delete(llt.activeUpdates, key)
		return nil
	}
	
	return fmt.Errorf("live location not found")
}

// GetActiveLiveLocations gets active live locations for a chat
func (llt *LiveLocationTracker) GetActiveLiveLocations(ctx context.Context, chatID int64) ([]*LiveLocationUpdate, error) {
	var updates []*LiveLocationUpdate
	
	for _, update := range llt.activeUpdates {
		if update.ChatID == chatID && update.IsActive && time.Now().Before(update.ExpiresAt) {
			updates = append(updates, update)
		}
	}
	
	return updates, nil
}

// trackLocation tracks a live location in background
func (llt *LiveLocationTracker) trackLocation(ctx context.Context, key string, update *LiveLocationUpdate) {
	ticker := time.NewTicker(llt.config.UpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().After(update.ExpiresAt) {
				update.IsActive = false
				delete(llt.activeUpdates, key)
				return
			}
			
			// Here you would typically send location updates to subscribers
			// This is a placeholder for the actual implementation
		}
	}
}

// VenueSearcher searches for venues
type VenueSearcher struct {
	config *LocationConfig
}

// NewVenueSearcher creates a new venue searcher
func NewVenueSearcher(config *LocationConfig) *VenueSearcher {
	return &VenueSearcher{config: config}
}

// SearchNearby searches for venues near coordinates
func (vs *VenueSearcher) SearchNearby(ctx context.Context, latitude, longitude float64, radius int) ([]*VenueInfo, error) {
	// This is a placeholder implementation
	// In production, integrate with Foursquare, Google Places, or other venue APIs
	return []*VenueInfo{
		{
			ID:       "venue_1",
			Title:    "Sample Venue",
			Address:  "123 Main St",
			Category: "Restaurant",
			Rating:   4.5,
		},
	}, nil
}

// Search searches for venues with query
func (vs *VenueSearcher) Search(ctx context.Context, latitude, longitude float64, query string, radius int) ([]*VenueInfo, error) {
	// This is a placeholder implementation
	// In production, implement actual venue search with query
	return vs.SearchNearby(ctx, latitude, longitude, radius)
}
