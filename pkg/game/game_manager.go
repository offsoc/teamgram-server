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

package game

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// GameManager handles game platform functionality
type GameManager struct {
	config       *GameConfig
	games        map[string]*Game
	users        map[int64]*GameUser
	scores       map[string][]*GameScore
	leaderboards map[string]*Leaderboard
	mutex        sync.RWMutex
	logger       logx.Logger
}

// GameConfig represents game configuration
type GameConfig struct {
	// Game settings
	MaxGamesPerUser int           `json:"max_games_per_user"`
	MaxScorePerGame int64         `json:"max_score_per_game"`
	ScoreExpiry     time.Duration `json:"score_expiry"`

	// Leaderboard settings
	LeaderboardSize           int           `json:"leaderboard_size"`
	LeaderboardUpdateInterval time.Duration `json:"leaderboard_update_interval"`

	// Statistics settings
	EnableStatistics    bool          `json:"enable_statistics"`
	StatisticsRetention time.Duration `json:"statistics_retention"`

	// Anti-cheat settings
	EnableAntiCheat bool `json:"enable_anti_cheat"`
	ScoreValidation bool `json:"score_validation"`
	RateLimiting    bool `json:"rate_limiting"`
}

// Game represents a game
type Game struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	ShortName   string    `json:"short_name"`
	BotUsername string    `json:"bot_username"`
	BotID       int64     `json:"bot_id"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Game properties
	Type     GameType `json:"type"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	Language string   `json:"language"`

	// Statistics
	TotalPlayers int64   `json:"total_players"`
	TotalGames   int64   `json:"total_games"`
	AverageScore float64 `json:"average_score"`
	HighScore    int64   `json:"high_score"`
}

// GameType represents game type
type GameType string

const (
	GameTypeArcade    GameType = "arcade"
	GameTypePuzzle    GameType = "puzzle"
	GameTypeRacing    GameType = "racing"
	GameTypeStrategy  GameType = "strategy"
	GameTypeAction    GameType = "action"
	GameTypeAdventure GameType = "adventure"
)

// GameUser represents a user's game profile
type GameUser struct {
	UserID     int64     `json:"user_id"`
	Username   string    `json:"username"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	CreatedAt  time.Time `json:"created_at"`
	LastPlayed time.Time `json:"last_played"`

	// Statistics
	TotalGames   int64   `json:"total_games"`
	TotalScore   int64   `json:"total_score"`
	AverageScore float64 `json:"average_score"`
	BestScore    int64   `json:"best_score"`
	GamesWon     int64   `json:"games_won"`

	// Achievements
	Achievements []*Achievement `json:"achievements"`
	Level        int            `json:"level"`
	Experience   int64          `json:"experience"`
}

// GameScore represents a game score
type GameScore struct {
	ID        string        `json:"id"`
	GameID    string        `json:"game_id"`
	UserID    int64         `json:"user_id"`
	Score     int64         `json:"score"`
	Level     int           `json:"level"`
	Duration  time.Duration `json:"duration"`
	Date      time.Time     `json:"date"`
	Validated bool          `json:"validated"`

	// Additional data
	Data      map[string]interface{} `json:"data"`
	ReplayURL string                 `json:"replay_url"`
}

// Leaderboard represents a game leaderboard
type Leaderboard struct {
	GameID    string       `json:"game_id"`
	Type      string       `json:"type"` // daily, weekly, monthly, all-time
	UpdatedAt time.Time    `json:"updated_at"`
	Scores    []*GameScore `json:"scores"`
}

// Achievement represents a game achievement
type Achievement struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Icon        string    `json:"icon"`
	UnlockedAt  time.Time `json:"unlocked_at"`
	Progress    int       `json:"progress"`
	MaxProgress int       `json:"max_progress"`
}

// NewGameManager creates a new game manager
func NewGameManager(config *GameConfig) (*GameManager, error) {
	if config == nil {
		config = DefaultGameConfig()
	}

	manager := &GameManager{
		config:       config,
		games:        make(map[string]*Game),
		users:        make(map[int64]*GameUser),
		scores:       make(map[string][]*GameScore),
		leaderboards: make(map[string]*Leaderboard),
		logger:       logx.WithContext(context.Background()),
	}

	// Start background tasks
	go manager.updateLeaderboards()
	go manager.cleanupExpiredScores()

	return manager, nil
}

// CreateGame creates a new game
func (m *GameManager) CreateGame(ctx context.Context, title, description, shortName, botUsername string, gameType GameType) (*Game, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate short name
	if err := m.validateShortName(shortName); err != nil {
		return nil, err
	}

	// Check if short name already exists
	for _, game := range m.games {
		if game.ShortName == shortName {
			return nil, fmt.Errorf("short name already exists")
		}
	}

	// Generate game ID
	gameID := m.generateGameID()

	// Create game
	game := &Game{
		ID:          gameID,
		Title:       title,
		Description: description,
		ShortName:   shortName,
		BotUsername: botUsername,
		BotID:       m.generateBotID(),
		Active:      true,
		Type:        gameType,
		Category:    "general",
		Tags:        make([]string, 0),
		Language:    "en",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	m.games[gameID] = game

	m.logger.Infof("Created game: %s (%s)", title, gameID)
	return game, nil
}

// SubmitScore submits a game score
func (m *GameManager) SubmitScore(ctx context.Context, gameID string, userID int64, score int64, level int, duration time.Duration, data map[string]interface{}) (*GameScore, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate game
	game, exists := m.games[gameID]
	if !exists || !game.Active {
		return nil, fmt.Errorf("game not found or inactive")
	}

	// Validate score
	if score < 0 || score > m.config.MaxScorePerGame {
		return nil, fmt.Errorf("invalid score: %d", score)
	}

	// Get or create user
	user, exists := m.users[userID]
	if !exists {
		user = &GameUser{
			UserID:       userID,
			CreatedAt:    time.Now(),
			Achievements: make([]*Achievement, 0),
			Level:        1,
		}
		m.users[userID] = user
	}

	// Create game score
	gameScore := &GameScore{
		ID:        m.generateScoreID(),
		GameID:    gameID,
		UserID:    userID,
		Score:     score,
		Level:     level,
		Duration:  duration,
		Date:      time.Now(),
		Validated: m.config.EnableAntiCheat,
		Data:      data,
	}

	// Add to scores
	m.scores[gameID] = append(m.scores[gameID], gameScore)

	// Update user statistics
	user.TotalGames++
	user.TotalScore += score
	user.AverageScore = float64(user.TotalScore) / float64(user.TotalGames)
	user.LastPlayed = time.Now()

	if score > user.BestScore {
		user.BestScore = score
	}

	// Update game statistics
	game.TotalGames++
	game.TotalPlayers++
	// Calculate average score from all users (simplified)
	game.AverageScore = float64(user.TotalScore) / float64(game.TotalGames)
	game.UpdatedAt = time.Now()

	if score > game.HighScore {
		game.HighScore = score
	}

	// Check for achievements
	m.checkAchievements(user, gameScore)

	m.logger.Infof("Submitted score: %d for game %s by user %d", score, gameID, userID)
	return gameScore, nil
}

// GetLeaderboard returns a game leaderboard
func (m *GameManager) GetLeaderboard(ctx context.Context, gameID, leaderboardType string, limit int) (*Leaderboard, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if game exists
	if _, exists := m.games[gameID]; !exists {
		return nil, fmt.Errorf("game not found")
	}

	// Get leaderboard key
	key := fmt.Sprintf("%s_%s", gameID, leaderboardType)
	leaderboard, exists := m.leaderboards[key]
	if !exists {
		leaderboard = &Leaderboard{
			GameID:    gameID,
			Type:      leaderboardType,
			UpdatedAt: time.Now(),
			Scores:    make([]*GameScore, 0),
		}
	}

	// Filter scores based on type
	var filteredScores []*GameScore
	now := time.Now()

	switch leaderboardType {
	case "daily":
		startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		for _, score := range m.scores[gameID] {
			if score.Date.After(startOfDay) {
				filteredScores = append(filteredScores, score)
			}
		}
	case "weekly":
		startOfWeek := now.AddDate(0, 0, -int(now.Weekday()))
		startOfWeek = time.Date(startOfWeek.Year(), startOfWeek.Month(), startOfWeek.Day(), 0, 0, 0, 0, startOfWeek.Location())
		for _, score := range m.scores[gameID] {
			if score.Date.After(startOfWeek) {
				filteredScores = append(filteredScores, score)
			}
		}
	case "monthly":
		startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		for _, score := range m.scores[gameID] {
			if score.Date.After(startOfMonth) {
				filteredScores = append(filteredScores, score)
			}
		}
	case "all-time":
		filteredScores = m.scores[gameID]
	}

	// Sort by score (descending)
	sort.Slice(filteredScores, func(i, j int) bool {
		return filteredScores[i].Score > filteredScores[j].Score
	})

	// Limit results
	if limit > 0 && len(filteredScores) > limit {
		filteredScores = filteredScores[:limit]
	}

	leaderboard.Scores = filteredScores
	leaderboard.UpdatedAt = time.Now()

	return leaderboard, nil
}

// GetUserStats returns user game statistics
func (m *GameManager) GetUserStats(ctx context.Context, userID int64) (*GameUser, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	user, exists := m.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// GetGameStats returns game statistics
func (m *GameManager) GetGameStats(ctx context.Context, gameID string) (*Game, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	game, exists := m.games[gameID]
	if !exists {
		return nil, fmt.Errorf("game not found")
	}

	return game, nil
}

// GetTopPlayers returns top players across all games
func (m *GameManager) GetTopPlayers(ctx context.Context, limit int) ([]*GameUser, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var users []*GameUser
	for _, user := range m.users {
		users = append(users, user)
	}

	// Sort by total score (descending)
	sort.Slice(users, func(i, j int) bool {
		return users[i].TotalScore > users[j].TotalScore
	})

	// Limit results
	if limit > 0 && len(users) > limit {
		users = users[:limit]
	}

	return users, nil
}

// GetUserScores returns user's scores for a game
func (m *GameManager) GetUserScores(ctx context.Context, userID int64, gameID string, limit int) ([]*GameScore, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var userScores []*GameScore
	for _, score := range m.scores[gameID] {
		if score.UserID == userID {
			userScores = append(userScores, score)
		}
	}

	// Sort by date (descending)
	sort.Slice(userScores, func(i, j int) bool {
		return userScores[i].Date.After(userScores[j].Date)
	})

	// Limit results
	if limit > 0 && len(userScores) > limit {
		userScores = userScores[:limit]
	}

	return userScores, nil
}

// validateShortName validates game short name
func (m *GameManager) validateShortName(shortName string) error {
	if len(shortName) < 3 || len(shortName) > 32 {
		return fmt.Errorf("short name must be between 3 and 32 characters")
	}

	// Check for valid characters
	for _, char := range shortName {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_') {
			return fmt.Errorf("short name can only contain lowercase letters, numbers, and underscores")
		}
	}

	return nil
}

// checkAchievements checks for new achievements
func (m *GameManager) checkAchievements(user *GameUser, score *GameScore) {
	// Example achievements
	achievements := []struct {
		id          string
		title       string
		description string
		condition   func(*GameUser, *GameScore) bool
	}{
		{
			id:          "first_game",
			title:       "First Game",
			description: "Play your first game",
			condition:   func(u *GameUser, s *GameScore) bool { return u.TotalGames == 1 },
		},
		{
			id:          "high_scorer",
			title:       "High Scorer",
			description: "Score 1000+ points in a single game",
			condition:   func(u *GameUser, s *GameScore) bool { return s.Score >= 1000 },
		},
		{
			id:          "veteran",
			title:       "Veteran",
			description: "Play 100 games",
			condition:   func(u *GameUser, s *GameScore) bool { return u.TotalGames >= 100 },
		},
	}

	for _, achievement := range achievements {
		// Check if already unlocked
		alreadyUnlocked := false
		for _, unlocked := range user.Achievements {
			if unlocked.ID == achievement.id {
				alreadyUnlocked = true
				break
			}
		}

		if !alreadyUnlocked && achievement.condition(user, score) {
			// Unlock achievement
			newAchievement := &Achievement{
				ID:          achievement.id,
				Title:       achievement.title,
				Description: achievement.description,
				Icon:        fmt.Sprintf("achievement_%s.png", achievement.id),
				UnlockedAt:  time.Now(),
				Progress:    1,
				MaxProgress: 1,
			}
			user.Achievements = append(user.Achievements, newAchievement)
		}
	}
}

// updateLeaderboards updates leaderboards periodically
func (m *GameManager) updateLeaderboards() {
	ticker := time.NewTicker(m.config.LeaderboardUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.mutex.Lock()

		// Update all leaderboards
		for gameID := range m.games {
			for _, leaderboardType := range []string{"daily", "weekly", "monthly", "all-time"} {
				key := fmt.Sprintf("%s_%s", gameID, leaderboardType)
				leaderboard := &Leaderboard{
					GameID:    gameID,
					Type:      leaderboardType,
					UpdatedAt: time.Now(),
					Scores:    make([]*GameScore, 0),
				}
				m.leaderboards[key] = leaderboard
			}
		}

		m.mutex.Unlock()
	}
}

// cleanupExpiredScores removes expired scores
func (m *GameManager) cleanupExpiredScores() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.mutex.Lock()

		cutoff := time.Now().Add(-m.config.ScoreExpiry)

		for gameID, scores := range m.scores {
			var validScores []*GameScore
			for _, score := range scores {
				if score.Date.After(cutoff) {
					validScores = append(validScores, score)
				}
			}
			m.scores[gameID] = validScores
		}

		m.mutex.Unlock()
	}
}

// generateGameID generates a unique game ID
func (m *GameManager) generateGameID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// generateBotID generates a unique bot ID
func (m *GameManager) generateBotID() int64 {
	return time.Now().UnixNano()
}

// generateScoreID generates a unique score ID
func (m *GameManager) generateScoreID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// DefaultGameConfig returns default game configuration
func DefaultGameConfig() *GameConfig {
	return &GameConfig{
		MaxGamesPerUser:           1000,
		MaxScorePerGame:           999999999,
		ScoreExpiry:               365 * 24 * time.Hour, // 1 year
		LeaderboardSize:           100,
		LeaderboardUpdateInterval: 1 * time.Hour,
		EnableStatistics:          true,
		StatisticsRetention:       2 * 365 * 24 * time.Hour, // 2 years
		EnableAntiCheat:           true,
		ScoreValidation:           true,
		RateLimiting:              true,
	}
}
