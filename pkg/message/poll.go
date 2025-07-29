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
	"time"
)

// PollProcessor handles poll functionality
type PollProcessor struct {
	storage PollStorage
	config  *PollConfig
}

// PollConfig contains poll configuration
type PollConfig struct {
	MaxOptions           int           `json:"max_options"`            // 10
	MaxOptionLength      int           `json:"max_option_length"`      // 100 characters
	MaxQuestionLength    int           `json:"max_question_length"`    // 300 characters
	MaxExplanationLength int           `json:"max_explanation_length"` // 200 characters
	DefaultCloseDate     time.Duration `json:"default_close_date"`     // 24 hours
	MaxCloseDate         time.Duration `json:"max_close_date"`         // 7 days
	AllowAnonymous       bool          `json:"allow_anonymous"`
	AllowMultipleAnswers bool          `json:"allow_multiple_answers"`
}

// PollInfo represents poll information
type PollInfo struct {
	ID                    string           `json:"id"`
	Question              string           `json:"question"`
	Options               []*PollOption    `json:"options"`
	TotalVoterCount       int              `json:"total_voter_count"`
	IsClosed              bool             `json:"is_closed"`
	IsAnonymous           bool             `json:"is_anonymous"`
	Type                  string           `json:"type"` // "regular" or "quiz"
	AllowsMultipleAnswers bool             `json:"allows_multiple_answers"`
	CorrectOptionID       int              `json:"correct_option_id,omitempty"` // for quiz
	Explanation           string           `json:"explanation,omitempty"`       // for quiz
	ExplanationEntities   []*MessageEntity `json:"explanation_entities,omitempty"`
	OpenPeriod            int              `json:"open_period,omitempty"` // in seconds
	CloseDate             *time.Time       `json:"close_date,omitempty"`
	CreatedAt             time.Time        `json:"created_at"`
	CreatedBy             int64            `json:"created_by"`
	ChatID                int64            `json:"chat_id"`
	MessageID             int              `json:"message_id"`
}

// PollOption represents a poll option
type PollOption struct {
	Text       string  `json:"text"`
	VoterCount int     `json:"voter_count"`
	Voters     []int64 `json:"voters,omitempty"` // only for non-anonymous polls
}

// PollAnswer represents a user's poll answer
type PollAnswer struct {
	PollID    string    `json:"poll_id"`
	UserID    int64     `json:"user_id"`
	OptionIDs []int     `json:"option_ids"`
	Timestamp time.Time `json:"timestamp"`
}

// PollVote represents a vote event
type PollVote struct {
	PollID    string    `json:"poll_id"`
	UserID    int64     `json:"user_id"`
	OptionIDs []int     `json:"option_ids"`
	Retracted bool      `json:"retracted"`
	Timestamp time.Time `json:"timestamp"`
}

// PollResult represents poll results
type PollResult struct {
	Poll           *PollInfo       `json:"poll"`
	Results        []*OptionResult `json:"results"`
	TotalVotes     int             `json:"total_votes"`
	VoterCount     int             `json:"voter_count"`
	IsComplete     bool            `json:"is_complete"`
	WinnerOptionID int             `json:"winner_option_id,omitempty"`
}

// OptionResult represents results for a poll option
type OptionResult struct {
	OptionID   int     `json:"option_id"`
	Text       string  `json:"text"`
	VoteCount  int     `json:"vote_count"`
	Percentage float64 `json:"percentage"`
	IsCorrect  bool    `json:"is_correct,omitempty"` // for quiz
	IsWinner   bool    `json:"is_winner,omitempty"`
}

// NewPollProcessor creates a new poll processor
func NewPollProcessor(storage PollStorage, config *PollConfig) *PollProcessor {
	return &PollProcessor{
		storage: storage,
		config:  config,
	}
}

// CreatePoll creates a new poll
func (pp *PollProcessor) CreatePoll(ctx context.Context, poll *PollInfo) (*PollInfo, error) {
	// Validate poll
	if err := pp.validatePoll(poll); err != nil {
		return nil, fmt.Errorf("poll validation failed: %w", err)
	}

	// Set defaults
	if poll.ID == "" {
		poll.ID = generatePollID()
	}

	if poll.CreatedAt.IsZero() {
		poll.CreatedAt = time.Now()
	}

	// Set close date if open period is specified
	if poll.OpenPeriod > 0 {
		closeDate := poll.CreatedAt.Add(time.Duration(poll.OpenPeriod) * time.Second)
		poll.CloseDate = &closeDate
	}

	// Initialize options
	for i := range poll.Options {
		if poll.Options[i] == nil {
			poll.Options[i] = &PollOption{}
		}
		poll.Options[i].VoterCount = 0
		if !poll.IsAnonymous {
			poll.Options[i].Voters = make([]int64, 0)
		}
	}

	// Save poll
	if err := pp.storage.SavePoll(ctx, poll); err != nil {
		return nil, fmt.Errorf("failed to save poll: %w", err)
	}

	return poll, nil
}

// VotePoll processes a poll vote
func (pp *PollProcessor) VotePoll(ctx context.Context, pollID string, userID int64, optionIDs []int) (*PollResult, error) {
	// Get poll
	poll, err := pp.storage.GetPoll(ctx, pollID)
	if err != nil {
		return nil, fmt.Errorf("failed to get poll: %w", err)
	}

	// Validate vote
	if err := pp.validateVote(poll, optionIDs); err != nil {
		return nil, fmt.Errorf("vote validation failed: %w", err)
	}

	// Get existing vote
	existingVote, err := pp.storage.GetUserVote(ctx, pollID, userID)
	if err != nil && err.Error() != "vote not found" {
		return nil, fmt.Errorf("failed to get existing vote: %w", err)
	}

	// Process vote change
	if existingVote != nil {
		// Remove old votes
		for _, oldOptionID := range existingVote.OptionIDs {
			if oldOptionID < len(poll.Options) {
				poll.Options[oldOptionID].VoterCount--
				if !poll.IsAnonymous {
					poll.Options[oldOptionID].Voters = removeUserFromVoters(poll.Options[oldOptionID].Voters, userID)
				}
			}
		}
	}

	// Add new votes
	for _, optionID := range optionIDs {
		if optionID < len(poll.Options) {
			poll.Options[optionID].VoterCount++
			if !poll.IsAnonymous {
				poll.Options[optionID].Voters = append(poll.Options[optionID].Voters, userID)
			}
		}
	}

	// Update total voter count
	pp.updateTotalVoterCount(poll)

	// Save vote
	vote := &PollAnswer{
		PollID:    pollID,
		UserID:    userID,
		OptionIDs: optionIDs,
		Timestamp: time.Now(),
	}

	if err := pp.storage.SaveVote(ctx, vote); err != nil {
		return nil, fmt.Errorf("failed to save vote: %w", err)
	}

	// Update poll
	if err := pp.storage.SavePoll(ctx, poll); err != nil {
		return nil, fmt.Errorf("failed to update poll: %w", err)
	}

	// Return results
	return pp.GetPollResults(ctx, pollID)
}

// ClosePoll closes a poll
func (pp *PollProcessor) ClosePoll(ctx context.Context, pollID string, userID int64) (*PollResult, error) {
	poll, err := pp.storage.GetPoll(ctx, pollID)
	if err != nil {
		return nil, fmt.Errorf("failed to get poll: %w", err)
	}

	// Check permissions (only creator can close)
	if poll.CreatedBy != userID {
		return nil, fmt.Errorf("only poll creator can close the poll")
	}

	if poll.IsClosed {
		return nil, fmt.Errorf("poll is already closed")
	}

	poll.IsClosed = true

	if err := pp.storage.SavePoll(ctx, poll); err != nil {
		return nil, fmt.Errorf("failed to close poll: %w", err)
	}

	return pp.GetPollResults(ctx, pollID)
}

// GetPollResults gets poll results
func (pp *PollProcessor) GetPollResults(ctx context.Context, pollID string) (*PollResult, error) {
	poll, err := pp.storage.GetPoll(ctx, pollID)
	if err != nil {
		return nil, fmt.Errorf("failed to get poll: %w", err)
	}

	// Calculate results
	totalVotes := 0
	for _, option := range poll.Options {
		totalVotes += option.VoterCount
	}

	results := make([]*OptionResult, len(poll.Options))
	winnerOptionID := -1
	maxVotes := 0

	for i, option := range poll.Options {
		percentage := 0.0
		if totalVotes > 0 {
			percentage = float64(option.VoterCount) / float64(totalVotes) * 100
		}

		isCorrect := false
		if poll.Type == "quiz" && poll.CorrectOptionID == i {
			isCorrect = true
		}

		if option.VoterCount > maxVotes {
			maxVotes = option.VoterCount
			winnerOptionID = i
		}

		results[i] = &OptionResult{
			OptionID:   i,
			Text:       option.Text,
			VoteCount:  option.VoterCount,
			Percentage: percentage,
			IsCorrect:  isCorrect,
		}
	}

	// Mark winner
	if winnerOptionID >= 0 {
		results[winnerOptionID].IsWinner = true
	}

	return &PollResult{
		Poll:           poll,
		Results:        results,
		TotalVotes:     totalVotes,
		VoterCount:     poll.TotalVoterCount,
		IsComplete:     poll.IsClosed,
		WinnerOptionID: winnerOptionID,
	}, nil
}

// GetPoll gets a poll by ID
func (pp *PollProcessor) GetPoll(ctx context.Context, pollID string) (*PollInfo, error) {
	return pp.storage.GetPoll(ctx, pollID)
}

// validatePoll validates poll data
func (pp *PollProcessor) validatePoll(poll *PollInfo) error {
	if poll.Question == "" {
		return fmt.Errorf("poll question cannot be empty")
	}

	if len(poll.Question) > pp.config.MaxQuestionLength {
		return fmt.Errorf("poll question exceeds maximum length %d", pp.config.MaxQuestionLength)
	}

	if len(poll.Options) < 2 {
		return fmt.Errorf("poll must have at least 2 options")
	}

	if len(poll.Options) > pp.config.MaxOptions {
		return fmt.Errorf("poll cannot have more than %d options", pp.config.MaxOptions)
	}

	for i, option := range poll.Options {
		if option.Text == "" {
			return fmt.Errorf("option %d text cannot be empty", i)
		}

		if len(option.Text) > pp.config.MaxOptionLength {
			return fmt.Errorf("option %d text exceeds maximum length %d", i, pp.config.MaxOptionLength)
		}
	}

	if poll.Type == "quiz" {
		if poll.CorrectOptionID < 0 || poll.CorrectOptionID >= len(poll.Options) {
			return fmt.Errorf("invalid correct option ID for quiz")
		}

		if poll.Explanation != "" && len(poll.Explanation) > pp.config.MaxExplanationLength {
			return fmt.Errorf("quiz explanation exceeds maximum length %d", pp.config.MaxExplanationLength)
		}
	}

	if poll.OpenPeriod > 0 {
		maxSeconds := int(pp.config.MaxCloseDate.Seconds())
		if poll.OpenPeriod > maxSeconds {
			return fmt.Errorf("open period %d exceeds maximum %d seconds", poll.OpenPeriod, maxSeconds)
		}
	}

	return nil
}

// validateVote validates a poll vote
func (pp *PollProcessor) validateVote(poll *PollInfo, optionIDs []int) error {
	if poll.IsClosed {
		return fmt.Errorf("poll is closed")
	}

	if poll.CloseDate != nil && time.Now().After(*poll.CloseDate) {
		return fmt.Errorf("poll voting period has ended")
	}

	if len(optionIDs) == 0 {
		return fmt.Errorf("no options selected")
	}

	if !poll.AllowsMultipleAnswers && len(optionIDs) > 1 {
		return fmt.Errorf("multiple answers not allowed for this poll")
	}

	for _, optionID := range optionIDs {
		if optionID < 0 || optionID >= len(poll.Options) {
			return fmt.Errorf("invalid option ID: %d", optionID)
		}
	}

	// Check for duplicate option IDs
	seen := make(map[int]bool)
	for _, optionID := range optionIDs {
		if seen[optionID] {
			return fmt.Errorf("duplicate option ID: %d", optionID)
		}
		seen[optionID] = true
	}

	return nil
}

// updateTotalVoterCount updates the total voter count
func (pp *PollProcessor) updateTotalVoterCount(poll *PollInfo) {
	if poll.IsAnonymous {
		// For anonymous polls, we can't track unique voters accurately
		// This is a simplified approach
		maxVotes := 0
		for _, option := range poll.Options {
			if option.VoterCount > maxVotes {
				maxVotes = option.VoterCount
			}
		}
		poll.TotalVoterCount = maxVotes
	} else {
		// For non-anonymous polls, count unique voters
		voters := make(map[int64]bool)
		for _, option := range poll.Options {
			for _, voterID := range option.Voters {
				voters[voterID] = true
			}
		}
		poll.TotalVoterCount = len(voters)
	}
}

// removeUserFromVoters removes a user from voters list
func removeUserFromVoters(voters []int64, userID int64) []int64 {
	for i, voter := range voters {
		if voter == userID {
			return append(voters[:i], voters[i+1:]...)
		}
	}
	return voters
}

// generatePollID generates a unique poll ID
func generatePollID() string {
	return fmt.Sprintf("poll_%d", time.Now().UnixNano())
}

// PollStorage interface for poll storage operations
type PollStorage interface {
	SavePoll(ctx context.Context, poll *PollInfo) error
	GetPoll(ctx context.Context, pollID string) (*PollInfo, error)
	SaveVote(ctx context.Context, vote *PollAnswer) error
	GetUserVote(ctx context.Context, pollID string, userID int64) (*PollAnswer, error)
	GetPollVotes(ctx context.Context, pollID string) ([]*PollAnswer, error)
}
