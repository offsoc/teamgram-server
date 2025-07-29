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

package mysql

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Config represents MySQL configuration
type Config struct {
	DSN          string        `json:"dsn"`
	MaxOpenConns int           `json:"max_open_conns"`
	MaxIdleConns int           `json:"max_idle_conns"`
	MaxLifetime  time.Duration `json:"max_lifetime"`
}

// Client represents a MySQL client
type Client struct {
	db     *sql.DB
	config *Config
}

// NewClient creates a new MySQL client
func NewClient(config *Config) (*Client, error) {
	db, err := sql.Open("mysql", config.DSN)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.MaxLifetime)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Client{
		db:     db,
		config: config,
	}, nil
}

// GetDB returns the database connection
func (c *Client) GetDB() *sql.DB {
	return c.db
}

// Close closes the database connection
func (c *Client) Close() error {
	return c.db.Close()
}
