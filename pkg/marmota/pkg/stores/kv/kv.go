// Copyright 2022 Teamgram Authors
//  All rights reserved.
//
// Author: Benqi (wubenqi@gmail.com)
//

package kv

import (
	"context"

	"github.com/zeromicro/go-zero/core/stores/kv"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

// Pipeline interface for Redis pipeline operations
type Pipeline interface {
	Exec(ctx context.Context) ([]interface{}, error)
	Discard() error
	Close() error
}

// Pipeliner interface for creating pipelines
type Pipeliner interface {
	Pipeline() Pipeline
	TxPipeline() Pipeline
}

// MapStringStringCmd for Redis HGETALL compatibility
type MapStringStringCmd struct {
	val map[string]string
	err error
}

func (cmd *MapStringStringCmd) Result() (map[string]string, error) {
	return cmd.val, cmd.err
}

func (cmd *MapStringStringCmd) Val() map[string]string {
	return cmd.val
}

func (cmd *MapStringStringCmd) Err() error {
	return cmd.err
}

type (
	KvConf = kv.KvConf
	Store  = kv.Store

	// IntCmd is an alias of redis.IntCmd.
	IntCmd = redis.IntCmd
	// FloatCmd is an alias of redis.FloatCmd.
	FloatCmd = redis.FloatCmd
	// StringCmd is an alias of redis.StringCmd.
	StringCmd = redis.StringCmd
)

var (
	ErrNoRedisNode = kv.ErrNoRedisNode
	NewStore       = kv.NewStore
)
