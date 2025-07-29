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

package calls

import (
	"context"
	"fmt"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/rpc/metadata"
	"github.com/teamgram/teamgram-server/pkg/calls"
	"github.com/zeromicro/go-zero/core/logx"
)

// CallsHandler handles call operations
type CallsHandler struct {
	ctx    context.Context
	svcCtx *ServiceContext
	logx.Logger
	MD *metadata.RpcMetadata
}

// ServiceContext represents service context
type ServiceContext struct {
	CallManager *calls.CallManager
}

// NewCallsHandler creates a new calls handler
func NewCallsHandler(ctx context.Context, svcCtx *ServiceContext) *CallsHandler {
	return &CallsHandler{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
		MD:     metadata.RpcMetadataFromIncoming(ctx),
	}
}

// RequestCall requests a call
func (h *CallsHandler) RequestCall(ctx context.Context, request *mtproto.TLPhoneRequestCall) (*mtproto.Phone_PhoneCall, error) {
	return &mtproto.Phone_PhoneCall{
		PhoneCall: &mtproto.PhoneCall{},
		Users:     []*mtproto.User{},
	}, nil
}

// AcceptCall accepts a call
func (h *CallsHandler) AcceptCall(ctx context.Context, request *mtproto.TLPhoneAcceptCall) (*mtproto.Phone_PhoneCall, error) {
	return &mtproto.Phone_PhoneCall{
		PhoneCall: &mtproto.PhoneCall{},
		Users:     []*mtproto.User{},
	}, nil
}

// ConfirmCall confirms a call
func (h *CallsHandler) ConfirmCall(ctx context.Context, request *mtproto.TLPhoneConfirmCall) (*mtproto.Phone_PhoneCall, error) {
	return &mtproto.Phone_PhoneCall{
		PhoneCall: &mtproto.PhoneCall{},
		Users:     []*mtproto.User{},
	}, nil
}

// DiscardCall discards a call
func (h *CallsHandler) DiscardCall(ctx context.Context, request *mtproto.TLPhoneDiscardCall) (*mtproto.Updates, error) {
	return &mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}, nil
}

// CreateGroupCall creates a group call
func (h *CallsHandler) CreateGroupCall(ctx context.Context, request *mtproto.TLPhoneCreateGroupCall) (*mtproto.Updates, error) {
	return &mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}, nil
}

// JoinGroupCall joins a group call
func (h *CallsHandler) JoinGroupCall(ctx context.Context, request *mtproto.TLPhoneJoinGroupCall) (*mtproto.Updates, error) {
	return &mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}, nil
}

// LeaveGroupCall leaves a group call
func (h *CallsHandler) LeaveGroupCall(ctx context.Context, request *mtproto.TLPhoneLeaveGroupCall) (*mtproto.Updates, error) {
	return &mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}, nil
}

// ToggleGroupCallSettings toggles group call settings
func (h *CallsHandler) ToggleGroupCallSettings(ctx context.Context, request *mtproto.TLPhoneToggleGroupCallSettings) (*mtproto.Updates, error) {
	return &mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}, nil
}

// Helper methods

func (h *CallsHandler) validateRequestCall(request *mtproto.TLPhoneRequestCall) error {
	if request == nil {
		return fmt.Errorf("request is nil")
	}

	if request.UserId == nil {
		return fmt.Errorf("invalid user ID")
	}

	return nil
}

func (h *CallsHandler) validateAcceptCall(request *mtproto.TLPhoneAcceptCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Peer == nil {
		return fmt.Errorf("peer is required")
	}

	if request.GB == nil || len(request.GB) == 0 {
		return fmt.Errorf("GB is required")
	}

	if request.Protocol == nil {
		return fmt.Errorf("protocol is required")
	}

	return nil
}

func (h *CallsHandler) validateConfirmCall(request *mtproto.TLPhoneConfirmCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Peer == nil {
		return fmt.Errorf("peer is required")
	}

	if request.GA == nil || len(request.GA) == 0 {
		return fmt.Errorf("GA is required")
	}

	if request.KeyFingerprint <= 0 {
		return fmt.Errorf("invalid key fingerprint")
	}

	if request.Protocol == nil {
		return fmt.Errorf("protocol is required")
	}

	return nil
}

func (h *CallsHandler) validateDiscardCall(request *mtproto.TLPhoneDiscardCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Peer == nil {
		return fmt.Errorf("peer is required")
	}

	return nil
}

func (h *CallsHandler) validateCreateGroupCall(request *mtproto.TLPhoneCreateGroupCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Peer == nil {
		return fmt.Errorf("peer is required")
	}

	if request.RandomId <= 0 {
		return fmt.Errorf("invalid random ID")
	}

	return nil
}

func (h *CallsHandler) validateJoinGroupCall(request *mtproto.TLPhoneJoinGroupCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Call == nil {
		return fmt.Errorf("call is required")
	}

	if request.Params == nil {
		return fmt.Errorf("params is required")
	}

	return nil
}

func (h *CallsHandler) validateLeaveGroupCall(request *mtproto.TLPhoneLeaveGroupCall) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Call == nil {
		return fmt.Errorf("call is required")
	}

	return nil
}

func (h *CallsHandler) validateToggleGroupCallSettings(request *mtproto.TLPhoneToggleGroupCallSettings) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}

	if request.Call == nil {
		return fmt.Errorf("call is required")
	}

	return nil
}

func (h *CallsHandler) convertCallToPhoneCall(call *calls.Call) *mtproto.PhoneCall {
	return &mtproto.PhoneCall{
		Id:             call.ID,
		AccessHash:     call.AccessHash,
		Date:           int32(call.Date),
		AdminId:        call.AdminID,
		ParticipantId:  call.ParticipantID,
		GAOrB:          call.GAOrB,
		KeyFingerprint: call.KeyFingerprint,
		Protocol:       h.convertCallProtocol(call.Protocol),
		Connections:    h.convertCallConnections(call.Connections),
		StartDate:      int32(call.StartDate),
	}
}

func (h *CallsHandler) convertCallToGroupCall(call *calls.Call) *mtproto.GroupCall {
	return &mtproto.GroupCall{}
}

func (h *CallsHandler) convertCallProtocol(protocol *calls.CallProtocol) *mtproto.PhoneCallProtocol {
	return &mtproto.PhoneCallProtocol{
		MinLayer:        0,
		MaxLayer:        0,
		UdpP2P:          false,
		UdpReflector:    false,
		LibraryVersions: []string{},
	}
}

func (h *CallsHandler) convertCallConnections(connections []*calls.CallConnection) []*mtproto.PhoneConnection {
	result := make([]*mtproto.PhoneConnection, 0, len(connections))
	for _, conn := range connections {
		result = append(result, &mtproto.PhoneConnection{
			Ip:      conn.IP,
			Port:    0,
			PeerTag: conn.PeerTag,
		})
	}
	return result
}

func (h *CallsHandler) convertParticipants(participants []*calls.CallParticipant) []*mtproto.GroupCallParticipant {
	result := make([]*mtproto.GroupCallParticipant, 0, len(participants))
	for range participants {
		result = append(result, &mtproto.GroupCallParticipant{})
	}
	return result
}

func (h *CallsHandler) convertParticipantVideo(video *calls.CallParticipantVideo) *mtproto.GroupCallParticipantVideo {
	return &mtproto.GroupCallParticipantVideo{}
}

func (h *CallsHandler) calculatePFlags(call *calls.Call) int32 {
	var flags int32

	if call.IsOutgoing {
		flags |= 1 << 0
	}

	if call.IsVideo {
		flags |= 1 << 1
	}

	if call.IsGroup {
		flags |= 1 << 2
	}

	if call.IsScreenShare {
		flags |= 1 << 3
	}

	if call.IsRecording {
		flags |= 1 << 4
	}

	return flags
}
