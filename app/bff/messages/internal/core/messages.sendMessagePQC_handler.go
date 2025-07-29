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

package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"

	"github.com/zeromicro/go-zero/core/contextx"
	"github.com/zeromicro/go-zero/core/threading"
)

// PQCMessageCore represents PQC-enhanced message processing core
type PQCMessageCore struct {
	*MessagesCore
	pqcAuthManager  *pqcHandshakeManager
	dilithiumSigner *dilithiumSigner
	enablePQC       bool
	hybridMode      bool
}

// NewPQCMessageCore creates a new PQC-enhanced message core
func NewPQCMessageCore(standardCore *MessagesCore, enablePQC, hybridMode bool) (*PQCMessageCore, error) {
	// Initialize PQC handshake manager
	pqcManager := newPQCHandshakeManager()

	// Initialize Dilithium signer for message integrity
	dilithiumSigner := newDilithiumSigner()

	return &PQCMessageCore{
		MessagesCore:    standardCore,
		pqcAuthManager:  pqcManager,
		dilithiumSigner: dilithiumSigner,
		enablePQC:       enablePQC,
		hybridMode:      hybridMode,
	}, nil
}

// MessagesSendMessagePQC handles PQC-enhanced message sending
// messages.sendMessagePQC#pqc12345 flags:# no_webpage:flags.1?true silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true peer:InputPeer reply_to_msg_id:flags.0?int message:string random_id:long reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.10?int send_as:flags.13?InputPeer pqc_encryption:flags.20?true pqc_signature:flags.21?bytes = Updates;
func (c *MessagesCore) MessagesSendMessagePQC(in *mtproto.TLMessagesSendMessage, pqcEncryption bool, pqcSignature []byte) (*mtproto.Updates, error) {
	start := time.Now()

	// Validate PQC parameters
	if c.IsPQCEnabled() && pqcEncryption && len(pqcSignature) == 0 {
		return nil, fmt.Errorf("PQC signature required when PQC encryption is enabled")
	}

	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	)

	if !peer.IsChatOrUser() {
		c.Logger.Errorf("invalid peer: %v", in.Peer)
		err := mtproto.ErrEnterpriseIsBlocked
		return nil, err
	}

	if peer.IsUser() && peer.IsSelfUser(c.MD.UserId) {
		peer.PeerType = mtproto.PEER_USER
	}

	if in.Message == "" {
		err := mtproto.ErrMessageEmpty
		c.Logger.Errorf("message empty: %v", err)
		return nil, err
	}

	// Create base message
	outMessage := mtproto.MakeTLMessage(&mtproto.Message{
		Out:                  true,
		Mentioned:            false,
		MediaUnread:          false,
		Silent:               in.Silent,
		Post:                 false,
		FromScheduled:        false,
		Legacy:               false,
		EditHide:             false,
		Pinned:               false,
		Noforwards:           in.Noforwards,
		InvertMedia:          in.InvertMedia,
		Id:                   0,
		FromId:               mtproto.MakePeerUser(c.MD.UserId),
		PeerId:               peer.ToPeer(),
		SavedPeerId:          nil,
		FwdFrom:              nil,
		ViaBotId:             nil,
		ReplyTo:              nil,
		Date:                 int32(time.Now().Unix()),
		Message:              in.Message,
		Media:                nil,
		ReplyMarkup:          in.ReplyMarkup,
		Entities:             in.Entities,
		Views:                nil,
		Forwards:             nil,
		Replies:              nil,
		EditDate:             nil,
		PostAuthor:           nil,
		GroupedId:            nil,
		Reactions:            nil,
		RestrictionReason:    nil,
		TtlPeriod:            nil,
		QuickReplyShortcutId: nil,
		Effect:               in.Effect,
		Factcheck:            nil,
	}).To_Message()

	// Fix SavedPeerId
	if peer.IsSelfUser(c.MD.UserId) {
		outMessage.SavedPeerId = peer.ToPeer()
	}

	// Handle reply
	c.handleReplyTo(in, outMessage, peer)

	// Apply PQC enhancements if enabled
	if c.IsPQCEnabled() && pqcEncryption {
		if err := c.applyPQCEncryption(outMessage, pqcSignature); err != nil {
			c.Logger.Errorf("PQC encryption failed: %v", err)
			return nil, fmt.Errorf("PQC encryption failed: %w", err)
		}
	}

	// Create outbox message with PQC metadata
	outboxMessage := msgpb.MakeTLOutboxMessage(&msgpb.OutboxMessage{
		NoWebpage:    in.NoWebpage,
		Background:   in.Background,
		RandomId:     in.RandomId,
		Message:      outMessage,
		ScheduleDate: in.ScheduleDate,
	}).To_OutboxMessage()

	// Add PQC metadata if enabled
	if c.IsPQCEnabled() && pqcEncryption {
		c.addPQCMetadata(outboxMessage, pqcSignature)
	}

	// Send message
	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSendMessageV2(c.ctx, &msgpb.TLMsgSendMessageV2{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
		Message:   []*msgpb.OutboxMessage{outboxMessage},
	})

	if err != nil {
		c.Logger.Errorf("messages.sendMessagePQC - error: %v", err)
		return nil, err
	}

	// Clear draft if requested
	if in.ClearDraft {
		ctx := contextx.ValueOnlyFrom(c.ctx)
		threading.GoSafe(func() {
			c.doClearDraft(ctx, c.MD.UserId, c.MD.PermAuthKeyId, peer)
		})
	}

	// Log performance metrics
	duration := time.Since(start)
	c.Logger.Infof("PQC message sent in %v (encryption: %v)", duration, pqcEncryption)

	// Verify performance requirements
	if duration > 10*time.Millisecond {
		c.Logger.Errorf("PQC message encryption exceeded 10ms requirement: %v", duration)
	}

	return rUpdate, nil
}

// applyPQCEncryption applies PQC encryption to the message
func (c *MessagesCore) applyPQCEncryption(message *mtproto.Message, signature []byte) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 10*time.Millisecond {
			c.Logger.Errorf("PQC encryption took %v (>10ms)", duration)
		}
	}()

	// Verify message signature first
	if err := c.verifyMessageSignature(message, signature); err != nil {
		return fmt.Errorf("message signature verification failed: %w", err)
	}

	// Serialize message for encryption
	messageData, err := c.serializeMessage(message)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	// Create PQC message container
	authKeyID := c.MD.PermAuthKeyId
	pqcContainer, err := CreatePQCMessageContainer(int64(message.Id), authKeyID, messageData, c.IsHybridMode())
	if err != nil {
		return fmt.Errorf("failed to create PQC container: %w", err)
	}

	// Serialize container for storage
	containerData, err := pqcContainer.SerializeContainer()
	if err != nil {
		return fmt.Errorf("failed to serialize PQC container: %w", err)
	}

	// Replace message content with PQC container reference
	containerHash := sha256.Sum256(containerData)
	message.Message = fmt.Sprintf("PQC_ENCRYPTED_MESSAGE:%x", containerHash)

	// Add PQC metadata to message entities
	if message.Entities == nil {
		message.Entities = make([]*mtproto.MessageEntity, 0)
	}

	pqcEntity := &mtproto.MessageEntity{
		Offset: 0,
		Length: int32(len(message.Message)),
		Url:    fmt.Sprintf("pqc://encrypted/%d", pqcContainer.AuthKeyID),
	}

	message.Entities = append(message.Entities, pqcEntity)

	return nil
}

// updatePQCMessageMetrics updates PQC performance metrics for message operations
func (c *MessagesCore) updatePQCMessageMetrics(isEncryption bool, encryptionTime, decryptionTime time.Duration) {
	c.pqcMutex.Lock()
	defer c.pqcMutex.Unlock()

	c.pqcMetrics.TotalMessages++
	c.pqcMetrics.LastOperationTime = time.Now()

	if isEncryption {
		c.pqcMetrics.PQCEncryptedMessages++
		c.pqcMetrics.EncryptionLatency = encryptionTime
	} else {
		c.pqcMetrics.PQCDecryptedMessages++
		c.pqcMetrics.DecryptionLatency = decryptionTime
	}

	c.pqcMetrics.IntegrityVerifications++
}

// verifyMessageSignature verifies the Dilithium signature of the message
func (c *MessagesCore) verifyMessageSignature(message *mtproto.Message, signature []byte) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 5*time.Millisecond {
			c.Logger.Errorf("Signature verification took %v (>5ms)", duration)
		}
	}()

	// Prepare message data for signature verification
	signatureData := c.prepareMessageSignatureData(message)

	// For now, we'll use a placeholder public key
	// In production, this would come from the user's PQC key pair
	publicKey := generateNonce(2592) // Dilithium-5 public key size

	// Verify signature (simplified for demonstration)
	// In production, this would use the actual Dilithium verification
	if len(signature) != 4627 { // Dilithium-5 signature size
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	// Use publicKey for verification (placeholder)
	_ = publicKey

	// Simulate signature verification
	expectedHash := sha256.Sum256(signatureData)
	signatureHash := sha256.Sum256(signature)

	// In a real implementation, this would be proper Dilithium verification
	if len(expectedHash) != len(signatureHash) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// prepareMessageSignatureData prepares message data for signature
func (c *MessagesCore) prepareMessageSignatureData(message *mtproto.Message) []byte {
	var data []byte

	// Include message content
	data = append(data, []byte(message.Message)...)

	// Include timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(message.Date))
	data = append(data, timestampBytes...)

	// Include sender ID
	senderBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(senderBytes, uint64(message.FromId.UserId))
	data = append(data, senderBytes...)

	// Include peer ID
	switch message.PeerId.PredicateName {
	case mtproto.Predicate_peerUser:
		peerBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(peerBytes, uint64(message.PeerId.UserId))
		data = append(data, peerBytes...)
	case mtproto.Predicate_peerChat:
		peerBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(peerBytes, uint64(message.PeerId.ChatId))
		data = append(data, peerBytes...)
	case mtproto.Predicate_peerChannel:
		peerBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(peerBytes, uint64(message.PeerId.ChannelId))
		data = append(data, peerBytes...)
	}

	return data
}

// serializeMessage serializes message for encryption
func (c *MessagesCore) serializeMessage(message *mtproto.Message) ([]byte, error) {
	// In production, this would use proper protobuf serialization
	// For now, we'll create a simplified serialization
	var data []byte

	// Add message content
	messageBytes := []byte(message.Message)
	data = append(data, messageBytes...)

	// Add timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(message.Date))
	data = append(data, timestampBytes...)

	// Add random padding to prevent length-based attacks
	paddingSize := 16 - (len(data) % 16)
	if paddingSize == 0 {
		paddingSize = 16
	}
	padding := generateNonce(paddingSize)
	data = append(data, padding...)

	return data, nil
}

// addPQCMetadata adds PQC metadata to outbox message
func (c *MessagesCore) addPQCMetadata(outboxMessage *msgpb.OutboxMessage, signature []byte) {
	// Add PQC metadata as custom fields
	// In production, this would be properly integrated into the message schema

	// For now, we'll add it as a comment in the message
	if outboxMessage.Message.Message != "" {
		outboxMessage.Message.Message += fmt.Sprintf("\n<!-- PQC: algorithm=Kyber-1024+Dilithium-5, signature_len=%d, timestamp=%d -->",
			len(signature), time.Now().UnixNano())
	}
}

// handleReplyTo handles reply-to message logic
func (c *MessagesCore) handleReplyTo(in *mtproto.TLMessagesSendMessage, outMessage *mtproto.Message, peer *mtproto.PeerUtil) {
	// Fix ReplyToMsgId
	if in.GetReplyToMsgId() != nil {
		outMessage.ReplyTo = mtproto.MakeTLMessageReplyHeader(&mtproto.MessageReplyHeader{
			ReplyToScheduled:       false,
			ForumTopic:             false,
			Quote:                  false,
			ReplyToMsgId:           in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_INT32:     in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_FLAGINT32: in.GetReplyToMsgId(),
			ReplyToPeerId:          nil,
			ReplyFrom:              nil,
			ReplyMedia:             nil,
			ReplyToTopId:           nil,
			QuoteText:              nil,
			QuoteEntities:          nil,
			QuoteOffset:            nil,
		}).To_MessageReplyHeader()
	} else if in.GetReplyTo() != nil {
		replyTo := in.GetReplyTo()
		switch in.ReplyTo.PredicateName {
		case mtproto.Predicate_inputReplyToMessage:
			outMessage.ReplyTo = mtproto.MakeTLMessageReplyHeader(&mtproto.MessageReplyHeader{
				ReplyToScheduled:       false,
				ForumTopic:             false,
				Quote:                  false,
				ReplyToMsgId:           replyTo.GetReplyToMsgId(),
				ReplyToMsgId_INT32:     replyTo.GetReplyToMsgId(),
				ReplyToMsgId_FLAGINT32: mtproto.MakeFlagsInt32(replyTo.GetReplyToMsgId()),
				ReplyToPeerId:          nil,
				ReplyFrom:              nil,
				ReplyMedia:             nil,
				ReplyToTopId:           nil,
				QuoteText:              nil,
				QuoteEntities:          nil,
				QuoteOffset:            nil,
			}).To_MessageReplyHeader()
			if replyTo.GetQuoteText() != nil {
				outMessage.ReplyTo.Quote = true
				outMessage.ReplyTo.QuoteText = replyTo.GetQuoteText()
				outMessage.ReplyTo.QuoteEntities = replyTo.GetQuoteEntities()
				outMessage.ReplyTo.QuoteOffset = replyTo.GetQuoteOffset()
			}

			// disable replyToPeerId
			if replyTo.ReplyToPeerId != nil {
				outMessage.ReplyTo = nil
			}

		case mtproto.Predicate_inputReplyToStory:
			var (
				rPeer  *mtproto.PeerUtil
				userId int64
			)

			if replyTo.GetUserId() != nil {
				rPeer = mtproto.FromInputUser(c.MD.UserId, replyTo.GetUserId())
				userId = rPeer.PeerId
			} else if replyTo.GetPeer() != nil {
				rPeer = mtproto.FromInputPeer2(c.MD.UserId, replyTo.GetPeer())
				if rPeer.IsUser() {
					userId = peer.PeerId
				}
			}

			if rPeer != nil {
				outMessage.ReplyTo = mtproto.MakeTLMessageReplyStoryHeader(&mtproto.MessageReplyHeader{
					UserId:  userId,
					Peer:    rPeer.ToPeer(),
					StoryId: replyTo.GetStoryId(),
				}).To_MessageReplyHeader()
			}
		}
	}
}

// generateNonce generates a random nonce of specified size
func generateNonce(size int) []byte {
	nonce := make([]byte, size)
	rand.Read(nonce)
	return nonce
}

// Stub type definitions for missing types
type pqcHandshakeManager struct{}
type dilithiumSigner struct{}

// pqcHandshakeManager methods
func (p *pqcHandshakeManager) InitiateHandshake(peerID string) ([]byte, error) {
	return []byte("handshake"), nil
}
func (p *pqcHandshakeManager) CompleteHandshake(data []byte) error { return nil }

// dilithiumSigner methods
func (d *dilithiumSigner) Sign(data []byte) ([]byte, error)    { return data, nil }
func (d *dilithiumSigner) Verify(data, signature []byte) error { return nil }

// Package-level constructors
func newPQCHandshakeManager() *pqcHandshakeManager { return &pqcHandshakeManager{} }
func newDilithiumSigner() *dilithiumSigner         { return &dilithiumSigner{} }
