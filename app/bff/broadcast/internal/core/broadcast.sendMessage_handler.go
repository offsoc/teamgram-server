package core

import (
	"context"
	"errors"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// BroadcastSendMessage
// broadcast.sendMessage#d9d75a4 flags:# chat_id:int message:string = Updates;
func (c *BroadcastCore) BroadcastSendMessage(ctx context.Context, in *mtproto.TLBroadcastSendMessage) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to send broadcast messages
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to send broadcast messages")
		c.Logger.Errorf("user does not have permission to send broadcast messages: %v", err)
		return nil, err
	}

	// Create message
	outMessage := mtproto.MakeTLMessage(&mtproto.Message{
		Out:                  true,
		Mentioned:            false,
		MediaUnread:          false,
		Silent:               false,
		Post:                 false,
		FromScheduled:        false,
		Legacy:               false,
		EditHide:             false,
		Pinned:               false,
		Noforwards:           false,
		InvertMedia:          false,
		Id:                   0,
		FromId:               mtproto.MakePeerUser(c.MD.UserId),
		PeerId:               mtproto.MakePeerChat(in.ChatId),
		SavedPeerId:          nil,
		FwdFrom:              nil,
		ViaBotId:             nil,
		ReplyTo:              nil,
		Date:                 int32(time.Now().Unix()),
		Message:              in.Message,
		Media:                nil,
		ReplyMarkup:          nil,
		Entities:             nil,
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
		Effect:               nil,
		Factcheck:            nil,
	}).To_Message()

	// Send the message
	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSendMessageV2(ctx, &msgpb.TLMsgSendMessageV2{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  mtproto.PEER_CHAT,
		PeerId:    in.ChatId,
		Message: []*msgpb.OutboxMessage{
			msgpb.MakeTLOutboxMessage(&msgpb.OutboxMessage{
				NoWebpage:    true,
				Background:   false,
				RandomId:     0,
				Message:      outMessage,
				ScheduleDate: nil,
			}).To_OutboxMessage(),
		},
	})

	if err != nil {
		c.Logger.Errorf("broadcast.sendMessage - error: %v", err)
		return nil, err
	}

	return rUpdate, nil
}
