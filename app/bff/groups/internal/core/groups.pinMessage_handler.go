package core

import (
	"context"
	"errors"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// GroupsPinMessage
// groups.pinMessage#d9d75a4 flags:# chat_id:int message_id:int = Updates;
func (c *GroupsCore) GroupsPinMessage(ctx context.Context, in *mtproto.TLGroupsPinMessage) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to pin messages
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to pin messages")
		c.Logger.Errorf("user does not have permission to pin messages: %v", err)
		return nil, err
	}

	// Pin message
	err = c.svcCtx.ChatClient.ChatPinMessage(ctx, &chat.TLChatPinMessage{
		ChatId:    in.ChatId,
		MessageId: in.MessageId,
	})
	if err != nil {
		c.Logger.Errorf("failed to pin message: %v", err)
		return nil, err
	}

	// Create updates
	updates := mtproto.MakeTLUpdates(&mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}).To_Updates()

	return updates, nil
}

// GroupsArrangePinnedMessages
// groups.arrangePinnedMessages#d9d75a4 flags:# chat_id:int message_ids:Vector<int> = Updates;
func (c *GroupsCore) GroupsArrangePinnedMessages(ctx context.Context, in *mtproto.TLGroupsArrangePinnedMessages) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to arrange pinned messages
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to arrange pinned messages")
		c.Logger.Errorf("user does not have permission to arrange pinned messages: %v", err)
		return nil, err
	}

	// Arrange pinned messages
	err = c.svcCtx.ChatClient.ChatArrangePinnedMessages(ctx, &chat.TLChatArrangePinnedMessages{
		ChatId:     in.ChatId,
		MessageIds: in.MessageIds,
	})
	if err != nil {
		c.Logger.Errorf("failed to arrange pinned messages: %v", err)
		return nil, err
	}

	// Create updates
	updates := mtproto.MakeTLUpdates(&mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{},
	}).To_Updates()

	return updates, nil
}
