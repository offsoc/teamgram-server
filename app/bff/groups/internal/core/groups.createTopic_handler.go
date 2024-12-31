package core

import (
	"context"
	"errors"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// GroupsCreateTopic
// groups.createTopic#d9d75a4 flags:# chat_id:int title:string = Updates;
func (c *GroupsCore) GroupsCreateTopic(ctx context.Context, in *mtproto.TLGroupsCreateTopic) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to create topics
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to create topics")
		c.Logger.Errorf("user does not have permission to create topics: %v", err)
		return nil, err
	}

	// Create topic
	topic, err := c.svcCtx.ChatClient.ChatCreateTopic(ctx, &chat.TLChatCreateTopic{
		ChatId: in.ChatId,
		Title:  in.Title,
	})
	if err != nil {
		c.Logger.Errorf("failed to create topic: %v", err)
		return nil, err
	}

	// Create updates
	updates := mtproto.MakeTLUpdates(&mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{topic},
	}).To_Updates()

	return updates, nil
}

// GroupsJoinTopic
// groups.joinTopic#d9d75a4 flags:# chat_id:int topic_id:int = Updates;
func (c *GroupsCore) GroupsJoinTopic(ctx context.Context, in *mtproto.TLGroupsJoinTopic) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to join topics
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionMember) {
		err = errors.New("user does not have permission to join topics")
		c.Logger.Errorf("user does not have permission to join topics: %v", err)
		return nil, err
	}

	// Join topic
	err = c.svcCtx.ChatClient.ChatJoinTopic(ctx, &chat.TLChatJoinTopic{
		ChatId:  in.ChatId,
		TopicId: in.TopicId,
		UserId:  c.MD.UserId,
	})
	if err != nil {
		c.Logger.Errorf("failed to join topic: %v", err)
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
