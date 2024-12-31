package core

import (
	"context"
	"errors"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// GroupsCreateGroup
// groups.createGroup#d9d75a4 flags:# title:string members:Vector<InputUser> = Updates;
func (c *GroupsCore) GroupsCreateGroup(ctx context.Context, in *mtproto.TLGroupsCreateGroup) (*mtproto.Updates, error) {
	var (
		err error
	)

	if len(in.Members) > 200 {
		err = errors.New("group member limit exceeded")
		c.Logger.Errorf("group member limit exceeded: %v", err)
		return nil, err
	}

	// Create group
	group, err := c.svcCtx.ChatClient.ChatCreateGroup(ctx, &chat.TLChatCreateGroup{
		Title:   in.Title,
		Members: in.Members,
	})
	if err != nil {
		c.Logger.Errorf("failed to create group: %v", err)
		return nil, err
	}

	// Create updates
	updates := mtproto.MakeTLUpdates(&mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{group},
	}).To_Updates()

	return updates, nil
}

// GroupsCreateSuperGroup
// groups.createSuperGroup#d9d75a4 flags:# title:string members:Vector<InputUser> = Updates;
func (c *GroupsCore) GroupsCreateSuperGroup(ctx context.Context, in *mtproto.TLGroupsCreateSuperGroup) (*mtproto.Updates, error) {
	var (
		err error
	)

	if len(in.Members) > 200000 {
		err = errors.New("supergroup member limit exceeded")
		c.Logger.Errorf("supergroup member limit exceeded: %v", err)
		return nil, err
	}

	// Create supergroup
	superGroup, err := c.svcCtx.ChatClient.ChatCreateSuperGroup(ctx, &chat.TLChatCreateSuperGroup{
		Title:   in.Title,
		Members: in.Members,
	})
	if err != nil {
		c.Logger.Errorf("failed to create supergroup: %v", err)
		return nil, err
	}

	// Create updates
	updates := mtproto.MakeTLUpdates(&mtproto.Updates{
		Updates: []*mtproto.Update{},
		Users:   []*mtproto.User{},
		Chats:   []*mtproto.Chat{superGroup},
	}).To_Updates()

	return updates, nil
}
