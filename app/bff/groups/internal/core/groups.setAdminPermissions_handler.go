package core

import (
	"context"
	"errors"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// GroupsSetAdminPermissions
// groups.setAdminPermissions#d9d75a4 flags:# chat_id:int user_id:InputUser admin_rights:ChatAdminRights = Updates;
func (c *GroupsCore) GroupsSetAdminPermissions(ctx context.Context, in *mtproto.TLGroupsSetAdminPermissions) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to set admin roles
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to set admin roles")
		c.Logger.Errorf("user does not have permission to set admin roles: %v", err)
		return nil, err
	}

	// Set admin roles
	err = c.svcCtx.ChatClient.SetAdminRoles(ctx, in.ChatId, in.UserId, in.AdminRights)
	if err != nil {
		c.Logger.Errorf("failed to set admin roles: %v", err)
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

// GroupsDisableFeatures
// groups.disableFeatures#d9d75a4 flags:# chat_id:int features:Vector<string> = Updates;
func (c *GroupsCore) GroupsDisableFeatures(ctx context.Context, in *mtproto.TLGroupsDisableFeatures) (*mtproto.Updates, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to disable features
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to disable features")
		c.Logger.Errorf("user does not have permission to disable features: %v", err)
		return nil, err
	}

	// Disable specific features
	err = c.svcCtx.ChatClient.DisableFeatures(ctx, in.ChatId, in.Features)
	if err != nil {
		c.Logger.Errorf("failed to disable features: %v", err)
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
