package core

import (
	"context"
	"errors"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// GroupsCreateInviteLink
// groups.createInviteLink#d9d75a4 flags:# chat_id:int expire_date:flags.0?int usage_limit:flags.1?int = ExportedChatInvite;
func (c *GroupsCore) GroupsCreateInviteLink(ctx context.Context, in *mtproto.TLGroupsCreateInviteLink) (*mtproto.ExportedChatInvite, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to create invite links
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to create invite links")
		c.Logger.Errorf("user does not have permission to create invite links: %v", err)
		return nil, err
	}

	// Create invite link
	inviteLink, err := c.svcCtx.ChatClient.ChatCreateInviteLink(ctx, &chat.TLChatCreateInviteLink{
		ChatId:     in.ChatId,
		ExpireDate: in.ExpireDate,
		UsageLimit: in.UsageLimit,
	})
	if err != nil {
		c.Logger.Errorf("failed to create invite link: %v", err)
		return nil, err
	}

	return inviteLink, nil
}

// GroupsCreateQRCode
// groups.createQRCode#d9d75a4 flags:# chat_id:int expire_date:flags.0?int usage_limit:flags.1?int = ExportedChatInvite;
func (c *GroupsCore) GroupsCreateQRCode(ctx context.Context, in *mtproto.TLGroupsCreateQRCode) (*mtproto.ExportedChatInvite, error) {
	var (
		err error
	)

	// Check if the user has the necessary permissions to create QR codes
	if !c.svcCtx.ChatClient.HasPermission(ctx, in.ChatId, c.MD.UserId, chat.PermissionAdmin) {
		err = errors.New("user does not have permission to create QR codes")
		c.Logger.Errorf("user does not have permission to create QR codes: %v", err)
		return nil, err
	}

	// Create QR code
	qrCode, err := c.svcCtx.ChatClient.ChatCreateQRCode(ctx, &chat.TLChatCreateQRCode{
		ChatId:     in.ChatId,
		ExpireDate: in.ExpireDate,
		UsageLimit: in.UsageLimit,
	})
	if err != nil {
		c.Logger.Errorf("failed to create QR code: %v", err)
		return nil, err
	}

	return qrCode, nil
}
