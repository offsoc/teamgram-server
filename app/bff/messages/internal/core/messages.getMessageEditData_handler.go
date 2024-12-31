package core

import (
	"github.com/teamgram/proto/mtproto"
	chatpb "github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
	"github.com/teamgram/teamgram-server/app/service/biz/message/message"
)

// MessagesGetMessageEditData
// messages.getMessageEditData#fda68d36 peer:InputPeer id:int = messages.MessageEditData;
func (c *MessagesCore) MessagesGetMessageEditData(in *mtproto.TLMessagesGetMessageEditData) (*mtproto.Messages_MessageEditData, error) {
	var (
		peer   = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
		boxMsg *mtproto.MessageBox
		err    error
	)

	if c.MD.IsBot {
		err = mtproto.ErrBotMethodInvalid
		c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
		return nil, err
	}

	switch peer.PeerType {
	case mtproto.PEER_SELF,
		mtproto.PEER_USER,
		mtproto.PEER_CHAT:
		boxMsg, err = c.svcCtx.Dao.MessageClient.MessageGetUserMessage(c.ctx, &message.TLMessageGetUserMessage{
			UserId: c.MD.UserId,
			Id:     in.Id,
		})
		if err != nil {
			c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
			return nil, err
		}

		if boxMsg.PeerType != mtproto.PEER_USER && boxMsg.PeerId != peer.PeerId {
			err = mtproto.ErrMessageAuthorRequired
			c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
			return nil, err
		}

		if peer.PeerType == mtproto.PEER_CHAT {
			if c.MD.UserId != boxMsg.SenderUserId {
				mChat, err := c.svcCtx.Dao.ChatClient.Client().ChatGetChatBySelfId(c.ctx, &chatpb.TLChatGetChatBySelfId{
					SelfId: c.MD.UserId,
					ChatId: peer.PeerId,
				})
				if err != nil {
					c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
					return nil, mtproto.ErrChatAdminRequired
				}
				me, _ := mChat.GetImmutableChatParticipant(c.MD.UserId)
				if me == nil {
					c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
					return nil, mtproto.ErrChatAdminRequired
				}
				if !me.CanAdminEditMessages() {
					err = mtproto.ErrChatAdminRequired
					c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
					return nil, mtproto.ErrChatAdminRequired
				}
			}
		} else {
			if c.MD.UserId != boxMsg.SenderUserId {
				err = mtproto.ErrMessageAuthorRequired
				c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
				return nil, err
			}
		}
	case mtproto.PEER_CHANNEL:
		c.Logger.Errorf("messages.getMessageEditData blocked, License key from https://teamgram.net required to unlock enterprise features.")
		return nil, mtproto.ErrEnterpriseIsBlocked
	default:
		err = mtproto.ErrPeerIdInvalid
		c.Logger.Errorf("messages.getMessageEditData - error: %v", err)
		return nil, err
	}

	// Add support for secret chat
	if boxMsg.Message.GetSecretChat() {
		// Handle secret chat messages
	}

	// Add support for reservations
	if boxMsg.Message.GetReservation() {
		// Handle reservation messages
	}

	return mtproto.MakeTLMessagesMessageEditData(&mtproto.Messages_MessageEditData{
		Caption: false,
	}).To_Messages_MessageEditData(), nil
}
