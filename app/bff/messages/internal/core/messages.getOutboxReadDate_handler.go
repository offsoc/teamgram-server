package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/message/message"
	"github.com/zeromicro/go-zero/core/mr"
)

// MessagesGetOutboxReadDate
// messages.getOutboxReadDate#8c4bfe5d peer:InputPeer msg_id:int = OutboxReadDate;
func (c *MessagesCore) MessagesGetOutboxReadDate(in *mtproto.TLMessagesGetOutboxReadDate) (*mtproto.OutboxReadDate, error) {
	// Possible errors
	// Code	Type	Description
	// 400	MESSAGE_ID_INVALID	The provided message id is invalid.
	// 400	MESSAGE_NOT_READ_YET	The specified message wasn't read yet.
	// 400	MESSAGE_TOO_OLD	The message is too old, the requested information is not available.
	// 400	PEER_ID_INVALID	The provided peer id is invalid.
	// 403	USER_PRIVACY_RESTRICTED	The user's privacy settings do not allow you to do this.
	// 403	YOUR_PRIVACY_RESTRICTED	You cannot fetch the read date of this message because you have disallowed other users to do so for your messages; to fix, allow other users to see your exact last online date OR purchase a Telegram Premium subscription.

	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
		rV   *mtproto.OutboxReadDate
	)

	if !peer.IsUser() {
		c.Logger.Errorf("messages.getOutboxReadDate - only user peer is supported")
		return nil, mtproto.ErrPeerIdInvalid
	}

	// TODO: 1. Check USER_PRIVACY_RESTRICTED
	//		 2. Check YOUR_PRIVACY_RESTRICTED

	err := mr.Finish(
		func() error {
			msgBox, err := c.svcCtx.Dao.MessageClient.MessageGetUserMessage(c.ctx, &message.TLMessageGetUserMessage{
				UserId: c.MD.UserId,
				Id:     in.MsgId,
			})
			if err != nil {
				c.Logger.Errorf("messages.getOutboxReadDate - error: %v", err)
				return mtproto.ErrMessageIdInvalid
			}

			if msgBox.PeerType != mtproto.PEER_USER {
				c.Logger.Errorf("messages.getOutboxReadDate - only user peer is supported")
				return mtproto.ErrPeerIdInvalid
			} else if msgBox.GetPeerId() != peer.PeerId {
				c.Logger.Errorf("messages.getOutboxReadDate - only user peer is supported")
				return mtproto.ErrPeerIdInvalid
			}

			// TODO: Check MESSAGE_TOO_OLD
			return nil
		},
		func() error {
			rList, err := c.svcCtx.Dao.MessageClient.MessageGetOutboxReadDate(c.ctx, &message.TLMessageGetOutboxReadDate{
				UserId:   c.MD.UserId,
				PeerType: peer.PeerType,
				PeerId:   peer.PeerId,
				MsgId:    in.MsgId,
			})

			if err != nil {
				c.Logger.Errorf("messages.getOutboxReadDate - error: %v", err)
				return err
			}

			// rList = rV.GetDatas()
			if len(rList.GetDatas()) != 1 {
				c.Logger.Errorf("messages.getOutboxReadDate - len(rList) == 0")
				return mtproto.ErrMessageNotReadYet
			} else {
				rV = mtproto.MakeTLOutboxReadDate(&mtproto.OutboxReadDate{
					Date: rList.GetDatas()[0].GetDate(),
				}).To_OutboxReadDate()
			}

			return nil
		})
	if err != nil {
		return nil, err
	}

	// Add support for secret chat
	if rV.GetSecretChat() {
		// Handle secret chat messages
	}

	// Add support for reservations
	if rV.GetReservation() {
		// Handle reservation messages
	}

	return rV, nil
}
