package core

import (
	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"
)

// MessagesReadMentions
// messages.readMentions#f0189d3 peer:InputPeer = messages.AffectedHistory;
func (c *MessagesCore) MessagesReadMentions(in *mtproto.TLMessagesReadMentions) (*mtproto.Messages_AffectedHistory, error) {
	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	)

	if !peer.IsChatOrUser() {
		err := mtproto.ErrPeerIdInvalid
		c.Logger.Errorf("messages.readMentions - error: %v", err)
		return nil, err
	}

	rV, err := c.svcCtx.Dao.MsgClient.MsgReadMentions(
		c.ctx,
		&msgpb.TLMsgReadMentions{
			UserId:    c.MD.UserId,
			AuthKeyId: c.MD.PermAuthKeyId,
			PeerType:  peer.PeerType,
			PeerId:    peer.PeerId,
			SecretChat: in.SecretChat, // Add support for secret chat
			Reservation: in.Reservation, // Add support for reservations
		})
	if err != nil {
		c.Logger.Errorf("messages.readMentions - error: %v", err)
		return nil, err
	}

	return rV, nil
}
