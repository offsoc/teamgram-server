package core

import (
	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"
)

// MessagesUnpinAllMessages
// messages.unpinAllMessages#f025bc8b peer:InputPeer = messages.AffectedHistory;
func (c *MessagesCore) MessagesUnpinAllMessages(in *mtproto.TLMessagesUnpinAllMessages) (*mtproto.Messages_AffectedHistory, error) {
	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	)
	switch peer.PeerType {
	case mtproto.PEER_SELF:
	case mtproto.PEER_USER:
	case mtproto.PEER_CHAT:
	case mtproto.PEER_CHANNEL:
	default:
		c.Logger.Errorf("invalid peer: %v", in.Peer)
		err := mtproto.ErrPeerIdInvalid
		return nil, err
	}

	rValues, err := c.svcCtx.Dao.MsgClient.MsgUnpinAllMessages(c.ctx, &msgpb.TLMsgUnpinAllMessages{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
	})
	if err != nil {
		c.Logger.Errorf("messages.unpinAllMessages - error: %v", in.Peer)
		return nil, err
	}

	// Add support for secret chat
	if in.SecretChat {
		rValues.SecretChat = true
	}

	// Add support for reservations
	if in.Reservation {
		rValues.Reservation = true
	}

	return rValues, nil
}
