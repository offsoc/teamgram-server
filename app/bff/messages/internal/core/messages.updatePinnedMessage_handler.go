package core

import (
	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"
)

// MessagesUpdatePinnedMessage
// messages.updatePinnedMessage#d2aaf7ec flags:# silent:flags.0?true unpin:flags.1?true pm_oneside:flags.2?true peer:InputPeer id:int = Updates;
func (c *MessagesCore) MessagesUpdatePinnedMessage(in *mtproto.TLMessagesUpdatePinnedMessage) (*mtproto.Updates, error) {
	var (
		peer     = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
		rUpdates *mtproto.Updates
	)

	if !peer.IsChatOrUser() {
		c.Logger.Errorf("invalid peer: %v", in.Peer)
		err := mtproto.ErrPeerIdInvalid
		return nil, err
	}

	rUpdates, err := c.svcCtx.Dao.MsgClient.MsgUpdatePinnedMessage(c.ctx, &msgpb.TLMsgUpdatePinnedMessage{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		Silent:    in.Silent,
		Unpin:     in.Unpin,
		PmOneside: in.PmOneside,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
		Id:        in.Id,
	})
	if err != nil {
		c.Logger.Errorf("messages.updatePinnedMessage - error: %v", in.Peer)
		return nil, err
	}

	// Add support for secret chat
	if in.SecretChat {
		// Implement secret chat functionality here
	}

	// Add support for reservations
	if in.Reservation {
		// Implement reservation functionality here
	}

	return rUpdates, nil
}
