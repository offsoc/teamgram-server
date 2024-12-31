package core

import (
	"time"

	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"
)

// MessagesSetAutoDestruct
// messages.setAutoDestruct#e9d75a4 flags:# peer:InputPeer message_id:int ttl:int = Updates;
func (c *MessagesCore) MessagesSetAutoDestruct(in *mtproto.TLMessagesSetAutoDestruct) (*mtproto.Updates, error) {
	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	)

	if !peer.IsChatOrUser() {
		c.Logger.Errorf("invalid peer: %v", in.Peer)
		err := mtproto.ErrEnterpriseIsBlocked
		return nil, err
	}

	if peer.IsUser() && peer.IsSelfUser(c.MD.UserId) {
		peer.PeerType = mtproto.PEER_USER
	}

	if in.MessageId == 0 {
		err := mtproto.ErrMessageIdInvalid
		c.Logger.Errorf("message id invalid: %v", err)
		return nil, err
	}

	if in.Ttl <= 0 {
		err := mtproto.ErrTtlInvalid
		c.Logger.Errorf("ttl invalid: %v", err)
		return nil, err
	}

	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSetAutoDestruct(c.ctx, &msgpb.TLMsgSetAutoDestruct{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
		MessageId: in.MessageId,
		Ttl:       in.Ttl,
	})

	if err != nil {
		c.Logger.Errorf("messages.setAutoDestruct#e9d75a4 - error: %v", err)
		return nil, err
	}

	return rUpdate, nil
}
