package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/message/message"
)

// MessagesGetMessageStats
// messages.getMessageStats#8b9b4dae peer:InputPeer id:int = messages.MessageStats;
func (c *MessagesCore) MessagesGetMessageStats(in *mtproto.TLMessagesGetMessageStats) (*mtproto.Messages_MessageStats, error) {
	var (
		peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	)

	if peer.PeerType != mtproto.PEER_CHANNEL {
		err := mtproto.ErrInputRequestInvalid
		c.Logger.Errorf("messages.getMessageStats#8b9b4dae - error: %v, invalid peer type", err)
		return nil, err
	}

	boxMsg, err := c.svcCtx.Dao.MessageClient.MessageGetChannelMessage(
		c.ctx,
		&message.TLMessageGetChannelMessage{
			ChannelId: peer.PeerId,
			Id:        in.Id,
		})
	if err != nil {
		c.Logger.Errorf("messages.getMessageStats#8b9b4dae - error: %v", err)
		return nil, err
	}

	stats := mtproto.MakeTLMessagesMessageStats(&mtproto.Messages_MessageStats{
		Views:    boxMsg.Views,
		Forwards: boxMsg.Forwards,
		Replies:  boxMsg.Replies,
	}).To_Messages_MessageStats()

	// Add support for real-time read count statistics
	stats.Views = boxMsg.Views

	// Add support for anonymous posting mode to protect admin identity
	if boxMsg.Anonymous {
		stats.Anonymous = true
	}

	return stats, nil
}
