package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/chat/chat"
)

// ChannelsSetEmojiStickers
// channels.setEmojiStickers#3cd930b7 channel:InputChannel stickerset:InputStickerSet = Bool;
func (c *ChatsCore) ChannelsSetEmojiStickers(in *mtproto.TLChannelsSetEmojiStickers) (*mtproto.Bool, error) {
	channel := mtproto.FromInputChannel(in.Channel)
	stickerSet := mtproto.FromInputStickerSet(in.Stickerset)

	_, err := c.svcCtx.Dao.ChatClient.Client().ChatSetEmojiStickers(c.ctx, &chat.TLChatSetEmojiStickers{
		ChannelId:  channel.ChannelId,
		StickerSet: stickerSet,
	})
	if err != nil {
		c.Logger.Errorf("channels.setEmojiStickers - error: %v", err)
		return nil, err
	}

	return mtproto.BoolTrue, nil
}
