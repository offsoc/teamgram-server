package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/message/message"
)

// MessagesSearchSentMedia
// messages.searchSentMedia#107e31a0 q:string filter:MessagesFilter limit:int = messages.Messages;
func (c *MessagesCore) MessagesSearchSentMedia(in *mtproto.TLMessagesSearchSentMedia) (*mtproto.Messages_Messages, error) {
	var (
		rValues  *mtproto.Messages_Messages
		limit    = in.Limit
		boxList  *mtproto.MessageBoxList
		err      error
	)

	if limit > 50 {
		limit = 50
	}

	rValues = mtproto.MakeTLMessagesMessages(&mtproto.Messages_Messages{
		Messages: []*mtproto.Message{},
		Chats:    []*mtproto.Chat{},
		Users:    []*mtproto.User{},
	}).To_Messages_Messages()

	filterType := mtproto.FromMessagesFilter(in.Filter)
	switch filterType {
	case mtproto.FilterPhotos:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_PHOTO,
			Limit:     limit,
		})
	case mtproto.FilterVideo:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_VIDEO,
			Limit:     limit,
		})
	case mtproto.FilterPhotoVideo:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_PHOTOVIDEO,
			Limit:     limit,
		})
	case mtproto.FilterDocument:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_FILE,
			Limit:     limit,
		})
	case mtproto.FilterUrl:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_URL,
			Limit:     limit,
		})
	case mtproto.FilterGif:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_GIF,
			Limit:     limit,
		})
	case mtproto.FilterMusic:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_MUSIC,
			Limit:     limit,
		})
	case mtproto.FilterChatPhotos:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_CHAT_PHOTO,
			Limit:     limit,
		})
	case mtproto.FilterRoundVoice:
		boxList, err = c.svcCtx.Dao.MessageClient.MessageSearchSentMedia(c.ctx, &message.TLMessageSearchSentMedia{
			UserId:    c.MD.UserId,
			Q:         in.Q,
			MediaType: mtproto.MEDIA_AUDIO,
			Limit:     limit,
		})
	default:
		err = mtproto.ErrInputFilterInvalid
		c.Logger.Errorf("messages.searchSentMedia - error: %v", err)
		return nil, err
	}

	if err != nil {
		c.Logger.Errorf("messages.searchSentMedia - error: %v", err)
		return rValues, nil
	}

	boxList.Visit(c.MD.UserId,
		func(messageList []*mtproto.Message) {
			rValues.Messages = messageList
		},
		func(userIdList []int64) {
			mUsers, _ := c.svcCtx.Dao.UserClient.UserGetMutableUsers(c.ctx,
				&userpb.TLUserGetMutableUsers{
					Id: userIdList,
				})
			rValues.Users = append(rValues.Users, mUsers.GetUserListByIdList(c.MD.UserId, userIdList...)...)
		},
		func(chatIdList []int64) {
			mChats, _ := c.svcCtx.Dao.ChatClient.Client().ChatGetChatListByIdList(c.ctx,
				&chatpb.TLChatGetChatListByIdList{
					IdList: chatIdList,
				})
			rValues.Chats = append(rValues.Chats, mChats.GetChatListByIdList(c.MD.UserId, chatIdList...)...)
		},
		func(channelIdList []int64) {
			//mChannels, _ := c.svcCtx.Dao.ChannelClient.ChannelGetChannelListByIdList(c.ctx,
			//	&channelpb.TLChannelGetChannelListByIdList{
			//		SelfUserId: c.MD.UserId,
			//		Id:         channelIdList,
			//	})
			//if len(mChannels.GetDatas()) > 0 {
			//	rValues.Chats = append(rValues.Chats, mChannels.GetDatas()...)
			//}
		})

	// Add support for secret chat
	if in.SecretChat {
		// Handle secret chat messages
	}

	// Add support for reservations
	if in.Reservation {
		// Handle reservation messages
	}

	return rValues, nil
}
