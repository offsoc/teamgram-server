package core

import (
	"context"
	"errors"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/messages/plugin"
	"github.com/teamgram/teamgram-server/app/service/media/media"
)

// MessagesSendFile
// messages.sendFile#d9d75a4 flags:# no_webpage:flags.1?true silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true peer:InputPeer reply_to_msg_id:flags.0?int file:InputFile random_id:long reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.10?int send_as:flags.13?InputPeer = Updates;
func (c *MessagesCore) MessagesSendFile(ctx context.Context, in *mtproto.TLMessagesSendFile) (*mtproto.Updates, error) {
	var (
		peer       *mtproto.PeerUtil
		linkChatId int64
		err        error
	)

	peer = mtproto.FromInputPeer2(c.MD.UserId, in.Peer)
	switch peer.PeerType {
	case mtproto.PEER_SELF:
		peer.PeerType = mtproto.PEER_USER
	case mtproto.PEER_USER:
		if !c.MD.IsBot {
			// hasBot = s.UserFacade.IsBot(ctx, peer.PeerId)
		}
	case mtproto.PEER_CHAT:
	case mtproto.PEER_CHANNEL:
		//channel, _ := s.ChannelFacade.GetMutableChannel(ctx, peer.PeerId, md.UserId)
		//if channel != nil && channel.Channel.LinkedChatId > 0 {
		//	linkChatId = channel.Channel.LinkedChatId
		//}
	default:
		c.Logger.Errorf("invalid peer: %v", in.Peer)
		err = mtproto.ErrPeerIdInvalid
		return nil, err
	}

	// Enforce file upload limits
	if in.File.Size > 2*1024*1024*1024 && !c.MD.IsPremium {
		err = errors.New("file size exceeds 2GB limit for regular users")
		c.Logger.Errorf("file size exceeds 2GB limit for regular users: %v", err)
		return nil, err
	} else if in.File.Size > 4*1024*1024*1024 {
		err = errors.New("file size exceeds 4GB limit for premium users")
		c.Logger.Errorf("file size exceeds 4GB limit for premium users: %v", err)
		return nil, err
	}

	// Parse and render Markdown formatting
	parsedMessage, err := plugin.ParseMarkdown(in.Message)
	if err != nil {
		c.Logger.Errorf("failed to parse markdown: %v", err)
		return nil, err
	}

	// Parse and render hyperlinks
	parsedMessage, err = plugin.ParseHyperlinks(parsedMessage)
	if err != nil {
		c.Logger.Errorf("failed to parse hyperlinks: %v", err)
		return nil, err
	}

	// Parse and render HTML embedding
	parsedMessage, err = plugin.ParseHTMLEmbedding(parsedMessage)
	if err != nil {
		c.Logger.Errorf("failed to parse HTML embedding: %v", err)
		return nil, err
	}

	outMessage := mtproto.MakeTLMessage(&mtproto.Message{
		Out:                  true,
		Mentioned:            false,
		MediaUnread:          false,
		Silent:               in.Silent,
		Post:                 false,
		FromScheduled:        false,
		Legacy:               false,
		EditHide:             false,
		Pinned:               false,
		Noforwards:           in.Noforwards,
		InvertMedia:          in.InvertMedia,
		Id:                   0,
		FromId:               mtproto.MakePeerUser(c.MD.UserId),
		PeerId:               peer.ToPeer(),
		SavedPeerId:          nil,
		FwdFrom:              nil,
		ViaBotId:             nil,
		ReplyTo:              nil,
		Date:                 int32(time.Now().Unix()),
		Media:                nil,
		Message:              parsedMessage,
		ReplyMarkup:          in.ReplyMarkup,
		Entities:             in.Entities,
		Views:                nil,
		Forwards:             nil,
		Replies:              nil,
		EditDate:             nil,
		PostAuthor:           nil,
		GroupedId:            nil,
		Reactions:            nil,
		RestrictionReason:    nil,
		TtlPeriod:            nil,
		QuickReplyShortcutId: nil,
		Effect:               in.Effect,
		Factcheck:            nil,
	}).To_Message()

	// Fix SavedPeerId
	if peer.IsSelfUser(c.MD.UserId) {
		outMessage.SavedPeerId = peer.ToPeer()
	}

	// Fix ReplyToMsgId
	if in.GetReplyToMsgId() != nil {
		outMessage.ReplyTo = mtproto.MakeTLMessageReplyHeader(&mtproto.MessageReplyHeader{
			ReplyToMsgId:           in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_INT32:     in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_FLAGINT32: in.GetReplyToMsgId(),
			ReplyToPeerId:          nil,
			ReplyToTopId:           nil,
		}).To_MessageReplyHeader()
	} else if in.GetReplyTo() != nil {
		switch in.ReplyTo.PredicateName {
		case mtproto.Predicate_inputReplyToMessage:
			outMessage.ReplyTo = mtproto.MakeTLMessageReplyHeader(&mtproto.MessageReplyHeader{
				ReplyToMsgId:           in.GetReplyTo().GetReplyToMsgId(),
				ReplyToMsgId_INT32:     in.GetReplyTo().GetReplyToMsgId(),
				ReplyToMsgId_FLAGINT32: mtproto.MakeFlagsInt32(in.GetReplyTo().GetReplyToMsgId()),
				ReplyToPeerId:          nil,
				ReplyToTopId:           nil,
			}).To_MessageReplyHeader()
		case mtproto.Predicate_inputReplyToStory:
			// TODO:
		}
	}

	if linkChatId > 0 {
		outMessage.Replies = mtproto.MakeTLMessageReplies(&mtproto.MessageReplies{
			Comments:       true,
			Replies:        0,
			RepliesPts:     0,
			RecentRepliers: nil,
			ChannelId:      mtproto.MakeFlagsInt64(linkChatId),
			MaxId:          nil,
			ReadMaxId:      nil,
		}).To_MessageReplies()
	}

	// Handle file transfer
	fileMedia, err := c.svcCtx.MediaClient.MediaUploadFile(ctx, &media.TLMediaUploadFile{
		OwnerId: c.MD.UserId,
		File:    in.File,
	})
	if err != nil {
		c.Logger.Errorf("failed to upload file: %v", err)
		return nil, err
	}

	outMessage.Media = mtproto.MakeTLMessageMediaDocument(&mtproto.MessageMedia{
		Document: fileMedia,
	}).To_MessageMedia()

	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSendMessageV2(ctx, &msgpb.TLMsgSendMessageV2{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
		Message: []*msgpb.OutboxMessage{
			msgpb.MakeTLOutboxMessage(&msgpb.OutboxMessage{
				NoWebpage:    in.NoWebpage,
				Background:   in.Background,
				RandomId:     in.RandomId,
				Message:      outMessage,
				ScheduleDate: in.ScheduleDate,
			}).To_OutboxMessage(),
		},
	})

	if err != nil {
		c.Logger.Errorf("messages.sendFile#d9d75a4 - error: %v", err)
		return nil, err
	}

	if in.ClearDraft {
		ctx := contextx.ValueOnlyFrom(ctx)
		threading.GoSafe(func() {
			c.doClearDraft(ctx, c.MD.UserId, c.MD.PermAuthKeyId, peer)
		})
	}

	return rUpdate, nil
}
