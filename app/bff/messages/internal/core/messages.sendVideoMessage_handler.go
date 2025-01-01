package core

import (
	"time"

	"github.com/teamgram/proto/mtproto"
	msgpb "github.com/teamgram/teamgram-server/app/messenger/msg/msg/msg"

	"github.com/zeromicro/go-zero/core/contextx"
	"github.com/zeromicro/go-zero/core/threading"
	"github.com/teamgram/teamgram-server/app/bff/messages/plugin"
)

// MessagesSendVideoMessage
// messages.sendVideoMessage#d9d75a4 flags:# no_webpage:flags.1?true silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true peer:InputPeer reply_to_msg_id:flags.0?int message:string random_id:long reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.10?int send_as:flags.13?InputPeer = Updates;
func (c *MessagesCore) MessagesSendVideoMessage(in *mtproto.TLMessagesSendVideoMessage) (*mtproto.Updates, error) {
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

	if in.Message == "" {
		err := mtproto.ErrMessageEmpty
		c.Logger.Errorf("message empty: %v", err)
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
		Message:              parsedMessage,
		Media:                nil,
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
			ReplyToScheduled:       false,
			ForumTopic:             false,
			Quote:                  false,
			ReplyToMsgId:           in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_INT32:     in.GetReplyToMsgId().GetValue(),
			ReplyToMsgId_FLAGINT32: in.GetReplyToMsgId(),
			ReplyToPeerId:          nil,
			ReplyFrom:              nil,
			ReplyMedia:             nil,
			ReplyToTopId:           nil,
			QuoteText:              nil,
			QuoteEntities:          nil,
			QuoteOffset:            nil,
		}).To_MessageReplyHeader()
	} else if in.GetReplyTo() != nil {
		replyTo := in.GetReplyTo()
		switch in.ReplyTo.PredicateName {
		case mtproto.Predicate_inputReplyToMessage:
			outMessage.ReplyTo = mtproto.MakeTLMessageReplyHeader(&mtproto.MessageReplyHeader{
				ReplyToScheduled:       false,
				ForumTopic:             false,
				Quote:                  false,
				ReplyToMsgId:           replyTo.GetReplyToMsgId(),
				ReplyToMsgId_INT32:     replyTo.GetReplyToMsgId(),
				ReplyToMsgId_FLAGINT32: mtproto.MakeFlagsInt32(replyTo.GetReplyToMsgId()),
				ReplyToPeerId:          nil,
				ReplyFrom:              nil,
				ReplyMedia:             nil,
				ReplyToTopId:           nil,
				QuoteText:              nil,
				QuoteEntities:          nil,
				QuoteOffset:            nil,
			}).To_MessageReplyHeader()
			if replyTo.GetQuoteText() != nil {
				outMessage.ReplyTo.Quote = true
				outMessage.ReplyTo.QuoteText = replyTo.GetQuoteText()
				outMessage.ReplyTo.QuoteEntities = replyTo.GetQuoteEntities()
				outMessage.ReplyTo.QuoteOffset = replyTo.GetQuoteOffset()
			}

			// disable replyToPeerId
			// TODO enable replyToPeerId
			if replyTo.ReplyToPeerId != nil {
				outMessage.ReplyTo = nil
			}

		case mtproto.Predicate_inputReplyToStory:
			// TODO:
			var (
				rPeer  *mtproto.PeerUtil
				userId int64
			)

			if replyTo.GetUserId() != nil {
				rPeer = mtproto.FromInputUser(c.MD.UserId, replyTo.GetUserId())
				userId = rPeer.PeerId
			} else if replyTo.GetPeer() != nil {
				rPeer = mtproto.FromInputPeer2(c.MD.UserId, replyTo.GetPeer())
				if rPeer.IsUser() {
					userId = peer.PeerId
				}
			}

			if rPeer != nil {
				outMessage.ReplyTo = mtproto.MakeTLMessageReplyStoryHeader(&mtproto.MessageReplyHeader{
					UserId:  userId,
					Peer:    rPeer.ToPeer(),
					StoryId: replyTo.GetStoryId(),
				}).To_MessageReplyHeader()
			}
		}
	}

	// Add support for dynamic autoplay of circular video messages
	if in.DynamicAutoplay {
		outMessage.DynamicAutoplay = true
	}

	// Add support for full-screen view on click
	if in.FullScreenOnClick {
		outMessage.FullScreenOnClick = true
	}

	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSendMessageV2(c.ctx, &msgpb.TLMsgSendMessageV2{
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
		c.Logger.Errorf("messages.sendVideoMessage#fa88427a - error: %v", err)
		return nil, err
	}

	if in.ClearDraft {
		ctx := contextx.ValueOnlyFrom(c.ctx)
		threading.GoSafe(func() {
			c.doClearDraft(ctx, c.MD.UserId, c.MD.PermAuthKeyId, peer)
		})
	}

	return rUpdate, nil
}
