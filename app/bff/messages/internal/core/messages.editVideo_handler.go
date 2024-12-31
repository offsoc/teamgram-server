package core

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/pkg/goffmpeg/transcoder"
)

// MessagesEditVideo
// messages.editVideo#d9d75a4 flags:# peer:InputPeer id:int video:InputFile crop:flags.0?InputCrop compress:flags.1?InputCompress = Updates;
func (c *MessagesCore) MessagesEditVideo(ctx context.Context, in *mtproto.TLMessagesEditVideo) (*mtproto.Updates, error) {
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

	if in.Video == nil {
		err := mtproto.ErrVideoEmpty
		c.Logger.Errorf("video empty: %v", err)
		return nil, err
	}

	// Initialize transcoder
	trans := new(transcoder.Transcoder)
	err := trans.InitializeEmptyTranscoder()
	if err != nil {
		c.Logger.Errorf("failed to initialize transcoder: %v", err)
		return nil, err
	}

	// Set input and output paths
	inputPath := fmt.Sprintf("/tmp/%d_input.mp4", in.Id)
	outputPath := fmt.Sprintf("/tmp/%d_output.mp4", in.Id)
	err = trans.SetInputPath(inputPath)
	if err != nil {
		c.Logger.Errorf("failed to set input path: %v", err)
		return nil, err
	}
	err = trans.SetOutputPath(outputPath)
	if err != nil {
		c.Logger.Errorf("failed to set output path: %v", err)
		return nil, err
	}

	// Apply cropping if specified
	if in.Crop != nil {
		cropCmd := fmt.Sprintf("crop=%d:%d:%d:%d", in.Crop.Width, in.Crop.Height, in.Crop.X, in.Crop.Y)
		trans.MediaFile().SetFilter(cropCmd)
	}

	// Apply compression if specified
	if in.Compress != nil {
		compressCmd := fmt.Sprintf("scale=%d:%d", in.Compress.Width, in.Compress.Height)
		trans.MediaFile().SetFilter(compressCmd)
	}

	// Run transcoding process
	done := trans.Run(false)
	err = <-done
	if err != nil {
		c.Logger.Errorf("failed to transcode video: %v", err)
		return nil, err
	}

	// Upload the edited video
	editedVideo, err := c.svcCtx.Dao.MediaClient.MediaUploadFile(ctx, &mtproto.TLMediaUploadFile{
		OwnerId: c.MD.UserId,
		File:    outputPath,
	})
	if err != nil {
		c.Logger.Errorf("failed to upload edited video: %v", err)
		return nil, err
	}

	// Create message with edited video
	outMessage := mtproto.MakeTLMessage(&mtproto.Message{
		Out:                  true,
		Mentioned:            false,
		MediaUnread:          false,
		Silent:               false,
		Post:                 false,
		FromScheduled:        false,
		Legacy:               false,
		EditHide:             false,
		Pinned:               false,
		Noforwards:           false,
		InvertMedia:          false,
		Id:                   0,
		FromId:               mtproto.MakePeerUser(c.MD.UserId),
		PeerId:               peer.ToPeer(),
		SavedPeerId:          nil,
		FwdFrom:              nil,
		ViaBotId:             nil,
		ReplyTo:              nil,
		Date:                 int32(time.Now().Unix()),
		Message:              "",
		Media:                mtproto.MakeTLMessageMediaDocument(&mtproto.MessageMedia{Document: editedVideo}).To_MessageMedia(),
		ReplyMarkup:          nil,
		Entities:             nil,
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
		Effect:               nil,
		Factcheck:            nil,
	}).To_Message()

	// Send the message
	rUpdate, err := c.svcCtx.Dao.MsgClient.MsgSendMessageV2(ctx, &msgpb.TLMsgSendMessageV2{
		UserId:    c.MD.UserId,
		AuthKeyId: c.MD.PermAuthKeyId,
		PeerType:  peer.PeerType,
		PeerId:    peer.PeerId,
		Message: []*msgpb.OutboxMessage{
			msgpb.MakeTLOutboxMessage(&msgpb.OutboxMessage{
				NoWebpage:    true,
				Background:   false,
				RandomId:     0,
				Message:      outMessage,
				ScheduleDate: nil,
			}).To_OutboxMessage(),
		},
	})

	if err != nil {
		c.Logger.Errorf("messages.editVideo - error: %v", err)
		return nil, err
	}

	return rUpdate, nil
}
