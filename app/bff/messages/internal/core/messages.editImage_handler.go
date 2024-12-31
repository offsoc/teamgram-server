package core

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/pkg/goffmpeg/transcoder"
)

// MessagesEditImage
// messages.editImage#d9d75a4 flags:# peer:InputPeer id:int image:InputFile filters:flags.0?InputFilters crop:flags.1?InputCrop annotate:flags.2?InputAnnotate = Updates;
func (c *MessagesCore) MessagesEditImage(ctx context.Context, in *mtproto.TLMessagesEditImage) (*mtproto.Updates, error) {
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

	if in.Image == nil {
		err := mtproto.ErrImageEmpty
		c.Logger.Errorf("image empty: %v", err)
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
	inputPath := fmt.Sprintf("/tmp/%d_input.jpg", in.Id)
	outputPath := fmt.Sprintf("/tmp/%d_output.jpg", in.Id)
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

	// Apply filters if specified
	if in.Filters != nil {
		filterCmd := strings.Join(in.Filters, ",")
		trans.MediaFile().SetFilter(filterCmd)
	}

	// Apply cropping if specified
	if in.Crop != nil {
		cropCmd := fmt.Sprintf("crop=%d:%d:%d:%d", in.Crop.Width, in.Crop.Height, in.Crop.X, in.Crop.Y)
		trans.MediaFile().SetFilter(cropCmd)
	}

	// Apply annotation if specified
	if in.Annotate != nil {
		annotateCmd := fmt.Sprintf("drawtext=text='%s':x=%d:y=%d:fontsize=%d:fontcolor=%s", in.Annotate.Text, in.Annotate.X, in.Annotate.Y, in.Annotate.FontSize, in.Annotate.FontColor)
		trans.MediaFile().SetFilter(annotateCmd)
	}

	// Run transcoding process
	done := trans.Run(false)
	err = <-done
	if err != nil {
		c.Logger.Errorf("failed to transcode image: %v", err)
		return nil, err
	}

	// Upload the edited image
	editedImage, err := c.svcCtx.Dao.MediaClient.MediaUploadFile(ctx, &mtproto.TLMediaUploadFile{
		OwnerId: c.MD.UserId,
		File:    outputPath,
	})
	if err != nil {
		c.Logger.Errorf("failed to upload edited image: %v", err)
		return nil, err
	}

	// Create message with edited image
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
		Media:                mtproto.MakeTLMessageMediaDocument(&mtproto.MessageMedia{Document: editedImage}).To_MessageMedia(),
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
		c.Logger.Errorf("messages.editImage - error: %v", err)
		return nil, err
	}

	return rUpdate, nil
}
