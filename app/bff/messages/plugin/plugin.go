package plugin

import (
	"context"

	"github.com/teamgram/proto/mtproto"
)

type MessagesPlugin interface {
	GetWebpagePreview(ctx context.Context, url string) (*mtproto.WebPage, error)
	GetMessageMedia(ctx context.Context, userId, ownerId int64, media *mtproto.InputMedia) (*mtproto.MessageMedia, error)
	ParseMarkdown(ctx context.Context, text string) (string, error)
	ParseHyperlinks(ctx context.Context, text string) (string, error)
	ParseHTMLEmbedding(ctx context.Context, text string) (string, error)
}
