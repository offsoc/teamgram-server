package core

import (
	"github.com/teamgram/proto/mtproto"
	"google.golang.org/grpc/status"
)

var (
	ErrWebfileNotAvailable = status.Error(mtproto.ErrBadRequest, "WEBFILE_NOT_AVAILABLE")
)

// UploadGetWebFile
// upload.getWebFile#24e6818d location:InputWebFileLocation offset:int limit:int = upload.WebFile;
func (c *FilesCore) UploadGetWebFile(in *mtproto.TLUploadGetWebFile) (*mtproto.Upload_WebFile, error) {
	switch in.GetLocation().GetPredicateName() {
	case mtproto.Predicate_inputWebFileAudioAlbumThumbLocation:
		err := ErrWebfileNotAvailable
		c.Logger.Errorf("upload.getWebFile - error: %v", err)

		return nil, err
	case mtproto.Predicate_inputWebFileLocation:
		// Implement functionality for handling web files
		// Placeholder for actual implementation
		return &mtproto.Upload_WebFile{
			Type:   mtproto.MakeTLStorageFileUnknown(nil).To_Storage_FileType(),
			Mtime:  int32(0),
			Bytes:  []byte{},
		}, nil
	default:
		err := mtproto.ErrEnterpriseIsBlocked
		c.Logger.Errorf("upload.getWebFile - error: %v", err)

		return nil, err
	}
}
