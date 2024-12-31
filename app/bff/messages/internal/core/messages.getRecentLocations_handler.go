package core

import (
	"github.com/teamgram/proto/mtproto"
)

// MessagesGetRecentLocations
// messages.getRecentLocations#702a40e0 peer:InputPeer limit:int hash:long = messages.Messages;
func (c *MessagesCore) MessagesGetRecentLocations(in *mtproto.TLMessagesGetRecentLocations) (*mtproto.Messages_Messages, error) {
	// Add support for secret chat
	if in.GetSecretChat() {
		// Handle secret chat messages
	}

	// Add support for reservations
	if in.GetReservation() {
		// Handle reservation messages
	}

	// TODO: not impl
	c.Logger.Errorf("messages.getRecentLocations blocked, License key from https://teamgram.net required to unlock enterprise features.")

	return nil, mtproto.ErrEnterpriseIsBlocked
}
