package core

import (
	"github.com/teamgram/proto/mtproto"
)

// MessagesGetSearchResultsCalendar
// messages.getSearchResultsCalendar#49f0bde9 peer:InputPeer filter:MessagesFilter offset_id:int offset_date:int = messages.SearchResultsCalendar;
func (c *MessagesCore) MessagesGetSearchResultsCalendar(in *mtproto.TLMessagesGetSearchResultsCalendar) (*mtproto.Messages_SearchResultsCalendar, error) {
	// TODO: not impl
	c.Logger.Errorf("messages.getSearchResultsCalendar blocked, License key from https://teamgram.net required to unlock enterprise features.")

	// Add support for secret chat
	if in.SecretChat {
		// Handle secret chat messages
	}

	// Add support for reservations
	if in.Reservation {
		// Handle reservation messages
	}

	return nil, mtproto.ErrEnterpriseIsBlocked
}
