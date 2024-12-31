package core

import (
	"github.com/teamgram/proto/mtproto"
)

// MessagesReceivedMessages
// messages.receivedMessages#5a954c0 max_id:int = Vector<ReceivedNotifyMessage>;
func (c *MessagesCore) MessagesReceivedMessages(in *mtproto.TLMessagesReceivedMessages) (*mtproto.Vector_ReceivedNotifyMessage, error) {
	// TODO: not impl
	rValueList := &mtproto.Vector_ReceivedNotifyMessage{
		Datas: []*mtproto.ReceivedNotifyMessage{},
	}

	// Add support for secret chat
	for _, msg := range rValueList.Datas {
		if msg.GetSecretChat() {
			// Handle secret chat messages
		}
	}

	// Add support for reservations
	for _, msg := range rValueList.Datas {
		if msg.GetReservation() {
			// Handle reservation messages
		}
	}

	return rValueList, nil
}
