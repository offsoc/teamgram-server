package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountSendConfirmPhoneCode
// account.sendConfirmPhoneCode#1b3faa88 hash:string settings:CodeSettings = auth.SentCode;
func (c *AccountCore) AccountSendConfirmPhoneCode(in *mtproto.TLAccountSendConfirmPhoneCode) (*mtproto.Auth_SentCode, error) {
	// Decrypt the hash before sending the confirmation code
	decryptedHash, err := encryption.DecryptMessage(in.GetHash(), "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.sendConfirmPhoneCode - decryption error: %v", err)
		return nil, err
	}

	// TODO: not impl
	c.Logger.Errorf("account.sendConfirmPhoneCode blocked, License key from https://teamgram.net required to unlock enterprise features.")

	return nil, mtproto.ErrEnterpriseIsBlocked
}
