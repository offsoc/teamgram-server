package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountConfirmPhone
// account.confirmPhone#5f2178c3 phone_code_hash:string phone_code:string = Bool;
func (c *AccountCore) AccountConfirmPhone(in *mtproto.TLAccountConfirmPhone) (*mtproto.Bool, error) {
	// Decrypt the phone code hash before confirming it
	decryptedPhoneCodeHash, err := encryption.DecryptMessage(in.GetPhoneCodeHash(), "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.confirmPhone - decryption error: %v", err)
		return nil, err
	}

	// Decrypt the phone code before confirming it
	decryptedPhoneCode, err := encryption.DecryptMessage(in.GetPhoneCode(), "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.confirmPhone - decryption error: %v", err)
		return nil, err
	}

	// TODO: not impl
	c.Logger.Errorf("account.confirmPhone blocked, License key from https://teamgram.net required to unlock enterprise features.")

	return nil, mtproto.ErrEnterpriseIsBlocked
}
