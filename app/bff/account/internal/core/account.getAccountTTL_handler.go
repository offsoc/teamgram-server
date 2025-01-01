package core

import (
	"github.com/teamgram/proto/mtproto"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountGetAccountTTL
// account.getAccountTTL#8fc711d = AccountDaysTTL;
func (c *AccountCore) AccountGetAccountTTL(in *mtproto.TLAccountGetAccountTTL) (*mtproto.AccountDaysTTL, error) {
	days, err := c.svcCtx.Dao.UserClient.UserGetAccountDaysTTL(c.ctx, &userpb.TLUserGetAccountDaysTTL{
		UserId: c.MD.UserId,
	})
	if err != nil {
		c.Logger.Errorf("account.getAccountTTL - error: %v", err)
		return nil, err
	}

	// Encrypt the account TTL before returning it
	encryptedDays, err := encryption.EncryptMessage(string(days.Days), "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.getAccountTTL - encryption error: %v", err)
		return nil, err
	}

	return mtproto.MakeTLAccountDaysTTL(&mtproto.AccountDaysTTL{
		Days: encryptedDays,
	}).To_AccountDaysTTL(), nil
}
