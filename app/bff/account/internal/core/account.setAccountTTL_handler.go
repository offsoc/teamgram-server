package core

import (
	"github.com/teamgram/proto/mtproto"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountSetAccountTTL
// account.setAccountTTL#2442485e ttl:AccountDaysTTL = Bool;
func (c *AccountCore) AccountSetAccountTTL(in *mtproto.TLAccountSetAccountTTL) (*mtproto.Bool, error) {
	// TODO(@benqi): Check ttl
	// 1 * 30 * 24 * 60 * 60,
	// 3 * 30 * 24 * 60 * 60,
	// 6 * 30 * 24 * 60 * 60,
	// 365 * 24 * 60 * 60,
	// 548 * 24 * 60 * 60,
	// 730 * 24 * 60 * 60

	ttl := in.GetTtl().GetDays()
	switch ttl {
	case 30:
	case 90:
	case 180:
	case 182:
	case 183:
	case 365:
	case 548:
	case 730:
	default:
		err := mtproto.ErrTtlDaysInvalid
		c.Logger.Errorf("account.setAccountTTL - error: %v", err)
		return nil, err
	}

	// Encrypt the TTL before setting it
	encryptedTTL, err := encryption.EncryptMessage(string(ttl), "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.setAccountTTL - encryption error: %v", err)
		return nil, err
	}

	if _, err := c.svcCtx.Dao.UserClient.UserSetAccountDaysTTL(c.ctx, &userpb.TLUserSetAccountDaysTTL{
		UserId: c.MD.UserId,
		Ttl:    encryptedTTL,
	}); err != nil {
		c.Logger.Errorf("account.setAccountTTL - error: %v", err)
	}

	return mtproto.BoolTrue, nil
}
