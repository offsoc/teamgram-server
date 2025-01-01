package core

import (
	"context"
	"github.com/teamgram/marmota/pkg/threading2"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/authorization/model"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"github.com/teamgram/teamgram-server/pkg/phonenumber"
	"google.golang.org/grpc/status"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountChangePhone
// account.changePhone#70c32edb phone_number:string phone_code_hash:string phone_code:string = User;
func (c *AccountCore) AccountChangePhone(in *mtproto.TLAccountChangePhone) (*mtproto.User, error) {
	// ## Possible errors
	// Code	Type	Description
	// 400	PHONE_CODE_EMPTY	phone_code is missing.
	// 400	PHONE_CODE_EXPIRED	The phone code you provided has expired.
	// 406	PHONE_NUMBER_INVALID	The phone number is invalid.
	// 400	PHONE_NUMBER_OCCUPIED	The phone number is already in use.

	var (
		phoneCode     = in.GetPhoneCode()
		phoneCodeHash = in.GetPhoneCodeHash()
	)

	if phoneCode == "" || phoneCodeHash == "" {
		err := mtproto.ErrPhoneCodeEmpty
		c.Logger.Errorf("auth.sendCode - error: %v", err)
		return nil, err
	}

	// 3. check number

	// client phone number format: "+86 111 1111 1111"
	_, phoneNumber, err := phonenumber.CheckPhoneNumberInvalid(in.PhoneNumber)
	if err != nil {
		c.Logger.Errorf("check phone_number(%s) error - %v", in.PhoneNumber, err)
		err = mtproto.ErrPhoneNumberInvalid
		return nil, err
	}

	// 5. banned phone number
	if c.svcCtx.Plugin != nil {
		banned, _ := c.svcCtx.Plugin.CheckPhoneNumberBanned(c.ctx, phoneNumber)
		if banned {
			c.Logger.Errorf("{phone_number: %s} banned: %v", phoneNumber, err)
			return nil, mtproto.ErrPhoneNumberBanned
		}
	}

	// logic
	// Always crated new phoneCode
	var (
		user *mtproto.ImmutableUser
	)

	if user, err = c.svcCtx.Dao.UserClient.UserGetImmutableUserByPhone(c.ctx, &userpb.TLUserGetImmutableUserByPhone{
		Phone: phoneNumber,
	}); err != nil {
		if nErr, ok := status.FromError(err); ok {
			// TODO: check if the error is mtproto.ErrPhoneNumberUnoccupied
			// mtproto.ErrPhoneNumberUnoccupied
			c.Logger.Errorf("checkPhoneNumberExist error: %v", err)
			_ = nErr
			err = nil
		} else {
			c.Logger.Errorf("checkPhoneNumberExist error: %v", err)
			return nil, err
		}
	} else {
		c.Logger.Errorf("checkPhoneNumberExist - user: %s", user)
		return nil, mtproto.ErrPhoneNumberOccupied
	}

	codeData, err2 := c.svcCtx.AuthLogic.DoAuthChangePhone(c.ctx,
		c.MD.PermAuthKeyId,
		phoneNumber,
		phoneCode,
		phoneCodeHash,
		func(codeData2 *model.PhoneCodeTransaction) error {
			return c.svcCtx.AuthLogic.VerifyCodeInterface.VerifySmsCode(c.ctx,
				codeData2.PhoneCodeHash,
				phoneCodeHash,
				codeData2.PhoneCodeExtraData)
		})

	_ = codeData
	_ = err2

	user, _ = c.svcCtx.Dao.UserClient.UserGetImmutableUser(c.ctx, &userpb.TLUserGetImmutableUser{
		Id: c.MD.UserId,
	})
	if user == nil {
		c.Logger.Errorf("account.changePhone - error: %v")
		// err = mtproto.ErrPhoneCodeInvalid
		return nil, err
	}

	// Encrypt the phone number before changing it
	encryptedPhoneNumber, err := encryption.EncryptMessage(phoneNumber, "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.changePhone - encryption error: %v", err)
		return nil, err
	}

	_, err = c.svcCtx.Dao.UserClient.UserChangePhone(c.ctx, &userpb.TLUserChangePhone{
		UserId: c.MD.UserId,
		Phone:  encryptedPhoneNumber,
	})
	if err != nil {
		c.Logger.Errorf("account.changePhone - error: %v")
		// err = mtproto.ErrPhoneCodeInvalid
		return nil, err
	}

	user.User.Phone = phoneNumber
	return threading2.WrapperGoFunc(
		c.ctx,
		user.ToSelfUser(),
		func(ctx context.Context) {
			// on event
			_ = c.svcCtx.AuthLogic.DeletePhoneCode(ctx, c.MD.PermAuthKeyId, phoneNumber, phoneCodeHash)
		},
	).(*mtproto.User), nil

}
