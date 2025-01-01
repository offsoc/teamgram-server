package core

import (
	"context"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/authorization/model"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"github.com/teamgram/teamgram-server/pkg/phonenumber"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"

	"google.golang.org/grpc/status"
)

/*
   } else if (request instanceof TLRPC.TL_account_sendChangePhoneCode) {
       if (error.text.contains("PHONE_NUMBER_INVALID")) {
           showSimpleAlert(fragment, LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
       } else if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
           showSimpleAlert(fragment, LocaleController.getString("InvalidCode", R.string.InvalidCode));
       } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
           showSimpleAlert(fragment, LocaleController.getString("CodeExpired", R.string.CodeExpired));
       } else if (error.text.startsWith("FLOOD_WAIT")) {
           showSimpleAlert(fragment, LocaleController.getString("FloodWait", R.string.FloodWait));
       } else if (error.text.startsWith("PHONE_NUMBER_OCCUPIED")) {
           showSimpleAlert(fragment, LocaleController.formatString("ChangePhoneNumberOccupied", R.string.ChangePhoneNumberOccupied, args[0]));
       } else {
           showSimpleAlert(fragment, LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred));
       }
*/

// AccountSendChangePhoneCode
// account.sendChangePhoneCode#82574ae5 phone_number:string settings:CodeSettings = auth.SentCode;
func (c *AccountCore) AccountSendChangePhoneCode(in *mtproto.TLAccountSendChangePhoneCode) (*mtproto.Auth_SentCode, error) {
	// ## Possible errors
	// Code	Type	Description
	// 406	FRESH_CHANGE_PHONE_FORBIDDEN	You can't change phone number right after logging in, please wait at least 24 hours.
	// 400	PHONE_NUMBER_BANNED	The provided phone number is banned from telegram.
	// 406	PHONE_NUMBER_INVALID	The phone number is invalid.
	// 400	PHONE_NUMBER_OCCUPIED	The phone number is already in use.

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

	codeData, err2 := c.svcCtx.AuthLogic.DoAuthSendCode(
		c.ctx,
		c.MD.PermAuthKeyId,
		c.MD.SessionId,
			phoneNumber,
		in.Settings.AllowFlashcall,
		in.Settings.CurrentNumber,
		func(codeData2 *model.PhoneCodeTransaction) error {
			if codeData2.State == model.CodeStateSent {
				c.Logger.Infof("codeSent")
				return nil
			}

			c.Logger.Infof("send code by sms")
			extraData, err2 := c.svcCtx.AuthLogic.VerifyCodeInterface.SendSmsVerifyCode(
				context.Background(),
				phoneNumber,
				codeData2.PhoneCode,
				codeData2.PhoneCodeHash)
			if err2 != nil {
				c.Logger.Errorf("send sms code error: %v", err2)
				return err2
			} else {
				// codeData2.SentCodeType = model.CodeTypeSms
				codeData2.SentCodeType = model.SentCodeTypeSms
				codeData2.PhoneCodeExtraData = extraData
			}

			codeData2.NextCodeType = model.CodeTypeSms
			codeData2.State = model.CodeStateSent

			return nil
		})

	if err2 != nil {
		c.Logger.Errorf("auth.sendCode - error: %v", err2)
		return nil, err2
	}

	// Encrypt the phone code before sending it
	encryptedPhoneCode, err := encryption.EncryptMessage(codeData.PhoneCode, "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.sendChangePhoneCode - encryption error: %v", err)
		return nil, err
	}
	codeData.PhoneCode = encryptedPhoneCode

	return codeData.ToAuthSentCode(), nil
}
