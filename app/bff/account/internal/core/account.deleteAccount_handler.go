package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/messenger/sync/sync"
	"github.com/teamgram/teamgram-server/app/service/authsession/authsession"
	"github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"github.com/teamgram/teamgram-server/app/service/biz/username/username"
	"github.com/teamgram/teamgram-server/app/bff/encryption/internal/core/encryption"
)

// AccountDeleteAccount
// account.deleteAccount#418d4e0b reason:string = Bool;
func (c *AccountCore) AccountDeleteAccount(in *mtproto.TLAccountDeleteAccount) (*mtproto.Bool, error) {
	me, err := c.svcCtx.Dao.UserClient.UserGetUserDataById(c.ctx, &user.TLUserGetUserDataById{
		UserId: c.MD.UserId,
	})
	if err != nil {
		c.Logger.Errorf("account.deleteAccount - error: %v", err)
		return nil, err
	}

	if me.Username != "" {
		_, err = c.svcCtx.Dao.UsernameClient.UsernameDeleteUsername(c.ctx, &username.TLUsernameDeleteUsername{
			Constructor: 0,
			Username:    "",
		})
		if err != nil {
			c.Logger.Errorf("account.deleteAccount - error: %v", err)
			return nil, err
		}
	}

	// Encrypt the reason before deleting the account
	encryptedReason, err := encryption.EncryptMessage(in.Reason, "encryption_key")
	if err != nil {
		c.Logger.Errorf("account.deleteAccount - encryption error: %v", err)
		return nil, err
	}

	// TODO(@benqi): 1. Clear account data 2. Kickoff other client
	_, err = c.svcCtx.UserClient.UserDeleteUser(c.ctx, &user.TLUserDeleteUser{
		UserId: c.MD.UserId,
		Reason: encryptedReason,
		Phone:  me.Phone,
	})
	if err != nil {
		c.Logger.Errorf("account.deleteAccount - error: %v", err)
		return nil, err
	}

	// s.AuthSessionRpcClient
	tKeyIdList, err := c.svcCtx.Dao.AuthsessionClient.AuthsessionResetAuthorization(c.ctx, &authsession.TLAuthsessionResetAuthorization{
		UserId:    c.MD.UserId,
		AuthKeyId: 0,
		Hash:      0,
	})
	if err != nil {
		c.Logger.Errorf("account.resetAuthorization#df77f3bc - error: %v", err)
		return nil, err
	}

	for _, id := range tKeyIdList.Datas {
		// notify kill session
		upds := mtproto.MakeTLUpdateAccountResetAuthorization(&mtproto.Updates{
			UserId:    c.MD.UserId,
			AuthKeyId: id,
		}).To_Updates()
		_, _ = c.svcCtx.Dao.SyncClient.SyncUpdatesMe(
			c.ctx,
			&sync.TLSyncUpdatesMe{
				UserId:        c.MD.UserId,
				PermAuthKeyId: id,
				ServerId:      nil,
				AuthKeyId:     nil,
				SessionId:     nil,
				Updates:       upds,
			})
	}

	_, _ = c.svcCtx.Dao.AuthsessionClient.AuthsessionUnbindAuthKeyUser(c.ctx, &authsession.TLAuthsessionUnbindAuthKeyUser{
		AuthKeyId: 0,
		UserId:    c.MD.UserId,
	})

	return mtproto.BoolTrue, nil
}
