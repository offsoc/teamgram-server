package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/service/biz/privacy/privacy"
)

// PrivacySetPrivacySettings
// privacy.setPrivacySettings#8b9b4dae user_id:int settings:PrivacySettings = Bool;
func (c *PrivacyCore) PrivacySetPrivacySettings(in *mtproto.TLPrivacySetPrivacySettings) (*mtproto.Bool, error) {
	var (
		userId = in.UserId
		settings = in.Settings
	)

	// Add logic to hide online status, last seen time, phone number, and profile picture
	if settings.HideOnlineStatus {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetOnlineStatus(c.ctx, &privacy.TLPrivacySetOnlineStatus{
			UserId: userId,
			Status: mtproto.PrivacyStatusHidden,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	if settings.HideLastSeenTime {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetLastSeenTime(c.ctx, &privacy.TLPrivacySetLastSeenTime{
			UserId: userId,
			Status: mtproto.PrivacyStatusHidden,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	if settings.HidePhoneNumber {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetPhoneNumber(c.ctx, &privacy.TLPrivacySetPhoneNumber{
			UserId: userId,
			Status: mtproto.PrivacyStatusHidden,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	if settings.HideProfilePicture {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetProfilePicture(c.ctx, &privacy.TLPrivacySetProfilePicture{
			UserId: userId,
			Status: mtproto.PrivacyStatusHidden,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	// Add logic to customize privacy rules by list (blacklist/whitelist)
	if settings.Blacklist != nil {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetBlacklist(c.ctx, &privacy.TLPrivacySetBlacklist{
			UserId: userId,
			List:   settings.Blacklist,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	if settings.Whitelist != nil {
		err := c.svcCtx.Dao.PrivacyClient.PrivacySetWhitelist(c.ctx, &privacy.TLPrivacySetWhitelist{
			UserId: userId,
			List:   settings.Whitelist,
		})
		if err != nil {
			c.Logger.Errorf("privacy.setPrivacySettings#8b9b4dae - error: %v", err)
			return nil, err
		}
	}

	return mtproto.BoolTrue, nil
}
