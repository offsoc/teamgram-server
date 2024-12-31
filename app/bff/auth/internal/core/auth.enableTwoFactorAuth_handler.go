package core

import (
	"context"
	"errors"
	"teamgram-server/app/bff/auth/internal/svc"
	"teamgram-server/app/bff/auth/internal/types"
	"teamgram-server/pkg/crypto"
	"teamgram-server/pkg/otp"
)

type AuthEnableTwoFactorAuthHandler struct {
	svcCtx *svc.ServiceContext
}

func NewAuthEnableTwoFactorAuthHandler(svcCtx *svc.ServiceContext) *AuthEnableTwoFactorAuthHandler {
	return &AuthEnableTwoFactorAuthHandler{
		svcCtx: svcCtx,
	}
}

func (h *AuthEnableTwoFactorAuthHandler) EnableTwoFactorAuth(ctx context.Context, req *types.EnableTwoFactorAuthRequest) (*types.EnableTwoFactorAuthResponse, error) {
	// Verify the password
	user, err := h.svcCtx.UserModel.FindOne(ctx, req.UserId)
	if err != nil {
		return nil, err
	}

	if !crypto.CheckPasswordHash(req.Password, user.Password) {
		return nil, errors.New("invalid password")
	}

	// Generate and send OTP
	otpCode, err := otp.GenerateOTP()
	if err != nil {
		return nil, err
	}

	err = h.svcCtx.OTPService.SendOTP(ctx, user.Email, otpCode)
	if err != nil {
		return nil, err
	}

	// Save OTP to the database
	err = h.svcCtx.OTPModel.SaveOTP(ctx, req.UserId, otpCode)
	if err != nil {
		return nil, err
	}

	return &types.EnableTwoFactorAuthResponse{
		Message: "OTP sent to your email",
	}, nil
}
