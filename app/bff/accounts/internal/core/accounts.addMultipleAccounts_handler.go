package core

import (
	"context"
	"errors"
	"teamgram-server/app/bff/accounts/internal/svc"
	"teamgram-server/app/bff/accounts/internal/types"
)

type AccountsAddMultipleAccountsHandler struct {
	svcCtx *svc.ServiceContext
}

func NewAccountsAddMultipleAccountsHandler(svcCtx *svc.ServiceContext) *AccountsAddMultipleAccountsHandler {
	return &AccountsAddMultipleAccountsHandler{
		svcCtx: svcCtx,
	}
}

func (h *AccountsAddMultipleAccountsHandler) AddMultipleAccounts(ctx context.Context, req *types.AddMultipleAccountsRequest) (*types.AddMultipleAccountsResponse, error) {
	// Check if the device already has 3 accounts
	accounts, err := h.svcCtx.AccountModel.FindAccountsByDevice(ctx, req.DeviceId)
	if err != nil {
		return nil, err
	}

	if len(accounts) >= 3 {
		return nil, errors.New("maximum number of accounts reached")
	}

	// Add the new account
	err = h.svcCtx.AccountModel.AddAccount(ctx, req.DeviceId, req.Account)
	if err != nil {
		return nil, err
	}

	return &types.AddMultipleAccountsResponse{
		Message: "Account added successfully",
	}, nil
}
