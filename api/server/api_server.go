package server

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/vault/api"
	"github.com/skip-mev/platform-take-home/logging"
	"github.com/skip-mev/platform-take-home/types"
	"github.com/skip-mev/platform-take-home/utils"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type APIServerImpl struct {
	types.UnimplementedAPIServer

	vault  *api.Client
	logger *zap.Logger
}

var _ types.APIServer = &APIServerImpl{}

func NewDefaultAPIServer(logger *zap.Logger, vaultClient *api.Client) *APIServerImpl {
	return &APIServerImpl{
		vault:  vaultClient,
		logger: logger,
	}
}

func (s *APIServerImpl) CreateWallet(ctx context.Context, request *types.CreateWalletRequest) (*types.CreateWalletResponse, error) {
	logging.FromContext(ctx).Info("CreateWallet", zap.String("name", request.Name))

	// Create a new key
	path := "transit/keys/" + request.Name
	wallet, err := s.vault.Logical().Write(path, map[string]interface{}{
		"type": "ecdsa-p256",
	})
	if err != nil {
		logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
		return nil, err
	}

	addressBytes, address, pubkey, err := utils.ParsePEM(wallet, ctx)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to parse PEM key", zap.Error(err))
		return nil, err
	}

	return &types.CreateWalletResponse{
		Wallet: &types.Wallet{
			Name:         request.Name,
			Address:      address,
			AddressBytes: addressBytes,
			Pubkey:       []byte(pubkey),
		},
	}, nil
}

func (s *APIServerImpl) GetWallet(ctx context.Context, request *types.GetWalletRequest) (*types.GetWalletResponse, error) {
	logging.FromContext(ctx).Info("GetWallet", zap.String("name", request.Name))

	if request.Name == "" {
		return nil, errors.New("name is required")
	}

	wallet, err := s.vault.Logical().Read("transit/keys/" + request.Name)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
		return nil, err
	}
	if wallet == nil {
		logging.FromContext(ctx).Error("Wallet not found", zap.String("Wallet Name", request.Name))
		return nil, status.Errorf(codes.NotFound, "wallet with name '%s' not found", request.Name)
	}

	logging.FromContext(ctx).Info("Wallet", zap.Any("wallet", wallet))

	addressBytes, address, pubkey, err := utils.ParsePEM(wallet, ctx)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to parse PEM key", zap.Error(err))
		return nil, err
	}

	return &types.GetWalletResponse{
		Wallet: &types.Wallet{
			Name:         request.Name,
			Address:      address,
			AddressBytes: addressBytes,
			Pubkey:       []byte(pubkey),
		},
	}, nil
}

func (s *APIServerImpl) GetWallets(ctx context.Context, request *types.EmptyRequest) (*types.GetWalletsResponse, error) {
	wallets, err := s.vault.Logical().List("transit/keys")
	if err != nil {
		logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
	}

	keys := wallets.Data
	logging.FromContext(ctx).Info("Wallet", zap.Any("KEYS TO LOOK AT: ", keys))
	if keyValue, ok := keys["keys"].([]interface{}); ok {

		res := make([]*types.Wallet, len(keyValue))

		for i, w := range keyValue {
			if key, ok := w.(string); ok {
				wallet, err := s.vault.Logical().Read("transit/keys/" + key)
				if err != nil {
					logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
				}

				logging.FromContext(ctx).Info("Wallet", zap.Any("wallet", wallet))

				if err != nil {
					logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
				}

				addressBytes, address, pubkey, err := utils.ParsePEM(wallet, ctx)
				if err != nil {
					logging.FromContext(ctx).Error("Failed to parse PEM key", zap.Error(err))
					return nil, err
				}
				res[i] = &types.Wallet{
					Name:         key,
					Address:      address,
					AddressBytes: addressBytes,
					Pubkey:       []byte(pubkey),
				}
			} else {
				logging.FromContext(ctx).Error("Error", zap.Error(err))
			}
		}
		return &types.GetWalletsResponse{
			Wallets: res,
		}, nil
	}

	return &types.GetWalletsResponse{
		Wallets: nil,
	}, nil
}

func (s *APIServerImpl) VerifySignature(ctx context.Context, request *types.WalletVerifySignatureRequest) (*types.WalletVerifySignatureResponse, error) {
	logging.FromContext(ctx).Info("VerifySignature", zap.String("Signature: ", request.Signature))
	if request.WalletName == "" {
		return nil, errors.New("name is required")
	}

	if request.TxBytes == nil {
		return nil, errors.New("data is required")
	}

	if request.Signature == "" {
		return nil, errors.New("signature is required")
	}

	//hashedBytes := sha256.Sum256(request.TxBytes)
	base64EncodedHash := base64.StdEncoding.EncodeToString(request.TxBytes)

	response, err := s.vault.Logical().Write("transit/verify/"+request.WalletName, map[string]interface{}{
		"signature":      request.Signature,
		"input":          base64EncodedHash,
		"hash_algorithm": "sha2-256",
	})

	if err != nil {
		logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
		return nil, err
	}

	validation := response.Data["valid"].(bool)
	return &types.WalletVerifySignatureResponse{
		Valid: validation,
	}, nil

}

func (s *APIServerImpl) Sign(ctx context.Context, request *types.WalletSignatureRequest) (*types.WalletSignatureResponse, error) {
	if request.WalletName == "" {
		return nil, errors.New("name is required")
	}

	if request.TxBytes == nil {
		return nil, errors.New("data is required")
	}

	//hashedBytes := sha256.Sum256(request.TxBytes)
	base64EncodedHash := base64.StdEncoding.EncodeToString(request.TxBytes)
	response, err := s.vault.Logical().Write("transit/sign/"+request.WalletName, map[string]interface{}{
		"input":          base64EncodedHash,
		"hash_algorithm": "sha2-256",
		//"prehashed":      true,
	})
	if err != nil {
		logging.FromContext(ctx).Error("Failed to create wallet key", zap.Error(err))
		return nil, err
	}

	// Extract the signature from the response
	signatureRaw, ok := response.Data["signature"].(string)
	if !ok {
		return nil, errors.New("signature not found")
	}

	// Return the response with the serialized signature
	return &types.WalletSignatureResponse{
		Signature: signatureRaw,
	}, nil
}
