// package utils

package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/hashicorp/vault/api"
	"github.com/skip-mev/platform-take-home/logging"
	"go.uber.org/zap"
)

// DecodeECDSAPublicKey decodes a PEM-encoded ECDSA P-256 public key
// and returns the X and Y coordinates as byte slices.
func DecodeECDSAPublicKey(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an ECDSA public key")
	}

	xBytes := ecdsaPub.X.Bytes()
	yBytes := ecdsaPub.Y.Bytes()

	// Combine xBytes and yBytes
	combinedBytes := append(xBytes, yBytes...)

	return combinedBytes, nil
}

func ParsePEM(wallet *api.Secret, ctx context.Context) ([]byte, string, string, error) {
	keysData, _ := wallet.Data["keys"].(map[string]interface{})

	key1Data, _ := keysData["1"].(map[string]interface{})

	pemKey, _ := key1Data["public_key"].(string)

	addressBytes, err := DecodeECDSAPublicKey(pemKey)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to decode public key", zap.Error(err))
		return nil, "", "", err
	}

	bech32Addr, err := sdk.Bech32ifyAddressBytes("cosmos", addressBytes)

	if err != nil {
		logging.FromContext(ctx).Error("Failed to convert public key to bech32", zap.Error(err))
		return nil, "", "", err
	}

	return addressBytes, bech32Addr, pemKey, nil
}
