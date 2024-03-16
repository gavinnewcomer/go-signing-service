package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/skip-mev/platform-take-home/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func createWallet(name string) (*types.Wallet, error) {
	req := map[string]string{
		"name": name,
	}

	reqJson, err := json.Marshal(req)

	if err != nil {
		return nil, err
	}

	res, err := http.Post("http://localhost:8080/wallet", "application/json", bytes.NewBuffer(reqJson))

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status 200, got %d", res.StatusCode)
	}

	var walletResponse struct {
		Wallet struct {
			Name         string `json:"name"`
			Pubkey       string `json:"pubkey"`       // Now expecting a base64-encoded string
			AddressBytes string `json:"addressBytes"` // Now expecting a base64-encoded string
			Address      string `json:"address"`
		} `json:"wallet"`
	}

	decBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(decBody, &walletResponse)
	if err != nil {
		return nil, err
	}

	// Decode the base64-encoded pubkey and addressBytes
	decodedPubkey, err := base64.StdEncoding.DecodeString(walletResponse.Wallet.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	decodedAddressBytes, err := base64.StdEncoding.DecodeString(walletResponse.Wallet.AddressBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode addressBytes: %w", err)
	}

	// Constructing the types.Wallet instance with decoded bytes
	return &types.Wallet{
		Name:         walletResponse.Wallet.Name,
		Pubkey:       decodedPubkey,
		AddressBytes: decodedAddressBytes,
		Address:      walletResponse.Wallet.Address,
	}, nil
}

func getWallet(name string) (*types.Wallet, error) {
	res, err := http.Get(fmt.Sprintf("http://localhost:8080/wallet/%s", name))

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status 200, got %d", res.StatusCode)
	}

	var walletResponse struct {
		Wallet struct {
			Name         string `json:"name"`
			Pubkey       string `json:"pubkey"`       // Now expecting a base64-encoded string
			AddressBytes string `json:"addressBytes"` // Now expecting a base64-encoded string
			Address      string `json:"address"`
		} `json:"wallet"`
	}

	decBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(decBody, &walletResponse)
	if err != nil {
		return nil, err
	}

	// Decode the base64-encoded pubkey and addressBytes
	decodedPubkey, err := base64.StdEncoding.DecodeString(walletResponse.Wallet.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	decodedAddressBytes, err := base64.StdEncoding.DecodeString(walletResponse.Wallet.AddressBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode addressBytes: %w", err)
	}

	// Constructing the types.Wallet instance with decoded bytes
	return &types.Wallet{
		Name:         walletResponse.Wallet.Name,
		Pubkey:       decodedPubkey,
		AddressBytes: decodedAddressBytes,
		Address:      walletResponse.Wallet.Address,
	}, nil
}

func TestCreateWallet(t *testing.T) {
	createWalletName := "test_create_wallet"
	wallet, err := createWallet(createWalletName)

	if err != nil {
		t.Fatal(err)
	}

	if wallet.Name != createWalletName {
		t.Fatalf("expected name %s, got %s", createWalletName, wallet.Name)
	}

	if wallet.Address == "" {
		t.Fatalf("expected address, got empty")
	}

	if wallet.AddressBytes == nil {
		t.Fatalf("expected address bytes, got empty")
	}

	if wallet.Pubkey == nil {
		t.Fatalf("expected pubkey, got empty")
	}

	bech32Addr, err := sdk.Bech32ifyAddressBytes("cosmos", wallet.AddressBytes)

	if err != nil {
		t.Fatal(err)
	}

	if bech32Addr != wallet.Address {
		t.Fatalf("expected bech32 address %s, got %s", bech32Addr, wallet.Address)
	}
}

func TestGetWallet(t *testing.T) {
	createWalletName := "test_get_wallet"
	createdWallet, err := createWallet(createWalletName)

	if err != nil {
		t.Fatal(err)
	}

	wallet, err := getWallet(createWalletName)

	if err != nil {
		t.Fatal(err)
	}

	if wallet.Name != createWalletName {
		t.Fatalf("expected name %s, got %s", createWalletName, wallet.Name)
	}

	if wallet.Address == "" {
		t.Fatalf("expected address %s, got empty", createdWallet.Address)
	}

	if wallet.Pubkey == nil {
		t.Fatalf("expected pubkey %s, got empty", createdWallet.Pubkey)
	}

	if createdWallet.AddressBytes == nil {
		t.Fatalf("expected address bytes, got empty")
	}

	if !bytes.Equal(createdWallet.AddressBytes, wallet.AddressBytes) {
		t.Fatalf("expected address bytes %x, got %x", createdWallet.AddressBytes, wallet.AddressBytes)
	}

	if wallet.Address != createdWallet.Address {
		t.Fatalf("expected address %s, got %s", createdWallet.Address, wallet.Address)
	}

	if !bytes.Equal(wallet.Pubkey, createdWallet.Pubkey) {
		t.Fatalf("expected pubkey %s, got %s", createdWallet.Pubkey, wallet.Pubkey)
	}
}

func TestGetWallets(t *testing.T) {
	createWalletName := "test_get_wallets"
	wallet, err := createWallet(createWalletName)

	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Get("http://localhost:8080/wallet")

	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	var walletResponse struct {
		Wallets []types.Wallet
	}

	err = json.NewDecoder(res.Body).Decode(&walletResponse)

	if err != nil {
		t.Fatal(err)
	}
	if len(walletResponse.Wallets) < 1 {
		t.Fatalf("expected at least 1 wallet, got %d", len(walletResponse.Wallets))
	}

	var ourWallet *types.Wallet

	for _, w := range walletResponse.Wallets {

		if w.Name == createWalletName {
			ourWallet = &w
			break
		}
	}

	if ourWallet == nil {
		t.Fatalf("expected wallet with name %s, got none", createWalletName)
	}

	if ourWallet.Name != createWalletName {
		t.Fatalf("expected name %s, got %s", wallet.Name, ourWallet.Name)
	}

	if ourWallet.Pubkey == nil {
		t.Fatalf("expected pubkey %x, got empty", wallet.Pubkey)
	}

	if ourWallet.Address == "" {
		t.Fatalf("expected address %s, got empty", wallet.Address)
	}

	if ourWallet.Address != wallet.Address {
		t.Fatalf("expected address %s, got %s", wallet.Address, ourWallet.Address)
	}

	if !bytes.Equal(ourWallet.Pubkey, wallet.Pubkey) {
		t.Fatalf("expected pubkey %x, got %x", wallet.Pubkey, ourWallet.Pubkey)
	}
}

func TestCreateWalletMissingName(t *testing.T) {
	walletName := ""
	_, err := createWallet(walletName)

	if err == nil {
		t.Fatal("expected non-200 status code, got 200 status code")
	}
}

func TestGetWalletMissingName(t *testing.T) {
	res, _ := http.Get("http://localhost:8080/wallet/")

	if res.StatusCode == 200 {
		t.Fatal("expected non-200 status code, got 200 status code")
	}
}

func TestGetNonExistingWallet(t *testing.T) {
	res, _ := http.Get("http://localhost:8080/wallet/bing_bong")
	if res.StatusCode != 404 {
		t.Fatal("expected 404 status code, got 200 status code")
	}
}

func TestSignatureWVault(t *testing.T) {
	walletName := "test_signature"
	_, err := createWallet(walletName)

	if err != nil {
		t.Fatal(err)
	}

	txBytes := []byte("test_signature")

	req := map[string]any{
		"wallet_name": walletName,
		"tx_bytes":    txBytes,
	}

	reqJson, err := json.Marshal(req)

	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Post("http://localhost:8080/sign", "application/json", bytes.NewBuffer(reqJson))

	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	decBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("%d", err)
	}
	var signatureResponse types.WalletSignatureResponse

	err = json.Unmarshal(decBody, &signatureResponse)
	if err != nil {
		t.Fatalf("%d", err)
	}

	newReq := map[string]any{
		"wallet_name": walletName,
		"tx_bytes":    txBytes,
		"signature":   signatureResponse.Signature,
	}

	newReqJson, _ := json.Marshal(newReq)

	validationRes, err := http.Post("http://localhost:8080/verify", "application/json", bytes.NewBuffer(newReqJson))

	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	var validationResponse types.WalletVerifySignatureResponse

	err = json.NewDecoder(validationRes.Body).Decode(&validationResponse)

	if err != nil {
		t.Fatal(err)
	}

	if !validationResponse.Valid {
		t.Fatalf("expected valid signature, got invalid")
	}
}

func TestSignature(t *testing.T) {
	walletName := "test_signature2"
	wallet, err := createWallet(walletName)

	if err != nil {
		t.Fatal(err)
	}

	txBytes := []byte("test_signature")

	req := map[string]any{
		"wallet_name": walletName,
		"tx_bytes":    txBytes,
	}

	reqJson, err := json.Marshal(req)

	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Post("http://localhost:8080/sign", "application/json", bytes.NewBuffer(reqJson))

	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	var signatureResponse types.WalletSignatureResponse

	err = json.NewDecoder(res.Body).Decode(&signatureResponse)

	if err != nil {
		t.Fatal(err)
	}

	if len(signatureResponse.Signature) < 1 {
		t.Fatalf("expected signature, got empty")
	}

	pk := pubKeyFromBytes(wallet.AddressBytes)

	if pk == nil {
		t.Fatal("Public key is nil")
	}

	if pk.X == nil || pk.Y == nil {
		t.Fatal("Public key coordinates are nil")
	}

	stripedSignature := strings.TrimPrefix(signatureResponse.Signature, "vault:v1:")
	decodedSignature, err := base64.StdEncoding.DecodeString(stripedSignature)
	if err != nil {
		t.Fatal(err)
	}

	verification := VerifySignature(pk, txBytes, decodedSignature)

	if !verification {
		t.Fatalf("expected signature verification, got false")
	}
}
