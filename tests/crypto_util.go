package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

func pubKeyFromBytes(pubKeyBytes []byte) *ecdsa.PublicKey {
	if len(pubKeyBytes) != 64 { // Assuming uncompressed 256-bit keys, adjust accordingly
		fmt.Println("invalid public key length", len(pubKeyBytes))
		return nil
	}

	curve := elliptic.P256() // Adjust the curve accordingly
	x := big.NewInt(0).SetBytes(pubKeyBytes[:32])
	y := big.NewInt(0).SetBytes(pubKeyBytes[32:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

// signature holds the r and s values of an ECDSA signature.
type signature struct {
	R, S *big.Int
}

// signatureFromDER parses a DER-encoded ECDSA signature and returns the signature components.
func signatureFromDER(sig []byte) (*signature, error) {
	var sigStruct struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(sig, &sigStruct); err != nil {
		return nil, err
	}

	return &signature{R: sigStruct.R, S: sigStruct.S}, nil
}

// VerifySignature verifies the ECDSA signature of a message.
func VerifySignature(pk *ecdsa.PublicKey, msg, sig []byte) bool {

	// Attempt to parse the signature from DER format
	s, err := signatureFromDER(sig)
	if err != nil {
		fmt.Println("failed to parse DER signature:", err)
		return false
	}

	// Compute the hash of the message
	h := sha256.Sum256(msg)

	// Verify the signature
	return ecdsa.Verify(pk, h[:], s.R, s.S)
}
