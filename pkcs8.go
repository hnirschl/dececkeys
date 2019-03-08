package dececkeys

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type ecPrivKey struct {
	Version    int
	PrivateKey []byte
	Params     asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey  asn1.RawValue `asn1:"optional,tag:1"`
}

// PKCS8Key decodes an ECDSA private key in PKCS #8 format to
// an ecdsa.PrivateKey.
func PKCS8Key(encoded []byte) (*ecdsa.PrivateKey, error) {
	var val privateKey
	rest, err := asn1.Unmarshal(encoded, &val)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("only part of the key parsed")
	}
	if val.Version != 0 {
		return nil, fmt.Errorf("don't understand version %v", val.Version)
	}
	curve, err := processAlgorithm(val.Algorithm)
	if err != nil {
		return nil, err
	}
	var pk ecPrivKey
	rest, err = asn1.Unmarshal(val.PrivateKey, &pk)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("only part of the parameters parsed")
	}
	if pk.Version != 1 {
		return nil, fmt.Errorf("don't understand EC priv key version %v", pk.Version)
	}
	var k ecdsa.PrivateKey
	k.Curve = curve
	k.D = new(big.Int).SetBytes(pk.PrivateKey)
	k.X, k.Y = curve.ScalarBaseMult(pk.PrivateKey)
	return &k, nil
}
