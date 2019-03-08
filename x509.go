// This package provides functions to convert ECDSA encoded
// private and public keys to the cooked versions.
package dececkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
)

// X509Key decodes an X.509 encoded subject public key
// to an ecdsa.PublicKey
func X509Key(encoded []byte) (*ecdsa.PublicKey, error) {
	var val publicKey
	rest, err := asn1.Unmarshal(encoded, &val)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("only part of the key parsed")
	}
	var pub ecdsa.PublicKey
	pub.Curve, err = processAlgorithm(val.Algorithm)
	if err != nil {
		return nil, err
	}
	if val.PublicKey.BitLength%8 != 0 {
		return nil, errors.New("implementation limit: public key bit string length must be a multiple of 8")
	}
	pub.X, pub.Y, err = splitECPoint(pub.Curve, val.PublicKey.Bytes)
	return &pub, err
}

func splitECPoint(c elliptic.Curve, b []byte) (*big.Int, *big.Int, error) {
	if len(b) < 1 || b[0] != 4 {
		return nil, nil, errors.New("wrong ECPoint format")
	}
	params := c.Params()
	l := (params.BitSize + 7) / 8
	if len(b)-1 != 2*l {
		return nil, nil, errors.New("wrong ECPoint format")
	}
	x := toInt(b[1 : l+1])
	y := toInt(b[l+1:])
	if !c.IsOnCurve(x, y) {
		return nil, nil, errors.New("point is not on curve")
	}
	return x, y, nil
}

func toInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
