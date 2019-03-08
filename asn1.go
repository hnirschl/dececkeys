package dececkeys

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
)

// publicKey is the X509 public key info according to RFC-5480.
type publicKey struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// privateKey is the ASN.1 structure holding the PKCS8 private key
type privateKey struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

var ecPublicKeyID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// curveTable contains the named curves mentioned in RFC-5480
var curveTable = []struct {
	id        asn1.ObjectIdentifier
	name      string
	construct func() elliptic.Curve
}{
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}, "secp192r1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 1}, "sect163k1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 15}, "sect163r2", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 33}, "secp224r1", elliptic.P224},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 26}, "sect233k1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 27}, "sect233r1", nil},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, "secp256r1", elliptic.P256},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 16}, "sect283k1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 17}, "sect283r1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 34}, "secp384r1", elliptic.P384},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 36}, "sect409k1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 37}, "sect409r1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 35}, "secp521r1", elliptic.P521},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 38}, "sect571k1", nil},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 39}, "sect571r1", nil},
}

func processAlgorithm(alg algorithmIdentifier) (elliptic.Curve, error) {
	if !ecPublicKeyID.Equal(alg.Algorithm) {
		return nil, fmt.Errorf("don't understand algorithm %v", alg.Algorithm)
	}
	if alg.Parameters.Tag != asn1.TagOID {
		return nil, fmt.Errorf("don't understand ECParameters tag %v", alg.Parameters.Tag)
	}
	var params asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("only part of the parameters parsed")
	}
	for _, entry := range curveTable {
		if entry.id.Equal(params) {
			if entry.construct != nil {
				return entry.construct(), nil
			}
			return nil, fmt.Errorf("curve %s (%v) is not implemented", entry.name, params)
		}
	}
	return nil, fmt.Errorf("don't understand named curve ID %v", params)
}
