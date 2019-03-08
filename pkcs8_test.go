package dececkeys

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestPrivKey(t *testing.T) {
	var encodingB64 = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBtK/m1JWEnnWP96KedGwqwNSP/WSFQJLoWmdpd9k0bsg=="
	encoding, err := base64.StdEncoding.DecodeString(encodingB64)
	if err != nil {
		t.Error("unexpected: ", err)
	}
	privkey, err := PKCS8Key(encoding)
	if err != nil {
		t.Error("unexpected: ", err)
	}
	// check private key
	if privkey.D.String() != "49379798337888726399305435621821074790117080582627840894191843353398604536754" {
		t.Errorf("d got %v, want %v", privkey.D, "49379798337888726399305435621821074790117080582627840894191843353398604536754")
	}
	// check public key
	var pubkey = &privkey.PublicKey
	if pubkey.Curve.Params().Name != "P-256" {
		t.Errorf("expected curve P-256, got %v", pubkey.Curve.Params().Name)
	}
	if pubkey.X.String() != "103791898280958320699663693721428385816927650469917974546280444603469568334009" {
		t.Errorf("x got %v, want %v", pubkey.X, "103791898280958320699663693721428385816927650469917974546280444603469568334009")
	}
	if pubkey.Y.String() != "106133900156671930375769819576933777534991539721889010851266360405221451615038" {
		t.Errorf("x got %v, want %v", pubkey.Y, "106133900156671930375769819576933777534991539721889010851266360405221451615038")
	}
	if !pubkey.IsOnCurve(pubkey.X, pubkey.Y) {
		t.Error("pubkey is not on the curve")
	}
	x, y := pubkey.ScalarMult(pubkey.X, pubkey.Y, pubkey.Params().N.Bytes())
	if x.Cmp(big.NewInt(0)) != 0 || y.Cmp(big.NewInt(0)) != 0 {
		t.Error("N*pubkey is not 0")
	}
}
