package record

import (
	"encoding/base64"
	"strings"
	"testing"

	u "github.com/ipfs/go-ipfs-util"
	ci "github.com/libp2p/go-libp2p-crypto"
)

var OffensiveKey = "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDjXAQQMal4SB2tSnX6NJIPmC69/BT8A8jc7/gDUZNkEhdhYHvc7k7S4vntV/c92nJGxNdop9fKJyevuNMuXhhHAgMBAAE="

func validatePk(k string, pkb []byte) error {
	ns, k, err := splitPath(k)
	if err != nil {
		return err
	}

	r := &ValidationRecord{Namespace: ns, Key: k, Value: pkb}
	return ValidatePublicKeyRecord(r)
}

func TestValidatePublicKey(t *testing.T) {

	pkb, err := base64.StdEncoding.DecodeString(OffensiveKey)
	if err != nil {
		t.Fatal(err)
	}

	pubk, err := ci.UnmarshalPublicKey(pkb)
	if err != nil {
		t.Fatal(err)
	}

	pkb2, err := pubk.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	pkh := u.Hash(pkb2)
	k := "/pk/" + string(pkh)

	// Good public key should pass
	if err := validatePk(k, pkb); err != nil {
		t.Fatal(err)
	}

	// Bad key format should fail
	var badf = "/aa/" + string(pkh)
	if err := validatePk(badf, pkb); err == nil {
		t.Fatal("Failed to detect bad prefix")
	}

	// Bad key hash should fail
	var badk = "/pk/" + strings.Repeat("A", len(pkh))
	if err := validatePk(badk, pkb); err == nil {
		t.Fatal("Failed to detect bad public key hash")
	}

	// Bad public key should fail
	pkb[0] = 'A'
	if err := validatePk(k, pkb); err == nil {
		t.Fatal("Failed to detect bad public key data")
	}
}

func TestVerifyRecordUnsigned(t *testing.T) {
	sr := u.NewSeededRand(15) // generate deterministic keypair
	sk, pubk, err := ci.GenerateKeyPairWithReader(ci.RSA, 1024, sr)
	if err != nil {
		t.Fatal(err)
	}

	pubkb, err := pubk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pkh := u.Hash(pubkb)
	k := "/pk/" + string(pkh)
	r, err := MakePutRecord(sk, k, pubkb, false)
	if err != nil {
		t.Fatal(err)
	}

	validator := make(Validator)
	validator["pk"] = PublicKeyValidator
	err = validator.VerifyRecord(r)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRecordSigned(t *testing.T) {
	sr := u.NewSeededRand(15) // generate deterministic keypair
	sk, pubk, err := ci.GenerateKeyPairWithReader(ci.RSA, 1024, sr)
	if err != nil {
		t.Fatal(err)
	}

	pubkb, err := pubk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pkh := u.Hash(pubkb)
	k := "/pk/" + string(pkh)
	r, err := MakePutRecord(sk, k, pubkb, true)
	if err != nil {
		t.Fatal(err)
	}

	var pubkValidatorWithSig = &ValidChecker{
		Func: ValidatePublicKeyRecord,
		Sign: true,
	}
	validator := make(Validator)
	validator["pk"] = pubkValidatorWithSig
	err = validator.VerifyRecord(r)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckRecordSig(r, pubk)
	if err != nil {
		t.Fatal(err)
	}

	// New Public Key
	_, pubk2, err := ci.GenerateKeyPairWithReader(ci.RSA, 1024, u.NewSeededRand(20))
	if err != nil {
		t.Fatal(err)
	}

	// Check against wrong public key.
	err = CheckRecordSig(r, pubk2)
	if err == nil {
		t.Error("signature should not validate with bad key")
	}

	// Corrupt record.
	r.Value[0] = 1

	// Check bad data against correct key
	err = CheckRecordSig(r, pubk)
	if err == nil {
		t.Error("signature should not validate with bad data")
	}
}
