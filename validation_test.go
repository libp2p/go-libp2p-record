package record

import (
	"encoding/base64"
	"strings"
	"testing"

	u "github.com/ipfs/go-ipfs-util"
	ci "github.com/libp2p/go-libp2p-crypto"
)

var OffensiveKey = "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDjXAQQMal4SB2tSnX6NJIPmC69/BT8A8jc7/gDUZNkEhdhYHvc7k7S4vntV/c92nJGxNdop9fKJyevuNMuXhhHAgMBAAE="

var badPaths = []string{
	"foo/bar/baz",
	"//foo/bar/baz",
	"/ns",
	"ns",
	"ns/",
	"",
	"//",
	"/",
	"////",
}

func TestSplitPath(t *testing.T) {
	ns, key, err := SplitKey("/foo/bar/baz")
	if err != nil {
		t.Fatal(err)
	}
	if ns != "foo" {
		t.Errorf("wrong namespace: %s", ns)
	}
	if key != "bar/baz" {
		t.Errorf("wrong key: %s", key)
	}

	ns, key, err = SplitKey("/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if ns != "foo" {
		t.Errorf("wrong namespace: %s", ns)
	}
	if key != "bar" {
		t.Errorf("wrong key: %s", key)
	}

	for _, badP := range badPaths {
		_, _, err := SplitKey(badP)
		if err == nil {
			t.Errorf("expected error for bad path: %s", badP)
		}
	}
}

func TestBadRecords(t *testing.T) {
	v := Validator{
		"pk": PublicKeyValidator,
	}

	sr := u.NewSeededRand(15) // generate deterministic keypair
	_, pubk, err := ci.GenerateKeyPairWithReader(ci.RSA, 1024, sr)
	if err != nil {
		t.Fatal(err)
	}

	pkb, err := pubk.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	for _, badP := range badPaths {
		r := MakePutRecord(badP, pkb)
		if v.VerifyRecord(r) == nil {
			t.Errorf("expected error for path: %s", badP)
		}
	}

	// Test missing namespace
	r := MakePutRecord("/missing/ns", pkb)
	if v.VerifyRecord(r) == nil {
		t.Error("expected error for missing namespace 'missing'")
	}

	// Test valid namespace
	pkh := u.Hash(pkb)
	k := "/pk/" + string(pkh)
	r = MakePutRecord(k, pkb)
	err = v.VerifyRecord(r)
	if err != nil {
		t.Fatal(err)
	}
}

func validatePk(k string, pkb []byte) error {
	ns, k, err := SplitKey(k)
	if err != nil {
		return err
	}

	r := &ValidationRecord{Namespace: ns, Key: k, Value: pkb}
	return PublicKeyValidator(r)
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
