package record

import (
	"strings"
	"testing"

	"github.com/ipfs/go-test/random"
	ci "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	mh "github.com/multiformats/go-multihash"
)

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
	v := NamespacedValidator{
		"pk": PublicKeyValidator{},
	}

	sr := random.NewSeededRand(15) // generate deterministic keypair
	_, pubk, err := ci.GenerateKeyPairWithReader(ci.RSA, 2048, sr)
	if err != nil {
		t.Fatal(err)
	}

	pkb, err := ci.MarshalPublicKey(pubk)
	if err != nil {
		t.Fatal(err)
	}

	for _, badP := range badPaths {
		if v.Validate(badP, pkb) == nil {
			t.Errorf("expected error for path: %s", badP)
		}
	}

	// Test missing namespace
	if v.Validate("/missing/ns", pkb) == nil {
		t.Error("expected error for missing namespace 'missing'")
	}

	// Test valid namespace
	pkh, err := mh.Sum(pkb, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	k := "/pk/" + string(pkh)
	err = v.Validate(k, pkb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidatePublicKey(t *testing.T) {
	var pkv PublicKeyValidator

	sr := random.NewSeededRand(16) // generate deterministic keypair
	_, pubk, err := ci.GenerateKeyPairWithReader(ci.RSA, 2048, sr)
	if err != nil {
		t.Fatal(err)
	}
	pkb, err := ci.MarshalPublicKey(pubk)
	if err != nil {
		t.Fatal(err)
	}

	pkb2, err := ci.MarshalPublicKey(pubk)
	if err != nil {
		t.Fatal(err)
	}

	pkh, err := mh.Sum(pkb2, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	k := "/pk/" + string(pkh)

	// Good public key should pass
	if err := pkv.Validate(k, pkb); err != nil {
		t.Fatal(err)
	}

	// Bad key format should fail
	badf := "/aa/" + string(pkh)
	if err := pkv.Validate(badf, pkb); err == nil {
		t.Fatal("Failed to detect bad prefix")
	}

	// Bad key hash should fail
	badk := "/pk/" + strings.Repeat("A", len(pkh))
	if err := pkv.Validate(badk, pkb); err == nil {
		t.Fatal("Failed to detect bad public key hash")
	}

	// Bad public key should fail
	pkb[0] = 'A'
	if err := pkv.Validate(k, pkb); err == nil {
		t.Fatal("Failed to detect bad public key data")
	}
}

func TestValidateEd25519PublicKey(t *testing.T) {
	var pkv PublicKeyValidator

	_, pk, err := test.RandTestKeyPair(ci.Ed25519, 0)
	if err != nil {
		t.Fatal(err)
	}

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	pkb, err := ci.MarshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	k := "/pk/" + string(id)

	// Good public key should pass
	if err := pkv.Validate(k, pkb); err != nil {
		t.Fatal(err)
	}
}

func TestBestRecord(t *testing.T) {
	sel := NamespacedValidator{
		"pk": PublicKeyValidator{},
	}

	i, err := sel.Select("/pk/thing", [][]byte{[]byte("first"), []byte("second")})
	if err != nil {
		t.Fatal(err)
	}
	if i != 0 {
		t.Error("expected to select first record")
	}

	_, err = sel.Select("/pk/thing", nil)
	if err == nil {
		t.Fatal("expected error for no records")
	}

	_, err = sel.Select("/other/thing", [][]byte{[]byte("first"), []byte("second")})
	if err == nil {
		t.Fatal("expected error for unregistered ns")
	}

	_, err = sel.Select("bad", [][]byte{[]byte("first"), []byte("second")})
	if err == nil {
		t.Fatal("expected error for bad key")
	}
}
