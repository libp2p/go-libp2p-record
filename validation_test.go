package record

import (
	"encoding/base64"
	"context"
	"testing"

	proto "github.com/gogo/protobuf/proto"
	u "github.com/ipfs/go-ipfs-util"
	ci "github.com/libp2p/go-libp2p-crypto"
	pb "github.com/libp2p/go-libp2p-record/pb"
)

var OffensiveKey = "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDjXAQQMal4SB2tSnX6NJIPmC69/BT8A8jc7/gDUZNkEhdhYHvc7k7S4vntV/c92nJGxNdop9fKJyevuNMuXhhHAgMBAAE="

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

	record := new(pb.Record)
	record.Key = proto.String(string(k))
	record.Value = pkb
	record.Author = proto.String(string(pkh))

	err = ValidatePublicKeyRecord(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
}
