package record

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	u "github.com/ipfs/go-ipfs-util"
	logging "github.com/ipfs/go-log"
	pb "github.com/libp2p/go-libp2p-record/pb"
	mh "github.com/multiformats/go-multihash"
)

var log = logging.Logger("routing/record")

// ErrBadRecord is returned any time a dht record is found to be
// incorrectly formatted or signed.
var ErrBadRecord = errors.New("bad dht record")

// ErrInvalidRecordType is returned if a DHTRecord keys prefix
// is not found in the Validator map of the DHT.
var ErrInvalidRecordType = errors.New("invalid record keytype")

type ValidationRecord struct {
	Namespace string
	Key       string
	Value     []byte
}

// ValidatorFunc is a function that is called to validate a given
// type of DHTRecord.
type ValidatorFunc func(*ValidationRecord) error

// Validator is an object that helps ensure routing records are valid.
// It is a collection of validator functions, each of which implements
// its own notion of validity.
type Validator map[string]ValidatorFunc

func splitPath(key string) (string, string, error) {
	if len(key) == 0 || key[0] != '/' {
		return "", "", ErrInvalidRecordType
	}

	key = key[1:]

	i := strings.IndexByte(key, '/')
	if i <= 0 {
		return "", "", ErrInvalidRecordType
	}

	return key[:i], key[i+1:], nil
}

func parseRecord(r *pb.Record) (*ValidationRecord, error) {
	namespace, key, err := splitPath(r.GetKey())
	if err != nil {
		return nil, err
	}

	return &ValidationRecord{
		Namespace: namespace,
		Key:       key,
		Value:     r.GetValue(),
	}, nil
}

// VerifyRecord checks a record and ensures it is still valid.
// It runs needed validators.
// Note that VerifyRecord does not perform signature verification.
func (v Validator) VerifyRecord(r *pb.Record) error {
	vr, err := parseRecord(r)
	if err != nil {
		return err
	}
	f, ok := v[vr.Namespace]
	if !ok {
		log.Infof("Unrecognized key prefix: %s", vr.Namespace)
		return ErrInvalidRecordType
	}
	return f(vr)
}

// ValidatePublicKeyRecord implements ValidatorFunc and
// verifies that the passed in record value is the PublicKey
// that matches the passed in key.
func PublicKeyValidator(r *ValidationRecord) error {
	if r.Namespace != "pk" {
		return errors.New("namespace not 'pk'")
	}

	keyhash := []byte(r.Key)
	if _, err := mh.Cast(keyhash); err != nil {
		return fmt.Errorf("key did not contain valid multihash: %s", err)
	}

	pkh := u.Hash(r.Value)
	if !bytes.Equal(keyhash, pkh) {
		return errors.New("public key does not match storage key")
	}
	return nil
}
