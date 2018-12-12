package record

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-record/pb"
	"github.com/stretchr/testify/require"
)

func TestCompatibility(t *testing.T) {
	b, err := proto.Marshal(&record_pb.StoredRecord{Record: &record_pb.Record{Key: []byte("hello"), Value: []byte("world")}})
	require.NoError(t, err)
	var sr record_pb.Record
	require.NoError(t, proto.Unmarshal(b, &sr))
	t.Logf("%#v", sr)
}
