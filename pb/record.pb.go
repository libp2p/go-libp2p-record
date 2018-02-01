// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: record.proto

/*
Package record_pb is a generated protocol buffer package.

It is generated from these files:
	record.proto

It has these top-level messages:
	Record
*/
package record_pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// Record represents a dht record that contains a value
// for a key value pair
type Record struct {
	// The key that references this record
	Key *string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	// The actual value this record is storing
	Value []byte `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	// Time the record was received, set by receiver
	TimeReceived     *string `protobuf:"bytes,5,opt,name=timeReceived" json:"timeReceived,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Record) Reset()                    { *m = Record{} }
func (m *Record) String() string            { return proto.CompactTextString(m) }
func (*Record) ProtoMessage()               {}
func (*Record) Descriptor() ([]byte, []int) { return fileDescriptorRecord, []int{0} }

func (m *Record) GetKey() string {
	if m != nil && m.Key != nil {
		return *m.Key
	}
	return ""
}

func (m *Record) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Record) GetTimeReceived() string {
	if m != nil && m.TimeReceived != nil {
		return *m.TimeReceived
	}
	return ""
}

func init() {
	proto.RegisterType((*Record)(nil), "record.pb.Record")
}

func init() { proto.RegisterFile("record.proto", fileDescriptorRecord) }

var fileDescriptorRecord = []byte{
	// 105 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x29, 0x4a, 0x4d, 0xce,
	0x2f, 0x4a, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0xf1, 0x92, 0x94, 0x42, 0xb8,
	0xd8, 0x82, 0xc0, 0x1c, 0x21, 0x01, 0x2e, 0xe6, 0xec, 0xd4, 0x4a, 0x09, 0x46, 0x05, 0x46, 0x0d,
	0xce, 0x20, 0x10, 0x53, 0x48, 0x84, 0x8b, 0xb5, 0x2c, 0x31, 0xa7, 0x34, 0x55, 0x82, 0x49, 0x81,
	0x51, 0x83, 0x27, 0x08, 0xc2, 0x11, 0x52, 0xe2, 0xe2, 0x29, 0xc9, 0xcc, 0x4d, 0x0d, 0x4a, 0x4d,
	0x4e, 0xcd, 0x2c, 0x4b, 0x4d, 0x91, 0x60, 0x05, 0x6b, 0x40, 0x11, 0x03, 0x04, 0x00, 0x00, 0xff,
	0xff, 0xde, 0x8a, 0xe0, 0xec, 0x6f, 0x00, 0x00, 0x00,
}
