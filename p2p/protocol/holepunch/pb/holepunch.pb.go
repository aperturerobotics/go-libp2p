// Code generated by protoc-gen-go-lite. DO NOT EDIT.
// protoc-gen-go-lite version: v0.7.0
// source: github.com/libp2p/go-libp2p/p2p/protocol/holepunch/pb/holepunch.proto

package holepunch_pb

import (
	base64 "encoding/base64"
	fmt "fmt"
	io "io"
	strconv "strconv"
	strings "strings"

	protobuf_go_lite "github.com/aperturerobotics/protobuf-go-lite"
)

type HolePunch_Type int32

const (
	HolePunch_CONNECT HolePunch_Type = 100
	HolePunch_SYNC    HolePunch_Type = 300
)

// Enum value maps for HolePunch_Type.
var (
	HolePunch_Type_name = map[int32]string{
		100: "CONNECT",
		300: "SYNC",
	}
	HolePunch_Type_value = map[string]int32{
		"CONNECT": 100,
		"SYNC":    300,
	}
)

func (x HolePunch_Type) Enum() *HolePunch_Type {
	p := new(HolePunch_Type)
	*p = x
	return p
}

func (x HolePunch_Type) String() string {
	name, valid := HolePunch_Type_name[int32(x)]
	if valid {
		return name
	}
	return strconv.Itoa(int(x))
}

// spec: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
type HolePunch struct {
	unknownFields []byte
	Type          *HolePunch_Type `protobuf:"varint,1,req,name=type" json:"type,omitempty"`
	ObsAddrs      [][]byte        `protobuf:"bytes,2,rep,name=ObsAddrs" json:"ObsAddrs,omitempty"`
}

func (x *HolePunch) Reset() {
	*x = HolePunch{}
}

func (*HolePunch) ProtoMessage() {}

func (x *HolePunch) GetType() HolePunch_Type {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return HolePunch_CONNECT
}

func (x *HolePunch) GetObsAddrs() [][]byte {
	if x != nil {
		return x.ObsAddrs
	}
	return nil
}

func (m *HolePunch) CloneVT() *HolePunch {
	if m == nil {
		return (*HolePunch)(nil)
	}
	r := new(HolePunch)
	if rhs := m.Type; rhs != nil {
		tmpVal := *rhs
		r.Type = &tmpVal
	}
	if rhs := m.ObsAddrs; rhs != nil {
		tmpContainer := make([][]byte, len(rhs))
		for k, v := range rhs {
			tmpBytes := make([]byte, len(v))
			copy(tmpBytes, v)
			tmpContainer[k] = tmpBytes
		}
		r.ObsAddrs = tmpContainer
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *HolePunch) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (this *HolePunch) EqualVT(that *HolePunch) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if p, q := this.Type, that.Type; (p == nil && q != nil) || (p != nil && (q == nil || *p != *q)) {
		return false
	}
	if len(this.ObsAddrs) != len(that.ObsAddrs) {
		return false
	}
	for i, vx := range this.ObsAddrs {
		vy := that.ObsAddrs[i]
		if string(vx) != string(vy) {
			return false
		}
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *HolePunch) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*HolePunch)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}

// NOTE: protobuf-go-lite json only supports proto3: proto2 is not supported.

func (m *HolePunch) MarshalVT() (dAtA []byte, err error) {
	if m == nil {
		return nil, nil
	}
	size := m.SizeVT()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBufferVT(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *HolePunch) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *HolePunch) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
	if m == nil {
		return 0, nil
	}
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.unknownFields != nil {
		i -= len(m.unknownFields)
		copy(dAtA[i:], m.unknownFields)
	}
	if len(m.ObsAddrs) > 0 {
		for iNdEx := len(m.ObsAddrs) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.ObsAddrs[iNdEx])
			copy(dAtA[i:], m.ObsAddrs[iNdEx])
			i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.ObsAddrs[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Type == nil {
		return 0, fmt.Errorf("proto: required field type not set")
	} else {
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(*m.Type))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *HolePunch) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != nil {
		n += 1 + protobuf_go_lite.SizeOfVarint(uint64(*m.Type))
	}
	if len(m.ObsAddrs) > 0 {
		for _, b := range m.ObsAddrs {
			l = len(b)
			n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
		}
	}
	n += len(m.unknownFields)
	return n
}

func (x HolePunch_Type) MarshalProtoText() string {
	return x.String()
}
func (x *HolePunch) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("HolePunch {")
	if x.Type != nil {
		if sb.Len() > 11 {
			sb.WriteString(" ")
		}
		sb.WriteString("type: ")
		sb.WriteString("\"")
		sb.WriteString(x.Type.String())
		sb.WriteString("\"")
	}
	if len(x.ObsAddrs) > 0 {
		if sb.Len() > 11 {
			sb.WriteString(" ")
		}
		sb.WriteString("ObsAddrs: [")
		for i, v := range x.ObsAddrs {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("\"")
			sb.WriteString(base64.StdEncoding.EncodeToString(v))
			sb.WriteString("\"")
		}
		sb.WriteString("]")
	}
	sb.WriteString("}")
	return sb.String()
}

func (x *HolePunch) String() string {
	return x.MarshalProtoText()
}
func (m *HolePunch) UnmarshalVT(dAtA []byte) error {
	var hasFields [1]uint64
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return protobuf_go_lite.ErrIntOverflow
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: HolePunch: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HolePunch: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var v HolePunch_Type
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= HolePunch_Type(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Type = &v
			hasFields[0] |= uint64(0x00000001)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObsAddrs", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ObsAddrs = append(m.ObsAddrs, make([]byte, postIndex-iNdEx))
			copy(m.ObsAddrs[len(m.ObsAddrs)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := protobuf_go_lite.Skip(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.unknownFields = append(m.unknownFields, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}
	if hasFields[0]&uint64(0x00000001) == 0 {
		return fmt.Errorf("proto: required field type not set")
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
