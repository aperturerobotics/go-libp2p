// Code generated by protoc-gen-go-lite. DO NOT EDIT.
// protoc-gen-go-lite version: v0.6.1
// source: github.com/libp2p/go-libp2p/core/crypto/pb/crypto.proto

package pb

import (
	base64 "encoding/base64"
	fmt "fmt"
	io "io"
	strconv "strconv"
	strings "strings"

	protobuf_go_lite "github.com/aperturerobotics/protobuf-go-lite"
	json "github.com/aperturerobotics/protobuf-go-lite/json"
)

type KeyType int32

const (
	KeyType_RSA          KeyType = 0
	KeyType_Ed25519      KeyType = 1
	KeyType_EdDilithium3 KeyType = 4
)

// Enum value maps for KeyType.
var (
	KeyType_name = map[int32]string{
		0: "RSA",
		1: "Ed25519",
		4: "EdDilithium3",
	}
	KeyType_value = map[string]int32{
		"RSA":          0,
		"Ed25519":      1,
		"EdDilithium3": 4,
	}
)

func (x KeyType) Enum() *KeyType {
	p := new(KeyType)
	*p = x
	return p
}

func (x KeyType) String() string {
	name, valid := KeyType_name[int32(x)]
	if valid {
		return name
	}
	return strconv.Itoa(int(x))
}

type PublicKey struct {
	unknownFields []byte
	Type          KeyType `protobuf:"varint,1,opt,name=Type,proto3" json:"Type,omitempty"`
	Data          []byte  `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (x *PublicKey) Reset() {
	*x = PublicKey{}
}

func (*PublicKey) ProtoMessage() {}

func (x *PublicKey) GetType() KeyType {
	if x != nil {
		return x.Type
	}
	return KeyType_RSA
}

func (x *PublicKey) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type PrivateKey struct {
	unknownFields []byte
	Type          KeyType `protobuf:"varint,1,opt,name=Type,proto3" json:"Type,omitempty"`
	Data          []byte  `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (x *PrivateKey) Reset() {
	*x = PrivateKey{}
}

func (*PrivateKey) ProtoMessage() {}

func (x *PrivateKey) GetType() KeyType {
	if x != nil {
		return x.Type
	}
	return KeyType_RSA
}

func (x *PrivateKey) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (m *PublicKey) CloneVT() *PublicKey {
	if m == nil {
		return (*PublicKey)(nil)
	}
	r := new(PublicKey)
	r.Type = m.Type
	if rhs := m.Data; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Data = tmpBytes
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *PublicKey) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (m *PrivateKey) CloneVT() *PrivateKey {
	if m == nil {
		return (*PrivateKey)(nil)
	}
	r := new(PrivateKey)
	r.Type = m.Type
	if rhs := m.Data; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Data = tmpBytes
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *PrivateKey) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (this *PublicKey) EqualVT(that *PublicKey) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if this.Type != that.Type {
		return false
	}
	if string(this.Data) != string(that.Data) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *PublicKey) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*PublicKey)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}
func (this *PrivateKey) EqualVT(that *PrivateKey) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if this.Type != that.Type {
		return false
	}
	if string(this.Data) != string(that.Data) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *PrivateKey) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*PrivateKey)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}

// MarshalProtoJSON marshals the KeyType to JSON.
func (x KeyType) MarshalProtoJSON(s *json.MarshalState) {
	s.WriteEnumString(int32(x), KeyType_name)
}

// MarshalText marshals the KeyType to text.
func (x KeyType) MarshalText() ([]byte, error) {
	return []byte(json.GetEnumString(int32(x), KeyType_name)), nil
}

// MarshalJSON marshals the KeyType to JSON.
func (x KeyType) MarshalJSON() ([]byte, error) {
	return json.DefaultMarshalerConfig.Marshal(x)
}

// UnmarshalProtoJSON unmarshals the KeyType from JSON.
func (x *KeyType) UnmarshalProtoJSON(s *json.UnmarshalState) {
	v := s.ReadEnum(KeyType_value)
	if err := s.Err(); err != nil {
		s.SetErrorf("could not read KeyType enum: %v", err)
		return
	}
	*x = KeyType(v)
}

// UnmarshalText unmarshals the KeyType from text.
func (x *KeyType) UnmarshalText(b []byte) error {
	i, err := json.ParseEnumString(string(b), KeyType_value)
	if err != nil {
		return err
	}
	*x = KeyType(i)
	return nil
}

// UnmarshalJSON unmarshals the KeyType from JSON.
func (x *KeyType) UnmarshalJSON(b []byte) error {
	return json.DefaultUnmarshalerConfig.Unmarshal(b, x)
}

// MarshalProtoJSON marshals the PublicKey message to JSON.
func (x *PublicKey) MarshalProtoJSON(s *json.MarshalState) {
	if x == nil {
		s.WriteNil()
		return
	}
	s.WriteObjectStart()
	var wroteField bool
	if x.Type != 0 || s.HasField("Type") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("Type")
		x.Type.MarshalProtoJSON(s)
	}
	if len(x.Data) > 0 || s.HasField("Data") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("Data")
		s.WriteBytes(x.Data)
	}
	s.WriteObjectEnd()
}

// MarshalJSON marshals the PublicKey to JSON.
func (x *PublicKey) MarshalJSON() ([]byte, error) {
	return json.DefaultMarshalerConfig.Marshal(x)
}

// UnmarshalProtoJSON unmarshals the PublicKey message from JSON.
func (x *PublicKey) UnmarshalProtoJSON(s *json.UnmarshalState) {
	if s.ReadNil() {
		return
	}
	s.ReadObject(func(key string) {
		switch key {
		default:
			s.Skip() // ignore unknown field
		case "Type":
			s.AddField("Type")
			x.Type.UnmarshalProtoJSON(s)
		case "Data":
			s.AddField("Data")
			x.Data = s.ReadBytes()
		}
	})
}

// UnmarshalJSON unmarshals the PublicKey from JSON.
func (x *PublicKey) UnmarshalJSON(b []byte) error {
	return json.DefaultUnmarshalerConfig.Unmarshal(b, x)
}

// MarshalProtoJSON marshals the PrivateKey message to JSON.
func (x *PrivateKey) MarshalProtoJSON(s *json.MarshalState) {
	if x == nil {
		s.WriteNil()
		return
	}
	s.WriteObjectStart()
	var wroteField bool
	if x.Type != 0 || s.HasField("Type") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("Type")
		x.Type.MarshalProtoJSON(s)
	}
	if len(x.Data) > 0 || s.HasField("Data") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("Data")
		s.WriteBytes(x.Data)
	}
	s.WriteObjectEnd()
}

// MarshalJSON marshals the PrivateKey to JSON.
func (x *PrivateKey) MarshalJSON() ([]byte, error) {
	return json.DefaultMarshalerConfig.Marshal(x)
}

// UnmarshalProtoJSON unmarshals the PrivateKey message from JSON.
func (x *PrivateKey) UnmarshalProtoJSON(s *json.UnmarshalState) {
	if s.ReadNil() {
		return
	}
	s.ReadObject(func(key string) {
		switch key {
		default:
			s.Skip() // ignore unknown field
		case "Type":
			s.AddField("Type")
			x.Type.UnmarshalProtoJSON(s)
		case "Data":
			s.AddField("Data")
			x.Data = s.ReadBytes()
		}
	})
}

// UnmarshalJSON unmarshals the PrivateKey from JSON.
func (x *PrivateKey) UnmarshalJSON(b []byte) error {
	return json.DefaultUnmarshalerConfig.Unmarshal(b, x)
}

func (m *PublicKey) MarshalVT() (dAtA []byte, err error) {
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

func (m *PublicKey) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *PublicKey) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x12
	}
	if m.Type != 0 {
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *PrivateKey) MarshalVT() (dAtA []byte, err error) {
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

func (m *PrivateKey) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *PrivateKey) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x12
	}
	if m.Type != 0 {
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *PublicKey) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != 0 {
		n += 1 + protobuf_go_lite.SizeOfVarint(uint64(m.Type))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *PrivateKey) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != 0 {
		n += 1 + protobuf_go_lite.SizeOfVarint(uint64(m.Type))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (x KeyType) MarshalProtoText() string {
	return x.String()
}
func (x *PublicKey) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("PublicKey { ")
	if x.Type != 0 {
		sb.WriteString(" Type: ")
		sb.WriteString(KeyType(x.Type).String())
	}
	if len(x.Data) > 0 {
		sb.WriteString(" Data: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Data))
		sb.WriteString("\"")
	}
	sb.WriteString("}")
	return sb.String()
}
func (x *PublicKey) String() string {
	return x.MarshalProtoText()
}
func (x *PrivateKey) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("PrivateKey { ")
	if x.Type != 0 {
		sb.WriteString(" Type: ")
		sb.WriteString(KeyType(x.Type).String())
	}
	if len(x.Data) > 0 {
		sb.WriteString(" Data: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Data))
		sb.WriteString("\"")
	}
	sb.WriteString("}")
	return sb.String()
}
func (x *PrivateKey) String() string {
	return x.MarshalProtoText()
}
func (m *PublicKey) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: PublicKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PublicKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= KeyType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
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
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
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

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *PrivateKey) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: PrivateKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PrivateKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= KeyType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
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
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
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

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
