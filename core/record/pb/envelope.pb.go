// Code generated by protoc-gen-go-lite. DO NOT EDIT.
// protoc-gen-go-lite version: v0.7.0
// source: github.com/libp2p/go-libp2p/core/record/pb/envelope.proto

package record_pb

import (
	base64 "encoding/base64"
	fmt "fmt"
	io "io"
	strings "strings"

	protobuf_go_lite "github.com/aperturerobotics/protobuf-go-lite"
	json "github.com/aperturerobotics/protobuf-go-lite/json"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

// Envelope encloses a signed payload produced by a peer, along with the public
// key of the keypair it was signed with so that it can be statelessly validated
// by the receiver.
//
// The payload is prefixed with a byte string that determines the type, so it
// can be deserialized deterministically. Often, this byte string is a
// multicodec.
type Envelope struct {
	unknownFields []byte
	// public_key is the public key of the keypair the enclosed payload was
	// signed with.
	PublicKey *pb.PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"publicKey,omitempty"`
	// payload_type encodes the type of payload, so that it can be deserialized
	// deterministically.
	PayloadType []byte `protobuf:"bytes,2,opt,name=payload_type,json=payloadType,proto3" json:"payloadType,omitempty"`
	// payload is the actual payload carried inside this envelope.
	Payload []byte `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	// signature is the signature produced by the private key corresponding to
	// the enclosed public key, over the payload, prefixing a domain string for
	// additional security.
	Signature []byte `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *Envelope) Reset() {
	*x = Envelope{}
}

func (*Envelope) ProtoMessage() {}

func (x *Envelope) GetPublicKey() *pb.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Envelope) GetPayloadType() []byte {
	if x != nil {
		return x.PayloadType
	}
	return nil
}

func (x *Envelope) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Envelope) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (m *Envelope) CloneVT() *Envelope {
	if m == nil {
		return (*Envelope)(nil)
	}
	r := new(Envelope)
	if rhs := m.PublicKey; rhs != nil {
		r.PublicKey = rhs.CloneVT()
	}
	if rhs := m.PayloadType; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.PayloadType = tmpBytes
	}
	if rhs := m.Payload; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Payload = tmpBytes
	}
	if rhs := m.Signature; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Signature = tmpBytes
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *Envelope) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (this *Envelope) EqualVT(that *Envelope) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if !this.PublicKey.EqualVT(that.PublicKey) {
		return false
	}
	if string(this.PayloadType) != string(that.PayloadType) {
		return false
	}
	if string(this.Payload) != string(that.Payload) {
		return false
	}
	if string(this.Signature) != string(that.Signature) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *Envelope) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*Envelope)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}

// MarshalProtoJSON marshals the Envelope message to JSON.
func (x *Envelope) MarshalProtoJSON(s *json.MarshalState) {
	if x == nil {
		s.WriteNil()
		return
	}
	s.WriteObjectStart()
	var wroteField bool
	if x.PublicKey != nil || s.HasField("publicKey") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("publicKey")
		x.PublicKey.MarshalProtoJSON(s.WithField("publicKey"))
	}
	if len(x.PayloadType) > 0 || s.HasField("payloadType") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("payloadType")
		s.WriteBytes(x.PayloadType)
	}
	if len(x.Payload) > 0 || s.HasField("payload") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("payload")
		s.WriteBytes(x.Payload)
	}
	if len(x.Signature) > 0 || s.HasField("signature") {
		s.WriteMoreIf(&wroteField)
		s.WriteObjectField("signature")
		s.WriteBytes(x.Signature)
	}
	s.WriteObjectEnd()
}

// MarshalJSON marshals the Envelope to JSON.
func (x *Envelope) MarshalJSON() ([]byte, error) {
	return json.DefaultMarshalerConfig.Marshal(x)
}

// UnmarshalProtoJSON unmarshals the Envelope message from JSON.
func (x *Envelope) UnmarshalProtoJSON(s *json.UnmarshalState) {
	if s.ReadNil() {
		return
	}
	s.ReadObject(func(key string) {
		switch key {
		default:
			s.Skip() // ignore unknown field
		case "public_key", "publicKey":
			if s.ReadNil() {
				x.PublicKey = nil
				return
			}
			x.PublicKey = &pb.PublicKey{}
			x.PublicKey.UnmarshalProtoJSON(s.WithField("public_key", true))
		case "payload_type", "payloadType":
			s.AddField("payload_type")
			x.PayloadType = s.ReadBytes()
		case "payload":
			s.AddField("payload")
			x.Payload = s.ReadBytes()
		case "signature":
			s.AddField("signature")
			x.Signature = s.ReadBytes()
		}
	})
}

// UnmarshalJSON unmarshals the Envelope from JSON.
func (x *Envelope) UnmarshalJSON(b []byte) error {
	return json.DefaultUnmarshalerConfig.Unmarshal(b, x)
}

func (m *Envelope) MarshalVT() (dAtA []byte, err error) {
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

func (m *Envelope) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *Envelope) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if len(m.Signature) > 0 {
		i -= len(m.Signature)
		copy(dAtA[i:], m.Signature)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.Payload) > 0 {
		i -= len(m.Payload)
		copy(dAtA[i:], m.Payload)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Payload)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.PayloadType) > 0 {
		i -= len(m.PayloadType)
		copy(dAtA[i:], m.PayloadType)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.PayloadType)))
		i--
		dAtA[i] = 0x12
	}
	if m.PublicKey != nil {
		size, err := m.PublicKey.MarshalToSizedBufferVT(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Envelope) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.PublicKey != nil {
		l = m.PublicKey.SizeVT()
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	l = len(m.PayloadType)
	if l > 0 {
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	l = len(m.Payload)
	if l > 0 {
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (x *Envelope) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("Envelope {")
	if x.PublicKey != nil {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("public_key: ")
		sb.WriteString(x.PublicKey.MarshalProtoText())
	}
	if x.PayloadType != nil {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("payload_type: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.PayloadType))
		sb.WriteString("\"")
	}
	if x.Payload != nil {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("payload: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Payload))
		sb.WriteString("\"")
	}
	if x.Signature != nil {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("signature: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Signature))
		sb.WriteString("\"")
	}
	sb.WriteString("}")
	return sb.String()
}

func (x *Envelope) String() string {
	return x.MarshalProtoText()
}
func (m *Envelope) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: Envelope: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Envelope: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PublicKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PublicKey == nil {
				m.PublicKey = &pb.PublicKey{}
			}
			if err := m.PublicKey.UnmarshalVT(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PayloadType", wireType)
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
			m.PayloadType = append(m.PayloadType[:0], dAtA[iNdEx:postIndex]...)
			if m.PayloadType == nil {
				m.PayloadType = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Payload", wireType)
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
			m.Payload = append(m.Payload[:0], dAtA[iNdEx:postIndex]...)
			if m.Payload == nil {
				m.Payload = []byte{}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signature", wireType)
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
			m.Signature = append(m.Signature[:0], dAtA[iNdEx:postIndex]...)
			if m.Signature == nil {
				m.Signature = []byte{}
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
