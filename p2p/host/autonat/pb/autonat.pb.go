// Code generated by protoc-gen-go-lite. DO NOT EDIT.
// protoc-gen-go-lite version: v0.7.0
// source: github.com/libp2p/go-libp2p/p2p/host/autonat/pb/autonat.proto

package autonat_pb

import (
	base64 "encoding/base64"
	fmt "fmt"
	io "io"
	strconv "strconv"
	strings "strings"

	protobuf_go_lite "github.com/aperturerobotics/protobuf-go-lite"
)

type Message_MessageType int32

const (
	Message_DIAL          Message_MessageType = 0
	Message_DIAL_RESPONSE Message_MessageType = 1
)

// Enum value maps for Message_MessageType.
var (
	Message_MessageType_name = map[int32]string{
		0: "DIAL",
		1: "DIAL_RESPONSE",
	}
	Message_MessageType_value = map[string]int32{
		"DIAL":          0,
		"DIAL_RESPONSE": 1,
	}
)

func (x Message_MessageType) Enum() *Message_MessageType {
	p := new(Message_MessageType)
	*p = x
	return p
}

func (x Message_MessageType) String() string {
	name, valid := Message_MessageType_name[int32(x)]
	if valid {
		return name
	}
	return strconv.Itoa(int(x))
}

type Message_ResponseStatus int32

const (
	Message_OK               Message_ResponseStatus = 0
	Message_E_DIAL_ERROR     Message_ResponseStatus = 100
	Message_E_DIAL_REFUSED   Message_ResponseStatus = 101
	Message_E_BAD_REQUEST    Message_ResponseStatus = 200
	Message_E_INTERNAL_ERROR Message_ResponseStatus = 300
)

// Enum value maps for Message_ResponseStatus.
var (
	Message_ResponseStatus_name = map[int32]string{
		0:   "OK",
		100: "E_DIAL_ERROR",
		101: "E_DIAL_REFUSED",
		200: "E_BAD_REQUEST",
		300: "E_INTERNAL_ERROR",
	}
	Message_ResponseStatus_value = map[string]int32{
		"OK":               0,
		"E_DIAL_ERROR":     100,
		"E_DIAL_REFUSED":   101,
		"E_BAD_REQUEST":    200,
		"E_INTERNAL_ERROR": 300,
	}
)

func (x Message_ResponseStatus) Enum() *Message_ResponseStatus {
	p := new(Message_ResponseStatus)
	*p = x
	return p
}

func (x Message_ResponseStatus) String() string {
	name, valid := Message_ResponseStatus_name[int32(x)]
	if valid {
		return name
	}
	return strconv.Itoa(int(x))
}

type Message struct {
	unknownFields []byte
	Type          *Message_MessageType  `protobuf:"varint,1,opt,name=type" json:"type,omitempty"`
	Dial          *Message_Dial         `protobuf:"bytes,2,opt,name=dial" json:"dial,omitempty"`
	DialResponse  *Message_DialResponse `protobuf:"bytes,3,opt,name=dialResponse" json:"dialResponse,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
}

func (*Message) ProtoMessage() {}

func (x *Message) GetType() Message_MessageType {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return Message_DIAL
}

func (x *Message) GetDial() *Message_Dial {
	if x != nil {
		return x.Dial
	}
	return nil
}

func (x *Message) GetDialResponse() *Message_DialResponse {
	if x != nil {
		return x.DialResponse
	}
	return nil
}

type Message_PeerInfo struct {
	unknownFields []byte
	Id            []byte   `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Addrs         [][]byte `protobuf:"bytes,2,rep,name=addrs" json:"addrs,omitempty"`
}

func (x *Message_PeerInfo) Reset() {
	*x = Message_PeerInfo{}
}

func (*Message_PeerInfo) ProtoMessage() {}

func (x *Message_PeerInfo) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Message_PeerInfo) GetAddrs() [][]byte {
	if x != nil {
		return x.Addrs
	}
	return nil
}

type Message_Dial struct {
	unknownFields []byte
	Peer          *Message_PeerInfo `protobuf:"bytes,1,opt,name=peer" json:"peer,omitempty"`
}

func (x *Message_Dial) Reset() {
	*x = Message_Dial{}
}

func (*Message_Dial) ProtoMessage() {}

func (x *Message_Dial) GetPeer() *Message_PeerInfo {
	if x != nil {
		return x.Peer
	}
	return nil
}

type Message_DialResponse struct {
	unknownFields []byte
	Status        *Message_ResponseStatus `protobuf:"varint,1,opt,name=status" json:"status,omitempty"`
	StatusText    *string                 `protobuf:"bytes,2,opt,name=statusText" json:"statusText,omitempty"`
	Addr          []byte                  `protobuf:"bytes,3,opt,name=addr" json:"addr,omitempty"`
}

func (x *Message_DialResponse) Reset() {
	*x = Message_DialResponse{}
}

func (*Message_DialResponse) ProtoMessage() {}

func (x *Message_DialResponse) GetStatus() Message_ResponseStatus {
	if x != nil && x.Status != nil {
		return *x.Status
	}
	return Message_OK
}

func (x *Message_DialResponse) GetStatusText() string {
	if x != nil && x.StatusText != nil {
		return *x.StatusText
	}
	return ""
}

func (x *Message_DialResponse) GetAddr() []byte {
	if x != nil {
		return x.Addr
	}
	return nil
}

func (m *Message_PeerInfo) CloneVT() *Message_PeerInfo {
	if m == nil {
		return (*Message_PeerInfo)(nil)
	}
	r := new(Message_PeerInfo)
	if rhs := m.Id; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Id = tmpBytes
	}
	if rhs := m.Addrs; rhs != nil {
		tmpContainer := make([][]byte, len(rhs))
		for k, v := range rhs {
			tmpBytes := make([]byte, len(v))
			copy(tmpBytes, v)
			tmpContainer[k] = tmpBytes
		}
		r.Addrs = tmpContainer
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *Message_PeerInfo) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (m *Message_Dial) CloneVT() *Message_Dial {
	if m == nil {
		return (*Message_Dial)(nil)
	}
	r := new(Message_Dial)
	r.Peer = m.Peer.CloneVT()
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *Message_Dial) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (m *Message_DialResponse) CloneVT() *Message_DialResponse {
	if m == nil {
		return (*Message_DialResponse)(nil)
	}
	r := new(Message_DialResponse)
	if rhs := m.Status; rhs != nil {
		tmpVal := *rhs
		r.Status = &tmpVal
	}
	if rhs := m.StatusText; rhs != nil {
		tmpVal := *rhs
		r.StatusText = &tmpVal
	}
	if rhs := m.Addr; rhs != nil {
		tmpBytes := make([]byte, len(rhs))
		copy(tmpBytes, rhs)
		r.Addr = tmpBytes
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *Message_DialResponse) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (m *Message) CloneVT() *Message {
	if m == nil {
		return (*Message)(nil)
	}
	r := new(Message)
	r.Dial = m.Dial.CloneVT()
	r.DialResponse = m.DialResponse.CloneVT()
	if rhs := m.Type; rhs != nil {
		tmpVal := *rhs
		r.Type = &tmpVal
	}
	if len(m.unknownFields) > 0 {
		r.unknownFields = make([]byte, len(m.unknownFields))
		copy(r.unknownFields, m.unknownFields)
	}
	return r
}

func (m *Message) CloneMessageVT() protobuf_go_lite.CloneMessage {
	return m.CloneVT()
}

func (this *Message_PeerInfo) EqualVT(that *Message_PeerInfo) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if p, q := this.Id, that.Id; (p == nil && q != nil) || (p != nil && q == nil) || string(p) != string(q) {
		return false
	}
	if len(this.Addrs) != len(that.Addrs) {
		return false
	}
	for i, vx := range this.Addrs {
		vy := that.Addrs[i]
		if string(vx) != string(vy) {
			return false
		}
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *Message_PeerInfo) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*Message_PeerInfo)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}
func (this *Message_Dial) EqualVT(that *Message_Dial) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if !this.Peer.EqualVT(that.Peer) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *Message_Dial) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*Message_Dial)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}
func (this *Message_DialResponse) EqualVT(that *Message_DialResponse) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if p, q := this.Status, that.Status; (p == nil && q != nil) || (p != nil && (q == nil || *p != *q)) {
		return false
	}
	if p, q := this.StatusText, that.StatusText; (p == nil && q != nil) || (p != nil && (q == nil || *p != *q)) {
		return false
	}
	if p, q := this.Addr, that.Addr; (p == nil && q != nil) || (p != nil && q == nil) || string(p) != string(q) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *Message_DialResponse) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*Message_DialResponse)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}
func (this *Message) EqualVT(that *Message) bool {
	if this == that {
		return true
	} else if this == nil || that == nil {
		return false
	}
	if p, q := this.Type, that.Type; (p == nil && q != nil) || (p != nil && (q == nil || *p != *q)) {
		return false
	}
	if !this.Dial.EqualVT(that.Dial) {
		return false
	}
	if !this.DialResponse.EqualVT(that.DialResponse) {
		return false
	}
	return string(this.unknownFields) == string(that.unknownFields)
}

func (this *Message) EqualMessageVT(thatMsg any) bool {
	that, ok := thatMsg.(*Message)
	if !ok {
		return false
	}
	return this.EqualVT(that)
}

// NOTE: protobuf-go-lite json only supports proto3: proto2 is not supported.

func (m *Message_PeerInfo) MarshalVT() (dAtA []byte, err error) {
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

func (m *Message_PeerInfo) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *Message_PeerInfo) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if len(m.Addrs) > 0 {
		for iNdEx := len(m.Addrs) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Addrs[iNdEx])
			copy(dAtA[i:], m.Addrs[iNdEx])
			i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Addrs[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Id != nil {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Message_Dial) MarshalVT() (dAtA []byte, err error) {
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

func (m *Message_Dial) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *Message_Dial) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if m.Peer != nil {
		size, err := m.Peer.MarshalToSizedBufferVT(dAtA[:i])
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

func (m *Message_DialResponse) MarshalVT() (dAtA []byte, err error) {
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

func (m *Message_DialResponse) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *Message_DialResponse) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if m.Addr != nil {
		i -= len(m.Addr)
		copy(dAtA[i:], m.Addr)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(m.Addr)))
		i--
		dAtA[i] = 0x1a
	}
	if m.StatusText != nil {
		i -= len(*m.StatusText)
		copy(dAtA[i:], *m.StatusText)
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(len(*m.StatusText)))
		i--
		dAtA[i] = 0x12
	}
	if m.Status != nil {
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(*m.Status))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Message) MarshalVT() (dAtA []byte, err error) {
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

func (m *Message) MarshalToVT(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVT(dAtA[:size])
}

func (m *Message) MarshalToSizedBufferVT(dAtA []byte) (int, error) {
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
	if m.DialResponse != nil {
		size, err := m.DialResponse.MarshalToSizedBufferVT(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x1a
	}
	if m.Dial != nil {
		size, err := m.Dial.MarshalToSizedBufferVT(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x12
	}
	if m.Type != nil {
		i = protobuf_go_lite.EncodeVarint(dAtA, i, uint64(*m.Type))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Message_PeerInfo) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != nil {
		l = len(m.Id)
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	if len(m.Addrs) > 0 {
		for _, b := range m.Addrs {
			l = len(b)
			n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
		}
	}
	n += len(m.unknownFields)
	return n
}

func (m *Message_Dial) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Peer != nil {
		l = m.Peer.SizeVT()
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *Message_DialResponse) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Status != nil {
		n += 1 + protobuf_go_lite.SizeOfVarint(uint64(*m.Status))
	}
	if m.StatusText != nil {
		l = len(*m.StatusText)
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	if m.Addr != nil {
		l = len(m.Addr)
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *Message) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != nil {
		n += 1 + protobuf_go_lite.SizeOfVarint(uint64(*m.Type))
	}
	if m.Dial != nil {
		l = m.Dial.SizeVT()
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	if m.DialResponse != nil {
		l = m.DialResponse.SizeVT()
		n += 1 + l + protobuf_go_lite.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (x Message_MessageType) MarshalProtoText() string {
	return x.String()
}
func (x Message_ResponseStatus) MarshalProtoText() string {
	return x.String()
}
func (x *Message_PeerInfo) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("PeerInfo {")
	if x.Id != nil {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("id: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Id))
		sb.WriteString("\"")
	}
	if len(x.Addrs) > 0 {
		if sb.Len() > 10 {
			sb.WriteString(" ")
		}
		sb.WriteString("addrs: [")
		for i, v := range x.Addrs {
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

func (x *Message_PeerInfo) String() string {
	return x.MarshalProtoText()
}
func (x *Message_Dial) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("Dial {")
	if x.Peer != nil {
		if sb.Len() > 6 {
			sb.WriteString(" ")
		}
		sb.WriteString("peer: ")
		sb.WriteString(x.Peer.MarshalProtoText())
	}
	sb.WriteString("}")
	return sb.String()
}

func (x *Message_Dial) String() string {
	return x.MarshalProtoText()
}
func (x *Message_DialResponse) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("DialResponse {")
	if x.Status != nil {
		if sb.Len() > 14 {
			sb.WriteString(" ")
		}
		sb.WriteString("status: ")
		sb.WriteString("\"")
		sb.WriteString(x.Status.String())
		sb.WriteString("\"")
	}
	if x.StatusText != nil {
		if sb.Len() > 14 {
			sb.WriteString(" ")
		}
		sb.WriteString("statusText: ")
		sb.WriteString(strconv.Quote(*x.StatusText))
	}
	if x.Addr != nil {
		if sb.Len() > 14 {
			sb.WriteString(" ")
		}
		sb.WriteString("addr: ")
		sb.WriteString("\"")
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Addr))
		sb.WriteString("\"")
	}
	sb.WriteString("}")
	return sb.String()
}

func (x *Message_DialResponse) String() string {
	return x.MarshalProtoText()
}
func (x *Message) MarshalProtoText() string {
	var sb strings.Builder
	sb.WriteString("Message {")
	if x.Type != nil {
		if sb.Len() > 9 {
			sb.WriteString(" ")
		}
		sb.WriteString("type: ")
		sb.WriteString("\"")
		sb.WriteString(x.Type.String())
		sb.WriteString("\"")
	}
	if x.Dial != nil {
		if sb.Len() > 9 {
			sb.WriteString(" ")
		}
		sb.WriteString("dial: ")
		sb.WriteString(x.Dial.MarshalProtoText())
	}
	if x.DialResponse != nil {
		if sb.Len() > 9 {
			sb.WriteString(" ")
		}
		sb.WriteString("dialResponse: ")
		sb.WriteString(x.DialResponse.MarshalProtoText())
	}
	sb.WriteString("}")
	return sb.String()
}

func (x *Message) String() string {
	return x.MarshalProtoText()
}
func (m *Message_PeerInfo) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: Message_PeerInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Message_PeerInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
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
			m.Id = append(m.Id[:0], dAtA[iNdEx:postIndex]...)
			if m.Id == nil {
				m.Id = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addrs", wireType)
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
			m.Addrs = append(m.Addrs, make([]byte, postIndex-iNdEx))
			copy(m.Addrs[len(m.Addrs)-1], dAtA[iNdEx:postIndex])
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
func (m *Message_Dial) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: Message_Dial: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Message_Dial: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Peer", wireType)
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
			if m.Peer == nil {
				m.Peer = &Message_PeerInfo{}
			}
			if err := m.Peer.UnmarshalVT(dAtA[iNdEx:postIndex]); err != nil {
				return err
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
func (m *Message_DialResponse) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: Message_DialResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Message_DialResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var v Message_ResponseStatus
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= Message_ResponseStatus(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Status = &v
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StatusText", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return protobuf_go_lite.ErrInvalidLength
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			s := string(dAtA[iNdEx:postIndex])
			m.StatusText = &s
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addr", wireType)
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
			m.Addr = append(m.Addr[:0], dAtA[iNdEx:postIndex]...)
			if m.Addr == nil {
				m.Addr = []byte{}
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
func (m *Message) UnmarshalVT(dAtA []byte) error {
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
			return fmt.Errorf("proto: Message: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Message: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var v Message_MessageType
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protobuf_go_lite.ErrIntOverflow
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= Message_MessageType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Type = &v
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Dial", wireType)
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
			if m.Dial == nil {
				m.Dial = &Message_Dial{}
			}
			if err := m.Dial.UnmarshalVT(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DialResponse", wireType)
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
			if m.DialResponse == nil {
				m.DialResponse = &Message_DialResponse{}
			}
			if err := m.DialResponse.UnmarshalVT(dAtA[iNdEx:postIndex]); err != nil {
				return err
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
