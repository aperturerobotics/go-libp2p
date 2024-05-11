// Package crypto implements various cryptographic utilities used by libp2p.
// This includes a Public and Private key interface and key implementations
// for supported key algorithms.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

// KeyType is an enum with the set of possible key types.
type KeyType = pb.KeyType

const (
	// RSA is the RSA key type
	RSA = pb.KeyType_RSA
	// Ed25519 is the Ed25519 key type
	Ed25519 = pb.KeyType_Ed25519
	// EdDilithium3 is the hybrid Dilithium3 with Ed448 key type.
	EdDilithium3 = pb.KeyType_EdDilithium3
)

var (
	// ErrBadKeyType is returned when a key is not supported
	ErrBadKeyType = errors.New("invalid or unsupported key type")
	// KeyTypes is a list of supported keys
	KeyTypes = []pb.KeyType{
		RSA,
		Ed25519,
		EdDilithium3,
	}
)

// PubKeyUnmarshaller is a func that creates a PubKey from a given slice of bytes
type PubKeyUnmarshaller func(data []byte) (PubKey, error)

// PrivKeyUnmarshaller is a func that creates a PrivKey from a given slice of bytes
type PrivKeyUnmarshaller func(data []byte) (PrivKey, error)

// PubKeyUnmarshallers is a map of unmarshallers by key type
var PubKeyUnmarshallers = map[pb.KeyType]PubKeyUnmarshaller{
	pb.KeyType_RSA:          UnmarshalRsaPublicKey,
	pb.KeyType_Ed25519:      UnmarshalEd25519PublicKey,
	pb.KeyType_EdDilithium3: UnmarshalEdDilithium3PublicKey,
}

// PrivKeyUnmarshallers is a map of unmarshallers by key type
var PrivKeyUnmarshallers = map[pb.KeyType]PrivKeyUnmarshaller{
	pb.KeyType_RSA:          UnmarshalRsaPrivateKey,
	pb.KeyType_Ed25519:      UnmarshalEd25519PrivateKey,
	pb.KeyType_EdDilithium3: UnmarshalEdDilithium3PrivateKey,
}

// Key represents a crypto key that can be compared to another key
type Key interface {
	// Equals checks whether two PubKeys are the same
	Equals(Key) bool

	// Raw returns the raw bytes of the key (not wrapped in the
	// libp2p-crypto protobuf).
	//
	// This function is the inverse of {Priv,Pub}KeyUnmarshaler.
	Raw() ([]byte, error)

	// Type returns the protobuf key type.
	Type() pb.KeyType
}

// PrivKey represents a private key that can be used to generate a public key and sign data
type PrivKey interface {
	Key

	// Cryptographically sign the given bytes
	Sign([]byte) ([]byte, error)

	// Return a public key paired with this private key
	GetPublic() PubKey
}

// PubKey is a public key that can be used to verify data signed with the corresponding private key
type PubKey interface {
	Key

	// Verify that 'sig' is the signed hash of 'data'
	Verify(data []byte, sig []byte) (bool, error)
}

// GenSharedKey generates the shared key from a given private key
type GenSharedKey func([]byte) ([]byte, error)

// GenerateKeyPair generates a private and public key
func GenerateKeyPair(typ pb.KeyType, bits int) (PrivKey, PubKey, error) {
	return GenerateKeyPairWithReader(typ, bits, rand.Reader)
}

// GenerateKeyPairWithReader returns a keypair of the given type and bit-size
func GenerateKeyPairWithReader(typ pb.KeyType, bits int, src io.Reader) (PrivKey, PubKey, error) {
	switch typ {
	case RSA:
		return GenerateRSAKeyPair(bits, src)
	case Ed25519:
		return GenerateEd25519Key(src)
	case EdDilithium3:
		return GenerateEdDilithium3Key(src)
	default:
		return nil, nil, ErrBadKeyType
	}
}

// UnmarshalPublicKey converts a protobuf serialized public key into its
// representative object
func UnmarshalPublicKey(data []byte) (PubKey, error) {
	pmes := new(pb.PublicKey)
	err := pmes.UnmarshalVT(data)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromProto(pmes)
}

// PublicKeyFromProto converts an unserialized protobuf PublicKey message
// into its representative object.
func PublicKeyFromProto(pmes *pb.PublicKey) (PubKey, error) {
	um, ok := PubKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	data := pmes.GetData()

	pk, err := um(data)
	if err != nil {
		return nil, err
	}

	switch tpk := pk.(type) {
	case *RsaPublicKey:
		tpk.cached, err = pmes.MarshalVT()
		if err != nil {
			return nil, err
		}
	}

	return pk, nil
}

// MarshalPublicKey converts a public key object into a protobuf serialized
// public key
func MarshalPublicKey(k PubKey) ([]byte, error) {
	pbmes, err := PublicKeyToProto(k)
	if err != nil {
		return nil, err
	}

	return pbmes.MarshalVT()
}

// PublicKeyToProto converts a public key object into an unserialized
// protobuf PublicKey message.
func PublicKeyToProto(k PubKey) (*pb.PublicKey, error) {
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	return &pb.PublicKey{
		Type: k.Type(),
		Data: data,
	}, nil
}

// UnmarshalPrivateKey converts a protobuf serialized private key into its
// representative object
func UnmarshalPrivateKey(data []byte) (PrivKey, error) {
	pmes := new(pb.PrivateKey)
	err := pmes.UnmarshalVT(data)
	if err != nil {
		return nil, err
	}

	um, ok := PrivKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	return um(pmes.GetData())
}

// MarshalPrivateKey converts a key object into its protobuf serialized form.
func MarshalPrivateKey(k PrivKey) ([]byte, error) {
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	return (&pb.PrivateKey{
		Type: k.Type(),
		Data: data,
	}).MarshalVT()
}

// ConfigDecodeKey decodes from b64 (for config file) to a byte array that can be unmarshalled.
func ConfigDecodeKey(b string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b)
}

// ConfigEncodeKey encodes a marshalled key to b64 (for config file).
func ConfigEncodeKey(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// KeyEqual checks whether two Keys are equivalent (have identical byte representations).
func KeyEqual(k1, k2 Key) bool {
	if k1 == k2 {
		return true
	}

	return k1.Equals(k2)
}

func basicEquals(k1, k2 Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
