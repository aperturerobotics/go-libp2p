package crypto

import (
	"errors"
	"io"
	"strconv"

	"github.com/cloudflare/circl/sign/eddilithium3"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

// EdDilithium3PrivateKey is an hybrid signature scheme Ed448-Dilithium3 private key.
type EdDilithium3PrivateKey struct {
	k *eddilithium3.PrivateKey
}

// EdDilithium3PrivateKey is an hybrid signature scheme Ed448-Dilithium3 public key.
type EdDilithium3PublicKey struct {
	k *eddilithium3.PublicKey
}

// GenerateEdDilithium3Key generates a new private and public key pair.
func GenerateEdDilithium3Key(src io.Reader) (PrivKey, PubKey, error) {
	pub, priv, err := eddilithium3.GenerateKey(src)
	if err != nil {
		return nil, nil, err
	}

	return &EdDilithium3PrivateKey{
			k: priv,
		},
		&EdDilithium3PublicKey{
			k: pub,
		},
		nil
}

// Type of the private key (EdDilithium3).
func (k *EdDilithium3PrivateKey) Type() pb.KeyType {
	return pb.KeyType_EdDilithium3
}

// Raw private key bytes.
func (k *EdDilithium3PrivateKey) Raw() ([]byte, error) {
	return k.k.Bytes(), nil
}

// Equals compares two ed25519 private keys.
func (k *EdDilithium3PrivateKey) Equals(o Key) bool {
	edk, ok := o.(*EdDilithium3PrivateKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

// GetPublic returns an ed25519 public key from a private key.
func (k *EdDilithium3PrivateKey) GetPublic() PubKey {
	return &EdDilithium3PublicKey{k: k.k.Public().(*eddilithium3.PublicKey)}
}

// Sign returns a signature from an input message.
func (k *EdDilithium3PrivateKey) Sign(msg []byte) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "eddilithium3 signing") }()

	var sig [eddilithium3.SignatureSize]byte
	eddilithium3.SignTo(k.k, msg, sig[:])
	return sig[:], nil
}

// Type of the public key (EdDilithium3).
func (k *EdDilithium3PublicKey) Type() pb.KeyType {
	return pb.KeyType_EdDilithium3
}

// Raw public key bytes.
func (k *EdDilithium3PublicKey) Raw() ([]byte, error) {
	return k.k.Bytes(), nil
}

// Equals compares two ed25519 public keys.
func (k *EdDilithium3PublicKey) Equals(o Key) bool {
	edk, ok := o.(*EdDilithium3PublicKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

// Verify checks a signature against the input data.
func (k *EdDilithium3PublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "eddilithium3 signature verification")

		// To be safe.
		if err != nil {
			success = false
		}
	}()

	if len(sig) != eddilithium3.SignatureSize {
		return false, errors.New("expect eddilithium3 signature size to be " + strconv.Itoa(eddilithium3.SignatureSize))
	}

	return eddilithium3.Verify(k.k, data, sig), nil
}

// UnmarshalEdDilithium3PublicKey returns a public key from input bytes.
func UnmarshalEdDilithium3PublicKey(data []byte) (PubKey, error) {
	var buf [eddilithium3.PublicKeySize]byte
	if len(data) != eddilithium3.PublicKeySize {
		return nil, errors.New("expect eddilithium3 public key data size to be " + strconv.Itoa(eddilithium3.PublicKeySize))
	}
	copy(buf[:], data)

	pub := &eddilithium3.PublicKey{}
	pub.Unpack(&buf)
	return &EdDilithium3PublicKey{k: pub}, nil
}

// UnmarshalEdDilithium3PrivateKey returns a private key from input bytes.
func UnmarshalEdDilithium3PrivateKey(data []byte) (PrivKey, error) {
	var buf [eddilithium3.PrivateKeySize]byte
	if len(data) != eddilithium3.PrivateKeySize {
		return nil, errors.New("expect eddilithium3 private key data size to be " + strconv.Itoa(eddilithium3.PrivateKeySize))
	}
	copy(buf[:], data)

	priv := &eddilithium3.PrivateKey{}
	priv.Unpack(&buf)
	return &EdDilithium3PrivateKey{k: priv}, nil
}
