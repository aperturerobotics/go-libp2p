package crypto

import (
	"errors"
	"io"
	"strconv"

	"github.com/cloudflare/circl/sign/eddilithium2"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

// EdDilithium2PrivateKey is an hybrid signature scheme Ed448-Dilithium2 private key.
type EdDilithium2PrivateKey struct {
	k *eddilithium2.PrivateKey
}

// EdDilithium2PublicKey is an hybrid signature scheme Ed448-Dilithium2 public key.
type EdDilithium2PublicKey struct {
	k *eddilithium2.PublicKey
}

// GenerateEdDilithium2Key generates a new private and public key pair.
func GenerateEdDilithium2Key(src io.Reader) (PrivKey, PubKey, error) {
	pub, priv, err := eddilithium2.GenerateKey(src)
	if err != nil {
		return nil, nil, err
	}

	return &EdDilithium2PrivateKey{
			k: priv,
		},
		&EdDilithium2PublicKey{
			k: pub,
		},
		nil
}

// Type of the private key (EdDilithium2).
func (k *EdDilithium2PrivateKey) Type() pb.KeyType {
	return pb.KeyType_EdDilithium2
}

// Raw private key bytes.
func (k *EdDilithium2PrivateKey) Raw() ([]byte, error) {
	return k.k.Bytes(), nil
}

// Equals compares two EdDilithium2 private keys.
func (k *EdDilithium2PrivateKey) Equals(o Key) bool {
	edk, ok := o.(*EdDilithium2PrivateKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

// GetPublic returns an EdDilithium2 public key from a private key.
func (k *EdDilithium2PrivateKey) GetPublic() PubKey {
	return &EdDilithium2PublicKey{k: k.k.Public().(*eddilithium2.PublicKey)}
}

// Sign returns a signature from an input message.
func (k *EdDilithium2PrivateKey) Sign(msg []byte) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "eddilithium2 signing") }()

	var sig [eddilithium2.SignatureSize]byte
	eddilithium2.SignTo(k.k, msg, sig[:])
	return sig[:], nil
}

// Type of the public key (EdDilithium2).
func (k *EdDilithium2PublicKey) Type() pb.KeyType {
	return pb.KeyType_EdDilithium2
}

// Raw public key bytes.
func (k *EdDilithium2PublicKey) Raw() ([]byte, error) {
	return k.k.Bytes(), nil
}

// Equals compares two EdDilithium2 public keys.
func (k *EdDilithium2PublicKey) Equals(o Key) bool {
	edk, ok := o.(*EdDilithium2PublicKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

// Verify checks a signature against the input data.
func (k *EdDilithium2PublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "eddilithium2 signature verification")

		// To be safe.
		if err != nil {
			success = false
		}
	}()

	if len(sig) != eddilithium2.SignatureSize {
		return false, errors.New("expect eddilithium2 signature size to be " + strconv.Itoa(eddilithium2.SignatureSize))
	}

	return eddilithium2.Verify(k.k, data, sig), nil
}

// UnmarshalEdDilithium2PublicKey returns a public key from input bytes.
func UnmarshalEdDilithium2PublicKey(data []byte) (PubKey, error) {
	var buf [eddilithium2.PublicKeySize]byte
	if len(data) != eddilithium2.PublicKeySize {
		return nil, errors.New("expect eddilithium2 public key data size to be " + strconv.Itoa(eddilithium2.PublicKeySize))
	}
	copy(buf[:], data)

	pub := &eddilithium2.PublicKey{}
	pub.Unpack(&buf)
	return &EdDilithium2PublicKey{k: pub}, nil
}

// UnmarshalEdDilithium2PrivateKey returns a private key from input bytes.
func UnmarshalEdDilithium2PrivateKey(data []byte) (PrivKey, error) {
	var buf [eddilithium2.PrivateKeySize]byte
	if len(data) != eddilithium2.PrivateKeySize {
		return nil, errors.New("expect eddilithium2 private key data size to be " + strconv.Itoa(eddilithium2.PrivateKeySize))
	}
	copy(buf[:], data)

	priv := &eddilithium2.PrivateKey{}
	priv.Unpack(&buf)
	return &EdDilithium2PrivateKey{k: priv}, nil
}
