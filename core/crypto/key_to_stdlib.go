package crypto

import (
	"crypto"
	"crypto/ed25519"
	"errors"
)

var (
	// ErrNilPrivateKey is returned when a nil private key is provided
	ErrNilPrivateKey = errors.New("private key is nil")
	// ErrNilPublicKey is returned when a nil public key is provided
	ErrNilPublicKey = errors.New("public key is nil")
)

// KeyPairFromStdKey wraps standard library (and secp256k1) private keys in libp2p/go-libp2p/core/crypto keys
func KeyPairFromStdKey(priv crypto.PrivateKey) (PrivKey, PubKey, error) {
	if priv == nil {
		return nil, nil, ErrNilPrivateKey
	}

	switch p := priv.(type) {
	case *ed25519.PrivateKey:
		pubIfc := p.Public()
		pub, _ := pubIfc.(ed25519.PublicKey)
		return &Ed25519PrivateKey{*p}, &Ed25519PublicKey{pub}, nil

	default:
		return nil, nil, ErrBadKeyType
	}
}

// PrivKeyToStdKey converts libp2p/go-libp2p/core/crypto private keys to standard library (and secp256k1) private keys
func PrivKeyToStdKey(priv PrivKey) (crypto.PrivateKey, error) {
	if priv == nil {
		return nil, ErrNilPrivateKey
	}

	switch p := priv.(type) {
	case *Ed25519PrivateKey:
		return &p.k, nil
	default:
		return nil, ErrBadKeyType
	}
}

// PubKeyToStdKey converts libp2p/go-libp2p/core/crypto private keys to standard library (and secp256k1) public keys
func PubKeyToStdKey(pub PubKey) (crypto.PublicKey, error) {
	if pub == nil {
		return nil, ErrNilPublicKey
	}

	switch p := pub.(type) {
	case *Ed25519PublicKey:
		return p.k, nil
	default:
		return nil, ErrBadKeyType
	}
}
