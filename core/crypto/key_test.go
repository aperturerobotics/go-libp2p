package crypto_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	. "github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/test"
)

func TestKeys(t *testing.T) {
	for _, typ := range KeyTypes {
		testKeyType(typ, t)
	}
}

func TestKeyPairFromKey(t *testing.T) {
	var (
		data = []byte(`hello world`)
	)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("err generating ed25519 key:\n%v", err)
	}
	sigEd := ed25519.Sign(edKey, data[:])

	for i, tt := range []struct {
		in  crypto.PrivateKey
		typ pb.KeyType
		sig []byte
	}{
		{
			&edKey,
			Ed25519,
			sigEd,
		},
	} {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			priv, pub, err := KeyPairFromStdKey(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			if priv == nil || pub == nil {
				t.Errorf("received nil private key or public key: %v, %v", priv, pub)
			}

			if priv == nil || priv.Type() != tt.typ {
				t.Errorf("want %v; got %v", tt.typ, priv.Type())
			}

			v, err := pub.Verify(data[:], tt.sig)
			if err != nil {
				t.Error(err)
			}

			if !v {
				t.Error("signature was not verified")
			}

			stdPub, err := PubKeyToStdKey(pub)
			if stdPub == nil {
				t.Errorf("err getting std public key from key: %v", err)
			}

			var stdPubBytes []byte

			switch p := stdPub.(type) {
			case ed25519.PublicKey:
				stdPubBytes = []byte(p)
			}

			if err != nil {
				t.Errorf("Error while marshaling %v key: %v", reflect.TypeOf(stdPub), err)
			}

			pubBytes, err := pub.Raw()
			if err != nil {
				t.Errorf("err getting raw bytes for %v key: %v", reflect.TypeOf(pub), err)
			}
			if !bytes.Equal(stdPubBytes, pubBytes) {
				t.Errorf("err roundtripping %v key", reflect.TypeOf(pub))
			}

			stdPriv, err := PrivKeyToStdKey(priv)
			if stdPub == nil {
				t.Errorf("err getting std private key from key: %v", err)
			}
			if err != nil {
				t.Errorf("err marshaling %v key: %v", reflect.TypeOf(stdPriv), err)
			}
		})
	}
}

func testKeyType(typ pb.KeyType, t *testing.T) {
	bits := 512
	sk, pk, err := test.RandTestKeyPair(typ, bits)
	if err != nil {
		t.Fatal(err)
	}

	testKeySignature(t, sk)
	testKeyEncoding(t, sk)
	testKeyEquals(t, sk)
	testKeyEquals(t, pk)
}

func testKeySignature(t *testing.T, sk PrivKey) {
	pk := sk.GetPublic()

	text := make([]byte, 16)
	if _, err := rand.Read(text); err != nil {
		t.Fatal(err)
	}

	sig, err := sk.Sign(text)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := pk.Verify(text, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("Invalid signature.")
	}
}

func testKeyEncoding(t *testing.T, sk PrivKey) {
	skbm, err := MarshalPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	sk2, err := UnmarshalPrivateKey(skbm)
	if err != nil {
		t.Fatal(err)
	}

	if !sk.Equals(sk2) {
		t.Error("Unmarshaled private key didn't match original.\n")
	}

	skbm2, err := MarshalPrivateKey(sk2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(skbm, skbm2) {
		t.Error("skb -> marshal -> unmarshal -> skb failed.\n", skbm, "\n", skbm2)
	}

	pk := sk.GetPublic()
	pkbm, err := MarshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := UnmarshalPublicKey(pkbm)
	if err != nil {
		t.Fatal(err)
	}

	if !pk.Equals(pk2) {
		t.Error("Unmarshaled public key didn't match original.\n")
	}

	pkbm2, err := MarshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkbm, pkbm2) {
		t.Error("skb -> marshal -> unmarshal -> skb failed.\n", pkbm, "\n", pkbm2)
	}
}

func testKeyEquals(t *testing.T, k Key) {
	if !KeyEqual(k, k) {
		t.Fatal("Key not equal to itself.")
	}

	sk, pk, err := test.RandTestKeyPair(Ed25519, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if KeyEqual(k, sk) {
		t.Fatal("Keys should not equal.")
	}

	if KeyEqual(k, pk) {
		t.Fatal("Keys should not equal.")
	}
}
