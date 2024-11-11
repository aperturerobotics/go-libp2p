package peer_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	. "github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"

	mh "github.com/multiformats/go-multihash"
)

var gen1 keyset // generated
var gen2 keyset // generated

func hash(b []byte) []byte {
	h, _ := mh.Sum(b, mh.SHA2_256, -1)
	return []byte(h)
}

func init() {
	if err := gen1.generate(); err != nil {
		panic(err)
	}
	if err := gen2.generate(); err != nil {
		panic(err)
	}

}

type keyset struct {
	sk   ic.PrivKey
	pk   ic.PubKey
	hpk  string
	hpkp string
}

func (ks *keyset) generate() error {
	var err error
	ks.sk, ks.pk, err = test.RandTestKeyPair(ic.Ed25519, 1024)
	if err != nil {
		return err
	}

	p2, err := IDFromPublicKey(ks.pk)
	if err != nil {
		return err
	}

	ks.hpk = string(p2)
	ks.hpkp = p2.String()

	return nil
}

func (ks *keyset) load(hpkp, skBytesStr string) error {
	skBytes, err := base64.StdEncoding.DecodeString(skBytesStr)
	if err != nil {
		return err
	}

	ks.sk, err = ic.UnmarshalPrivateKey(skBytes)
	if err != nil {
		return err
	}

	ks.pk = ks.sk.GetPublic()
	p2, err := IDFromPublicKey(ks.pk)
	if err != nil {
		return err
	}

	ks.hpk = string(p2)
	ks.hpkp = p2.String()
	if ks.hpkp != hpkp {
		return fmt.Errorf("hpkp %q doesn't match key %q", hpkp, ks.hpkp)
	}
	return nil
}

func TestIDMatchesPublicKey(t *testing.T) {
	test := func(ks keyset) {
		p1, err := Decode(ks.hpkp)
		if err != nil {
			t.Fatal(err)
		}

		if ks.hpk != string(p1) {
			t.Error("p1 and hpk differ")
		}

		if !p1.MatchesPublicKey(ks.pk) {
			t.Fatal("p1 does not match pk")
		}

		p2, err := IDFromPublicKey(ks.pk)
		if err != nil {
			t.Fatal(err)
		}

		if p1 != p2 {
			t.Error("p1 and p2 differ", p1.String(), p2.String())
		}

		if p2.String() != ks.hpkp {
			t.Error("hpkp and p2.String differ", ks.hpkp, p2.String())
		}
	}

	test(gen1)
	test(gen2)
}

func TestIDMatchesPrivateKey(t *testing.T) {

	test := func(ks keyset) {
		p1, err := Decode(ks.hpkp)
		if err != nil {
			t.Fatal(err)
		}

		if ks.hpk != string(p1) {
			t.Error("p1 and hpk differ")
		}

		if !p1.MatchesPrivateKey(ks.sk) {
			t.Fatal("p1 does not match sk")
		}

		p2, err := IDFromPrivateKey(ks.sk)
		if err != nil {
			t.Fatal(err)
		}

		if p1 != p2 {
			t.Error("p1 and p2 differ", p1.String(), p2.String())
		}
	}

	test(gen1)
	test(gen2)
}

func TestIDEncoding(t *testing.T) {
	test := func(ks keyset) {
		p1, err := Decode(ks.hpkp)
		if err != nil {
			t.Fatal(err)
		}

		if ks.hpk != string(p1) {
			t.Error("p1 and hpk differ")
		}

		p3, err := Decode(p1.String())
		if err != nil {
			t.Fatal(err)
		}
		if p3 != p1 {
			t.Fatal("failed to round trip through CID string")
		}

		if ks.hpkp != p1.String() {
			t.Fatal("should always encode peer IDs as base58 by default")
		}
	}

	test(gen1)
	test(gen2)

	exampleCid := "bafkreifoybygix7fh3r3g5rqle3wcnhqldgdg4shzf4k3ulyw3gn7mabt4"
	_, err := Decode(exampleCid)
	if err == nil {
		t.Fatal("should refuse to decode a non-peer ID CID")
	}
}

func TestPublicKeyExtraction(t *testing.T) {
	t.Skip("disabled until libp2p/go-libp2p-crypto#51 is fixed")
	// Happy path
	_, originalPub, err := ic.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	id, err := IDFromPublicKey(originalPub)
	if err != nil {
		t.Fatal(err)
	}

	extractedPub, err := id.ExtractPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if extractedPub == nil {
		t.Fatal("failed to extract public key")
	}
	if !originalPub.Equals(extractedPub) {
		t.Fatal("extracted public key doesn't match")
	}

	// Test invalid multihash (invariant of the type of public key)
	pk, err := ID("").ExtractPublicKey()
	if err == nil {
		t.Fatal("expected an error")
	}
	if pk != nil {
		t.Fatal("expected a nil public key")
	}

	// Shouldn't work for, e.g. RSA keys (too large)

	_, rsaPub, err := ic.GenerateKeyPair(ic.Ed25519, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaId, err := IDFromPublicKey(rsaPub)
	if err != nil {
		t.Fatal(err)
	}
	extractedRsaPub, err := rsaId.ExtractPublicKey()
	if err != ErrNoPublicKey {
		t.Fatal(err)
	}
	if extractedRsaPub != nil {
		t.Fatal("expected to fail to extract public key from rsa ID")
	}
}

func TestValidate(t *testing.T) {
	// Empty peer ID invalidates
	err := ID("").Validate()
	if err == nil {
		t.Error("expected error")
	} else if err != ErrEmptyPeerID {
		t.Error("expected error message: " + ErrEmptyPeerID.Error())
	}

	// Non-empty peer ID validates
	p, err := test.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}

	err = p.Validate()
	if err != nil {
		t.Error("expected nil, but found " + err.Error())
	}
}
