package tlsdiag

import (
	"crypto/rand"
	"fmt"

	ic "github.com/libp2p/go-libp2p/core/crypto"
)

func generateKey(keyType string) (priv ic.PrivKey, err error) {
	switch keyType {
	case "ed25519":
		fmt.Printf("Generated new peer with an Ed25519 key.")
		priv, _, err = ic.GenerateEd25519Key(rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}
	return
}
