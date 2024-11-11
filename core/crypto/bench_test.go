package crypto

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto/pb"
)

func BenchmarkSignEd255191B(b *testing.B)      { RunBenchmarkSignEd25519(b, 1) }
func BenchmarkSignEd2551910B(b *testing.B)     { RunBenchmarkSignEd25519(b, 10) }
func BenchmarkSignEd25519100B(b *testing.B)    { RunBenchmarkSignEd25519(b, 100) }
func BenchmarkSignEd255191000B(b *testing.B)   { RunBenchmarkSignEd25519(b, 1000) }
func BenchmarkSignEd2551910000B(b *testing.B)  { RunBenchmarkSignEd25519(b, 10000) }
func BenchmarkSignEd25519100000B(b *testing.B) { RunBenchmarkSignEd25519(b, 100000) }

func BenchmarkVerifyEd255191B(b *testing.B)      { RunBenchmarkVerifyEd25519(b, 1) }
func BenchmarkVerifyEd2551910B(b *testing.B)     { RunBenchmarkVerifyEd25519(b, 10) }
func BenchmarkVerifyEd25519100B(b *testing.B)    { RunBenchmarkVerifyEd25519(b, 100) }
func BenchmarkVerifyEd255191000B(b *testing.B)   { RunBenchmarkVerifyEd25519(b, 1000) }
func BenchmarkVerifyEd2551910000B(b *testing.B)  { RunBenchmarkVerifyEd25519(b, 10000) }
func BenchmarkVerifyEd25519100000B(b *testing.B) { RunBenchmarkVerifyEd25519(b, 100000) }

func RunBenchmarkSignEd25519(b *testing.B, numBytes int) {
	runBenchmarkSign(b, numBytes, Ed25519)
}

func runBenchmarkSign(b *testing.B, numBytes int, t pb.KeyType) {
	secret, _, err := GenerateKeyPair(t, 2048)
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, numBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := secret.Sign(someData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func RunBenchmarkVerifyEd25519(b *testing.B, numBytes int) {
	runBenchmarkVerify(b, numBytes, Ed25519)
}

func runBenchmarkVerify(b *testing.B, numBytes int, t pb.KeyType) {
	secret, public, err := GenerateKeyPair(t, 2048)
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, numBytes)
	signature, err := secret.Sign(someData)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := public.Verify(someData, signature)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("signature should be valid")
		}
	}
}
