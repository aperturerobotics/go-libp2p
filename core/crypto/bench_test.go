package crypto

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto/pb"
)

func BenchmarkSignRSA1B(b *testing.B)      { RunBenchmarkSignRSA(b, 1) }
func BenchmarkSignRSA10B(b *testing.B)     { RunBenchmarkSignRSA(b, 10) }
func BenchmarkSignRSA100B(b *testing.B)    { RunBenchmarkSignRSA(b, 100) }
func BenchmarkSignRSA1000B(b *testing.B)   { RunBenchmarkSignRSA(b, 1000) }
func BenchmarkSignRSA10000B(b *testing.B)  { RunBenchmarkSignRSA(b, 10000) }
func BenchmarkSignRSA100000B(b *testing.B) { RunBenchmarkSignRSA(b, 100000) }

func BenchmarkVerifyRSA1B(b *testing.B)      { RunBenchmarkVerifyRSA(b, 1) }
func BenchmarkVerifyRSA10B(b *testing.B)     { RunBenchmarkVerifyRSA(b, 10) }
func BenchmarkVerifyRSA100B(b *testing.B)    { RunBenchmarkVerifyRSA(b, 100) }
func BenchmarkVerifyRSA1000B(b *testing.B)   { RunBenchmarkVerifyRSA(b, 1000) }
func BenchmarkVerifyRSA10000B(b *testing.B)  { RunBenchmarkVerifyRSA(b, 10000) }
func BenchmarkVerifyRSA100000B(b *testing.B) { RunBenchmarkVerifyRSA(b, 100000) }

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

func BenchmarkSignEdDilithium31B(b *testing.B)      { RunBenchmarkSignEdDilithium3(b, 1) }
func BenchmarkSignEdDilithium310B(b *testing.B)     { RunBenchmarkSignEdDilithium3(b, 10) }
func BenchmarkSignEdDilithium3100B(b *testing.B)    { RunBenchmarkSignEdDilithium3(b, 100) }
func BenchmarkSignEdDilithium31000B(b *testing.B)   { RunBenchmarkSignEdDilithium3(b, 1000) }
func BenchmarkSignEdDilithium310000B(b *testing.B)  { RunBenchmarkSignEdDilithium3(b, 10000) }
func BenchmarkSignEdDilithium3100000B(b *testing.B) { RunBenchmarkSignEdDilithium3(b, 100000) }

func BenchmarkVerifyEdDilithium31B(b *testing.B)      { RunBenchmarkVerifyEdDilithium3(b, 1) }
func BenchmarkVerifyEdDilithium310B(b *testing.B)     { RunBenchmarkVerifyEdDilithium3(b, 10) }
func BenchmarkVerifyEdDilithium3100B(b *testing.B)    { RunBenchmarkVerifyEdDilithium3(b, 100) }
func BenchmarkVerifyEdDilithium31000B(b *testing.B)   { RunBenchmarkVerifyEdDilithium3(b, 1000) }
func BenchmarkVerifyEdDilithium310000B(b *testing.B)  { RunBenchmarkVerifyEdDilithium3(b, 10000) }
func BenchmarkVerifyEdDilithium3100000B(b *testing.B) { RunBenchmarkVerifyEdDilithium3(b, 100000) }

func RunBenchmarkSignRSA(b *testing.B, numBytes int) {
	runBenchmarkSign(b, numBytes, RSA)
}

func RunBenchmarkSignEd25519(b *testing.B, numBytes int) {
	runBenchmarkSign(b, numBytes, Ed25519)
}

func RunBenchmarkSignEdDilithium2(b *testing.B, numBytes int) {
	runBenchmarkSign(b, numBytes, EdDilithium2)
}

func RunBenchmarkSignEdDilithium3(b *testing.B, numBytes int) {
	runBenchmarkSign(b, numBytes, EdDilithium3)
}

func runBenchmarkSign(b *testing.B, numBytes int, t pb.KeyType) {
	var secret PrivKey
	var err error
	if t == EdDilithium2 || t == EdDilithium3 {
		secret, _, err = GenerateKeyPair(t, 0)
	} else {
		secret, _, err = GenerateKeyPair(t, 2048)
	}
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

func RunBenchmarkVerifyRSA(b *testing.B, numBytes int) {
	runBenchmarkVerify(b, numBytes, RSA)
}

func RunBenchmarkVerifyEd25519(b *testing.B, numBytes int) {
	runBenchmarkVerify(b, numBytes, Ed25519)
}

func RunBenchmarkVerifyEdDilithium3(b *testing.B, numBytes int) {
	runBenchmarkVerify(b, numBytes, EdDilithium3)
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
func BenchmarkSignEdDilithium21B(b *testing.B)      { RunBenchmarkSignEdDilithium2(b, 1) }
func BenchmarkSignEdDilithium210B(b *testing.B)     { RunBenchmarkSignEdDilithium2(b, 10) }
func BenchmarkSignEdDilithium2100B(b *testing.B)    { RunBenchmarkSignEdDilithium2(b, 100) }
func BenchmarkSignEdDilithium21000B(b *testing.B)   { RunBenchmarkSignEdDilithium2(b, 1000) }
func BenchmarkSignEdDilithium210000B(b *testing.B)  { RunBenchmarkSignEdDilithium2(b, 10000) }
func BenchmarkSignEdDilithium2100000B(b *testing.B) { RunBenchmarkSignEdDilithium2(b, 100000) }

func BenchmarkVerifyEdDilithium21B(b *testing.B)      { RunBenchmarkVerifyEdDilithium2(b, 1) }
func BenchmarkVerifyEdDilithium210B(b *testing.B)     { RunBenchmarkVerifyEdDilithium2(b, 10) }
func BenchmarkVerifyEdDilithium2100B(b *testing.B)    { RunBenchmarkVerifyEdDilithium2(b, 100) }
func BenchmarkVerifyEdDilithium21000B(b *testing.B)   { RunBenchmarkVerifyEdDilithium2(b, 1000) }
func BenchmarkVerifyEdDilithium210000B(b *testing.B)  { RunBenchmarkVerifyEdDilithium2(b, 10000) }
func BenchmarkVerifyEdDilithium2100000B(b *testing.B) { RunBenchmarkVerifyEdDilithium2(b, 100000) }
func RunBenchmarkVerifyEdDilithium2(b *testing.B, numBytes int) {
	runBenchmarkVerify(b, numBytes, EdDilithium2)
}
