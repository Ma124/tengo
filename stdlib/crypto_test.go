package stdlib_test

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"github.com/d5/tengo/stdlib"
	"testing"
)

const hashInp1 = "abc"
const hashSha256Hex1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
const hashSha512Hex1 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

func TestCryptoModuleHash(t *testing.T) {
	// load crypto/sha256 and crypto/sha512
	stdlib.ReloadCryptoAlgorithms()

	// to provide coverage on:
	// if _, ok := cryptoModule[n]; ok {
	//     continue
	// }
	stdlib.ReloadCryptoAlgorithms()

	testHashFunc(t, "sha256", hashInp1, hashSha256Hex1)
	testHashFunc(t, "sha512", hashInp1, hashSha512Hex1)

	module(t, `crypto`).call("sha256").expectError()
	module(t, `crypto`).call("sha256", 2).expectError()
	module(t, `crypto`).call("sha256", "a", "b").expectError()

	module(t, `crypto`).call("sha256_hex").expectError()
	module(t, `crypto`).call("sha256_hex", 2).expectError()
	module(t, `crypto`).call("sha256_hex", "a", "b").expectError()
}

func testHashFunc(t *testing.T, alg string, inp, hexs string) {
	t.Run(alg+"_"+inp, func(t *testing.T) {
		bys, err := hex.DecodeString(hexs)
		if err != nil {
			panic(err)
		}

		module(t, `crypto`).call(alg, inp).expect(bys)
		module(t, `crypto`).call(alg, []byte(inp)).expect(bys)
		module(t, `crypto`).call(alg+"_hex", inp).expect(hexs)
		module(t, `crypto`).call(alg+"_hex", []byte(inp)).expect(hexs)
	})
}
