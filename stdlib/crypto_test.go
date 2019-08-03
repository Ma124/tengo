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
const hmacKey1 = "foo"
const hmacSha256Hex1 = "2febde8cad3b3e67067bc8784b1bcf966529c89a999e6c430b9cd536e3a16b52"
const hmacSha512Hex1 = "8b1b13b14acf670d3da19159cf68c36121bde60cfab9a7dba8a8d241bdd10fcac4449c91c4e861bfc73de4cf55f2d9f3ee6ff6e608111942a9a7a953a4a9380f"

func TestCryptoModuleHash(t *testing.T) {
	// load crypto/sha256 and crypto/sha512
	stdlib.ReloadCryptoAlgorithms()

	// to provide coverage on:
	// if _, ok := cryptoModule[n]; ok {
	//     continue
	// }
	stdlib.ReloadCryptoAlgorithms()

	testHashFunc(t, "sha256", hashInp1, hashSha256Hex1, hmacKey1, hmacSha256Hex1)
	testHashFunc(t, "sha512", hashInp1, hashSha512Hex1, hmacKey1, hmacSha512Hex1)

	module(t, `crypto`).call("sha256").expectError()
	module(t, `crypto`).call("sha256", 2).expectError()
	module(t, `crypto`).call("sha256", "a", "b").expectError()

	module(t, `crypto`).call("sha256_hex").expectError()
	module(t, `crypto`).call("sha256_hex", 2).expectError()
	module(t, `crypto`).call("sha256_hex", "a", "b").expectError()

	module(t, `crypto`).call("hmac_sha256").expectError()
	module(t, `crypto`).call("hmac_sha256", "a").expectError()
	module(t, `crypto`).call("hmac_sha256", "a", "b", "c").expectError()
	module(t, `crypto`).call("hmac_sha256", 2, "b").expectError()
	module(t, `crypto`).call("hmac_sha256", "a", 2).expectError()

	module(t, `crypto`).call("hmac_sha256_hex").expectError()
	module(t, `crypto`).call("hmac_sha256_hex", "a").expectError()
	module(t, `crypto`).call("hmac_sha256_hex", "a", "b", "c").expectError()
	module(t, `crypto`).call("hmac_sha256_hex", 2, "b").expectError()
	module(t, `crypto`).call("hmac_sha256_hex", "a", 2).expectError()
}

func testHashFunc(t *testing.T, alg string, inp, hexs, macKey, macHex string) {
	t.Run(alg+"_"+inp, func(t *testing.T) {
		bys, err := hex.DecodeString(hexs)
		if err != nil {
			panic(err)
		}

		// only test non _hex function if _hex function was successful, avoids binary chars printed to diffs but still fails if alg or alg_hex fail
		if module(t, `crypto`).call(alg+"_hex", []byte(inp)).expect(hexs) {
			module(t, `crypto`).call(alg, []byte(inp)).expect(bys)
		}
		if module(t, `crypto`).call(alg+"_hex", inp).expect(hexs) {
			module(t, `crypto`).call(alg, inp).expect(bys)
		}
	})
	t.Run("hmac_"+alg+"_"+inp, func(t *testing.T) {
		macBys, err := hex.DecodeString(macHex)
		if err != nil {
			panic(err)
		}

		if module(t, `crypto`).call("hmac_"+alg+"_hex", inp, macKey).expect(macHex) {
			module(t, `crypto`).call("hmac_"+alg, inp, macKey).expect(macBys)
		}
		if module(t, `crypto`).call("hmac_"+alg+"_hex", []byte(inp), macKey).expect(macHex) {
			module(t, `crypto`).call("hmac_"+alg, []byte(inp), macKey).expect(macBys)
		}

		if module(t, `crypto`).call("hmac_"+alg+"_hex", inp, []byte(macKey)).expect(macHex) {
			module(t, `crypto`).call("hmac_"+alg, inp, []byte(macKey)).expect(macBys)
		}
		if module(t, `crypto`).call("hmac_"+alg+"_hex", []byte(inp), []byte(macKey)).expect(macHex) {
			module(t, `crypto`).call("hmac_"+alg, []byte(inp), []byte(macKey)).expect(macBys)
		}
	})
}
