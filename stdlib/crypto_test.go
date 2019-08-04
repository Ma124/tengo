package stdlib_test

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"github.com/d5/tengo/objects"
	"github.com/d5/tengo/stdlib"
	"testing"
)

// len(ciphAESIV) == AESBlockSize == 16
const ciphAESIV = "1234567890123456"

// len(ciphAES128Key) == AES128KeySize == 16
const ciphAES128Key = "6543210987654321"

// len(ciphPlain1) == AESBlockSize
const ciphPlain1 = "abcdefghijklmnop"

// len(ciphPlain2) == (AESBlockSize/2)-1
const ciphPlain2 = "abcdefg"

// len(ciphPlain3) == (AESBlockSize * 2) + ((AESBlockSize/2)-1)
const ciphPlain3 = "abcdefghijklmnopabcdefghijklmnopabcdefg"

func TestCryptoModuleCipher(t *testing.T) {
	testCipherFunc(t, "aes_cbc", ciphPlain1, ciphAES128Key, ciphAESIV, "L+BfSsDnX1I1eiSWDxxg3Q==")

	testCipherFunc(t, "aes_ctr", ciphPlain1, ciphAES128Key, ciphAESIV, "9Tv9rHveyjeO4a/6UDoRdQ==")
	testCipherFunc(t, "aes_ctr", ciphPlain2, ciphAES128Key, ciphAESIV, "9Tv9rHveyg==")
	testCipherFunc(t, "aes_ctr", ciphPlain3, ciphAES128Key, ciphAESIV, "9Tv9rHveyjeO4a/6UDoRdUTnR6fCxieR1473kNfqo4XzwKc0Cnw8")

	testCipherFunc(t, "aes_ofb", ciphPlain1, ciphAES128Key, ciphAESIV, "9Tv9rHveyjeO4a/6UDoRdQ==")
	testCipherFunc(t, "aes_ofb", ciphPlain2, ciphAES128Key, ciphAESIV, "9Tv9rHveyg==")
	testCipherFunc(t, "aes_ofb", ciphPlain3, ciphAES128Key, ciphAESIV, "9Tv9rHveyjeO4a/6UDoRdZ0leQQ8Z40RCwkMEr5igiBFUdFvJe/C")

	module(t, `crypto`).call("encrypt_aes_cbc").expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1).expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, ciphAES128Key).expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, ciphAES128Key, ciphAESIV, "too many").expectError()

	module(t, `crypto`).call("encrypt_aes_cbc", 1, ciphAES128Key, ciphAESIV).expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain3, ciphAES128Key, ciphAESIV).expectError()

	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, 1, ciphAESIV).expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, ciphAES128Key+"a", ciphAESIV).expectError()

	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, ciphAES128Key, 1).expectError()
	module(t, `crypto`).call("encrypt_aes_cbc", ciphPlain1, ciphAES128Key, ciphPlain3).expectError()
}

func testCipherFunc(t *testing.T, alg, plain, key, iv, ciphb64 string) {
	t.Run(alg+"__"+plain, func(t *testing.T) {
		ciph, err := base64.StdEncoding.DecodeString(ciphb64)
		if err != nil {
			panic(err)
		}

		module(t, `crypto`).call("encrypt_"+alg, plain, key, iv).expect(ciph)
		module(t, `crypto`).call("decrypt_"+alg, ciph, key, iv).expect([]byte(plain))
	})
}

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
	t.Run(alg+"__"+inp, func(t *testing.T) {
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
	t.Run("hmac_"+alg+"__"+inp, func(t *testing.T) {
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

func testPadFunc(t *testing.T, alg string, unpadded string, padded []byte, l int) {
	module(t, `crypto`).call("pad_" + alg, unpadded, l).expect(padded)
	module(t, `crypto`).call("unpad_" + alg, padded, l).expect([]byte(unpadded))
}

func TestCryptoModuleUtilities(t *testing.T) {
	testPadFunc(t, "pkcs7", "abc", []byte{'a', 'b', 'c', 0x02, 0x02}, 5)
	testPadFunc(t, "pkcs7", "abcde", []byte{'a', 'b', 'c', 'd', 'e', 0x05, 0x05, 0x05, 0x05, 0x05}, 5)

	module(t, `crypto`).call("pad_pkcs7").expectError()
	module(t, `crypto`).call("pad_pkcs7", "abc", &objects.Array{}).expectError()
	module(t, `crypto`).call("pad_pkcs7", &objects.Array{}, 5).expectError()
	module(t, `crypto`).call("pad_pkcs7", "abc", 5, "d").expectError()
	module(t, `crypto`).call("pad_pkcs7", "abc", 256).expectError()
	module(t, `crypto`).call("pad_pkcs7", "abc", -1).expectError()

	module(t, `crypto`).call("unpad_pkcs7").expectError()
	module(t, `crypto`).call("unpad_pkcs7", "abc", &objects.Array{}).expectError()
	module(t, `crypto`).call("unpad_pkcs7", &objects.Array{}, 5).expectError()
	module(t, `crypto`).call("unpad_pkcs7", "abc", 5, "d").expectError()
	module(t, `crypto`).call("unpad_pkcs7", "abc", 256).expectError()
	module(t, `crypto`).call("unpad_pkcs7", "abc", -1).expectError()

	module(t, `crypto`).call("unpad_pkcs7", "abc", 2).expectError()
	module(t, `crypto`).call("unpad_pkcs7", "abc", 3).expect(stdlib.ErrMalformedPadding)
	module(t, `crypto`).call("unpad_pkcs7", []byte{'a', 'b', 'c', 0x02, 0x03, 0x02}, 6).expect(stdlib.ErrMalformedPadding)
	module(t, `crypto`).call("unpad_pkcs7", []byte{'a', 'b', 'c', 0x02, 0x02, 0x03}, 6).expect(stdlib.ErrMalformedPadding)

	module(t, `crypto`).call("rand_bytes").expectError()
	module(t, `crypto`).call("rand_bytes", 1, 1).expectError()
	module(t, `crypto`).call("rand_bytes", -1).expectError()
	module(t, `crypto`).call("rand_bytes", &objects.Array{}).expectError()
	o := module(t, `crypto`).call("rand_bytes", 8).o
	bs, ok := o.(*objects.Bytes)
	if !ok {
		t.Errorf("crypto.rand_bytes(8) returns wrong type: %T", o)
	} else if len(bs.Value) != 8 {
		t.Errorf("crypto.rand_bytes(8) returns wrong length: %v", len(bs.Value))
	}
}