package stdlib

import (
	"crypto"
	"encoding/hex"
	"github.com/d5/tengo/objects"
	"hash"
	"strings"
)

var cryptoModule = make(map[string]objects.Object, len(hashNames))

// TODO [crypto](https://github.com/d5/tengo/blob/master/docs/stdlib-crypto.md): cryptographic functions like hashes and ciphers
// TODO ciphers

func init() {
	ReloadCryptoAlgorithms()
}

func ReloadCryptoAlgorithms() {
	for h, n := range hashNames {
		if !h.Available() {
			continue
		}

		n = strings.ToLower(n)

		if _, ok := cryptoModule[n]; ok {
			continue
		}
		cryptoModule[n] = &objects.UserFunction{Name: n, Value: newHashFunc(h.New(), false)}
		cryptoModule[n+"_hex"] = &objects.UserFunction{Name: n + "_hex", Value: newHashFunc(h.New(), true)}
	}
}

// Should be the same as crypto.maxHash
const maxHash = 20

// vim command for generation from buffer with newline separated entries: %s/\v^(\w+)$/crypto.\1: "\1",/g
var hashNames = map[crypto.Hash]string{
	crypto.MD4:         "MD4",
	crypto.MD5:         "MD5",
	crypto.SHA1:        "SHA1",
	crypto.SHA224:      "SHA224",
	crypto.SHA256:      "SHA256",
	crypto.SHA384:      "SHA384",
	crypto.SHA512:      "SHA512",
	crypto.MD5SHA1:     "MD5SHA1",
	crypto.RIPEMD160:   "RIPEMD160",
	crypto.SHA3_224:    "SHA3_224",
	crypto.SHA3_256:    "SHA3_256",
	crypto.SHA3_384:    "SHA3_384",
	crypto.SHA3_512:    "SHA3_512",
	crypto.SHA512_224:  "SHA512_224",
	crypto.SHA512_256:  "SHA512_256",
	crypto.BLAKE2s_256: "BLAKE2s_256",
	crypto.BLAKE2b_256: "BLAKE2b_256",
	crypto.BLAKE2b_384: "BLAKE2b_384",
	crypto.BLAKE2b_512: "BLAKE2b_512",
}

func newHashFunc(h hash.Hash, returnHex bool) objects.CallableFunc {
	return func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 1 {
			return nil, objects.ErrWrongNumArguments
		}

		inp, ok := args[0].(*objects.Bytes)
		if !ok {
			s, ok := args[0].(*objects.String)
			if ok {
				inp = &objects.Bytes{
					Value: []byte(s.Value),
				}
			} else {
				return nil, objects.ErrInvalidArgumentType{
					Name:     "first",
					Expected: "bytes",
					Found:    args[0].TypeName(),
				}
			}
		}

		h.Write(inp.Value)

		out := make([]byte, 0, h.Size())

		out = h.Sum(out)
		h.Reset()

		if returnHex {
			return &objects.String{
				Value: hex.EncodeToString(out),
			}, nil
		} else {
			return &objects.Bytes{
				Value: out,
			}, nil
		}
	}
}
