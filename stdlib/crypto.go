package stdlib

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/d5/tengo/objects"
	"hash"
	"strings"
)

var cryptoModule = make(
	map[string]objects.Object,
	len(hashNames)*4+ // # of hashes
		1*4*2+ // # of block ciphers
		3, // # of utilities
)

// TODO [crypto](https://github.com/d5/tengo/blob/master/docs/stdlib-crypto.md): cryptographic functions like hashes and ciphers
// TODO keyderiv
// TODO paddings for CBC PKCS#7
// TODO x509
// TODO asymmetric ciphers

var ErrMalformedPadding = &objects.Error{Value: &objects.String{Value: fmt.Sprintf("malformed padding")}}

func init() {
	ReloadCryptoAlgorithms()
	registerBlockCipher(&blockCiph{
		MName:      "aes",
		MBlockSize: aes.BlockSize,
		MKeySizes:  []int{128 / 8, 192 / 8, 256 / 8},
		NewBlock: func(key []byte) cipher.Block {
			c, err := aes.NewCipher(key)
			if err != nil {
				// key sizes are checked beforehand
				panic(err)
			}
			return c
		},
	})
	cryptoModule["pad_pkcs7"] = &objects.UserFunction{Name: "pad_pkcs7", Value: func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 2 {
			return nil, objects.ErrWrongNumArguments
		}

		data, ok := objects.ToByteSlice(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "data",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		l, ok := objects.ToInt(args[1])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "length",
				Expected: "int",
				Found:    args[1].TypeName(),
			}
		}

		if l <= 0 || l > 255 {
			return nil, objects.ErrIndexOutOfBounds
		}

		padLen := l - (len(data) % l)
		return &objects.Bytes{Value: append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)}, nil
	}}
	cryptoModule["unpad_pkcs7"] = &objects.UserFunction{Name: "pad_pkcs7", Value: func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 2 {
			return nil, objects.ErrWrongNumArguments
		}

		data, ok := objects.ToByteSlice(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "data",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		l, ok := objects.ToInt(args[1])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "length",
				Expected: "int",
				Found:    args[0].TypeName(),
			}
		}

		if l <= 0 || l > 255 {
			return nil, objects.ErrIndexOutOfBounds
		}

		if len(data) % l != 0 {
			return nil, ErrDataMultipleBlockSize
		}

		padLen := int(data[len(data)-1])

		if padLen >= len(data) {
			return ErrMalformedPadding, nil
		}

		for _, el := range data[len(data)-padLen:] {
			if el != byte(padLen) {
				// recoverable error
				return ErrMalformedPadding, nil
			}
		}

		return &objects.Bytes{Value: data[:len(data)-padLen]}, nil
	}}
	cryptoModule["rand_bytes"] = &objects.UserFunction{Name: "rand_bytes", Value: func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 1 {
			return nil, objects.ErrWrongNumArguments
		}

		l, ok := objects.ToInt(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "length",
				Expected: "int",
				Found:    args[0].TypeName(),
			}
		}

		if l < 0 {
			return nil, objects.ErrIndexOutOfBounds
		}

		bs := make([]byte, l)
		_, err := rand.Read(bs)
		if err != nil {
			return nil, err
		}

		return &objects.Bytes{Value: bs}, nil
	}}
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

		registerHash(n, h.New)
	}
}

type cipherI interface {
	Name() string

	IVSize() int
	BlockSize() int
	KeySizes() []int

	Encrypt(data, key, iv []byte)
	Decrypt(data, key, iv []byte)
}

type blockCiph struct {
	MName      string
	MBlockSize int
	MKeySizes  []int
	NewBlock   func(key []byte) cipher.Block
}

func (c *blockCiph) Name() string {
	return c.MName
}

func (c *blockCiph) IVSize() int {
	return -1
}

func (c *blockCiph) BlockSize() int {
	return c.MBlockSize
}

func (c *blockCiph) KeySizes() []int {
	return c.MKeySizes
}

func (c *blockCiph) Encrypt(data, key, iv []byte) {
	c.NewBlock(key).Encrypt(data, data)
}

func (c *blockCiph) Decrypt(data, key, iv []byte) {
	c.NewBlock(key).Decrypt(data, data)
}

type blockModeCiph struct {
	Cipher       cipherI
	NewEncrypter func(b cipher.Block, iv []byte) cipher.BlockMode
	NewDecrypter func(b cipher.Block, iv []byte) cipher.BlockMode
}

func (c *blockModeCiph) Name() string {
	return c.Cipher.Name()
}

func (c *blockModeCiph) IVSize() int {
	return c.BlockSize()
}

func (c *blockModeCiph) BlockSize() int {
	return c.Cipher.BlockSize()
}

func (c *blockModeCiph) KeySizes() []int {
	return c.Cipher.KeySizes()
}

func (c *blockModeCiph) Encrypt(data, key, iv []byte) {
	ciph := c.Cipher
	cbc := c.NewEncrypter(ciph.(*blockCiph).NewBlock(key), iv)
	cbc.CryptBlocks(data, data)
}

func (c *blockModeCiph) Decrypt(data, key, iv []byte) {
	ciph := c.Cipher
	cbc := c.NewDecrypter(ciph.(*blockCiph).NewBlock(key), iv)
	cbc.CryptBlocks(data, data)
}

type streamCiph struct {
	MName        string
	MIVSize      int
	MKeySizes    []int
	NewEncStream func(key, iv []byte) cipher.Stream
	NewDecStream func(key, iv []byte) cipher.Stream
}

func (c *streamCiph) Name() string {
	return c.MName
}

func (c *streamCiph) IVSize() int {
	return c.MIVSize
}

func (c *streamCiph) BlockSize() int {
	return -1
}

func (c *streamCiph) KeySizes() []int {
	return c.MKeySizes
}

func (c *streamCiph) Encrypt(data, key, iv []byte) {
	c.NewEncStream(key, iv).XORKeyStream(data, data)
}

func (c *streamCiph) Decrypt(data, key, iv []byte) {
	if c.NewDecStream == nil {
		c.NewEncStream(key, iv).XORKeyStream(data, data)
		return
	}
	c.NewDecStream(key, iv).XORKeyStream(data, data)
}

func registerBlockCipher(ciph cipherI) {
	registerBlockCipherFuncs(ciph.Name()+"_cbc", &blockModeCiph{
		Cipher:       ciph,
		NewEncrypter: cipher.NewCBCEncrypter,
		NewDecrypter: cipher.NewCBCDecrypter,
	})
	registerBlockCipherFuncs(ciph.Name()+"_ctr", &streamCiph{
		MName: ciph.Name(),
		NewEncStream: func(key, iv []byte) cipher.Stream {
			return cipher.NewCTR(ciph.(*blockCiph).NewBlock(key), iv)
		},
		MKeySizes: ciph.KeySizes(),
		MIVSize:   ciph.(*blockCiph).MBlockSize,
	})
	registerBlockCipherFuncs(ciph.Name()+"_ofb", &streamCiph{
		MName: ciph.Name(),
		NewEncStream: func(key, iv []byte) cipher.Stream {
			return cipher.NewOFB(ciph.(*blockCiph).NewBlock(key), iv)
		},
		MKeySizes: ciph.KeySizes(),
		MIVSize:   ciph.(*blockCiph).MBlockSize,
	})
}

func registerBlockCipherFuncs(n string, ciph cipherI) {
	cryptoModule["encrypt_"+n] = &objects.UserFunction{Name: "encrypt_" + n, Value: newCrypterFunc(ciph, true)}
	cryptoModule["decrypt_"+n] = &objects.UserFunction{Name: "decrypt_" + n, Value: newCrypterFunc(ciph, false)}
}

var ErrKeySize = errors.New("invalid key size")
var ErrIVSize = errors.New("invalid iv size")
var ErrDataMultipleBlockSize = errors.New("data must be multiple of block size")

func newCrypterFunc(ciph cipherI, encrypter bool) objects.CallableFunc {
	return func(args ...objects.Object) (objects.Object, error) {
		if ciph.IVSize() > 0 {
			if len(args) != 3 {
				return nil, objects.ErrWrongNumArguments
			}
		} else {
			if len(args) != 2 {
				return nil, objects.ErrWrongNumArguments
			}
		}

		data, ok := objects.ToByteSlice(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "data",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		if ciph.BlockSize() > 0 && len(data)%ciph.BlockSize() != 0 {
			return nil, ErrDataMultipleBlockSize
		}

		key, ok := objects.ToByteSlice(args[1])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "key",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		var iv []byte

		if ciph.IVSize() > 0 {
			if len(args) > 2 {
				iv, ok = objects.ToByteSlice(args[2])
				if !ok {
					return nil, objects.ErrInvalidArgumentType{
						Name:     "iv",
						Expected: "bytes",
						Found:    args[0].TypeName(),
					}
				}
				if len(iv) != ciph.IVSize() {
					return nil, ErrIVSize
				}
			}
		}

		for _, l := range ciph.KeySizes() {
			if l == len(key) {
				if encrypter {
					ciph.Encrypt(data, key, iv)
				} else {
					ciph.Decrypt(data, key, iv)
				}

				return &objects.Bytes{
					Value: data,
				}, nil
			}
		}

		// probably unrecoverable
		return nil, ErrKeySize
	}
}

func registerHash(n string, newHash func() hash.Hash) {
	cryptoModule[n] = &objects.UserFunction{Name: n, Value: newHashFunc(newHash, false)}
	cryptoModule[n+"_hex"] = &objects.UserFunction{Name: n + "_hex", Value: newHashFunc(newHash, true)} // See #216
	cryptoModule["hmac_"+n] = &objects.UserFunction{Name: "hmac_" + n, Value: newHMACFunc(hmacByHash(newHash), false)}
	cryptoModule["hmac_"+n+"_hex"] = &objects.UserFunction{Name: "hmac_" + n + "_hex", Value: newHMACFunc(hmacByHash(newHash), true)}
}

func hmacByHash(newHash func() hash.Hash) func(key []byte) hash.Hash {
	return func(key []byte) hash.Hash {
		return hmac.New(newHash, key)
	}
}

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

func newHashFunc(newHash func() hash.Hash, returnHex bool) objects.CallableFunc {
	return func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 1 {
			return nil, objects.ErrWrongNumArguments
		}

		inp, ok := objects.ToByteSlice(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "data",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		h := newHash()
		h.Write(inp)

		out := make([]byte, 0, h.Size())

		out = h.Sum(out)

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

func newHMACFunc(newMac func(key []byte) hash.Hash, returnHex bool) objects.CallableFunc {
	return func(args ...objects.Object) (objects.Object, error) {
		if len(args) != 2 {
			return nil, objects.ErrWrongNumArguments
		}

		inp, ok := objects.ToByteSlice(args[0])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "data",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		key, ok := objects.ToByteSlice(args[1])
		if !ok {
			return nil, objects.ErrInvalidArgumentType{
				Name:     "key",
				Expected: "bytes",
				Found:    args[0].TypeName(),
			}
		}

		h := newMac(key)
		h.Write(inp)

		out := make([]byte, 0, h.Size())

		out = h.Sum(out)

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
