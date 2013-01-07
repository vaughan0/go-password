package password

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"

	"code.google.com/p/go.crypto/bcrypt"
)

type Algorithm interface {
	Hash(password []byte) []byte
	Check(password, hashed []byte) bool
}

type Codec interface {
	Encode([]byte) string
	Decode(string) []byte
}

// Map of known algorithms by name
var Algorithms = make(map[string]Algorithm)

// Default algorithm to use when hashing passwords
var Default string

func Register(name string, algo Algorithm) {
	Algorithms[name] = algo
}

func RegisterHash(name string, h hash.Hash) {
	Algorithms[name] = &HashWrapper{h, 3}
}

func init() {
	RegisterHash("md5", md5.New())
	RegisterHash("sha256", sha256.New())
	RegisterHash("sha1", sha1.New())
	Register("bcrypt", Bcrypt{8})
	Default = "bcrypt"
}

type Manager struct {
	Default string
	Codec   Codec
}

func New() *Manager {
	return &Manager{
		Default: Default,
		Codec:   Base64Codec{base64.StdEncoding},
	}
}

func (m *Manager) Hash(password string) string {
	algo := Algorithms[m.Default]
	if algo == nil {
		panic("unknown default hash algorithm: " + m.Default)
	}
	hash := algo.Hash([]byte(password))
	return pack(m.Default, m.Codec.Encode(hash))
}

func (m *Manager) Check(password, hashed string) bool {
	algoName, hashed := unpack(hashed)
	algo := Algorithms[algoName]
	if algo == nil {
		panic("unknown hash algorithm: " + algoName)
	}
	return algo.Check([]byte(password), m.Codec.Decode(hashed))
}

func pack(algo, hash string) string {
	return algo + "$" + hash
}
func unpack(packed string) (algo, hash string) {
	fields := strings.SplitN(packed, "$", 2)
	if len(fields) != 2 {
		panic("invalid password hash")
	}
	return fields[0], fields[1]
}

/* Algorithm implementations */

// HashWrapper implements Algorithm by wrapping a hash.Hash instance, as well as providing random salt generation
type HashWrapper struct {
	Hasher hash.Hash
	Salt   int
}

func (h *HashWrapper) Hash(password []byte) []byte {
	salt := make([]byte, h.Salt)
	n, err := rand.Read(salt)
	if n < h.Salt || err != nil {
		panic("failed to generate random salt")
	}
	h.Hasher.Reset()
	h.Hasher.Write(salt)
	h.Hasher.Write(password)
	return h.Hasher.Sum(salt)
}

func (h *HashWrapper) Check(password, hashed []byte) bool {
	saltLen := len(hashed) - h.Hasher.Size()
	salt, answer := hashed[:saltLen], hashed[saltLen:]
	h.Hasher.Reset()
	h.Hasher.Write(salt)
	h.Hasher.Write(password)
	testHash := h.Hasher.Sum(nil)
	return subtle.ConstantTimeCompare(testHash, answer) == 1
}

type Bcrypt struct {
	Cost int
}

func (b Bcrypt) Hash(password []byte) []byte {
	result, err := bcrypt.GenerateFromPassword(password, b.Cost)
	if err != nil {
		panic(err)
	}
	return result
}

func (b Bcrypt) Check(password, hashed []byte) bool {
	return bcrypt.CompareHashAndPassword(hashed, password) == nil
}

/* Codec implementations */

type HexCodec struct{}

func (h HexCodec) Encode(data []byte) string {
	return hex.EncodeToString(data)
}
func (h HexCodec) Decode(str string) []byte {
	result, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return result
}

type Base64Codec struct {
	Encoding *base64.Encoding
}

func (b Base64Codec) Encode(data []byte) string {
	return b.Encoding.EncodeToString(data)
}
func (b Base64Codec) Decode(str string) []byte {
	result, err := b.Encoding.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return result
}
