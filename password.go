// Package password provides the facilities for working with cryptographically-secure password hashes.
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

type ErrUnknownAlgorithm string

func (e ErrUnknownAlgorithm) Error() string {
	return "unknown hash algorithm: " + string(e)
}

// The Algorithm interface represents cryptographic hash functions for hashing passwords
type Algorithm interface {
	// Returns the result of hashing the given password
	Hash(password []byte) []byte
	// Returns true if the given password matches the hash. The hash will have
	// been previously obtained by a call to this Algorithm's Hash() function.
	Check(password, hashed []byte) bool
}

// Implementations of the Codec interface are responsible for converting binary
// data to and from textual strings.
type Codec interface {
	Encode([]byte) string
	Decode(string) []byte
}

// Map of known algorithms by name
var Algorithms = make(map[string]Algorithm)

// Default algorithm to use when hashing passwords
var DefaultUse string

var defaultManager *Manager

// Globally registers a hash algorithm so that it can be used to generate and check hashes.
func Register(name string, algo Algorithm) {
	Algorithms[name] = algo
}

// Calls Register with a wrapped version of the hash. See HashWrapper.
func RegisterHash(name string, h hash.Hash) {
	Algorithms[name] = &HashWrapper{h, 3}
}

func init() {
	RegisterHash("md5", md5.New())
	RegisterHash("sha256", sha256.New())
	RegisterHash("sha1", sha1.New())
	Register("bcrypt", Bcrypt{8})
	DefaultUse = "bcrypt"
	defaultManager = New()
}

// A Manager provides the basic functions for working with password hashes, and has configurable fields.
type Manager struct {
	// The name of the algorithm to use when hashing passwords with Hash().
	Use string
	// A map of manager-specific algorithms, which is by default empty.
	// Algorithms in this map take preference over the global map of known algorithms.
	Algorithms map[string]Algorithm
	// Codec is used for encoding and decoding hash strings.
	Codec Codec
}

// Returns a new Manager with the default settings. The Manager will use bcrypt
// for hashing, and the Base64Codec (with the standard base64 encoding) for
// string/data conversions.
func New() *Manager {
	return &Manager{
		Use:        DefaultUse,
		Codec:      Base64Codec{base64.StdEncoding},
		Algorithms: make(map[string]Algorithm),
	}
}

func (m *Manager) getAlgorithm(name string) Algorithm {
	if algo := m.Algorithms[name]; algo != nil {
		return algo
	}
	if algo := Algorithms[name]; algo != nil {
		return algo
	}
	panic(ErrUnknownAlgorithm(name))
}

// Registers an algorithm with the Manager's local algorithm map.
func (m *Manager) Register(name string, algo Algorithm) {
	m.Algorithms[name] = algo
}

// See password.RegisterHash
func (m *Manager) RegisterHash(name string, h hash.Hash) {
	m.Algorithms[name] = &HashWrapper{h, 3}
}

// Hashes the given password with the default hashing algorithm and returns the resulting hash string.
func (m *Manager) Hash(password string) string {
	algo := m.getAlgorithm(m.Use)
	hash := algo.Hash([]byte(password))
	return pack(m.Use, m.Codec.Encode(hash))
}

// Returns true if the given password matches the given hash string.
// The hash string must be a result from a previous call to Hash().
func (m *Manager) Check(password, hashed string) bool {
	algoName, hashed := unpack(hashed)
	algo := m.getAlgorithm(algoName)
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

// Hashes the password using the default Manager.
func Hash(password string) string {
	return defaultManager.Hash(password)
}

// Checks a password and hash using the default Manager.
func Check(password, hashed string) bool {
	return defaultManager.Check(password, hashed)
}

/* Algorithm implementations */

// HashWrapper implements Algorithm by wrapping a hash.Hash instance, as well as providing random salt generation.
type HashWrapper struct {
	Hasher hash.Hash
	// Size, in bytes, of the randomly-generated salts
	Salt int
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

// Bcrypt uses the bcrypt algorithm with a fixed cost.
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

// HexCodec uses hexadecimal strings for encoding and decoding.
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

// Base64Codec uses base64 with a customizable Encoding for string/data conversions.
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
