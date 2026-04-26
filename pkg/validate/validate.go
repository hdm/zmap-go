// Package validate implements zmap's AES-128 ECB based response validation.
//
// On scan startup a random 128-bit key is generated. Validation tuples for
// each (src, dst, dport) probe are produced by encrypting the tuple as a
// single 128-bit block under that key. The first uint32 of the ciphertext is
// used as the TCP sequence number; the second-fourth halves are used for
// source-port selection, IP id, ICMP id/seq, etc. Responses can be validated
// by re-deriving the tuple from packet fields.
//
// This is a pure Go port of src/validate.c — CGO free.
package validate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// KeyBytes is the AES-128 key length.
const KeyBytes = 16

// TupleBytes is the ciphertext length (one AES block).
const TupleBytes = 16

// Validator generates per-probe validation tuples.
type Validator struct {
	block cipher.Block
}

// New creates a Validator with a freshly generated random key.
func New() (*Validator, error) {
	var key [KeyBytes]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("validate: random key: %w", err)
	}
	return NewFromKey(key[:])
}

// NewFromSeed creates a deterministic Validator from a 64-bit seed.
// Layout matches src/aesrand.c: low byte first.
func NewFromSeed(seed uint64) (*Validator, error) {
	var key [KeyBytes]byte
	for i := 0; i < 8; i++ {
		key[i] = byte((seed >> (8 * i)) & 0xff)
	}
	return NewFromKey(key[:])
}

// NewFromKey creates a Validator with the given AES-128 key.
func NewFromKey(key []byte) (*Validator, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("validate: key must be %d bytes", KeyBytes)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	return &Validator{block: b}, nil
}

// Gen generates a 16-byte tuple from (src, dst, dport, extra).
// All inputs are taken in host byte order.
func (v *Validator) Gen(src, dst, dport, extra uint32) [TupleBytes]byte {
	var in, out [16]byte
	binary.LittleEndian.PutUint32(in[0:4], src)
	binary.LittleEndian.PutUint32(in[4:8], dst)
	binary.LittleEndian.PutUint32(in[8:12], dport)
	binary.LittleEndian.PutUint32(in[12:16], extra)
	v.block.Encrypt(out[:], in[:])
	return out
}

// GenWords returns the same tuple as Gen but as four uint32 words in
// little-endian order, matching the layout used by zmap's probe modules
// (validation[0] = TCP seq, validation[1] = ICMP id seed, validation[2] =
// ICMP seq seed, validation[3] = source-port selector).
func (v *Validator) GenWords(src, dst, dport, extra uint32) [4]uint32 {
	t := v.Gen(src, dst, dport, extra)
	var w [4]uint32
	for i := 0; i < 4; i++ {
		w[i] = binary.LittleEndian.Uint32(t[i*4 : i*4+4])
	}
	return w
}
