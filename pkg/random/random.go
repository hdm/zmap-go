package random

import "crypto/rand"

// Bytes fills dst with cryptographically secure random bytes.
func Bytes(dst []byte) error {
	_, err := rand.Read(dst)
	return err
}

// NewBytes returns n cryptographically secure random bytes.
func NewBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if err := Bytes(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
