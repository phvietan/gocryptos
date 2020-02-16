package common

import (
	"crypto/rand"
	"encoding/binary"
)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Something is wrong with crypto/rand in GenerateRandomBytes")
	}
	return b
}

// Generate a uint64 from 0 -> 2^64 - 1
func GetRandomUInt64() uint64 {
	b := GenerateRandomBytes(8)
	return binary.BigEndian.Uint64(b)
}

// Generate random int from 0 -> n-1
func GetRandomToN(n int) int {
	res_uint := GetRandomUInt64() % uint64(n)
	return int(res_uint)
}
