package curve_util

import (
	"encoding/hex"

	C25519 "github.com/phvietan/ancrypto/curve_util/curve25519"
)

type Scalar struct {
	keys C25519.Key
}

func (this *Scalar) SetKey(k C25519.Key) *Scalar {
	if this == nil {
		this = new(Scalar)
	}
	this.keys = k
	return this
}

func RandomScalar() *Scalar {
	sc := new(Scalar)
	sc.keys = *C25519.RandomScalar()
	return sc
}

func HashToScalar(data ...[]byte) *Scalar {
	result := new(Scalar).SetKey(
		C25519.Key(C25519.Keccak256(data...)),
	)
	C25519.ScReduce32(&result.keys)
	return result
}

// Add 2 scalar and store to new pointer (a+b)
func AddNewScalar(a, b *Scalar) *Scalar {
	result := new(Scalar)
	C25519.ScAdd(&result.keys, &a.keys, &b.keys)
	return result
}

// Add 2 scalar. If this == nil then output new pointer with value = a
func (this *Scalar) AddTo(a *Scalar) {
	if this == nil {
		this = new(Scalar)
	}
	C25519.ScAdd(&this.keys, &this.keys, &a.keys)
}

// Sub 2 scalar and store to new pointer (a-b)
func SubNewScalar(a, b *Scalar) *Scalar {
	result := new(Scalar)
	C25519.ScSub(&result.keys, &a.keys, &b.keys)
	return result
}

// Sub 2 scalar. If this == nil then output new pointer with value = -a
func (this *Scalar) SubTo(a *Scalar) {
	if this == nil {
		this = new(Scalar)
	}
	C25519.ScSub(&this.keys, &this.keys, &a.keys)
}

func (this *Scalar) Reset() {
	if this == nil {
		this = new(Scalar)
	}
	C25519.Sc_0(&this.keys)
}

// Multiply 2 scalar and store to new pointer (a*b)
func MulNewScalar(a, b *Scalar) *Scalar {
	result := new(Scalar)
	C25519.ScMul(&result.keys, &a.keys, &b.keys)
	return result
}

// Multiply 2 scalar and store to this.
func (this *Scalar) MulTo(a *Scalar) {
	if this == nil {
		this = new(Scalar)
		return
	}
	C25519.ScMul(&this.keys, &this.keys, &a.keys)
}

func (this *Scalar) ToBytes() [C25519.KeyLength]byte {
	return [C25519.KeyLength]byte(this.keys)
}

func (this *Scalar) ToBytesS() []byte {
	b := this.keys.ToBytes()
	return b[:]
}

func (this *Scalar) ToHex() string {
	b := this.ToBytesS()
	return hex.EncodeToString(b)
}

func FromBytesToScalar(b [C25519.KeyLength]byte) *Scalar {
	result := new(Scalar)
	result.keys = b
	return result
}

func FromBytesSToScalar(b []byte) *Scalar {
	for len(b) < 32 {
		b = append(b, 0)
	}
	result := new(Scalar)
	copy(b, result.keys[:])
	return result
}

func FromHexToScalar(s string) *Scalar {
	byteSlice, _ := hex.DecodeString(s)
	return FromBytesSToScalar(byteSlice)
}
