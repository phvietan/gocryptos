package curve_util

import (
	"encoding/hex"

	C25519 "github.com/phvietan/ancrypto/curve_util/curve25519"
)

const KeySize int = C25519.KeyLength

type Point struct {
	keys C25519.Key
}

// set bytes of point to k
func (this *Point) SetKey(k C25519.Key) *Point {
	if this == nil {
		this = new(Point)
	}
	this.keys = k
	return this
}

func (this *Point) GetKey() C25519.Key {
	return this.keys
}

func (this *Point) Identity() *Point {
	return this.SetKey(C25519.Identity)
}

// Random a point on a*G. Where a is arbitrary scalar
func RandomPointOnBase() *Point {
	sc := C25519.RandomScalar()

	result := new(Point)
	result.keys = C25519.ScalarmultBase(*sc)
	return result
}

// Add to this point, if this is nil then calculate G + a
func (this *Point) AddTo(a *Point) {
	if this == nil {
		this = new(Point)
		this.keys = C25519.Identity
	}
	C25519.AddKeys(&this.keys, &this.keys, &a.keys)
}

// Calculate point addition a + b and store to new point
func AddNewPoint(a, b *Point) *Point {
	result := new(Point)
	C25519.AddKeys(&result.keys, &a.keys, &b.keys)
	return result
}

// Add to this point, if this is nil then calculate G - a
func (this *Point) SubTo(a *Point) {
	if this == nil {
		this = new(Point)
		this.keys = C25519.Identity
	}
	C25519.SubKeys(&this.keys, &this.keys, &a.keys)
}

// Calculate point subtraction a - b and store to new point
func SubNewPoint(a, b *Point) *Point {
	result := new(Point)
	C25519.SubKeys(&result.keys, &a.keys, &b.keys)
	return result
}

// Check if this point is identity
func (this *Point) IsIdentity() bool {
	return this.keys == C25519.Identity
}

// Calculate a*G
func ScalarMultBase(a *Scalar) *Point {
	return new(Point).SetKey(C25519.ScalarmultBase(a.keys))
}

// Calculate point multiply scalar: a*B and store to new point
func ScalarMultNewPoint(a *Scalar, b *Point) *Point {
	result := new(Point)
	result.keys = *C25519.ScalarMultKey(&b.keys, &a.keys)
	return result
}

func HashToPoint(data []byte) *Point {
	keyHash := C25519.Key(C25519.Keccak256(data))
	keyPoint := keyHash.HashToPoint()
	return new(Point).SetKey(keyPoint)
}

// Reset pointer Point to Identity
func (this *Point) Reset() {
	this.SetKey(C25519.Identity)
}

func (this *Point) ToBytes() [C25519.KeyLength]byte {
	return [C25519.KeyLength]byte(this.keys)
}

func (this *Point) ToBytesS() []byte {
	b := this.keys.ToBytes()
	return b[:]
}

func (this *Point) ToHex() string {
	b := this.ToBytesS()
	return hex.EncodeToString(b)
}

func FromBytesToPoint(b [C25519.KeyLength]byte) *Point {
	result := new(Point)
	result.keys = b
	return result
}

func FromBytesSToPoint(b []byte) *Point {
	for len(b) < 32 {
		b = append(b, 0)
	}
	result := new(Point)
	copy(b, result.keys[:])
	return result
}

func FromHexToPoint(s string) *Point {
	byteSlice, _ := hex.DecodeString(s)
	return FromBytesSToPoint(byteSlice)
}
