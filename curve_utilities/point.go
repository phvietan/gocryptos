package curve_utilities

import (
	C25519 "github.com/phvietan/ancrypto/curve_utilities/curve25519"
)

type Point struct {
	keys C25519.Key
}

func (this *Point) SetKey(k C25519.Key) *Point {
	if this == nil {
		this = new(Point)
	}
	this.keys = k
	return this
}

func (this *Point) Identity() *Point {
	return this.SetKey(C25519.Identity)
}

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

func (this *Point) GetKey() C25519.Key {
	return this.keys
}
