package lsag

import (
	"encoding/hex"

	"github.com/phvietan/ancrypto/common"
	util "github.com/phvietan/ancrypto/curve_util"
)

type Ring struct {
	keys []util.Point
}

func (this *Ring) ToBytesS() []byte {
	b := []byte{}
	for i := 0; i < len(this.keys); i += 1 {
		b = append(b, this.keys[i].ToBytesS()...)
	}
	return b
}

func NewRandomRing(privateKey *util.Scalar, size int) (ring *Ring, pi int) {
	ring = new(Ring)
	pi = common.GetRandomToN(size)

	keys := make([]util.Point, size)
	for i := 0; i < size; i += 1 {
		if i == pi {
			keys[i] = *privateKey.GetPublicKey()
		} else {
			keys[i] = *util.RandomPointOnBase()
		}
	}
	ring.keys = keys
	return
}

func (this *Ring) ToHex() string {
	b := this.ToBytesS()
	return hex.EncodeToString(b)
}
