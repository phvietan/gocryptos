package lsag

import (
	"crypto/sha256"
	"errors"
	"fmt"

	util "github.com/phvietan/ancrypto/curve_util"
)

type Lsag struct {
	ring       Ring
	pi         int
	keyImage   *util.Point
	privateKey *util.Scalar
}

func computeKeyImage(privateKey *util.Scalar, ring *Ring) *util.Point {
	hashRing := util.HashToPoint(ring.ToBytesS())
	return util.ScalarMultNewPoint(privateKey, hashRing)
}

func NewLsag(privateKey *util.Scalar, ring Ring, pi int) Lsag {
	keyImage := computeKeyImage(privateKey, &ring)
	return Lsag{
		ring,
		pi,
		keyImage,
		privateKey,
	}
}

func generateRandomChallenge(this *Lsag) (alpha *util.Scalar, r []*util.Scalar) {
	n := len(this.ring.keys)
	alpha = util.RandomScalar()
	r = make([]*util.Scalar, n)
	for i := 0; i < n; i += 1 {
		if i != this.pi {
			r[i] = util.RandomScalar()
		}
	}
	return
}

func calculateFirstC(this *Lsag, alpha *util.Scalar, digest [sha256.Size]byte) *util.Scalar {
	alphaG := util.ScalarMultBase(alpha)
	hashRing := util.HashToPoint(this.ring.ToBytesS())
	alphaH := util.ScalarMultNewPoint(alpha, hashRing)

	b := []byte{}
	b = append(b, this.ring.ToBytesS()...)
	b = append(b, this.keyImage.ToBytesS()...)
	b = append(b, digest[:]...)
	b = append(b, alphaG.ToBytesS()...)
	b = append(b, alphaH.ToBytesS()...)

	return util.HashToScalar(b)
}

func calculateNextC(ring *Ring, keyImage *util.Point, r *util.Scalar, c *util.Scalar, K *util.Point, digest [sha256.Size]byte) *util.Scalar {
	rG := util.ScalarMultBase(r)
	cK := util.ScalarMultNewPoint(c, K)
	rG_cK := util.AddNewPoint(rG, cK)

	hashRing := util.HashToPoint(ring.ToBytesS())
	rH := util.ScalarMultNewPoint(r, hashRing)
	cKI := util.ScalarMultNewPoint(c, keyImage)
	rH_cKI := util.AddNewPoint(rH, cKI)

	b := []byte{}
	b = append(b, ring.ToBytesS()...)
	b = append(b, keyImage.ToBytesS()...)
	b = append(b, digest[:]...)
	b = append(b, rG_cK.ToBytesS()...)
	b = append(b, rH_cKI.ToBytesS()...)

	return util.HashToScalar(b)
}

func generateC(this *Lsag, alpha *util.Scalar, r *[]*util.Scalar, digest [sha256.Size]byte) *util.Scalar {
	n := len(this.ring.keys)
	c := make([]*util.Scalar, n)

	i := (this.pi + 1) % n
	c[i] = calculateFirstC(this, alpha, digest)
	for i != this.pi {
		j := (i + 1) % n
		c[j] = calculateNextC(
			&this.ring,
			this.keyImage, (*r)[i], c[i],
			&this.ring.keys[i], digest,
		)
		i = j
	}
	ck := util.MulNewScalar(c[this.pi], this.privateKey)
	(*r)[this.pi] = util.SubNewScalar(alpha, ck)
	return c[0]
}

func (this *Lsag) SignString(message string) (*Signature, error) {
	return this.SignBytes([]byte(message))
}

func (this *Lsag) SignBytes(message []byte) (*Signature, error) {
	digest := sha256.Sum256(message)
	return this.signDigest(digest)
}

func (this *Lsag) signDigest(digest [sha256.Size]byte) (*Signature, error) {
	if this.pi >= len(this.ring.keys) {
		return nil, errors.New("Lsag signDigest error: pi is larger than length of ring")
	}
	// Random alpha challenge
	alpha, r := generateRandomChallenge(this)

	fmt.Println(r[this.pi])

	// Calculate C and change r[this.pi]
	c := generateC(this, alpha, &r, digest)
	return &Signature{
		this.keyImage,
		this.ring, c, r,
	}, nil
}

func VerifyString(sig *Signature, message string) bool {
	return VerifyBytes(sig, []byte(message))
}

func VerifyBytes(sig *Signature, message []byte) bool {
	digest := sha256.Sum256(message)
	return verifyDigest(sig, digest)
}

func verifyDigest(sig *Signature, digest [sha256.Size]byte) bool {
	lK := util.ScalarMultNewPoint(util.EdwardsOrder, sig.keyImage)
	if !lK.IsIdentity() {
		return false
	}
	cBefore := sig.c
	cRun := sig.c
	for i := 0; i < len(sig.r); i += 1 {
		cRun = calculateNextC(
			&sig.ring,
			sig.keyImage,
			sig.r[i], cRun,
			&sig.ring.keys[i], digest,
		)
	}
	return cRun.GetKey() == cBefore.GetKey()
}
