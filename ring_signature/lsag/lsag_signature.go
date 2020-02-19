package lsag

import util "github.com/phvietan/ancrypto/curve_util"

type Signature struct {
	keyImage *util.Point
	ring     Ring
	c        *util.Scalar
	r        []*util.Scalar
}
