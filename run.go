package main

import (
	"fmt"

	util "github.com/phvietan/ancrypto/curve_util"

	"github.com/phvietan/ancrypto/ring_signature/lsag"
)

func main() {
	fmt.Println("Running run")

	priv := util.RandomScalar()
	ring, pi := lsag.NewRandomRing(priv, 20)
	fmt.Println(ring)
	fmt.Println(pi)
}
