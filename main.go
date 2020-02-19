package main

import (
	"fmt"

	util "github.com/phvietan/ancrypto/curve_util"

	"github.com/phvietan/ancrypto/ring_signature/lsag"
)

func testCurveUtil() {
	fmt.Println("Running TestCurveUtil")
	priv := util.RandomScalar()
	fmt.Println(priv)
}

func testLsag() {
	numFake := 20
	privateKey := util.RandomScalar()

	ring, pi := lsag.NewRandomRing(privateKey, numFake)
	signer := lsag.NewLsag(privateKey, ring, pi)

	message := "Hello world"
	signature, err := signer.SignString(message)
	if err != nil {
		fmt.Println(err)
		return
	}
	// fmt.Println(signature)

	check := lsag.VerifyString(signature, message)
	fmt.Println(check)
}

func main() {
	// testCurveUtil()
	testLsag()
}
