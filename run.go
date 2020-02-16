package main

import (
	"fmt"

	curve_util "github.com/phvietan/ancrypto/curve_util"
)

func main() {
	fmt.Println("Running run")
	randPoint := curve_util.RandomPointOnBase()
	fmt.Println(randPoint)
}
