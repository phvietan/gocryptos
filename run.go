package main

import (
	"fmt"

	utilities "github.com/phvietan/ancrypto/curve_utilities"
)

func main() {
	fmt.Println("Running run")
	randPoint := utilities.RandomPointOnBase()
	fmt.Println(randPoint)
}
