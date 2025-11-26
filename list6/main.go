package main

import (
	"fmt"
	"list6/PerfectHiding"
	"list6/zad2"
)

func main() {

	zeros := 0
	onces := 0
	for i := 0; i < 1000; i++ {
		if zad2.Zad2() == "0" {
			zeros++
		} else {
			onces++
		}
	}
	fmt.Printf("zeros := %v\nonces := %v\n", zeros, onces)
	return

	message := "essa"
	r := "bardzo"
	C := PerfectHiding.Commit(message, r)
	// r = "bardzoo"
	res := PerfectHiding.Unpack(message, r, C)
	fmt.Printf("czy się udało %v\n", res)
}
