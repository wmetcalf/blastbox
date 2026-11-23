package main

import (
	"fmt"
	"os"
)

// Benign Loadout REA corpus fixture. The URL/IP below are inert strings for IOC extraction.
const beacon = "http://loadout-go-fixture.example.org/ping"
const relay = "198.51.100.23"

func main() {
	if len(os.Args) > 5 {
		fmt.Println(beacon, relay)
	}
	fmt.Printf("hello loadout go %d\n", len(os.Args)*3+7)
}
