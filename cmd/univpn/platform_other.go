//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "univpn only supports Linux")
	os.Exit(22)
}
