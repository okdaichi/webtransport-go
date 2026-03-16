package main

import (
	"fmt"
	"os"

	"github.com/okdaichi/webtransport-go/interop"
)

func main() {
	if err := interop.RunInteropServer(); err != nil {
		fmt.Printf("failed to run interop server: %v\n", err)
		os.Exit(1)
	}
}
