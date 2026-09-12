// Command meshcred provisions the Linux host-bound identity credential.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/meshtransit/meshd/internal/hostcred"
)

const provisionTimeout = 15 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := context.WithTimeout(context.Background(), provisionTimeout)
	defer cancel()

	if err := hostcred.Provision(ctx, hostcred.Config{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "meshcred: identity credential provisioning failed")

		return 1
	}

	return 0
}
