// Command meshcred manages the Linux host-bound identity credential.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/config"
	"github.com/meshtransit/meshtransit/client/internal/hostcred"
	"github.com/meshtransit/meshtransit/client/internal/identity"
	"github.com/meshtransit/meshtransit/client/internal/secretstore"
)

const (
	operationTimeout = 60 * time.Second
	systemctlPath    = "/usr/bin/systemctl"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	operation := "provision"
	if len(args) == 1 {
		operation = args[0]
	} else if len(args) > 1 {
		printUsage(stderr)

		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()

	var err error
	switch operation {
	case "provision":
		err = hostcred.Provision(ctx, hostcred.Config{})
	case "rotate":
		err = hostcred.Rotate(ctx, hostcred.Config{})
	case "finalize":
		err = runOffline(ctx, func() error {
			return hostcred.Finalize(ctx, hostcred.Config{}, verifyIdentities)
		})
	case "commit":
		err = runOffline(ctx, func() error {
			return hostcred.Commit(ctx, hostcred.Config{}, verifyIdentities)
		})
	case "recover":
		err = runOffline(ctx, func() error {
			return hostcred.Recover(ctx, hostcred.Config{})
		})
	default:
		printUsage(stderr)

		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshcred: %s failed\n", operation)

		return 1
	}

	return 0
}

func runOffline(ctx context.Context, operation func() error) error {
	if operation == nil {
		return errors.New("meshcred: offline operation is required")
	}
	if err := requireDaemonStopped(ctx); err != nil {
		return err
	}

	return operation()
}

func requireDaemonStopped(ctx context.Context) error {
	command := exec.CommandContext(
		ctx,
		systemctlPath,
		"show",
		"--property=ActiveState",
		"--value",
		"meshd.service",
	)
	output, err := command.Output()
	if err != nil || len(output) > 32 {
		return errors.New("meshcred: cannot verify meshd.service state")
	}
	if !isDaemonStopped(output) {
		return errors.New("meshcred: meshd.service must be stopped")
	}

	return nil
}

func isDaemonStopped(output []byte) bool {
	state := strings.TrimSpace(string(output))

	return state == "inactive" || state == "failed"
}

func verifyIdentities(ctx context.Context, activeKey []byte) error {
	protector, err := secretstore.New(activeKey)
	if err != nil {
		return errors.New("meshcred: active identity key is invalid")
	}
	store, err := identity.Open(config.DefaultStateDir, protector)
	if err != nil {
		_ = protector.Close()

		return errors.New("meshcred: cannot open identity state")
	}

	return errors.Join(store.VerifyAllCurrent(ctx), store.Close())
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(
		writer,
		"usage: meshcred [provision|rotate|finalize|commit|recover]",
	)
}
