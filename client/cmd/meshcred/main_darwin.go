// Command meshcred manages the macOS identity key of meshd.
//
// On macOS the key is an owner-only file of the meshd user, outside the state
// directory and excluded from Time Machine. Unlike the Linux systemd
// credential it is not bound to the host's hardware; a Keychain-backed key is
// planned.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/secretstore"
)

const (
	defaultMeshdUser = "_meshd"
	tmutilPath       = "/usr/bin/tmutil"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("meshcred", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyPath := flags.String("key", config.DefaultIdentityKeyPath, "identity key file")
	meshdUser := flags.String("user", defaultMeshdUser, "user meshd runs as")
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		printUsage(stderr)
		return 2
	}
	operation := "provision"
	if flags.NArg() == 1 {
		operation = flags.Arg(0)
	}
	switch operation {
	case "provision":
		owner, err := user.Lookup(*meshdUser)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "meshcred: unknown user %s\n", *meshdUser)
			return 1
		}
		uid, uidErr := strconv.Atoi(owner.Uid)
		gid, gidErr := strconv.Atoi(owner.Gid)
		if uidErr != nil || gidErr != nil {
			_, _ = fmt.Fprintln(stderr, "meshcred: meshd user has an invalid id")
			return 1
		}
		if err := provision(*keyPath, uid, gid, rand.Reader); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshcred: provision failed: %v\n", err)
			return 1
		}
		excludeFromBackups(*keyPath)
		return 0
	case "rotate", "finalize", "commit", "recover":
		_, _ = fmt.Fprintf(stderr, "meshcred: %s is not supported on macOS yet\n", operation)
		return 1
	default:
		printUsage(stderr)
		return 2
	}
}

// provision creates the key once, or checks the one already there: a regular
// file owned by uid, mode 0400 or 0600, holding exactly one key.
func provision(path string, uid, gid int, random io.Reader) error {
	if !filepath.IsAbs(path) {
		return errors.New("key path must be absolute")
	}
	info, err := os.Lstat(path)
	if err == nil {
		return checkExisting(path, info, uid)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	key := make([]byte, secretstore.KeySize)
	defer clear(key)
	if _, err := io.ReadFull(random, key); err != nil {
		return fmt.Errorf("generating the key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // root-chosen path, created exclusively
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	written, writeErr := file.Write(key)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil || written != len(key) {
		_ = os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, errors.Join(err, errors.New("short write")))
	}
	if err := os.Chown(path, uid, gid); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("handing %s to the meshd user: %w", path, err)
	}
	return nil
}

func checkExisting(path string, info os.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() != secretstore.KeySize {
		return fmt.Errorf("%s exists but is not an identity key", path)
	}
	if int(stat.Uid) != uid || info.Mode().Perm()&0o377 != 0 && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s has the wrong owner or permissions", path)
	}
	return nil
}

// excludeFromBackups keeps the key out of Time Machine, so a stolen backup
// does not carry both the key and the identity records it protects.
func excludeFromBackups(path string) {
	if _, err := os.Stat(tmutilPath); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, tmutilPath, "addexclusion", path).Run() //nolint:gosec // fixed system tool, root-chosen path
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "usage: meshcred [--key PATH] [--user NAME] [provision]")
}
