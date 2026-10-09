package main

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

type lookupUserFunc func(string) (*user.User, error)

func resolveAllowedUID(
	hasUID bool,
	uid uint64,
	username string,
	lookup lookupUserFunc,
) (uint32, error) {
	if hasUID == (username != "") {
		return 0, errors.New("exactly one of --allow-uid or --allow-user is required")
	}
	if hasUID {
		if uid > uint64(^uint32(0)) {
			return 0, errors.New("--allow-uid is outside uint32")
		}

		return uint32(uid), nil
	}
	if !validUserName(username) {
		return 0, errors.New("--allow-user must be a canonical local account name")
	}
	account, err := lookup(username)
	if err != nil {
		return 0, fmt.Errorf("looking up --allow-user: %w", err)
	}
	if account == nil {
		return 0, errors.New("looking up --allow-user returned no account")
	}
	parsed, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing --allow-user uid: %w", err)
	}

	return uint32(parsed), nil
}

func validUserName(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if index == 0 {
			if (character < 'a' || character > 'z') && character != '_' {
				return false
			}

			continue
		}
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}

	return true
}
