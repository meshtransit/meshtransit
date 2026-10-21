//go:build !windows

package main

import (
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/client/internal/routesettings/operator"
)

func TestOnlyTheOperatorChoicesSkipSudo(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want operator.Request
	}{
		{[]string{"exit-use", "World"}, operator.Request{Command: operator.CommandExitUse, ExitUse: "World"}},
		{[]string{"exit-use", "off"}, operator.Request{Command: operator.CommandExitUse, ExitUse: "off"}},
		{[]string{"accept", "on"}, operator.Request{Command: operator.CommandAccept, On: true}},
		{[]string{"exit-allow-lan", "off"}, operator.Request{Command: operator.CommandExitAllowLAN}},
	} {
		if got, ok := operatorRequest(test.args); !ok || got != test.want {
			t.Errorf("operatorRequest(%q) = %+v, %v; want %+v", test.args, got, ok, test.want)
		}
	}
	for _, args := range [][]string{
		{"exit-mode", "on"},
		{"router-mode", "on"},
		{"accept-public", "on"},
		{"advertise", "10.0.0.0/8"},
		{"exit-allow-managed", "on"},
		{"exit-captive", "on"},
		{"operators", "on"},
		{"accept", "maybe"},
		{"exit-use"},
		{"exit-use", "a", "b"},
	} {
		if _, ok := operatorRequest(args); ok {
			t.Errorf("operatorRequest(%q) skipped sudo", args)
		}
	}
}

func TestOnlyADeclinedOperatorAsksSudo(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		sudo bool
	}{
		{fmt.Errorf("%w: /s: no such file", operator.ErrUnreachable), true},
		{&operator.Error{Code: operator.CodeNotPermitted}, true},
		{&operator.Error{Code: operator.CodeOperatorsOff}, true},
		{&operator.Error{Code: operator.CodeRootSetting}, true},
		{&operator.Error{Code: operator.CodeInvalidValue}, false},
		{&operator.Error{Code: operator.CodeUnavailable}, false},
		{errors.New("operator: reading: i/o timeout"), false},
	} {
		if got := operatorDeclined(test.err); got != test.sudo {
			t.Errorf("operatorDeclined(%v) = %v, want %v", test.err, got, test.sudo)
		}
	}
}
