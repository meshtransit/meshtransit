package main

import "meshtransit.net/client/internal/cli/localapi"

// routeChoiceCommand is the change a routes command makes to the host's
// own choices, or show for show; ok is false for any other command.
func routeChoiceCommand(args []string) (change localapi.RouteChoiceChange, show, ok bool) {
	if len(args) == 1 && args[0] == "show" {
		return change, true, true
	}
	if len(args) != 2 || args[1] == "" {
		return change, false, false
	}
	switch args[0] {
	case "exit-use":
		use := args[1]
		change.ExitUse = &use
	case "accept", "exit-allow-lan":
		if args[1] != "on" && args[1] != "off" {
			return change, false, false
		}
		on := args[1] == "on"
		if args[0] == "accept" {
			change.AcceptRoutes = &on
		} else {
			change.ExitAllowLAN = &on
		}
	default:
		return change, false, false
	}
	return change, false, true
}
