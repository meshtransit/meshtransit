package httpapi

import (
	"context"
	"strings"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

// browserRegistrationShownSiblings is how many of the person's Devices on
// this machine the page lists before "Show more".
const browserRegistrationShownSiblings = 3

// browserRegistrationSelection is the Workspace the page shows and the page
// of its Networks: the Networks after `after`, in Core's order. The zero
// value is the page's own choice of Workspace and its first Networks.
type browserRegistrationSelection struct {
	workspace workspace.ID
	after     network.ID
}

// parseBrowserRegistrationSelection admits an empty query, or exactly the
// query the page itself writes: workspace=<id>, then optionally
// &after=<Network id>. Anything else is refused (the page's only inputs are
// its token and these two IDs).
func parseBrowserRegistrationSelection(raw string) (browserRegistrationSelection, bool) {
	if raw == "" {
		return browserRegistrationSelection{}, true
	}
	if len(raw) > 128 {
		return browserRegistrationSelection{}, false
	}
	first, rest, hasAfter := strings.Cut(raw, "&")
	value, ok := strings.CutPrefix(first, "workspace=")
	if !ok {
		return browserRegistrationSelection{}, false
	}
	chosen, err := workspace.ParseID(value)
	if err != nil {
		return browserRegistrationSelection{}, false
	}
	selection := browserRegistrationSelection{workspace: chosen}
	if hasAfter {
		value, ok = strings.CutPrefix(rest, "after=")
		if !ok {
			return browserRegistrationSelection{}, false
		}
		if selection.after, err = network.ParseID(value); err != nil {
			return browserRegistrationSelection{}, false
		}
	}
	if selection.query() != raw {
		return browserRegistrationSelection{}, false
	}
	return selection, true
}

// query is the selection as the page writes it.
func (selection browserRegistrationSelection) query() string {
	if !selection.workspace.IsValid() {
		return ""
	}
	query := "workspace=" + selection.workspace.String()
	if selection.after.IsValid() {
		query += "&after=" + selection.after.String()
	}
	return query
}

type browserRegistrationNetworkView struct {
	ID   string
	Name string
}

type browserRegistrationWorkspaceView struct {
	ID       string
	Name     string
	Initial  string
	Selected bool
}

type browserRegistrationChoiceView struct {
	Hostname string
	Path     string
	// Workspaces are the ones the person may join a Network in; Workspace is
	// the one shown, with its Networks this page lists (at most 100).
	Workspaces     []browserRegistrationWorkspaceView
	Workspace      browserRegistrationWorkspaceView
	Networks       []browserRegistrationNetworkView
	NetworkCount   int
	MoreWorkspaces bool
	// NextNetworks and FirstNetworks link to the next page of Networks and
	// back to the first; empty when there is none.
	NextNetworks  string
	FirstNetworks string
	// LeftOut reports that the list leaves out Networks of this Workspace:
	// this computer already is the person's Device there under another
	// account (the "Already on this computer" list names them).
	LeftOut bool
	// MoveElsewhere links to the Workspace of the Network this computer is
	// in, when the page shows another one.
	MoveElsewhere string
	MoveWorkspace string
	CSRF          string
	Action        string
	SwitchAccount bool
	// Move describes the person's own Device this machine already is, which
	// the page preselects; choosing another Network needs MoveConfirm.
	Move        browserRegistrationMoveView
	Resume      browserRegistrationMoveView
	MoveOther   bool
	MoveMissing bool
	// Siblings are the person's Devices on this machine under other
	// accounts in the app (duplicate-device design §7): the first few, then
	// the rest behind "Show more".
	Siblings        []browserRegistrationSiblingView
	MoreSiblings    []browserRegistrationSiblingView
	SiblingConflict bool
}

type browserRegistrationMoveView struct {
	DeviceID, Hostname, WorkspaceID, NetworkID, NetworkName string
}

// readPage reads what the landing shows: the Workspaces, what this machine
// already is, then the Networks of one Workspace (the one asked for, else
// the one this machine is in, else the first), never every Workspace's.
func (page *BrowserRegistrationPage) readPage(ctx context.Context, digest accountsession.Digest,
	encodedToken string, selection browserRegistrationSelection,
) (enrollment.BrowserIntentLanding, browserRegistrationChoiceView, bool, error) {
	workspaces, found, err := page.choices.ReadWorkspaces(ctx, digest, encodedToken,
		workspace.ID{}, browserRegistrationPageLimit)
	if err != nil || !found {
		return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
	}
	view := browserRegistrationChoiceView{MoreWorkspaces: workspaces.HasMore}
	if err := page.readMove(ctx, digest, encodedToken, &view); err != nil {
		return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
	}
	chosen, at := chooseWorkspace(workspaces.Choices.Workspaces, selection.workspace,
		view.Move.WorkspaceID, view.Resume.WorkspaceID)
	names := make(map[string]string, len(workspaces.Choices.Workspaces))
	for index, choice := range workspaces.Choices.Workspaces {
		names[choice.WorkspaceID.String()] = choice.DisplayName
		view.Workspaces = append(view.Workspaces, browserRegistrationWorkspaceView{
			ID: choice.WorkspaceID.String(), Name: choice.DisplayName,
			Initial: workspaceInitial(choice.DisplayName), Selected: index == at,
		})
	}
	path := browserRegistrationPagePrefix + encodedToken
	if at >= 0 {
		view.Workspace = view.Workspaces[at]
		after := network.ID{}
		if selection.workspace == chosen {
			after = selection.after
		}
		networks, found, err := page.choices.ReadNetworks(ctx, digest, encodedToken, chosen, after,
			browserRegistrationPageLimit)
		if err != nil {
			return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
		}
		var last network.ID
		if found {
			view.Networks = browserRegistrationNetworks(networks)
			if networks.HasMore && len(networks.Choices.Networks) > 0 {
				last = networks.Choices.Networks[len(networks.Choices.Networks)-1].NetworkID
				view.NextNetworks = pageLink(path, browserRegistrationSelection{workspace: chosen, after: last})
			}
		}
		if after.IsValid() {
			view.FirstNetworks = pageLink(path, browserRegistrationSelection{workspace: chosen})
		}
		pinOwnNetwork(&view, chosen.String(), after, last)
	}
	markOwnWorkspace(&view, workspaces.Choices.Workspaces, path)
	if err := page.readSiblings(ctx, digest, encodedToken, &view, names); err != nil {
		return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
	}
	view.NetworkCount = len(view.Networks)
	return workspaces.Landing, view, true, nil
}

// chooseWorkspace returns the Workspace the page shows and its index (-1
// when there is none): the one asked for when the person may join in it,
// else the one this machine is the person's Device in, else the first.
func chooseWorkspace(choices []enrollment.BrowserEnrollmentWorkspaceChoice, asked workspace.ID,
	preferred ...string,
) (workspace.ID, int) {
	if asked.IsValid() {
		for index, choice := range choices {
			if choice.WorkspaceID == asked {
				return choice.WorkspaceID, index
			}
		}
	}
	for _, id := range preferred {
		for index, choice := range choices {
			if id != "" && choice.WorkspaceID.String() == id {
				return choice.WorkspaceID, index
			}
		}
	}
	if len(choices) == 0 {
		return workspace.ID{}, -1
	}
	return choices[0].WorkspaceID, 0
}

// pageLink is the page's own address with a selection: the token path the
// request was admitted on and IDs Core gave.
func pageLink(path string, selection browserRegistrationSelection) string {
	return path + "?" + selection.query()
}

// pinOwnNetwork keeps the Network this computer is in (to sign it back in)
// first in the list when it is in the Workspace shown but on another page of
// Networks (review C1). Core pages Networks by ID (UUIDv7, ordered as
// text), so a Network inside this page's range that is not listed is one
// the person may not join any more: it is not offered (re-check R1).
// after is this page's cursor; last is its last Network when more follow.
func pinOwnNetwork(view *browserRegistrationChoiceView, shown string, after, last network.ID) {
	for _, own := range []browserRegistrationMoveView{view.Move, view.Resume} {
		if own.NetworkID == "" || own.WorkspaceID != shown {
			continue
		}
		for _, choice := range view.Networks {
			if choice.ID == own.NetworkID {
				return
			}
		}
		before := after.IsValid() && own.NetworkID <= after.String()
		beyond := last.IsValid() && own.NetworkID > last.String()
		if !before && !beyond {
			return
		}
		view.Networks = append([]browserRegistrationNetworkView{{ID: own.NetworkID, Name: own.NetworkName}},
			view.Networks...)
		return
	}
}

// markOwnWorkspace names the Workspace of the Network this computer is in,
// with a link to it when the page shows another one (review C1).
func markOwnWorkspace(view *browserRegistrationChoiceView,
	choices []enrollment.BrowserEnrollmentWorkspaceChoice, path string,
) {
	own := view.Move.WorkspaceID
	if own == "" {
		own = view.Resume.WorkspaceID
	}
	for _, choice := range choices {
		if choice.WorkspaceID.String() != own {
			continue
		}
		if own != view.Workspace.ID {
			view.MoveWorkspace = choice.DisplayName
			view.MoveElsewhere = pageLink(path, browserRegistrationSelection{workspace: choice.WorkspaceID})
		}
		return
	}
}

func workspaceInitial(name string) string {
	for _, character := range strings.TrimSpace(name) {
		return strings.ToUpper(string(character))
	}
	return "W"
}

func browserRegistrationNetworks(page control.BrowserChoicePage) []browserRegistrationNetworkView {
	names := make([]browserRegistrationNetworkView, 0, len(page.Choices.Networks))
	for _, choice := range page.Choices.Networks {
		names = append(names, browserRegistrationNetworkView{
			ID: choice.NetworkID.String(), Name: choice.DisplayName,
		})
	}
	return names
}
