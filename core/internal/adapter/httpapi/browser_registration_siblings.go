package httpapi

import (
	"context"
	"net/http"
	"net/url"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// BrowserRegistrationSiblings is an approver that knows the person's other
// Devices on this machine, held by its other profiles (schema 291,
// duplicate-device design §7): the page names them, and "Use that account"
// ends the sign-in without making a second Device in that Network.
type BrowserRegistrationSiblings interface {
	LookupSiblingDevices(context.Context, accountsession.Digest, string) ([]control.BrowserSiblingDevice, error)
	JoinExistingDevice(context.Context, accountsession.Digest, string, publicid.ID) (bool, error)
}

// browserRegistrationSiblingView is one of the person's Devices on this
// machine, in a Network the page does not let them pick again.
type browserRegistrationSiblingView struct {
	DeviceID, Hostname, NetworkName, WorkspaceName string
	SignedOut, Suspended                           bool
}

// browserRegistrationSiblingRow is one row of the "already on this
// computer" list with the page it is on (its form needs the page's proof).
type browserRegistrationSiblingRow struct {
	Page browserRegistrationChoiceView
	Row  browserRegistrationSiblingView
}

// browserRegistrationJoinedView is the result page of "Use that account".
type browserRegistrationJoinedView struct {
	NetworkName string
	SignedOut   bool
}

// siblings is the page's approver when it knows sibling Devices.
func (page *BrowserRegistrationPage) siblings() (BrowserRegistrationSiblings, bool) {
	siblings, ok := page.approval.(BrowserRegistrationSiblings)
	return siblings, ok
}

// readSiblings adds the person's Devices on this machine to the view and
// leaves their Networks out of the list. A Network this sign-in's own
// Device is in stays a choice: signing that Device back in comes first
// (design §8.1). names maps Workspace IDs to their names. Call it after
// readMove.
func (page *BrowserRegistrationPage) readSiblings(ctx context.Context, digest accountsession.Digest,
	encodedToken string, view *browserRegistrationChoiceView, names map[string]string,
) error {
	siblings, ok := page.siblings()
	if !ok {
		return nil
	}
	devices, err := siblings.LookupSiblingDevices(ctx, digest, encodedToken)
	if err != nil {
		return err
	}
	taken := make(map[string]bool, len(devices))
	var rows []browserRegistrationSiblingView
	for _, device := range devices {
		if device.NetworkID == "" || device.NetworkID == view.Move.NetworkID ||
			device.NetworkID == view.Resume.NetworkID || taken[device.NetworkID] {
			continue // an older duplicate (design §11): the first one speaks for the Network
		}
		taken[device.NetworkID] = true
		rows = append(rows, browserRegistrationSiblingView{
			DeviceID: device.DeviceID, Hostname: device.Hostname, NetworkName: device.NetworkName,
			WorkspaceName: names[device.WorkspaceID],
			SignedOut:     device.State == control.SiblingSignedOut || device.State == control.SiblingExpired,
			Suspended:     !device.Usable(),
		})
	}
	if len(rows) > browserRegistrationShownSiblings {
		view.Siblings, view.MoreSiblings = rows[:browserRegistrationShownSiblings], rows[browserRegistrationShownSiblings:]
	} else {
		view.Siblings = rows
	}
	kept := view.Networks[:0:0]
	for _, choice := range view.Networks {
		if taken[choice.ID] {
			view.LeftOut = true
			continue
		}
		kept = append(kept, choice)
	}
	view.Networks = kept
	return nil
}

// siblingConflict reports whether approving networkID would make a second
// Device of the person's in that Network on this machine (design §8.3). The
// store checks it again in the approving transaction.
func (page *BrowserRegistrationPage) siblingConflict(ctx context.Context, digest accountsession.Digest,
	encodedToken string, networkID network.ID, ownNetwork string,
) (bool, error) {
	siblings, ok := page.siblings()
	if !ok || networkID.String() == ownNetwork {
		return false, nil
	}
	devices, err := siblings.LookupSiblingDevices(ctx, digest, encodedToken)
	if err != nil {
		return false, err
	}
	for _, device := range devices {
		if device.NetworkID == networkID.String() {
			return true, nil
		}
	}
	return false, nil
}

// join answers "Use that account" (design §8.2): the sign-in ends, and the
// app switches to the profile whose Device it is.
func (page *BrowserRegistrationPage) join(ctx context.Context, response http.ResponseWriter,
	form url.Values, digests []accountsession.Digest, encodedToken string,
) {
	siblings, ok := page.siblings()
	if !ok || len(form) != 2 || len(form["join"]) != 1 {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	device, err := publicid.Parse(form.Get("join"))
	if err != nil || !device.IsValid() {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	for _, digest := range digests {
		devices, err := siblings.LookupSiblingDevices(ctx, digest, encodedToken)
		if err != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		chosen, found := findSibling(devices, device.String())
		if !found || !chosen.Usable() {
			continue
		}
		joined, err := siblings.JoinExistingDevice(ctx, digest, encodedToken, device)
		if err != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if joined {
			page.render(response, page.joinedPage, browserRegistrationJoinedView{
				NetworkName: chosen.NetworkName,
				SignedOut:   chosen.State == control.SiblingSignedOut || chosen.State == control.SiblingExpired,
			})
			return
		}
	}
	http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func findSibling(devices []control.BrowserSiblingDevice, deviceID string) (control.BrowserSiblingDevice, bool) {
	for _, device := range devices {
		if device.DeviceID == deviceID {
			return device, true
		}
	}
	return control.BrowserSiblingDevice{}, false
}

const browserRegistrationJoinedHTML = browserRegistrationHead + `<title>Already connected | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main>` + browserRegistrationBrand + `<section class="card" id="registration-joined"><span class="done" aria-hidden="true">✓</span><p class="eyebrow">Connect a device</p><h1>Already connected</h1><p class="muted">Return to MeshTransit. It switches to the account already in <strong>{{.NetworkName}}</strong>{{if .SignedOut}} and asks you to sign it back in{{end}}. You can close this tab.</p></section></main></body></html>`
