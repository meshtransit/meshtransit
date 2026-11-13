package mtcp

import (
	"context"
	"slices"
	"sync"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// siblingBrowser is fakeBrowser that also keeps and completes with the
// siblings a node proves (register.siblings1).
type siblingBrowser struct {
	*fakeBrowser
	mu        sync.Mutex
	recorded  [][32]byte
	completed [][32]byte
	records   int
	err       error // what completing with siblings answers, if set
}

func (browser *siblingBrowser) RecordSiblings(_ context.Context, _ control.AuthenticatedMachine, _ node.Key,
	approvalURL string, siblings [][32]byte,
) error {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	if approvalURL != testApprovalOrigin+approvalPath+"token-1" {
		return control.ErrInvalidBrowserRegistration
	}
	browser.records++
	browser.recorded = slices.Clone(siblings)
	return nil
}

func (browser *siblingBrowser) CompleteBrowserWithSiblings(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, hostname node.Hostname, followupURL string, siblings [][32]byte,
) (registration.Result, bool, error) {
	browser.mu.Lock()
	browser.completed = slices.Clone(siblings)
	err := browser.err
	browser.mu.Unlock()
	if err != nil {
		return registration.Result{}, false, err
	}
	return browser.CompleteBrowser(ctx, machine, nodeKey, hostname, followupURL)
}

func (browser *siblingBrowser) snapshot() (recorded, completed [][32]byte, records int) {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	return slices.Clone(browser.recorded), slices.Clone(browser.completed), browser.records
}

// newSiblingFixture is a conversation whose browser keeps siblings; with
// negotiated, the session negotiated register.siblings1.
func newSiblingFixture(t *testing.T, negotiated bool) (*conversationFixture, *siblingBrowser) {
	t.Helper()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	browser := &siblingBrowser{fakeBrowser: f.browser}
	f.talk.application.options.BrowserIssuer = browser
	f.talk.application.options.BrowserApproval = browser
	if negotiated {
		f.session.capabilities = append(f.session.capabilities, CapabilitySiblings)
	}
	return f, browser
}

// sibling is a machine key of another profile on the node's machine with
// its proof in f's session, or a wrong proof when forged.
func (f *conversationFixture) sibling(forged bool) (*mtcpv1.RegisterRequest_Sibling, [32]byte) {
	f.t.Helper()
	private, err := key.NewMachinePrivate(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	public := [32]byte(private.Public())
	hash := f.session.HandshakeHash()
	if forged {
		hash[0] ^= 1
	}
	proof, err := sharedmtcp.SiblingMachineKeyProof(private, f.control.Public(), hash)
	if err != nil {
		f.t.Fatal(err)
	}
	return &mtcpv1.RegisterRequest_Sibling{MachineKey: public[:], Proof: proof[:]}, public
}

// A browser sign-in keeps only the siblings proven in this session, and
// none unless the session negotiated register.siblings1 (mtcp-v1 §6.2).
func TestInteractiveRegistrationKeepsProvenSiblings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		negotiated bool
	}{{name: "negotiated", negotiated: true}, {name: "not negotiated"}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f, browser := newSiblingFixture(t, test.negotiated)
			f.run()
			first, firstKey := f.sibling(false)
			second, secondKey := f.sibling(false)
			forged, _ := f.sibling(true)
			own := f.session.Machine()
			request := f.request(4, interactiveAuth(""))
			request.Siblings = []*mtcpv1.RegisterRequest_Sibling{
				first, forged, second, first, // repeated
				{MachineKey: own[:], Proof: first.GetProof()},
				{MachineKey: []byte{1, 2}, Proof: first.GetProof()},
			}
			if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
				t.Fatal(err)
			}
			if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending() == nil {
				t.Fatal("no pending approval")
			}
			recorded, _, records := browser.snapshot()
			if !test.negotiated {
				if records != 0 {
					t.Fatalf("recorded %d sibling sets without register.siblings1", records)
				}
				return
			}
			if records != 1 || !slices.Equal(recorded, [][32]byte{firstKey, secondKey}) {
				t.Fatalf("recorded %d sets: %x", records, recorded)
			}
		})
	}
}

func TestInteractiveRegistrationRefusesTooManySiblings(t *testing.T) {
	t.Parallel()
	f, browser := newSiblingFixture(t, true)
	f.run()
	request := f.request(4, interactiveAuth(""))
	for range maxSiblings + 1 {
		entry, _ := f.sibling(false)
		request.Siblings = append(request.Siblings, entry)
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	rejected := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected()
	if rejected.GetCode() != mtcpv1.RegisterResponse_Rejected_INVALID {
		t.Fatalf("answered %v", rejected)
	}
	if _, _, records := browser.snapshot(); records != 0 {
		t.Fatal("refused siblings were recorded")
	}
}

// A sign-in the approver ended with "Use that account" answers
// already_in_network with the sibling's key, both while the node waits and
// on a resume; a node without register.siblings1 gets CONFLICT instead.
func TestInteractiveRegistrationAnswersAlreadyInNetwork(t *testing.T) {
	t.Parallel()
	sibling := [32]byte{9, 8, 7}
	joined := &registration.JoinedExistingError{SiblingMachineKey: sibling}
	for _, test := range []struct {
		name       string
		negotiated bool
		resume     bool
	}{
		{name: "waiting", negotiated: true},
		{name: "resumed", negotiated: true, resume: true},
		{name: "old node waiting"},
		{name: "old node resumed", resume: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f, browser := newSiblingFixture(t, test.negotiated)
			f.run()
			handle := ""
			if test.resume {
				handle = "token-1"
				browser.err = joined
			}
			entry, entryKey := f.sibling(false)
			request := f.request(4, interactiveAuth(handle))
			request.Siblings = []*mtcpv1.RegisterRequest_Sibling{entry}
			if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
				t.Fatal(err)
			}
			if !test.resume {
				f.expect(sharedmtcp.MessageRegisterResponse)
				browser.mu.Lock()
				browser.err = joined
				browser.mu.Unlock()
			}
			response := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse)
			if !test.negotiated {
				if response.GetRejected().GetCode() != mtcpv1.RegisterResponse_Rejected_CONFLICT {
					t.Fatalf("old node answered %v", response)
				}
				return
			}
			if got := response.GetAlreadyInNetwork().GetSiblingMachineKey(); [32]byte(got) != sibling {
				t.Fatalf("answered %v", response)
			}
			if _, completed, _ := browser.snapshot(); !slices.Equal(completed, [][32]byte{entryKey}) {
				t.Fatalf("completed with %x", completed)
			}
		})
	}
}

// A completion that would make a second Device of the person's in the
// approved Network answers CONFLICT with the sibling wording.
func TestInteractiveRegistrationRefusesSiblingConflict(t *testing.T) {
	t.Parallel()
	f, browser := newSiblingFixture(t, true)
	f.run()
	// The completion service passes it through unwrapped.
	browser.err = registration.ErrSiblingConflict
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, interactiveAuth("token-1"))); err != nil {
		t.Fatal(err)
	}
	rejected := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected()
	if rejected.GetCode() != mtcpv1.RegisterResponse_Rejected_CONFLICT || rejected.GetMessage() != siblingConflict.message {
		t.Fatalf("answered %v", rejected)
	}
}
