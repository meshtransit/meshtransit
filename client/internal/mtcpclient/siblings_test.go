package mtcpclient

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// siblingCore is registrationCore that keeps the sibling keys whose proofs
// hold in each request, and answers a follow-up with already_in_network for
// joined when set.
type siblingCore struct {
	*registrationCore
	mu       sync.Mutex
	proven   [][32]byte
	invalid  int
	received bool
	joined   [32]byte
}

func newSiblingCore(t *testing.T, offered bool) *siblingCore {
	core := &siblingCore{registrationCore: newRegistrationCore(t)}
	core.set(func(fake *fakeCore) {
		if offered {
			fake.extra = []string{siblingsCapability}
		}
		fake.serve = core.handle
	})
	return core
}

func (core *siblingCore) handle(s *coreSession) {
	_, message, err := s.receive(5 * time.Second)
	if err != nil {
		return
	}
	request, ok := message.(*mtcpv1.RegisterRequest)
	if !ok {
		return
	}
	core.mu.Lock()
	core.received = true
	core.proven, core.invalid = nil, 0
	for _, sibling := range request.GetSiblings() {
		if sharedmtcp.VerifySiblingMachineKeyProof(s.control, s.hash, [32]byte(sibling.GetMachineKey()),
			sibling.GetProof()) {
			core.proven = append(core.proven, [32]byte(sibling.GetMachineKey()))
		} else {
			core.invalid++
		}
	}
	joined := core.joined
	core.mu.Unlock()
	if request.GetAuth().GetInteractive().GetResumeHandle() != "" && joined != ([32]byte{}) {
		core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_AlreadyInNetwork_{
			AlreadyInNetwork: &mtcpv1.RegisterResponse_AlreadyInNetwork{SiblingMachineKey: joined[:]},
		}})
		return
	}
	core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Pending_{
		Pending: &mtcpv1.RegisterResponse_Pending{
			ApprovalUrl: core.approvalURL(), ResumeHandle: "token-1",
			ExpiresMs: time.Now().Add(10 * time.Minute).UnixMilli(),
		},
	}})
	answerPings(s)
}

func (core *siblingCore) seen() ([][32]byte, int, bool) {
	core.mu.Lock()
	defer core.mu.Unlock()
	return slices.Clone(core.proven), core.invalid, core.received
}

func siblingKey(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	encoded, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controlplane.ParsePrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := key.MachinePrivateFromBytes(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return encoded, [32]byte(machine.Public())
}

// A browser sign-in proves its siblings only where Core offers
// register.siblings1, leaves out its own key, repeats and malformed keys,
// and never sends them with an enrollment key.
func TestRegisterProvesSiblings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		offered bool
		authKey string
		want    int
	}{
		{name: "offered", offered: true, want: 2},
		{name: "not offered"},
		{name: "enrollment key", offered: true, authKey: "mtc1.good"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			core := newSiblingCore(t, test.offered)
			trust := core.trust(t)
			first, firstPublic := siblingKey(t)
			second, secondPublic := siblingKey(t)
			options := controlplane.RegisterOptions{
				Hostname: "laptop", PinnedFingerprint: trust.Fingerprint,
				AuthKey: test.authKey,
				SiblingMachinePrivateKeys: [][]byte{
					first, trust.Material.MachinePrivateKey, []byte("privkey:zz"), second, first,
				},
			}
			if _, err := core.client().Register(t.Context(), core.origin(), trust.Material, options); err != nil &&
				test.authKey == "" {
				t.Fatal(err)
			}
			proven, invalid, received := core.seen()
			if !received || invalid != 0 || len(proven) != test.want {
				t.Fatalf("proven %d, invalid %d", len(proven), invalid)
			}
			if test.want == 2 && !slices.Equal(proven, [][32]byte{firstPublic, secondPublic}) {
				t.Fatal("wrong siblings")
			}
		})
	}
}

// already_in_network answers with a key this session proved; any other key
// is refused.
func TestRegisterAlreadyInNetwork(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		other bool
	}{{name: "proved key"}, {name: "key not sent", other: true}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			core := newSiblingCore(t, true)
			trust := core.trust(t)
			sibling, public := siblingKey(t)
			core.mu.Lock()
			core.joined = public
			if test.other {
				core.joined = [32]byte{1}
			}
			core.mu.Unlock()
			options := controlplane.RegisterOptions{
				Hostname: "laptop", PinnedFingerprint: trust.Fingerprint,
				FollowupURL: core.approvalURL(), SiblingMachinePrivateKeys: [][]byte{sibling},
			}
			result, err := core.client().Register(t.Context(), core.origin(), trust.Material, options)
			if test.other {
				if !errors.Is(err, controlplane.ErrRegistration) {
					t.Fatalf("a key not sent = %+v, %v", result, err)
				}
				return
			}
			if err != nil || result.State != controlplane.RegistrationStateAlreadyInNetwork ||
				result.SiblingMachineKey != public {
				t.Fatalf("Register = %+v, %v", result, err)
			}
		})
	}
}
