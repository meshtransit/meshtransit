package mtcpclient

import (
	"slices"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// siblingsCapability is register.siblings1 (mtcp-v1 §6.2, duplicate-device
// design §5).
const siblingsCapability = "register.siblings1"

// maxSiblings bounds RegisterRequest.siblings; Core refuses more.
const maxSiblings = 16

// siblingCapabilities is register.siblings1 for a browser sign-in that has
// siblings to prove; nothing otherwise.
func siblingCapabilities(options controlplane.RegisterOptions) []string {
	if !browserSignIn(options) || len(options.SiblingMachinePrivateKeys) == 0 {
		return nil
	}
	return []string{siblingsCapability}
}

func browserSignIn(options controlplane.RegisterOptions) bool {
	return options.AuthKey == "" && options.ClusterJoin == nil
}

// attachSiblings adds the sibling proofs to a browser sign-in's request
// when Core offered register.siblings1, and returns the public keys sent.
// A key that does not parse, repeats, or is the session's own is left out:
// one bad profile never stops a sign-in.
func attachSiblings(s *session, request *mtcpv1.RegisterRequest, keys profileKeys,
	options controlplane.RegisterOptions,
) [][key.Size]byte {
	if !browserSignIn(options) || len(options.SiblingMachinePrivateKeys) == 0 ||
		!slices.Contains(s.reply.GetCapabilities(), siblingsCapability) {
		return nil
	}
	own := [key.Size]byte(keys.machine.Public())
	hash := s.noise.HandshakeHash()
	sent := make([][key.Size]byte, 0, min(len(options.SiblingMachinePrivateKeys), maxSiblings))
	for _, encoded := range options.SiblingMachinePrivateKeys {
		if len(sent) == maxSiblings {
			break
		}
		raw, err := controlplane.ParsePrivateKey(encoded)
		if err != nil {
			continue
		}
		machine, err := key.MachinePrivateFromBytes(raw[:])
		clear(raw[:])
		if err != nil {
			continue
		}
		public := [key.Size]byte(machine.Public())
		if public == own || slices.Contains(sent, public) {
			continue
		}
		proof, err := sharedmtcp.SiblingMachineKeyProof(machine, s.control, hash)
		if err != nil {
			continue
		}
		request.Siblings = append(request.Siblings, &mtcpv1.RegisterRequest_Sibling{
			MachineKey: public[:], Proof: proof[:],
		})
		sent = append(sent, public)
	}
	return sent
}
