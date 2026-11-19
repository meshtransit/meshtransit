package roles

import (
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestMemberEmailAndJoinTime(t *testing.T) {
	t.Parallel()
	principal, err := publicid.Parse("0199a0c6-8294-7d06-9cad-a54d198487fa")
	if err != nil {
		t.Fatal(err)
	}
	base := Member{PrincipalID: principal, DisplayName: "Lan", MembershipState: "active",
		JoinedAt: time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)}
	for _, test := range []struct {
		name  string
		edit  func(Member) Member
		valid bool
	}{
		{"no email yet", func(member Member) Member { return member }, true},
		{"an email", func(member Member) Member { member.Email = "lan@example.com"; return member }, true},
		{"no join time", func(member Member) Member { member.JoinedAt = time.Time{}; return member }, false},
		{"two @", func(member Member) Member { member.Email = "a@b@c"; return member }, false},
		{"leading @", func(member Member) Member { member.Email = "@example.com"; return member }, false},
		{"a space", func(member Member) Member { member.Email = "lan @example.com"; return member }, false},
		{"angle bracket", func(member Member) Member { member.Email = "<lan@example.com"; return member }, false},
		{"not ASCII", func(member Member) Member { member.Email = "lân@example.com"; return member }, false},
		{"too long", func(member Member) Member {
			member.Email = strings.Repeat("a", 250) + "@b.cd"
			return member
		}, false},
	} {
		if got := test.edit(base).IsValid(); got != test.valid {
			t.Errorf("%s: IsValid() = %v, want %v", test.name, got, test.valid)
		}
	}
}
