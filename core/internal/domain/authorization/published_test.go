package authorization

import (
	"slices"
	"testing"
)

// TD-API-21: the API shows only permissions an operation checks, in order;
// every hidden one is in the catalog, so roles keep it.
func TestPublishedStrings(t *testing.T) {
	t.Parallel()
	catalog := Permissions()
	for permission := range withoutOperation {
		if !slices.Contains(catalog, permission) {
			t.Errorf("%s is hidden but not in the catalog", permission)
		}
	}
	got := PublishedStrings([]Permission{PermissionNetworkRead, PermissionWorkspaceDelete, PermissionDeviceRead,
		PermissionPolicyDraft, PermissionEnrollmentCredentialIssue})
	want := []string{"network.read", "device.read", "enrollment_credential.issue"}
	if !slices.Equal(got, want) {
		t.Fatalf("PublishedStrings() = %v, want %v", got, want)
	}
	if len(PublishedStrings[Permission](nil)) != 0 {
		t.Fatal("PublishedStrings(nil) is not empty")
	}
}
