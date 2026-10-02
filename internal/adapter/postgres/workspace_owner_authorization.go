package postgres

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// Only the durable resolver can return owner authority. An owner has no
// RoleBinding or RoleDefinition; zero role identities must never be fabricated.
func parseNetworkPermissionAuthority(
	bindingValue, roleValue string,
	ownerGeneration int64,
) (publicid.ID, publicid.ID, error) {
	if ownerGeneration > 0 && bindingValue == "" && roleValue == "" {
		return publicid.ID{}, publicid.ID{}, nil
	}
	if ownerGeneration != 0 || bindingValue == "" || roleValue == "" {
		return publicid.ID{}, publicid.ID{}, errors.New("invalid Network permission authority")
	}
	binding, bindingErr := publicid.Parse(bindingValue)
	role, roleErr := publicid.Parse(roleValue)
	return binding, role, errors.Join(bindingErr, roleErr)
}

func validNetworkPermissionAuthority(
	binding, role publicid.ID,
	bindingGeneration, roleGeneration, ownerGeneration int64,
) bool {
	if ownerGeneration > 0 {
		return binding == (publicid.ID{}) && role == (publicid.ID{}) && bindingGeneration == 0 && roleGeneration == 0
	}
	return ownerGeneration == 0 && binding.IsValid() && role.IsValid() && bindingGeneration > 0 && roleGeneration > 0
}

func authorizationIDString(id publicid.ID) string {
	if !id.IsValid() {
		return ""
	}
	return id.String()
}
