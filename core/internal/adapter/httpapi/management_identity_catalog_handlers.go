package httpapi

import (
	"context"
	"net/http"

	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/publicid"
)

type identityGroupBody struct {
	GroupID     string `json:"group_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
	RuleCount   int    `json:"rule_count"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func newIdentityGroupBody(group identitygroup.Group) identityGroupBody {
	return identityGroupBody{
		GroupID: group.ID.String(), Name: group.Name, Description: group.Description,
		MemberCount: group.MemberCount, RuleCount: group.RuleCount, Version: group.Version,
		CreatedAt: managementTime(group.CreatedAt), UpdatedAt: managementTime(group.UpdatedAt),
	}
}

type deviceTagBody struct {
	TagID         string   `json:"tag_id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	OwnerGroupIDs []string `json:"owner_group_ids"`
	OwnerRoles    []string `json:"owner_roles"`
	DeviceCount   int      `json:"device_count"`
	RuleCount     int      `json:"rule_count"`
	Version       int64    `json:"version"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func newDeviceTagBody(tag devicetag.Tag) deviceTagBody {
	groups := make([]string, len(tag.OwnerGroups))
	for index, group := range tag.OwnerGroups {
		groups[index] = group.String()
	}
	return deviceTagBody{
		TagID: tag.ID.String(), Name: tag.Name, Description: tag.Description, OwnerGroupIDs: groups,
		OwnerRoles: append([]string{}, tag.OwnerRoles...), DeviceCount: tag.DeviceCount, RuleCount: tag.RuleCount,
		Version: tag.Version, CreatedAt: managementTime(tag.CreatedAt), UpdatedAt: managementTime(tag.UpdatedAt),
	}
}

func tagIDTexts(tags []devicetag.ID) []string {
	texts := make([]string, len(tags))
	for index, tag := range tags {
		texts[index] = tag.String()
	}
	return texts
}

func parsePublicIDs(texts []string, maximum int) ([]publicid.ID, bool) {
	if len(texts) > maximum {
		return nil, false
	}
	ids := make([]publicid.ID, len(texts))
	for index, text := range texts {
		id, ok := canonicalPublicID(text)
		if !ok {
			return nil, false
		}
		ids[index] = id
	}
	return ids, true
}

func (handler *ManagementHandler) handleIdentityGroups(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path identityCatalogPath, session accountsession.Session,
	fail func(managementError) string) string {
	groups := handler.identityGroups
	switch path.action {
	case "":
		listing, err := groups.List(ctx, session, path.scope)
		if err != nil {
			return fail(classifyIdentityGroupError(err))
		}
		bodies := make([]identityGroupBody, 0, len(listing.Groups))
		for _, group := range listing.Groups {
			bodies = append(bodies, newIdentityGroupBody(group))
		}
		var output struct {
			Data struct {
				Groups    []identityGroupBody `json:"groups"`
				CanManage bool                `json:"can_manage"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Groups, output.Data.CanManage, output.CorrelationID = bodies, listing.CanManage,
			correlationID.String()
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case "members":
		page, err := groups.Members(ctx, session, path.scope, path.groupID, path.after, path.limit)
		if err != nil {
			return fail(classifyIdentityGroupError(err))
		}
		type memberBody struct {
			PrincipalID string `json:"principal_id"`
			DisplayName string `json:"display_name"`
			Active      bool   `json:"active"`
			AddedAt     string `json:"added_at"`
		}
		members := make([]memberBody, 0, len(page.Members))
		for _, member := range page.Members {
			members = append(members, memberBody{
				PrincipalID: member.PrincipalID.String(), DisplayName: member.DisplayName, Active: member.Active,
				AddedAt: managementTime(member.AddedAt),
			})
		}
		var output struct {
			Data struct {
				Group   identityGroupBody `json:"group"`
				Members []memberBody      `json:"members"`
				Next    string            `json:"next_after,omitempty"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Group, output.Data.Members = newIdentityGroupBody(page.Group), members
		if page.HasMore && len(page.Members) > 0 {
			output.Data.Next = page.Members[len(page.Members)-1].PrincipalID.String()
		}
		output.CorrelationID = correlationID.String()
		response.Header().Set("ETag", strongVersionETag(page.Group.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case "change-members":
		return handler.changeIdentityGroupMembers(ctx, response, request, correlationID, path, session, fail)
	}
	var result identitygroup.Result
	var err error
	if path.action == "create" {
		definition, valid := parseIdentityGroupDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = groups.Create(ctx, session, path.scope, definition, correlationID)
	} else {
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			definition, valid := parseIdentityGroupDefinition(response, request)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = groups.Update(ctx, session, path.scope, path.groupID, expectedVersion, definition,
				correlationID)
		} else {
			result, err = groups.Delete(ctx, session, path.scope, path.groupID, expectedVersion, correlationID)
		}
	}
	if err != nil {
		return fail(classifyIdentityGroupError(err))
	}
	var output struct {
		Data struct {
			Group   identityGroupBody `json:"group"`
			Deleted bool              `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Group, output.Data.Deleted = newIdentityGroupBody(result.Group), result.Deleted
	output.CorrelationID = correlationID.String()
	status := http.StatusOK
	if path.action == "create" {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(result.Group.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func parseIdentityGroupDefinition(response http.ResponseWriter, request *http.Request) (identitygroup.Definition, bool) {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Name == nil || body.Description == nil {
		return identitygroup.Definition{}, false
	}
	definition := identitygroup.Definition{Name: *body.Name, Description: *body.Description}
	return definition, definition.IsValid()
}

func (handler *ManagementHandler) changeIdentityGroupMembers(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path identityCatalogPath, session accountsession.Session,
	fail func(managementError) string) string {
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var body struct {
		Add    *[]string `json:"add"`
		Remove *[]string `json:"remove"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Add == nil || body.Remove == nil {
		return fail(*invalidManagementRequest())
	}
	add, addOK := parsePublicIDs(*body.Add, identitygroup.MaximumMembersPerChange)
	remove, removeOK := parsePublicIDs(*body.Remove, identitygroup.MaximumMembersPerChange)
	if !addOK || !removeOK || len(add)+len(remove) == 0 {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.identityGroups.ChangeMembers(ctx, session, path.scope, path.groupID,
		expectedVersion, add, remove, correlationID)
	if err != nil {
		return fail(classifyIdentityGroupError(err))
	}
	var output struct {
		Data struct {
			Group           identityGroupBody `json:"group"`
			Added           int               `json:"added"`
			Removed         int               `json:"removed"`
			AccessAffecting bool              `json:"access_affecting"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Group, output.Data.Added, output.Data.Removed = newIdentityGroupBody(result.Group), result.Added,
		result.Removed
	output.Data.AccessAffecting, output.CorrelationID = result.AccessAffecting(), correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Group.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func parseDeviceTagDefinition(response http.ResponseWriter, request *http.Request) (devicetag.Definition, bool) {
	var body struct {
		Name          *string   `json:"name"`
		Description   *string   `json:"description"`
		OwnerGroupIDs *[]string `json:"owner_group_ids"`
		OwnerRoles    *[]string `json:"owner_roles"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Name == nil || body.Description == nil ||
		body.OwnerGroupIDs == nil || body.OwnerRoles == nil {
		return devicetag.Definition{}, false
	}
	ids, ok := parsePublicIDs(*body.OwnerGroupIDs, devicetag.MaximumOwners)
	if !ok {
		return devicetag.Definition{}, false
	}
	groups := make([]identitygroup.ID, len(ids))
	for index, id := range ids {
		groups[index] = identitygroup.ID(id)
	}
	definition := devicetag.Definition{
		Name: *body.Name, Description: *body.Description, OwnerGroups: groups,
		OwnerRoles: append([]string{}, *body.OwnerRoles...),
	}
	return definition, definition.IsValid()
}

func (handler *ManagementHandler) handleDeviceTags(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path identityCatalogPath, session accountsession.Session,
	fail func(managementError) string) string {
	tags := handler.deviceTags
	switch path.kind {
	case identityCatalogNetworkTags:
		devices, err := tags.NetworkTags(ctx, session, path.scope)
		if err != nil {
			return fail(classifyDeviceTagError(err))
		}
		type deviceBody struct {
			DeviceID string   `json:"device_id"`
			TagIDs   []string `json:"tag_ids"`
		}
		bodies := make([]deviceBody, 0, len(devices))
		for _, device := range devices {
			bodies = append(bodies, deviceBody{DeviceID: device.DeviceID.String(), TagIDs: tagIDTexts(device.Tags)})
		}
		var output struct {
			Data struct {
				Devices []deviceBody `json:"devices"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Devices, output.CorrelationID = bodies, correlationID.String()
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case identityCatalogDeviceTags:
		return handler.changeDeviceTags(ctx, response, request, correlationID, path, session, fail)
	case identityCatalogTagOptions:
		return handler.readTagOptions(ctx, response, correlationID, path, session, fail)
	}
	if path.action == "" {
		listing, err := tags.List(ctx, session, path.scope)
		if err != nil {
			return fail(classifyDeviceTagError(err))
		}
		bodies := make([]deviceTagBody, 0, len(listing.Tags))
		for _, tag := range listing.Tags {
			bodies = append(bodies, newDeviceTagBody(tag))
		}
		var output struct {
			Data struct {
				Tags      []deviceTagBody `json:"tags"`
				CanManage bool            `json:"can_manage"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Tags, output.Data.CanManage, output.CorrelationID = bodies, listing.CanManage,
			correlationID.String()
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}
	var result devicetag.Result
	var err error
	if path.action == "create" {
		definition, valid := parseDeviceTagDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = tags.Create(ctx, session, path.scope, definition, correlationID)
	} else {
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			definition, valid := parseDeviceTagDefinition(response, request)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = tags.Update(ctx, session, path.scope, path.tagID, expectedVersion, definition,
				correlationID)
		} else {
			result, err = tags.Delete(ctx, session, path.scope, path.tagID, expectedVersion, correlationID)
		}
	}
	if err != nil {
		return fail(classifyDeviceTagError(err))
	}
	var output struct {
		Data struct {
			Tag     deviceTagBody `json:"tag"`
			Deleted bool          `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Tag, output.Data.Deleted, output.CorrelationID = newDeviceTagBody(result.Tag), result.Deleted,
		correlationID.String()
	status := http.StatusOK
	if path.action == "create" {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(result.Tag.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func (handler *ManagementHandler) changeDeviceTags(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path identityCatalogPath, session accountsession.Session,
	fail func(managementError) string) string {
	var body struct {
		Add    *[]string `json:"add"`
		Remove *[]string `json:"remove"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Add == nil || body.Remove == nil {
		return fail(*invalidManagementRequest())
	}
	add, addOK := parsePublicIDs(*body.Add, devicetag.MaximumTagsPerChange)
	remove, removeOK := parsePublicIDs(*body.Remove, devicetag.MaximumTagsPerChange)
	if !addOK || !removeOK || len(add)+len(remove) == 0 {
		return fail(*invalidManagementRequest())
	}
	toTags := func(ids []publicid.ID) []devicetag.ID {
		tags := make([]devicetag.ID, len(ids))
		for index, id := range ids {
			tags[index] = devicetag.ID(id)
		}
		return tags
	}
	result, err := handler.deviceTags.ChangeAssignments(ctx, session, path.scope, path.deviceID, toTags(add),
		toTags(remove), correlationID)
	if err != nil {
		return fail(classifyDeviceTagError(err))
	}
	var output struct {
		Data struct {
			DeviceID string   `json:"device_id"`
			TagIDs   []string `json:"tag_ids"`
			Added    int      `json:"added"`
			Removed  int      `json:"removed"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.DeviceID, output.Data.TagIDs = result.DeviceID.String(), tagIDTexts(result.Tags)
	output.Data.Added, output.Data.Removed, output.CorrelationID = result.Added, result.Removed,
		correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

// readTagOptions answers the tags the session may apply in a Network, the
// tags its Devices carry, and the Devices of the Network the session owns.
func (handler *ManagementHandler) readTagOptions(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path identityCatalogPath, session accountsession.Session,
	fail func(managementError) string) string {
	options, err := handler.deviceTags.NetworkOptions(ctx, session, path.scope)
	if err != nil {
		return fail(classifyDeviceTagError(err))
	}
	type tagBody struct {
		TagID       string `json:"tag_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Apply       string `json:"apply"`
	}
	var output struct {
		Data struct {
			Tags           []tagBody `json:"tags"`
			OwnedDeviceIDs []string  `json:"owned_device_ids"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Tags = make([]tagBody, 0, len(options.Tags))
	for _, tag := range options.Tags {
		output.Data.Tags = append(output.Data.Tags, tagBody{
			TagID: tag.ID.String(), Name: tag.Name, Description: tag.Description, Apply: string(tag.Apply),
		})
	}
	output.Data.OwnedDeviceIDs = make([]string, 0, len(options.OwnedDevices))
	for _, device := range options.OwnedDevices {
		output.Data.OwnedDeviceIDs = append(output.Data.OwnedDeviceIDs, device.String())
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}
