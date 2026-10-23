package postgres

import (
	"context"
	"errors"
	"sort"
	"strings"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// ServiceNamePlanner checks approved service names as DNS and builds the
// changes that make them names of the consumer Network (DNS design D3):
// dnszone.Service. The share store applies them in the transaction that
// accepts the offer.
type ServiceNamePlanner interface {
	PlanServiceNameZone(session accountsession.Session, scope network.Scope, name string,
		correlationID publicid.ID) (dnszone.Change, error)
	PlanServiceName(zone dnszone.Domain, name string, share sharing.ImportedResourceID) (dnszone.NameOperation,
		error)
	Limits() dnszone.Limits
}

const findDNSZoneForNameSQL = `SELECT mesh_ops.find_dns_zone_for_name_v1(` + sessionArguments +
	`,$10::UUID,$11::UUID,$12::TEXT)::TEXT`

// shareDNSTransaction lets the DNS writes run in the share store's
// transaction; it never commits or rolls back on its own.
type shareDNSTransaction struct {
	tx resourceAuthorityDatabaseTransaction
}

func (transaction shareDNSTransaction) Exec(ctx context.Context, query string, args ...any) error {
	return transaction.tx.Exec(ctx, query, args...)
}

func (transaction shareDNSTransaction) QueryRow(ctx context.Context, query string, args ...any) accountSessionRow {
	return transaction.tx.QueryRow(ctx, query, args...)
}

var errShareDNSTransactionOwned = errors.New("postgres: the share transaction owns commit and rollback")

func (shareDNSTransaction) Commit(context.Context) error   { return errShareDNSTransactionOwned }
func (shareDNSTransaction) Rollback(context.Context) error { return errShareDNSTransactionOwned }

// readShareOfferServiceNames returns an offer's service names, in order, for
// the transaction's Network when it is the offer's provider or consumer.
func readShareOfferServiceNames(ctx context.Context, transaction resourceAuthorityDatabaseTransaction,
	offerID sharing.OfferID,
) ([]sharing.ServiceName, error) {
	// At most eight rows: one array read keeps the transaction interface to
	// QueryRow.
	var names []string
	if err := transaction.QueryRow(ctx, `SELECT COALESCE(pg_catalog.array_agg(listed.fqdn), '{}')
FROM mesh_ops.list_share_offer_service_names_v1($1::UUID) AS listed`, offerID.String()).Scan(&names); err != nil {
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	if len(names) > sharing.MaximumServiceNames {
		return nil, sharing.ErrUnavailable
	}
	parsed := make([]sharing.ServiceName, 0, len(names))
	for _, value := range names {
		name, err := sharing.ParseServiceName(value)
		if err != nil {
			return nil, sharing.ErrUnavailable
		}
		parsed = append(parsed, name)
	}
	return parsed, nil
}

// approvedServiceNames checks that the decisions answer each suggested name
// exactly once, and returns the approved ones with their place in the
// decisions.
func approvedServiceNames(suggested []sharing.ServiceName, decisions []sharing.ServiceNameDecision) (
	[]sharing.ServiceName, []int, error,
) {
	if len(suggested) != len(decisions) {
		return nil, nil, sharing.ErrServiceNameDecisions
	}
	answered := make(map[sharing.ServiceName]int, len(decisions))
	for index, decision := range decisions {
		answered[decision.Name] = index
	}
	approved := make([]sharing.ServiceName, 0, len(decisions))
	places := make([]int, 0, len(decisions))
	for _, name := range suggested {
		index, found := answered[name]
		if !found {
			return nil, nil, sharing.ErrServiceNameDecisions
		}
		if decisions[index].Approve {
			approved = append(approved, name)
			places = append(places, index)
		}
	}
	return approved, places, nil
}

// applyServiceNames makes each service name the consumer approves a DNS
// name of its Network pointing at the share just imported, in the accept's
// transaction (scoped to the consumer): in the longest zone that covers it,
// or in a zone of its own. The DNS functions authorize the session for
// dns.manage. A failure names the decision and rolls the accept back.
func (store *ResourceSharingStore) applyServiceNames(ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction, command sharing.DecideOffer,
	share sharing.ImportedResourceID,
) error {
	suggested, err := readShareOfferServiceNames(ctx, transaction, command.OfferID())
	if err != nil {
		return err
	}
	approved, places, err := approvedServiceNames(suggested, command.ServiceNames())
	if err != nil || len(approved) == 0 {
		return err
	}
	planner := store.options.ServiceNames
	if planner == nil {
		return &sharing.ServiceNameError{Index: places[0], Err: dnszone.ErrDisabled}
	}
	session, scope := command.AccountSession(), command.ConsumerScope()
	changeID, err := publicid.New()
	if err != nil {
		return sharing.ErrUnavailable
	}
	correlationID, err := publicid.New()
	if err != nil {
		return sharing.ErrUnavailable
	}
	// Parents before children: whatever the provider's order, a name under
	// another approved name lands in the zone that one makes.
	order := make([]int, len(approved))
	for position := range order {
		order[position] = position
	}
	sort.SliceStable(order, func(left, right int) bool {
		return strings.Count(approved[order[left]].String(), ".") < strings.Count(approved[order[right]].String(), ".")
	})
	tx := shareDNSTransaction{tx: transaction}
	changed := false
	for _, position := range order {
		made, err := applyServiceName(ctx, tx, planner, session, scope, approved[position].String(), share,
			correlationID, changeID)
		if err != nil {
			return &sharing.ServiceNameError{Index: places[position], Err: err}
		}
		changed = changed || made.Changed
	}
	if changed {
		if _, err := deferDNSChangeWakeup(ctx, tx, changeID); err != nil {
			return err
		}
	}
	return nil
}

// madeServiceName is a service name made a DNS name of the consumer
// Network: the name, the zone holding it, and whether anything was written.
type madeServiceName struct {
	Name    dnszone.Name
	Zone    dnszone.Zone
	Changed bool
}

// applyServiceName makes name a DNS name of the Network in tx's scope that
// points at share: in the longest zone that covers it or, when none does, in
// a zone of its own made for it. The DNS functions authorize the session for
// dns.manage and append the evidence; the caller defers the wakeup of
// changeID and commits. An error is the DNS reason.
func applyServiceName(ctx context.Context, tx accountSessionTransaction, planner ServiceNamePlanner,
	session accountsession.Session, scope network.Scope, name string, share sharing.ImportedResourceID,
	correlationID, changeID publicid.ID,
) (madeServiceName, error) {
	made := madeServiceName{}
	zone, err := findServiceNameZone(ctx, tx, session, scope, name)
	if err != nil {
		return made, err
	}
	if zone == nil {
		plan, err := planner.PlanServiceNameZone(session, scope, name, correlationID)
		if err != nil {
			return made, err
		}
		created, err := applyDNSZoneChange(ctx, tx, plan, changeID)
		if err != nil {
			return made, err
		}
		zone, made.Changed = &created.Zone, created.Changed
	}
	operation, err := planner.PlanServiceName(zone.Domain, name, share)
	if err != nil {
		return made, err
	}
	result, err := applyDNSNameChange(ctx, tx, dnszone.NameChange{
		Session: session, Scope: scope, ZoneID: zone.ID, ZoneClass: zone.Class,
		Operations: []dnszone.NameOperation{operation}, Limits: planner.Limits(), CorrelationID: correlationID,
	}, changeID)
	if failure := (*dnszone.OperationError)(nil); errors.As(err, &failure) {
		return made, failure.Err
	}
	if err != nil {
		return made, err
	}
	if len(result.Outcomes) != 1 {
		return made, dnszone.ErrInvalid
	}
	made.Name, made.Zone, made.Changed = result.Outcomes[0].Name, *zone, made.Changed || result.Changed
	return made, nil
}

// findServiceNameZone returns the zone of the Network that would hold name,
// or nil when none covers it.
func findServiceNameZone(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	scope network.Scope, name string,
) (*dnszone.Zone, error) {
	var encoded *string
	if err := tx.QueryRow(ctx, findDNSZoneForNameSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), name)...).Scan(&encoded); err != nil {
		return nil, dnsZoneDatabaseError(err)
	}
	if encoded == nil {
		return nil, nil
	}
	var document dnsZoneDocument
	if err := decodeDNSZoneJSON([]byte(*encoded), &document); err != nil {
		return nil, dnszone.ErrInvalid
	}
	zone, err := document.zone(false)
	if err != nil {
		return nil, dnszone.ErrInvalid
	}
	return &zone, nil
}

// OfferServiceNames returns the service names an offer suggests, in order,
// to its provider or consumer Network (network scope of the session's
// request); another Network sees none.
func (store *ResourceSharingStore) OfferServiceNames(ctx context.Context, scope network.Scope,
	offerID sharing.OfferID,
) (_ []sharing.ServiceName, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() || !offerID.IsValid() {
		return nil, sharing.ErrInvalidManagementRequest
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction)) }()
	if _, err := setResourceSharingScope(ctx, transaction, scope); err != nil {
		return nil, err
	}
	return readShareOfferServiceNames(ctx, transaction, offerID)
}
