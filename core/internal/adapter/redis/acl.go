package redis

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Redis ACL per Core role (role isolation design §6, TD-SEC-90 step S6).
//
// Each exported Client method declares what it sends to Redis: the commands,
// including those its Lua scripts call (Redis checks the ACL of every command
// a script runs, with its keys), the key prefixes it reads or writes, and the
// Pub/Sub channels it uses. A role's ACL is the union over the methods its
// composition calls (cmd/meshcore). Tests check that every exported method,
// script command, key prefix and channel is declared, so a new Redis use
// cannot ship without an ACL decision.
//
// Rollout: "meshcore redis acl apply" runs before the new pods (a Helm
// pre-upgrade hook), and helm rollback runs no hook. A permission is
// therefore added in the release whose code first needs it, and removed only
// in a release after the code stopped using it, so the pods of the previous
// release keep working through a rollout and a rollback.
//
// Redis channel rules do not tell publishing from subscribing: a role that
// listens on a wakeup channel may also publish on it. Wakeups are hints to
// read committed state, never authority, so a forged one costs a re-read.

// ErrUnknownACLRole reports a role without a Redis ACL.
var ErrUnknownACLRole = errors.New("unknown redis acl role")

// ACL roles. RoleAll is the self-host process that runs every role.
const (
	ACLRoleAPI     = "api"
	ACLRoleControl = "control"
	ACLRoleWorker  = "worker"
	ACLRoleAll     = "all"
)

// ACLRoles is every role with a Redis user, in apply order.
var ACLRoles = []string{ACLRoleAPI, ACLRoleControl, ACLRoleWorker, ACLRoleAll}

// connectionCommands are what the client sends on every connection: HELLO 3
// with AUTH, and PING for health and Pub/Sub keepalive.
var connectionCommands = []string{"hello", "auth", "ping"}

// scriptCommands run Lua scripts: EVALSHA first, EVAL when the script is not
// cached yet.
var scriptCommands = []string{"evalsha", "eval"}

var subscribeCommands = []string{"subscribe", "unsubscribe"}

// aclNeed is what one Client method sends to Redis. Writes include reads.
type aclNeed struct {
	commands []string
	reads    []string
	writes   []string
	channels []string
}

func scripted(commands ...string) []string { return slices.Concat(scriptCommands, commands) }

// readOnlyScripted is for a script run with RunRO: Redis treats the keys of
// EVAL and EVALSHA as read-write, so a role with read-only key patterns needs
// the _RO variants.
func readOnlyScripted(commands ...string) []string {
	return slices.Concat([]string{"evalsha_ro", "eval_ro"}, commands)
}

// deliveryScripts are the commands of the delivery scripts that also keep the
// DNS index (dnsIndexLua).
var deliveryScripts = scripted("hdel", "hget", "hmget", "hset", "pexpire", "zadd", "zrem", "zremrangebyscore")

// methodNeeds is keyed by Client method name.
var methodNeeds = map[string]aclNeed{
	// Process plumbing, shared by every role.
	"Check":            {commands: []string{"ping"}},
	"Component":        {},
	"MetricsCollector": {},
	"Close":            {},
	"Shutdown":         {},

	// Management rate limits (api).
	"ValidateRateLimiter": {},
	"Allow":               {commands: scripted("get", "set", "del", "time"), writes: []string{managementRateLimitKeyPrefix}},
	"Refund":              {commands: scripted("get", "set", "del", "time"), writes: []string{managementRateLimitKeyPrefix}},

	// Delivery observations, read by api and worker; a Device is online
	// while its presence key exists.
	"LoadObservations": {commands: readOnlyScripted("exists", "hmget"),
		reads: []string{deliveryKeyPrefix, presenceKeyPrefix}},

	// Site and exit selection: read, and stale entries pruned.
	"CountSiteRouters": {commands: []string{"hgetall", "hdel"}, writes: []string{siteSelectionPrefix}},
	"CountExitNodes":   {commands: []string{"hgetall", "hdel"}, writes: []string{siteSelectionPrefix}},

	// DNS index: read, and stale entries pruned.
	"LoadDNSZoneApplication": {commands: scripted("hscan", "hmget", "hdel", "hget"), writes: []string{dnsIndexPrefix}},
	"CountResolverHealth":    {commands: []string{"zcount"}, reads: []string{dnsIndexPrefix}},

	// Kubernetes CA marks (worker) and operation limits (control).
	"Compare":                  {commands: scripted("hmget", "hset", "pexpire"), writes: []string{kubernetesCAMarksPrefix}},
	"TakeKubernetesOperations": {commands: scripted("get", "set", "time"), writes: []string{kubernetesOperationLimitPrefix}},

	// Control replica load.
	"PublishLoad":  {commands: scripted("hdel", "hgetall", "hset", "pexpire", "time"), writes: []string{replicaLoadKey}},
	"Loads":        {commands: scripted("hdel", "hgetall", "hset", "pexpire", "time"), writes: []string{replicaLoadKey}},
	"WithdrawLoad": {commands: []string{"hdel"}, writes: []string{replicaLoadKey}},

	// Device presence and endpoints (control).
	"AcquirePresence": {commands: scripted("del", "hdel", "hget", "hset", "pexpire", "publish", "time"),
		writes: []string{presenceKeyPrefix, endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"RenewPresence": {commands: scripted("hget", "pexpire"), writes: []string{presenceKeyPrefix, endpointKeyPrefix}},
	"ReleasePresence": {commands: scripted("del", "hget", "publish"),
		writes: []string{presenceKeyPrefix, endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"AcquireGatewayPresence": {commands: scripted("del", "hdel", "hget", "hset", "pexpire", "publish", "time"),
		writes: []string{presenceKeyPrefix, endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"RenewGatewayPresence": {commands: scripted("hget", "pexpire"), writes: []string{presenceKeyPrefix, endpointKeyPrefix}},
	"ReleaseGatewayPresence": {commands: scripted("del", "hget", "publish"),
		writes: []string{presenceKeyPrefix, endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"HandOffGatewayPresence": {commands: scripted("hget", "hset"), writes: []string{presenceKeyPrefix}},
	"CheckGatewayRotation":   {commands: readOnlyScripted("hget", "time"), reads: []string{presenceKeyPrefix, endpointKeyPrefix}},
	"ObserveEndpoints": {commands: scripted("del", "hget", "hset", "pexpire", "publish", "time"),
		writes: []string{presenceKeyPrefix, endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"FlushEndpoints": {commands: scripted("hget", "hset", "publish", "time"),
		writes: []string{endpointKeyPrefix}, channels: []string{connectivityChangedChannel}},
	"LoadEndpoints":    {commands: readOnlyScripted("hget"), reads: []string{endpointKeyPrefix}},
	"LoadConnectivity": {commands: readOnlyScripted("hget"), reads: []string{presenceKeyPrefix, endpointKeyPrefix}},

	// Delivery records written by control (with the DNS index).
	"RecordDelivery":     {commands: deliveryScripts, writes: []string{deliveryKeyPrefix, dnsIndexPrefix}},
	"RecordEnforcement":  {commands: deliveryScripts, writes: []string{deliveryKeyPrefix, dnsIndexPrefix}},
	"TouchDelivery":      {commands: deliveryScripts, writes: []string{deliveryKeyPrefix, dnsIndexPrefix}},
	"RecordPaths":        {commands: scripted("hget", "hset", "pexpire", "hmget"), writes: []string{deliveryKeyPrefix}},
	"RecordConnectivity": {commands: scripted("hget", "hset", "pexpire", "hmget"), writes: []string{deliveryKeyPrefix}},
	"RecordRouteHealth": {commands: scripted("hmget", "hget", "hset", "pexpire", "publish"),
		writes: []string{deliveryKeyPrefix}, channels: []string{siteHealthFailedChannel}},
	"RecordDNSHealth": {commands: slices.Concat(deliveryScripts, []string{"hmget"}),
		writes: []string{deliveryKeyPrefix, dnsIndexPrefix}},
	"RecordRouteSelection": {commands: scripted("hmget", "hdel", "hget", "hset", "pexpire"),
		writes: []string{deliveryKeyPrefix, siteSelectionPrefix}},

	// Wakeups.
	"PublishNetworkRevisionAdvanced":   {commands: []string{"publish"}, channels: []string{networkRevisionAdvancedChannel}},
	"SubscribeNetworkRevisionAdvanced": {commands: subscribeCommands, channels: []string{networkRevisionAdvancedChannel}},
	"SubscribeConnectivityChanged":     {commands: subscribeCommands, channels: []string{connectivityChangedChannel}},
	"SubscribeSiteHealthFailed":        {commands: subscribeCommands, channels: []string{siteHealthFailedChannel}},
	"PublishDeviceAliasClaimed":        {commands: []string{"publish"}, channels: []string{deviceAliasClaimedChannel}},
	"SubscribeDeviceAliasClaimed":      {commands: subscribeCommands, channels: []string{deviceAliasClaimedChannel}},
	"PublishKubeCertQueued":            {commands: []string{"publish"}, channels: []string{kubeCertQueuedChannel}},
	"SubscribeKubeCertQueued":          {commands: subscribeCommands, channels: []string{kubeCertQueuedChannel}},
	"PublishKubeCertSettled":           {commands: []string{"publish"}, channels: []string{kubeCertSettledChannel}},
	"SubscribeKubeCertSettled":         {commands: subscribeCommands, channels: []string{kubeCertSettledChannel}},
}

// sharedMethods are called by every role (health, metrics, shutdown).
var sharedMethods = []string{"Check", "Component", "MetricsCollector", "Close", "Shutdown"}

// roleMethods lists, per role, the Client methods its composition calls
// (cmd/meshcore serve.go and the compose* functions it calls).
var roleMethods = map[string][]string{
	// Management API and its private identity runtime: rate limits, Device
	// observations, site and exit selection, DNS zone status.
	ACLRoleAPI: {"ValidateRateLimiter", "Allow", "Refund", "LoadObservations", "CountSiteRouters", "CountExitNodes",
		"LoadDNSZoneApplication", "CountResolverHealth"},
	// MTCP listener, map sessions, feeds, rebalance, Kubernetes audit limits
	// and certificate hints, alias claim announcements.
	ACLRoleControl: {"AcquirePresence", "RenewPresence", "ReleasePresence", "AcquireGatewayPresence",
		"RenewGatewayPresence", "ReleaseGatewayPresence", "HandOffGatewayPresence", "CheckGatewayRotation",
		"ObserveEndpoints", "FlushEndpoints", "LoadConnectivity", "RecordDelivery", "RecordEnforcement",
		"TouchDelivery", "RecordPaths", "RecordConnectivity", "RecordRouteHealth", "RecordDNSHealth",
		"RecordRouteSelection", "TakeKubernetesOperations", "PublishLoad", "Loads", "WithdrawLoad",
		"SubscribeNetworkRevisionAdvanced", "SubscribeConnectivityChanged", "PublishDeviceAliasClaimed",
		"PublishKubeCertQueued", "SubscribeKubeCertSettled"},
	// Revision, alias, Kubernetes CA, enforcement ledger and election workers.
	ACLRoleWorker: {"PublishNetworkRevisionAdvanced", "SubscribeNetworkRevisionAdvanced",
		"SubscribeDeviceAliasClaimed", "Compare", "SubscribeKubeCertQueued", "PublishKubeCertSettled",
		"LoadObservations", "SubscribeSiteHealthFailed"},
}

// ACLUser is the Redis user name of a role.
func ACLUser(role string) (string, error) {
	if !slices.Contains(ACLRoles, role) {
		return "", fmt.Errorf("%w: %q", ErrUnknownACLRole, role)
	}
	return "mesh_" + role, nil
}

// rootCommands are allowed outside any selector: they name no key (the
// connection, Pub/Sub on the role's channels).
var rootCommands = map[string]bool{"hello": true, "auth": true, "ping": true, "publish": true,
	"subscribe": true, "unsubscribe": true}

// RoleACLRules returns the ACL SETUSER rules of a role, without the user's
// state or password. The root allows only the commands that name no key
// and the role's channels; every method that touches keys gets a selector
// (Redis 7) with exactly its commands on exactly its key patterns (%R~ read,
// ~ read and write). A command is then allowed on a key only together with
// the method that needs it: a role that may HDEL one prefix and SET another
// cannot SET the first. Sorted, so the result is deterministic.
func RoleACLRules(role string) ([]string, error) {
	methods, err := roleMethodSet(role)
	if err != nil {
		return nil, err
	}
	root := map[string]bool{}
	channels := map[string]bool{}
	selectors := map[string]bool{}
	addAll(root, connectionCommands)
	for _, method := range methods {
		need, ok := methodNeeds[method]
		if !ok {
			return nil, fmt.Errorf("redis acl: method %s has no declared need", method)
		}
		addAll(channels, need.channels)
		selector, err := methodSelector(method, need, root)
		if err != nil {
			return nil, err
		}
		if selector != "" {
			selectors[selector] = true
		}
	}
	rules := []string{"resetkeys", "resetchannels", "clearselectors", "-@all"}
	for _, command := range sorted(root) {
		rules = append(rules, "+"+command)
	}
	for _, channel := range sorted(channels) {
		rules = append(rules, "&"+channel)
	}
	return append(rules, sorted(selectors)...), nil
}

// methodSelector returns the selector of one method's keyed commands; its
// key-free commands go to the root.
func methodSelector(method string, need aclNeed, root map[string]bool) (string, error) {
	var commands []string
	for _, command := range need.commands {
		if rootCommands[command] {
			root[command] = true
			continue
		}
		commands = append(commands, command)
	}
	if len(need.reads)+len(need.writes) == 0 {
		if len(commands) != 0 {
			return "", fmt.Errorf("redis acl: method %s sends %v without declaring keys", method, commands)
		}
		return "", nil
	}
	writes := map[string]bool{}
	addAll(writes, need.writes)
	var tokens []string
	for _, prefix := range sortedValues(need.reads) {
		if !writes[prefix] {
			tokens = append(tokens, "%R~"+keyPattern(prefix))
		}
	}
	for _, prefix := range sortedValues(need.writes) {
		tokens = append(tokens, "~"+keyPattern(prefix))
	}
	for _, command := range sortedValues(commands) {
		tokens = append(tokens, "+"+command)
	}
	return "(" + strings.Join(tokens, " ") + ")", nil
}

func sortedValues(values []string) []string {
	set := map[string]bool{}
	addAll(set, values)
	return sorted(set)
}

// roleMethodSet returns the methods of a role, with the shared ones; RoleAll
// is the union of every role.
func roleMethodSet(role string) ([]string, error) {
	set := map[string]bool{}
	addAll(set, sharedMethods)
	switch role {
	case ACLRoleAPI, ACLRoleControl, ACLRoleWorker:
		addAll(set, roleMethods[role])
	case ACLRoleAll:
		for _, methods := range roleMethods {
			addAll(set, methods)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownACLRole, role)
	}
	return sorted(set), nil
}

// keyPattern turns a key prefix ending in ':' into a glob; a full key name
// stays exact.
func keyPattern(prefix string) string {
	if prefix != "" && prefix[len(prefix)-1] == ':' {
		return prefix + "*"
	}
	return prefix
}

func addAll(set map[string]bool, values []string) {
	for _, value := range values {
		set[value] = true
	}
}

func sorted(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	slices.Sort(values)
	return values
}

// ACLProbe is one ACL DRYRUN a role's user must pass (Allowed) or fail,
// run after every apply: a wrong rule set is caught before any pod uses it.
type ACLProbe struct {
	Command []string
	Allowed bool
}

// probeKey is a key under prefix no Core code writes.
func probeKey(prefix string) string { return prefix + "acl-probe" }

// probeScript is a well-formed script digest; DRYRUN checks rights only.
const probeScript = "0000000000000000000000000000000000000000"

// RoleACLProbes returns the checks of a role's user.
func RoleACLProbes(role string) ([]ACLProbe, error) {
	if _, err := ACLUser(role); err != nil {
		return nil, err
	}
	readObservations := []string{"EVALSHA_RO", probeScript, "2", probeKey(deliveryKeyPrefix), probeKey(presenceKeyPrefix)}
	writePresence := []string{"HSET", probeKey(presenceKeyPrefix), "f", "v"}
	writeMarks := []string{"HSET", probeKey(kubernetesCAMarksPrefix), "f", "v"}
	writeDelivery := []string{"HSET", probeKey(deliveryKeyPrefix), "f", "v"}
	setRateLimit := []string{"SET", probeKey(managementRateLimitKeyPrefix), "v"}
	probes := []ACLProbe{
		{Command: []string{"PING"}, Allowed: true},
		{Command: []string{"FLUSHALL"}},
		{Command: []string{"CONFIG", "GET", "maxmemory"}},
		{Command: []string{"KEYS", "*"}},
	}
	switch role {
	case ACLRoleAPI:
		probes = append(probes,
			ACLProbe{Command: readObservations, Allowed: true},
			ACLProbe{Command: setRateLimit, Allowed: true},
			ACLProbe{Command: []string{"HDEL", probeKey(dnsIndexPrefix), "f"}, Allowed: true},
			ACLProbe{Command: []string{"SET", probeKey(dnsIndexPrefix), "v"}},
			ACLProbe{Command: writePresence},
			ACLProbe{Command: writeDelivery},
			ACLProbe{Command: []string{"PUBLISH", connectivityChangedChannel, "m"}})
	case ACLRoleControl:
		probes = append(probes,
			ACLProbe{Command: writePresence, Allowed: true},
			ACLProbe{Command: writeDelivery, Allowed: true},
			ACLProbe{Command: []string{"PUBLISH", connectivityChangedChannel, "m"}, Allowed: true},
			ACLProbe{Command: writeMarks},
			ACLProbe{Command: setRateLimit},
			ACLProbe{Command: readObservations})
	case ACLRoleWorker:
		probes = append(probes,
			ACLProbe{Command: writeMarks, Allowed: true},
			ACLProbe{Command: readObservations, Allowed: true},
			ACLProbe{Command: []string{"PUBLISH", networkRevisionAdvancedChannel, "m"}, Allowed: true},
			ACLProbe{Command: writeDelivery},
			ACLProbe{Command: writePresence},
			ACLProbe{Command: setRateLimit})
	case ACLRoleAll:
		probes = append(probes,
			ACLProbe{Command: readObservations, Allowed: true},
			ACLProbe{Command: writePresence, Allowed: true},
			ACLProbe{Command: writeMarks, Allowed: true},
			ACLProbe{Command: setRateLimit, Allowed: true},
			ACLProbe{Command: []string{"SET", probeKey(dnsIndexPrefix), "v"}})
	}
	return probes, nil
}
