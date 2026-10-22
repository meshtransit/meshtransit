# Changelog

Notable changes to MeshTransit. Component histories from before the monorepo
merge (2026-10-09) are kept below.

## Unreleased

- Core (DNS design D3b, schema 219): maps carry the DNS names that point at
  a share. Such a name answers the share's alias on each consumer Device
  whose map holds the share (a rule reaches it, the contract runs) and is
  left out anywhere else, with any CNAME that reaches it; it goes at once
  when the share or the rule ends. A `host` zone whose only name is its own
  domain sends no route where another zone the Device receives holds it.
  Each map now keeps its DNS routes within what a node routes (248 domains,
  15.5 KiB): a zone or name past it is left out whole and counted as
  `route_budget` in `meshtransit_mtcp_map_names_degraded_total`; before, a
  Network with that many zones and `host` names made the node refuse its
  whole DNS configuration.
- Core (DNS design D3a, schema 218): a share offer can suggest up to 8
  service names (`service_names`), the real names a provider's web app
  serves, such as `app.corp.com`. A suggestion resolves nowhere and reserves
  nothing in the consumer Network. The consumer answers each one when it
  accepts (`service_names: [{name, decision}]`, `approve` or `decline`); an
  approved name becomes a DNS name of its Network that points at the share,
  in the longest zone that covers it or in a zone of its own whose other
  names go to each Device's own DNS, in the same transaction. Approving needs
  `dns.manage`; a name that cannot be made fails the whole accept with its
  DNS error and `operation_index`. Offers show their names with `public`.
- Core (DNS design D3a, schema 217): a DNS name can point at a share its
  Network imports (`share_id`, the imported resource): it answers the
  share's alias, so a provider's web app opens under its real name. A new
  target must be a share whose contract runs now (else 422
  `dns_share_target_invalid`); a name keeps a share that has ended and
  answers nothing then. Names read back with `share_name`, `contract_id` and
  `share_state`. The schema 215 name functions and the schema 216 map reader
  leave such names out, so an older Core never reads or writes one by name;
  its zone writes still count, move and delete them with their zone. Maps do
  not carry them yet.
- Core (TD-CORE-80): a Device that reaches one share through several rules
  (ICMP and TCP 443, say) no longer fails its whole map: the share keeps one
  name.
- Clients (DNS design D2c, MTCP `dns.records1`): `meshd` with DNS on
  (Linux, macOS, Windows) applies DNS names and every zone kind.
  - A zone that answers `NXDOMAIN` is routed to the node, a private single
    label (`lan`) included. A zone that leaves its other names to the host is
    not routed as a whole: each of its names is, and the host's own DNS
    answers the rest. A forward zone that fails open with no resolver it can
    use is left to the host the same way.
  - The node answers A, AAAA, ANY and CNAME of the names it holds. HTTPS and
    SVCB get no data. Other types of a name in a host or forward zone go on
    to the zone's resolvers or the host's DNS. A name that only holds other
    names gets no data.
  - The node follows CNAMEs, at most 8 steps, asking outside names of the
    resolvers they would go to, in one 5-second budget. No answer from
    outside speaks for a name the node holds: only the asked chain stays,
    and every TTL is at most 5 seconds.
  - On Linux, DNSSEC validation is turned off on the mesh link.
- Core (DNS design D2b, schema 216, MTCP `dns.records1`): maps carry DNS
  names and every zone kind to nodes that declare `dns.records1` with
  `dns.forward1`. A zone whose other names are `nxdomain` is a route the node
  answers itself. One whose other names go to the host is an unavailable
  route that fails open.

  A name that points at a Device answers that Device's mesh addresses, and
  only to Devices a rule of the active release lets reach that live Device.
  A rule the other way is not enough, and a Device always sees its own
  names. Fixed-address names are A/AAAA records. A CNAME is a `CNAME`
  record, left out when its chain reaches a Device name the node may not
  see.

  Names come after the names MeshTransit gives, within 50,000 records and
  1 MiB. A limited map keeps the Devices names point at after explicit
  shares.

  Zone and name changes of a Network wake map sessions together: their
  outbox events wait for the end of a 30-second window the first change
  opens. Writes answer `applies_within_seconds`.
- Core (DNS design D2a, schema 215): names in DNS zones. A zone now says
  what the names it does not hold get (`other_names`): `forward` (its
  resolvers, as before), `nxdomain` (answered on the Device; never on a
  domain on the Internet) or `host` (the host's own DNS); only a forward
  zone has resolvers. A Network admin with `dns.manage` sets names under
  `/dns/zones/{zone}/names`: an address name points at one Device of the
  Network (its mesh addresses) or at 1 to 8 fixed addresses outside the
  overlay frame and special ranges, a `cname` name at another name outside
  the mesh names; the zone's own domain is `@` and never a CNAME. A name
  belongs to the longest zone that covers it. `POST .../names/actions/apply`
  changes up to 100 names in one transaction and names the failing operation
  (`operation_index`). Limits: 2,000 names per zone, 10,000 per Network, 200
  in `host` zones. A new zone over names a shorter zone holds takes them only
  with `adopt_names`; a zone that holds names is deleted with them only with
  `?with_names=true` (409 `dns_zone_holds_names` otherwise). Every name
  change is audited (`dns_name.*`), shares the person's zone write budget and
  advances the Network's revisions once per request. A Core with schema 213
  or 214 sees and sends forward zones only and never moves or deletes a
  name. Maps do not carry names yet (D2b).
- Clients (DNS design D1a.3, MTCP `dns.forward1`): `meshd` with DNS on
  (Linux, macOS, Windows) applies the DNS zones Core sends: each zone's
  domain, single labels included, goes to its resolvers in order, on their
  ports. When no resolver answers or none can be used, a zone that fails
  `closed` answers `SERVFAIL` and one that fails `open` asks the host's
  network resolvers (the exit node's forwarder while one is in use). A
  resolver that fails 3 times in a row is skipped for 30 seconds. While an
  exit node is in use, a zone's Internet resolvers are replaced by the exit
  node's forwarder.
- Core (DNS design D1a.2, schema 214, MTCP `dns.forward1`): maps carry DNS
  zones to nodes that declare `dns.split`, `dns.forward1` and `map.large1`:
  one route per zone sent to the Device, its resolvers in order with their
  ports, whether no resolver can be used now (`unavailable`) and whether the
  zone fails open. A resolver Device is listed only while it may serve, a rule
  of the active release admits UDP from the Device to its port, and both maps
  hold the pair; it is then a peer both maps keep. Zones with a search
  position follow the Network's zone as search domains. A resolver Device
  serves at most 9,744 Devices (was 10,000). One person may change one
  Network's zones 10 times in a row, then once every 6 seconds (429
  `rate_limited`).
- Core (DNS design D1a, schema 213): DNS zones. A Network admin with
  `dns.manage` creates, changes and deletes zones through
  `/api/v1/workspaces/{ws}/networks/{net}/dns/zones`: a domain, up to four
  resolvers in order (a Workspace-owned Device of the Network on port 53 or
  1024-65535, or an address on the Internet on port 53), the Device Groups it
  is sent to (or every Device), what its names get when no resolver answers
  (`open` or `closed`), a search position, and a confirmation for domains
  that exist on the Internet. Special-use names, public suffixes, the mesh
  names and the deployment's own host names (`MESHTRANSIT_DNS_PROTECTED_NAMES`)
  are refused. A resolver Device never becomes an exit node, and a Device
  Group a zone is sent to cannot be deleted. Every change is audited
  (`dns_zone.*`) and advances the Network's revisions. Off unless
  `MESHTRANSIT_DNS_ZONES_ENABLED`.
- Clients (exit, captive portals, exit node design §17): `meshd` finds a
  captive portal while the control session is down (the network's RFC 8908
  API on Linux, an HTTP probe of a relay that echoes a nonce, the network
  resolver's answer for the relay's name), says so on the `Exit` line with
  the sign-in page the network named, and keeps the exit node meanwhile.
  `meshctl exit captive [--for D] [--close]`, as root (an administrator on
  Windows), opens a window of 2 minutes (5 at most) in which TCP to ports 80
  and 443, and to the portal's own port, leaves by the default route's
  interface from its own address, and names go to the network's resolvers
  with answers kept 5 seconds; nothing else leaves. The window ends on time
  even without the helper (Linux: nftables element timeouts; macOS: a child
  process and the launchd job `net.meshtransit.meshnetd-captive`; Windows: a
  child holding a dynamic WFP session), when root closes it, and 15 seconds
  after the tunnel is back. `routes exit-captive off` refuses windows.
- Core (captive portals, exit node design §17.12; schema 211, 212): an Exit
  Pool's `captive_windows` (`allowed` by default, or `off`) reaches its
  consumers in the map (`captive_off`), and a client with this release then
  opens no captive portal window and closes one already open (older clients
  ignore it). Clients that use exits report
  each window that closed (MTCP `CaptiveWindowReport`, `captive.audit1`);
  Core writes one sealed `device.captive_window` audit event per window, at
  most 48 per Device per day, without the portal's address, and the
  enforcement ledger worker removes the records after 13 months.
- Relay: `--probe-http ADDRESS` (off by default; `0.0.0.0:80` in
  production) answers `GET /generate_204` with 204 and the client's nonce,
  rate limited, for the clients' captive portal check.
- Clients: the exit node in use is kept through 15 seconds of silence (a
  Site's router through 4, as before): leaving changes the public address
  and cuts every connection, and a poor Wi-Fi or a reconnecting relay made
  a Mac switch exit nodes twice within a minute. An exit node that answers
  but no longer reaches the Internet is still left after 5 seconds, as stuck.
- macOS: names resolved while an exit node is used. The MeshTransit DNS
  service asked to be the primary one (`OverridePrimary`), which configd
  ignores for a service without a router, so names went to the network's
  resolvers and the kill switch dropped them (cached names hid it). The
  service now matches the root domain, which makes its resolver the default
  one without touching the primary service or the routes.
- Clients: `meshctl exit approve` also approves, while no pool is used, an
  exit node added to a pool the host pinned before; status says
  `primary_unapproved` ("the primary waits for approval") when another
  exit node carries only because the primary is not approved yet
  (TD-CLI-49). Approving exit nodes over the local API needs root, or an
  elevated administrator on Windows (`exit_approval_needs_root`); the
  operators group alone no longer suffices.
- Clients (exit, TD-CLI-46): the exit node's DNS forwarder answers NXDOMAIN
  without asking for the exit network's own names (single labels, the
  host's search domains, `.local`, `.internal`, `.lan`, `.home.arpa`…),
  asks the resolvers behind systemd-resolved's stub, and reports failing
  without any resolver; a consumer whose settings name a pool resolves
  Core's name from resolved's upstreams at once; pins are written outside
  the failover lock and a full store forgets the pool used longest ago.
  The Linux helper checks every 5 seconds that the exit rules, table and
  kill switch are as it installed them, installs them again otherwise and
  reports `tampered` in status for 10 minutes; removing a stale exit rule
  with fewer attributes no longer deletes one of the helper's own.
- Core, Console and clients: spread Exit Pools (schema 210, exit node design
  §16), behind `MESHTRANSIT_EXIT_SPREAD_ENABLED`. A pool's `mode` is
  `failover` (as before) or `spread`: the worker elects a serving set (the
  healthy exit nodes of the best priority; one with `conntrack_high` or
  `egress_v4_failed` for a minute leaves until five calm minutes; at most
  one change every 30 s; audited `exit_pool.serving_changed`), and maps give
  each consumer its own exit node by rendezvous hashing with the pool's
  secret salt, in its own candidate order, so failover spreads too. MTCP
  `ExitPool.mode` and `ExitCandidate.draining`. Clients move back to the exit
  node Core assigned (spread) or off a draining one once nothing went
  through the exit for five minutes. The Console sets the mode and shows the
  serving set, Devices not yet moved and its changes.
- Core and Console: each Device's platform and public addresses. Core
  keeps the platform its client names in the MTCP ClientHello (`os`,
  `os_version`, `arch`, client version) and up to four public addresses of
  its endpoint report (what STUN saw or its gateway mapped, then public
  addresses of its interfaces; private and CGNAT addresses never), with its
  connectivity in the delivery record. Device reads (`include=status` rows
  and one Device's status, under `device.read`) give `platform` and
  `public_addresses` (`address`, `country`); the country comes from a DB-IP
  Lite table (`MESHTRANSIT_GEOIP_COUNTRY_FILE`). The Console shows an OS
  mark by the name, a Location column (flag and code) and the public
  address, hidden until the eye is pressed, on the list and the Device
  page.
- Clients: `meshctl exit use` waits, up to 15 s, until meshd applied the
  choice and prints one line (`Exit: via NODE in pool POOL`, `Exit: off …`,
  or why it is not routed) instead of every route setting; `exit serve`
  prints one line too.
- Clients: `meshctl exit use POOL|auto|off`, `meshctl exit serve on|off`,
  `meshctl exit status` and `meshctl routes COMMAND` (every `meshnetd
  routes` / Windows `meshd routes` command) on Linux, macOS and Windows. A
  change still needs root (Windows: an administrator terminal, which reading
  needs too): on Linux and macOS `meshctl` runs the same command again
  through `sudo -u root`, which asks for the password, once the change is
  valid, and never twice; reading needs nothing there. `meshctl` always
  uses the default settings file.
- Core: who uses which exit node. A consumer's exit selection
  (`RouteSelectionReport.exit`, of a pool it was sent, with a candidate) is
  stored with its Site routers: in the node's delivery record and counted
  per pool under `meshtransit:v1:site-selection:exit:<pool>` (no new Redis
  key prefix). One Exit Pool's read (`GET …/exit-pools/{p}`) gives each
  exit node its current `health` (`state`, `code`, `families`,
  `reported_at`, from the last 30 seconds) and `consumers` /
  `local_failover_consumers` (last three minutes); a Device's status gives
  its `exit` (`exit_pool_id`, `exit_node_device_id`, `via`: `primary`,
  `local_failover`, `sticky` or `none`). Both degrade to absent when Redis
  cannot be read within a second.
- Core: the Console Device list takes `include=status` (Console backlog D-1).
  Each row of `GET …/networks/{n}/devices` then carries its connection and
  policy status (`in_sync`, `behind`, `offline`, `never_connected`,
  `unknown`; `online`, `last_seen_at`, `delivered_network_revision`,
  `enforcement`), and the page its `network_revision`, `policy_revision`
  and `observations_available`. Core reads the revisions once and the
  page's delivery records in one batch (at most 100 Devices), never per
  Device. Devices without policy get a null status; a bad page fails
  closed, an outage degrades to null statuses and is logged. Without
  `include` the list is unchanged.

- Clients: Windows, macOS and Android consumers of exit nodes (exit node
  design E4, E5). Windows: the service routes `0/1`, `128/1`, `::/1`,
  `8000::/1` into Wintun behind a persistent WFP kill switch (`winfw`:
  only the service as LocalSystem, loopback, the adapter, DHCP, ND,
  link-local and the allowed LAN may connect out), an NRPT rule for every
  name, `meshd release-exit`; the installer enables `--enable-exits`.
  macOS: `meshnetd --enable-exits` routes the halves into the utun behind a
  pf anchor (`com.apple/250.MeshTransitExit`, `user _meshd`, pf enabled by
  reference), scoped defaults on the physical interfaces (`RTF_IFSCOPE`),
  `meshnetd --release-exit`; meshd binds its sockets to the physical
  interface and its address, redials relays when the exit route changes and
  keeps direct paths to peers through its bound WireGuard socket (a socket
  it could not bind sends nothing until it is). A pool's only exit
  node is kept when its direct-path proof expires. Android: the app's Exit node card; the VPN
  carries `0/0` and `::/0` (less the allowed LAN) with the exit node's
  resolvers as its DNS servers (a sinkhole while none answers); the
  library's `SetExitNode`, `ExitNode`, `ExitAllowsLAN`, `ApproveExitNodes`
  and `TunProvider.OpenTUN(addresses, routes, dns, mtu)`. On Windows and
  macOS meshd binds its own sockets, WireGuard's included, to the physical
  interface and resolves Core and relays from the networks' resolvers while
  a pool is chosen. On macOS meshd also redials its relays when the host's
  networks change under an exit node, at most once every 2 s while they
  keep changing, and meshnetd logs a scoped default route it could not
  keep. meshd picks its IPv6 source by the address flags: never anycast,
  tentative, duplicated or CLAT46, a stable address before a temporary one,
  a deprecated one only as the last choice, and a unique local address only
  towards a unique local destination.

- Clients: Linux consumers of exit nodes, second part (exit node design
  E3). Names go through the exit node: meshd becomes the host's default
  resolver while it uses one and asks the exit node's DNS forwarder (SERVFAIL
  without an exit node, no AAAA data without its IPv6); Site-routed suffixes
  keep their resolvers. Exit nodes answer on their overlay addresses (the
  helper redirects port 53 to 1055), only to the pool's sources, from the
  pool's `dns_upstreams` or the host's resolvers, without addresses of their
  own networks (A, AAAA, SVCB/HTTPS hints), bounded per consumer and without
  logging names; `dns_failed` degrades their health. The exit nodes of a
  pool's first use are pinned; a later one, or another pool given the name
  the settings use, waits for `meshctl exit approve ID` (status lists it),
  and `auto` keeps to pinned pools. The DNS forwarder of an exit node is
  only asked at the exit node's own mesh address. `auto` takes the nearest served pool by round trip and
  keeps it; unanswered new connections move the node to another exit node.
  A netns end-to-end test covers the exit path, failover, the exit node's
  LAN and leaks without an exit node.
- Clients: Linux consumers of exit nodes, first part (exit node design E3).
  With `--enable-exits` (on in the Linux package) meshd declares
  `routes.exit.v1`, takes the Exit Pools its rules grant and, once root names
  one (`meshnetd routes exit-use POOL|auto|off`; `exit-allow-managed`,
  `exit-allow-lan`), sends the host's Internet traffic through one of its
  exit nodes: the map's primary, kept while it works even after Core elects
  another (`STICKY`), left for the next answering candidate when it stops
  answering, is reported FAILED or leaves the pool (`LOCAL_FAILOVER`); the
  choice goes to Core in `RouteSelectionReport.exit`. Only that exit node
  holds the default routes in WireGuard, and meshd's filter accepts from it
  only replies from Internet addresses. meshnetd (`set_exit_route`) holds a
  kill switch (`inet meshtransit_exit`) and an exit table (`--exit-table`,
  5268 in the package) with an unreachable default, rules 5402–5405 keeping
  replies to inbound connections, DHCP and interface-bound sockets on the
  host's routes, local bridges and the allowed LAN outside, and IPv6 refused
  when the exit node has none. The kill switch follows root's `exit-use` alone (meshd and Core cannot
  lift it; it holds across restarts and before the first map); `meshnetd
  --release-exit`, which the package runs on removal, removes it. Status
  shows an `Exit` line (`exit` in the local API). DNS does not go through the
  exit node yet (names resolve only through a resolver in an allowed LAN);
  it comes next, with pinning exit nodes and `auto` by latency.
- Clients: Linux exit nodes, first part (exit node design E2). With
  `--enable-exit-node` meshd declares `router.exit.v1`, reports
  `exit_offered` from the root-owned `exit_mode`, and serves the Exit Pool
  in its map: meshnetd (`set_served_exit`, helper protocol 6) forwards only
  while exit mode is on, within Core's limits narrowed by the host's
  (`exit-conntrack-max`, `exit-max-consumers`, `exit-smtp`). Its nftables
  table drops what is not the Internet (the shared set plus the host's own
  addresses, attached subnets and gateways) before any accept, refuses TCP 25
  unless both allow it, bounds each consumer's connections (`ct count`) and
  translates every source; meshd's filter admits only the pool's rules to the
  Internet, never to the exit node's own addresses or the Sites it serves.
  Exit nodes measure their pool through their own forwarding path (TCP
  probes from the self-test addresses), report `exit_not_offered`,
  `egress_failed`, `egress_v6_failed` or `conntrack_high` with the address
  families that reach the Internet in `RouteHealthReport.exit`, leave their
  public addresses (as peers see them) out of the Internet, and show an
  `Exit node` line in `meshctl status` (`exit_node` in the local API). The
  DNS forwarder and consumers come next.
- Core: Explain, the Access Graph and the access ledger know Exit Pools
  (schemas 206–208). An Internet address no Site holds is explained through
  the first pool whose rules grant the Internet to the source
  (`target.exit_pool_id`, paths with `selector_kind` `exit_pool`); without
  one the deny reason is `no_matching_active_rule`. The Access Graph
  (`read_access_graph_v4`) and the ledger list one `exit_pool` edge per
  Device a rule grants a pool to, never its own exit nodes; history v3 returns
  them, while older readers leave them out. Pool names need `route.read`.
- Core: maps carry Exit Pools (schema 205, mtcp-v1 §7.7) with
  `MESHTRANSIT_EXIT_NODES_ENABLED` and the shared inventory. A node with
  `routes.exit.v1` gets each pool an active rule lets it use (never the pool
  it serves), with its exit nodes as candidates and peers, the primary Core
  elected (an elected Device no longer in the pool is no primary) and
  `SERVED`, `UNSERVED` or `CAPACITY`; each candidate carries its overlay
  addresses for DNS. An exit node with `router.exit.v1` gets the pool it
  serves, its probes, limits and DNS upstreams, and the pool's rules from
  its consumers to `0.0.0.0/0` and `::/0`, outside its packet filter
  (`meshtransit_mtcp_exit_filter_groups_omitted_total`). Exit nodes and
  Site routers share the peer limit. Exit nodes report their pool's health
  in `RouteHealthReport.exit`, which the Exit Pool election reads; a node's
  exit selection was validated and not stored yet (stored since: see
  above).
- Core: exit nodes offer and Core elects (schemas 203 and 204). A node
  says in MTCP `Hostinfo.exit_offered` whether its own configuration offers
  to be an exit node (only with `router.exit.v1`); a change is recorded as
  `device.exit_offer_changed` and, for an exit node, rebuilds the Network's
  maps. With `MESHTRANSIT_EXIT_NODES_ENABLED` a worker elects each Exit
  Pool's primary exit node as Sites elect their router
  (`exit_pool.primary_changed`, `meshtransit_exit_pool_election_*`); the
  pool's read carries `primary`, and `…/exit-pools/{pool}/primary-changes`
  pages its history (`route.read`). Site and Exit Pool elections share one
  package; Sites elect as before. MTCP v1 documents Exit Pools (§7.7):
  `ExitConfig`, `ServedExits`, exit health and selection reports, and the
  `routes.exit.v1` and `router.exit.v1` capabilities, which Core offers only
  with the flag.
- Core: an Access Rule may grant the Internet through an Exit Pool
  (schema 202): `destination_exit_pool_id` names the pool, with any source
  selector and the rule's protocol and ports, never addresses. The active
  policy lists such rules with `selector_kind` `exit_pool`, republishing and
  simulation keep them, and a pool, group, Identity Group or tag that active
  rules name cannot be deleted (409 `exit_pool_in_use` for a pool). Releases
  with exit rules hash under a new domain; earlier releases hash as before.
  Explain, the Access Graph and maps do not show exit rules yet.
- Core: a release holding both group rules and rules to Sites failed to
  publish (its projection identities were checked per kind against the
  wrong total); every kind is now checked against the whole release.
- Core: Networks have Exit Pools (schema 201), groups of exit nodes that
  will forward other Devices' Internet traffic. A pool is its own entity,
  never a kind of Site: `…/networks/{network}/exit-pools` lists, creates,
  changes and deletes pools (`route.read`, `route.approve`,
  `route.withdraw`), and `…/exit-pools/{pool}/nodes/{device}` assigns exit
  nodes. A Device is an exit node of one pool at most and serves only once
  its own configuration offers to. A pool's DNS resolvers and egress probes
  must be addresses on the Internet, a set shared by Core and nodes
  (`shared/internet`): private, shared, link-local (cloud metadata),
  documentation and other special ranges, the mesh's own ranges, and IPv6
  outside `2000::/3` are not. Policy rules to pools, maps and exit nodes
  themselves come next.
- Core: a route offer is stored in one statement (schema 200,
  `mesh_ops.report_device_route_offer_v2`), and a Device that is revoked,
  logged out or removed loses its offer in the same change. A router whose
  consumers fill its packet filter keeps its own rules and the Sites that
  fit, instead of failing its map
  (`meshtransit_mtcp_routed_filter_groups_omitted_total`).
- Clients: macOS and Windows reuse the interface found for a destination
  kept off subnet routes for half a second; Windows refuses routes with
  `settings_unusable` when the settings file is unsafe or unreadable, and
  forgets a subnet route that did not come back after its adapter's routes
  changed.
- Clients: local router failover also covers routers reached only through a
  relay. A node pings the routers of a Site it routes through, through the
  relay, every second while no direct path to them is proven, and counts
  their relayed PONG as an answer (disco v2 §3.2.1: a relayed PONG carries a
  zero `observed`). Nodes answer relayed PINGs at most once a second per
  peer; older nodes drop them.
- Subnet routers turn IPv4 forwarding on for the interface each end of a Site
  prefix leaves by, and stop their health checks as soon as the device
  closes.
- Core: `meshtransit_site_election_sites{state}` and
  `meshtransit_site_election_routers{state}` count Sites a router can serve,
  cannot serve now, or have no usable router, and routers by status, from the
  election worker's last sweep with router health; monitoring docs suggest an
  alert on degraded or unserved Sites.
- Core: the access ledger records rules to Sites (schema 199). Each Device a
  rule grants a Site to is an edge with `selector_kind` `site`,
  `destination_site_id` and `destination_prefixes`; the history read
  (`read_access_graph_history_v2`) returns them, while v1 leaves them out for
  older Cores. Existing edges keep their keys.
- Core: the Access Graph lists the Devices each rule to a Site reaches
  (schema 198, `mesh_ops.read_access_graph_v3`): one `site` edge per Device
  with the prefixes the rule grants, to a `site` node, in the same projection
  order and pages as other edges. A Site's routers get no edge, and a Site
  node is named only for callers with `route.read`.
- Core: explain answers for an address inside a Site (schema 197,
  `mesh_ops.explain_site_access_v1`). `destination_address` asks about it;
  the answer names the Site that holds the address and each rule to it that
  grants the address to the source Device, with the prefixes it grants.
- Core: policy simulation reports access to Sites. `site_access_changes`
  lists, per source Device, the part of a Site a proposal grants or takes
  away (at most 256 each, with counts), its Devices count as affected, and
  such a change enters the impact hash (an impact without Site changes keeps
  its hash).
- Sites may use IPv6 unique local prefixes (schema 196). Core refuses only
  `fd00::/48` and, with `site_prefix_invalid`, a prefix that overlaps the
  Workspace's overlay pool or the deployment's Device alias pools; clients
  refuse a route that overlaps the /48 of a mesh address or overlay route
  they hold, instead of all of `fd00::/8`.
- MTCP: `SiteRoute.name` (field 7) carries the Site's display name (schema
  195, `mesh_ops.load_map_network_sites_v3`). Clients show it in
  `meshctl status`, the local API (`name`) and the mobile status, and ignore
  a name longer than 64 characters or with control characters rather than
  the map.
- Core: `MESHTRANSIT_SITE_DENIED_CIDRS` lists the addresses no Site may
  cover (Core's endpoint, load balancers, relays); creating or changing such
  a Site is refused with `site_prefix_invalid`. Maps leave out any Site
  prefix that holds a relay address or a denied endpoint range, so a relay
  added after a Site was saved is never routed into the mesh.
- Packaging: the Linux `meshd` unit starts with `--enable-subnet-routes`, as
  macOS and Windows do; routes stay off until root runs
  `meshnetd routes accept on`.
- Client: a network change asks again at once for the subnet routes the map
  wants, instead of at the next 10-second refresh. The mobile library gains
  `Engine.SetHostServers` (DNS servers and gateways of the physical
  networks); a subnet route containing one is refused as `local_conflict`.
- Client: status names each granted Site by its prefixes and its router by
  the Device name without the DNS suffix (`meshctl status`, local API
  `prefixes`, mobile status `prefixes`); the map carries no Site name.
- Mobile library: the device reaches subnet routes once the app turns them
  on (`Engine.SetSubnetRoutes`, kept in the state directory, off by
  default). Admitted prefixes go on the VPN interface (a new interface when
  they change), except those overlapping an attached network reported with
  `SetHostAddresses`. The status JSON gains `subnetRoutes` and `sites` (the
  router each Site goes through); its schema stays 1.
- Client: Windows reaches subnet routes. The service (now installed with
  `--enable-subnet-routes`) installs on its adapter the granted prefixes
  that `C:\ProgramData\MeshTransit\settings\routes.json` admits, which an
  administrator changes with `meshd routes accept on` and which is ignored
  unless only SYSTEM and Administrators may access it. Routes overlapping a
  network the machine reaches, or holding another adapter's DNS server, are
  refused. A socket to an address inside an installed route leaves through
  the physical interface (`IP_UNICAST_IF`). The settings command moved to a
  shared package; `meshnetd routes` behaves as before.
- Client: macOS reaches subnet routes. `meshnetd --enable-subnet-routes`
  (now in the launch daemons) installs the granted prefixes the local
  settings admit (`sudo meshnetd routes accept on`) on the `utun` link,
  marked as its own, with the same local conflict checks and resolver pins
  as Linux. `meshd` binds a socket to an address inside an installed route
  to the physical interface (`IP_BOUND_IF`) and sends no datagram there.
  meshnetd's Linux-only flags (`--routed-table`, `--routed-priority`,
  `--router-nft-table`, `--router-state`) are no longer accepted on macOS.
  Flow log uploads now also go through the client's underlay sockets.
- Testing: `make e2e-subnet-router` (and a CI job) routes real traffic from a
  consumer through a subnet router into a Site's LAN in network namespaces,
  with the real helper and data plane, moves it to the other router when the
  first dies, checks an unserved Site is refused at once, and measures
  throughput and latency through the router.
- MTCP: `RouteSelectionReport` (0x36) and capability `routes.selection1`: a
  node reports the router it uses for each Site it reaches (`PRIMARY`,
  `LOCAL_FAILOVER` or `NONE`), on change and every 60 seconds. Core keeps it
  with the Device's session and per Site in Redis
  (`meshtransit:v1:site-selection:*`, which the Core ACL must allow): one
  Site's read gives each router's `clients` and `local_failover_clients`, a
  Device's status its `subnet_routes`. `meshctl status` names each Site's
  router; the Console shows them on the Site and Device pages.
- Client (Linux): a subnet router whose service stops tells Core first, with
  a last route health report of every Site it served failed as
  `going_away`, so Core elects another router within a second instead of
  after two minutes of silence. A package upgrade restarting meshd writes
  `/run/meshd/restart-expected` first, and the router then stays primary.
- Client: a node whose packets to a Site go unanswered for 5 seconds, while
  the Site's router stopped answering its direct path probes and another of
  the Site's routers answers, routes the Site through that router until Core
  elects again (backoff 10 s to 5 minutes; back to Core's choice once the
  Site is idle a minute). Routers reached only through a relay are left to
  Core.
- Core: a router's report that newly holds a failed Site wakes the Site
  election worker at once (Redis channel
  `meshtransit:v1:wakeup:site_health_failed`, which the Core ACL must allow;
  without it the worker elects at its next 10-second pass).
- Core: one Site's read carries the primary router Core elected (`primary`:
  device, generation, reason, time), and `GET …/sites/{site}/primary-changes`
  pages its changes from the audit history, newest first (schema 194).
  Console: the Site page marks the elected router primary instead of
  guessing by priority, says why and when it was chosen, and lists the
  primary changes 10 per page.
- Core: a Site has up to 32 routers, and Core elects its primary from their
  health about every 10 seconds: a router that reports the Site failed, goes
  silent for over 2 minutes, drains or can no longer serve is replaced in
  priority order; a recovered router waits 30 seconds, and failback 5 minutes.
  Silence proves nothing while Core cannot read health or many routers go
  silent at once. Each change is audited as `site.primary_changed` and
  advances the Network, and maps carry the elected router (schema 193). A
  Site without masquerade keeps one router (409
  `site_masquerade_requires_single_router`).
- Core: a Device's status carries `router` for a subnet router: its route
  enforcement (the route digest it reports against the served routes it was
  delivered: enforced, applying, mismatch, not_reported, unknown) and its
  current health of each Site; one Site's read gives each router's `health`
  of the Site and `route_enforcement`.
- Client: a router that serves nothing yet reports the empty set's route
  digest, as route digest v1 requires, instead of 32 zero bytes.
- MTCP: `RouteHealthReport` (0x35) and capability `router.health1`: a Linux
  subnet router sends Core the health of every Site it serves, on change and
  every 10 seconds. Core keeps it, only for the Sites it sent, with the
  Device's current map session in Redis, and also keeps the route digest of
  the served routes it delivers next to the one the router reports, so a
  router that serves something else can be told apart (Console views follow).
- Client (Linux): a subnet router measures each Site it serves every 2
  seconds and shows it in `meshctl status` and the local API
  (`subnet_router.site_health`): forwarding turned off, the router table
  gone, a prefix no longer offered or routed, connection tracking above
  80%, and the Site's probes, sent through the TUN from `100.64.0.0` /
  `fd00::` so they cross the forward path. A probe that never left the router
  is `forward_blocked` (such as Docker's or firewalld's forward policy), one
  without an answer `probe_failed`. `meshnetd` gains a
  `check_served_routes` operation, a self-test counter in its table and host
  routes for the two addresses; it still sends no packets.
- Core: the Console's Device list and Device read carry
  `advertised_prefixes`, the subnets a Device offers to forward as a subnet
  router (the first 16 in a list, all on one Device's read), and
  `advertised_prefix_count` (schema 192). Offering still grants nothing.
- Client (Linux): `meshd --enable-subnet-router` lets Core make the host a
  router of the subnets it offers. `meshd` offers what
  `/etc/meshtransit/routes.json` advertises while router mode is on;
  `meshnetd` forwards only into the part of Core's served routes the host
  offers, turns forwarding on only where needed (restoring it afterwards,
  also after a crash) and installs one atomically replaced nftables table
  (`inet meshtransit`, `--router-nft-table`): only served prefixes, Sites
  answer but never open connections, the router's own addresses stay out
  of reach, masquerade per Site (NAT66 for IPv6), MSS clamping. The packet
  filter applies the Site rules and admits ICMP errors about tracked flows
  (path MTU discovery); the enforcement report carries the route digest;
  `meshctl status` shows a `Subnet router` line. The packaged `meshnetd`
  unit may now write `/proc/sys/net/ipv{4,6}/conf`. New modules:
  `github.com/google/nftables` (Apache-2.0) with `github.com/mdlayher/netlink`
  and `github.com/mdlayher/socket` (MIT).
- Client (Linux): `meshd --enable-subnet-routes` reaches the Sites Core
  grants. It asks `meshnetd` for every granted Site's prefixes (again every
  10 seconds), sends a served Site's traffic to its primary router, lets a
  Site's hosts only answer flows the node opened, and answers traffic to a
  Site that is not served with ICMP host unreachable (at most 10 a second per
  Site) instead of letting it leave by the default route. Lazy peers install
  a Site's router on demand. `meshctl status` and the local API
  (`subnet_routes`) show installed and refused routes and the health
  `route_conflict_local` or `route_install_failed`. The flag is off by
  default; macOS and Windows report subnet routes unsupported.
- Client (Linux): `meshnetd` can install the subnet routes Core grants, in
  their own routing table, with a policy rule that keeps `meshd`'s own
  sockets out of it (the packaged unit uses `--routed-table=5267`). It
  installs only what the host's root-owned settings admit:
  `sudo meshnetd routes accept on` for private ranges, `accept-public on`
  for public ones; never default or very wide routes, the overlay frame,
  loopback, link-local, multicast or more than 4,096 routes. `advertise` and
  `router-mode` record what the host offers to forward. Everything is off by
  default and a change applies within seconds. It refuses a route that
  overlaps a network the host is attached to or reaches by an equal or more
  specific route (`local_conflict`), keeps system resolvers inside a route
  on their physical path, and checks again when the host's networks change.
- Core: maps carry subnet routes (mtcp-v1 §7.6) when
  `MESHTRANSIT_SUBNET_ROUTES_ENABLED` is on and Core reads Network inventory
  once per revision (the default). A node that lists `routes.subnet.v1` and
  `map.large1` gets the Sites its rules grant, intersected with each Site's
  current prefixes, with the Site's routers as candidates, the first active
  one as primary, the route revision as generation and a status: `SERVED`,
  `UNSERVED` (no router can serve: not live, not Workspace-owned or not
  offering the Site), `CONFLICT` (two granted Sites overlap) or `CAPACITY`
  (beyond the router's peer limit). Its routers are always peers of its
  map. A router that lists `router.subnet.v1` and `map.large1` gets the
  Sites it serves and a packet filter that admits its consumers into them,
  covered by its policy digest. Nodes that list neither see no change.
  `meshtransit_mtcp_map_route_sites_total` counts the Sites sent by status
  and those a map's bounds left out. Schema 191, no operator step. Turn the
  setting on only once every replica runs this Core: a node that reconnects
  to a replica without it gets a map without routes and drops them until it
  reconnects again.
- Core: stores the subnets a Device offers to forward from its
  `HostinfoReport` (`advertised_prefixes`), so it can be made a Site's
  router. Entries no Site could use are ignored and counted
  (`meshtransit_mtcp_route_offer_prefixes_dropped_total`); offers are stored
  at most 4 at once, then 1 per 10 s per session, keeping the latest, and an
  unchanged offer writes nothing (`meshtransit_mtcp_route_offers_total`).
  Each change is recorded as `device.route_offer_changed`; one that changes
  whether a router covers its Site also rebuilds the Network's maps. Schema
  190, no operator step; run the migration before the new Core (a Core
  without it logs a warning per report and stores nothing).
- Core: Access Rules can name a Site as destination (`destination_site_id`,
  with optional `destination_prefixes` inside the Site), from a Device,
  Device Group, Identity Group or Device Tag. Releases keep the granted
  prefixes. Refused: rules to different Sites that grant overlapping prefixes
  (`409 route_overlap`) and more than 16,384 granted prefixes in all (`422
  route_prefix_limit`). While active rules use them, a Site cannot be deleted
  (`409 site_in_use`) nor lose granted address space (`409
  site_prefixes_in_use`), and the groups and tags they select count as in
  use. `GET …/policy` returns them with `selector_kind` `site` and
  `destination_prefixes`. Off unless `MESHTRANSIT_SUBNET_ROUTES_ENABLED=true`
  on every role (`409 subnet_routes_disabled`). Maps do not carry routes yet.
  Schema 189, no operator step; a Core before this release that republishes
  a policy read from `GET …/policy` could not hold Site rules, so roll out
  every role before turning the setting on.
- Core: Network Sites, the first part of subnet routers. A Site is an address
  space behind the mesh (an office LAN, a VPC) with its prefixes, source
  translation and probe addresses; a Device of the Network can be its router.
  `GET|POST /api/v1/workspaces/{workspace}/networks/{network}/sites`,
  `GET|PATCH|DELETE …/sites/{site}` and `PUT|DELETE …/sites/{site}/routers/{device}`
  use the existing `route.read`, `route.approve` and `route.withdraw`
  permissions. A router must be an active, Workspace-owned Device whose own
  configuration offers the Site's prefixes; a Site has at most one router
  until high availability. Nothing is routed yet: maps and clients follow.
  Schema 188, no operator step.
- Client: a map change no longer drops established connections. The packet
  filter keeps every tracked flow the new map still authorizes and ends only
  those whose peer identity, key lifetime, alias grant or admitting rule
  changed; before, any peer joining or leaving reset replies of every open
  TCP connection. The flow table holds 32,768 flows (was 4,096).
- Client: a map whose addresses or allowed prefixes leave the overlay frame
  (`100.64.0.0/10`, `198.18.0.0/15`, `fd00::/8`) is refused, and on Android
  `meshd` refuses such addresses and routes before they reach the platform
  VPN interface. Core never sends them; this bounds a compromised control
  plane.
- Core: the Device alias pool tool accepts pools only inside `198.18.0.0/15`
  and `fd00::/8`, and the database refuses any overlay or alias pool outside
  the client overlay frame (schema 187). Adding the constraint checks
  existing pools: the migration stops on a deployment that has one outside the
  frame, which clients would refuse anyway; move that pool first.
- Core: deleting a Resource now supersedes its Device target, so the Device
  can get a new Resource; before, it answered `device_resource_exists` for
  good. A deleted Resource is still returned by GET and by
  `list?state=deleted`. Creating a Resource Group whose name is taken answers
  `409 resource_group_name_taken` instead of a 412. The Resource retirement
  worker counts Resources still in use apart from failures
  (`meshtransit_resource_retirement_worker_blocked_total`). Schema 186, no
  operator step; during the rollout an old worker logs a deferred retirement
  for a Resource in use and retries it.
- Core: removing a Device retires its Device Resource once nothing uses it
  (no open share, no rule of an active policy release in its Network or, to
  the shared Device, in a receiving Network, no current Resource Group); one
  still in use is looked at again every five minutes. The worker that ends shares of removed Devices now also runs a
  Resource retirement worker (`meshtransit_resource_retirement_worker_*`),
  which deletes the Resource, supersedes its Device target and records
  `resource.retired`, so the name and the hostname can be shared again.
  Schema 185 adds the queue, a trigger on Device removal, the worker entry
  points and queues the Resources of Devices already removed; no operator
  step. Creating a Resource with a taken name now answers
  `409 resource_name_taken`, and one for a Device that already has a Resource
  `409 device_resource_exists`, instead of a misleading 412.
- Core: a request by a member arriving while an administrator removed or
  suspended them, or ended their sessions, could deadlock (40P01): the
  permission check held the member's session row and waited for the
  Workspace, which the change held while it waited to end that session. The
  permission resolvers (`resolve_workspace_permission_v1`,
  `resolve_network_permission_v1` and `_v2`) now lock the Workspace before
  the session, so the
  request waits and then finds its session ended. Schema 184 replaces the
  three resolvers with the same signatures, no operator step.
- Core: creating a user group or a tag, and changing an invitation, read the
  Workspace row FOR SHARE in the permission check and then asked for FOR NO
  KEY UPDATE, so two such changes in one Workspace could deadlock (40P01).
  They now lock the Workspace first, as member changes do; tag and group
  updates and deletions are unchanged. A caller without the permission holds
  the lock until its call is refused. Schema 183 replaces the three
  functions with the same signatures, no operator step.
- Core: removing a member from a Workspace or a Network could deadlock
  (40P01) with a share or registration that held the Network revision and
  then wrote a row referencing the Workspace, such as its audit event. The
  16 functions that serialize Workspace changes now lock the Workspace row
  FOR NO KEY UPDATE instead of FOR UPDATE, so foreign key checks no longer
  wait for them; they stay serialized with each other and with sign-in.
  Schema 182 replaces the functions with the same signatures, no operator
  step.
- Core: 17 SQL functions (member and Network member changes, Device
  lifecycle and logout, Device and user groups, tags, invitations, alias
  ranges, session revocation) took the later of the database clock and the
  caller's evaluation time as now. They now use the database time at which
  the transaction started, the instant MeshCore already sends, for both their
  checks and their stamps, so no caller clock can move validity or recorded
  times forward. A stamp on an existing row never goes below that row's own
  times. Schema 181 replaces the functions with the same signatures, no
  operator step.
- Console: removing a member flags each of their Devices that looks like a
  server or a shared machine (enrolled with a key, never expires, or tagged)
  and sets it to move to the Workspace instead of being revoked. It checks
  the first 20 Devices, within 8 seconds, and stops early on a rate limit; a
  Device it could not check is marked Not checked and revoking it needs a
  confirmation.
- Core: `POST …/devices/{device}/actions/extend` (`device.manage`,
  `If-Match`, `duration_seconds` 3600–604800 and a reason) gives a member's
  Device that expired or expires within a day a short extension from now, so
  it reconnects until its user signs in again. Each extension is audited as
  `device.expiry_extended`. Schema 180 adds the function, no operator step.
  The Console offers it as Extend access on the Device page.
- Client and Core: a Device warns before it expires. `meshctl status` shows
  a `Device expiry` line (and `device_expires_at`, `device_expiry` in
  `--json`) that reminds the person to sign in again from 14 days before and
  urgently on the last day; the mobile status JSON carries the same two
  fields. Core exports `meshtransit_mtcp_sessions_device_expiring{within}`
  for the connected Devices expiring within 14 days and within one day.
- Core: each Network chooses how long a Device that signs in through the
  browser lives: 1 hour to 180 days, or never expires. Without a choice it
  lives 180 days instead of 30. `GET` and `PATCH …/networks/{network}/device-lifetime`
  (`network.read`, `network.update`, `If-Match`) read and set it, and each
  change is audited as `network.device_lifetime.updated`. The choice applies
  from the next sign-in; Devices already registered keep their expiry until
  their user signs in again. Schema 179 adds two empty columns, no operator
  step. The Console shows it under Network settings.
- Core: `POST …/devices/{device}/actions/revoke` removes a suspended or
  expired Device too, as removing a member already did; the suspension and
  any pending handover are cleared. Before, the request failed with a
  generic error.
- Core: removing a provider Device ends its shares. A trigger queues the open
  contracts of a Device that becomes revoked or deleted; the worker that
  finalizes expiry also moves them to `invalidated`, frees the consumer
  access name and alias, advances both Networks and audits
  `trust_contract.invalidated` (reason `provider_device_removed`) on both
  sides. Existing shares of removed Devices are queued by the migration
  (schema 178, operator step `000178` before rollout). The Console shows
  "Ended: the shared Device was removed or changed" to both sides.
- Core (breaking): every API path follows resource rules, still under `v1`,
  with no old paths kept. `POST` on a collection creates (device tags, user
  groups, Network device groups, guardrails, interchanges, invitations,
  enrollment keys, Network members); `PATCH` and `DELETE` on an item change
  and remove; group members change with `PATCH …/members`, a Device's tags
  with `PATCH …/devices/{device}/tags`; Workspaces and Devices are renamed
  with `PATCH` on the item and alias ranges changed with
  `PATCH …/alias-ranges`; a role assignment is revoked with `DELETE`. The
  audit export moves to `GET …/audit-exports`, the enforcement history to
  `GET …/networks/{network}/enforcement-history`, assignable tags to
  `GET …/networks/{network}/assignable-device-tags`. The Console's cookie
  path accepts `PATCH` and `DELETE` with a CSRF proof; a `DELETE` carries no
  body.
- Core: the Console lists Devices by name ten at a time with a name prefix
  (`q`) and an `active`/`inactive` filter, reads one Device with how it was
  enrolled and its tags (`GET …/devices/{device}`), its delivery status
  (`…/status`) and a page of the peers it reported (`…/peers`); the
  Network-wide `…/devices/distribution` read is removed (schema 177).

- Core: enrollment keys can be created, listed and revoked through the API
  (`…/networks/{network}/enrollment-keys`, `enrollment_credential.issue` and
  `.revoke`) and the Console. A key enrolls exactly one Device; its creator
  chooses how long the key can be used (5 minutes to 30 days, 24 hours by
  default) and how long the Device lives (1 hour to 180 days, or never). The
  Device belongs to the key's creator and is not affected when the key
  expires. Only a usable key can be revoked; a key that already enrolled its
  Device is refused (`409 enrollment_key_used`), and that Device is managed
  instead (schema 176). Each creation and revocation is recorded in the
  Network's activity log, and each registration records the Device lifetime
  it got. Schema 175; the `api` role reads `MESHTRANSIT_ENROLLMENT_DIGEST_*`
  to issue keys.
- Core: every `policy.published` event now records the published
  `policy_revision` and a `change_summary`: how many Access Rules were added,
  removed, changed or kept, and up to 20 of the changed rules with their
  destination (an Imported Resource by its consumer-local ID). Core computes
  the comparison itself from rule fingerprints that each release now keeps
  (schema 174, one row per release); the database does not compare compiled
  rules. A release published by an older Core has no fingerprints, so the
  next publication records `baseline: unavailable`; fingerprints that do not
  decode record `unreadable` and never block publication. The event stays
  within the 16 KiB audit bound: when it would not fit, it lists fewer
  changed rules, then fewer guardrail findings (with
  `guardrail_finding_count`), instead of failing the publication. Docs now
  say that approval is optional and `approval_policy.manage` grants nothing
  yet.
- Core: `meshcore migrate operator apply` runs the operator SQL steps from the
  binary instead of by hand with `psql`. It connects with its own
  `MESHTRANSIT_OPERATOR_*` settings as a superuser or `CREATEROLE` role, and
  refuses the migrator, runtime, worker and owner roles. It runs, in order
  and in one transaction under the migration lock, every step that does not
  hold (and the later steps again), never a step whose migration is not
  applied (`--through N` refuses one), and the steps of migrations 53 to 93,
  170 and 171 only with `--after-rollout`; it then checks that every step
  holds and rolls back otherwise. `--dry-run` rolls back always, and
  `meshcore migrate operator status` lists every step. A step holds when its
  roles, function owners and `EXECUTE` grants are in place, so steps applied
  by hand count too; nothing new is stored. `meshcore migrate verify` (with
  the migrator's settings) reports the schema state and exactly which role,
  owner or grant of which step is missing and any role membership of a
  MeshTransit role, and exits with status 3 while any of these is found. The
  command runs the statements it rebuilds from each parsed file, never the
  file's text, and each ownership file now starts with
  `-- operator-step: rollout=before|after`.
- Core: a pending operator step is now visible. Readiness stays up, since
  some steps must wait until a rollout ends, but a background read (at most
  once a minute) logs the pending steps when they change and exports
  `meshtransit_postgres_operator_steps_pending`; the policy publication,
  Imported Resource, share decision, alias worker and map reader paths
  export the function version they selected in
  `meshtransit_postgres_function_version` and log a warning naming the
  operator step while it is below the newest. The same background read exports
  `meshtransit_postgres_role_memberships` and warns when a MeshTransit role
  takes part in a membership.
- Core schema 172 and Core: every time Core persists, or compares with
  persisted state, now comes from the PostgreSQL clock: share, Resource,
  policy approval and publication, Device registration, revocation and
  Node-key rotation times, idempotency windows, invitation and browser
  registration lifetimes, session renewal, the instant authorization and
  expiry are evaluated at, relay revocation windows and Console reads. A
  Core host's clock only bounds local timeouts and backoff. Before, a host
  running ahead of or behind the database wrote rows out of order with the
  database's own writers: finalizing a just activated Private Endpoint, or
  revoking a share after its publication, failed with 23514; a new Device
  stayed out of maps until the database caught up; recent revocations could
  be left out of the relay state. Schema 172 also keeps `updated_at` in
  order on the Resource sharing rows, so a row a previous binary stamped
  ahead of the database no longer fails the next write; schema 173 logs
  each such case to the server log. Map streams measure key and projection
  deadlines from the database time of their read. No operator step.
  Every process with a PostgreSQL connection samples the database clock at
  start and every minute and exports `meshtransit_postgres_clock_skew_seconds`
  (with its round trip, sample time and a samples counter); a skew above one
  second logs `clock_skew_exceeded`. Sampling never affects readiness.
- Core schema 171: a shared Device that was suspended (or whose session or
  keys changed) gives its consumers the share back once it is active again.
  The alias worker used to quarantine the endpoint's Resource aliases for
  good, so the endpoint stayed provisioning and every consumer Device lost
  the share until it was revoked and created again. It now reserves the
  endpoint's own Resource aliases again, so the share keeps its addresses and
  DNS name, and makes each pair ready again; the old leases stay as
  quarantined history. A revoked or expired share, a deleted Device or a
  Resource that targets another Device still does not come back. Run the
  schema 171 operator step after the migration; until then the worker keeps
  the previous behaviour.
- Core schema 170: a consumer Device that was suspended (or whose session or
  keys changed) gets its shares back once it is active again. The alias
  worker used to withdraw the share for good, so the Device had no peer for
  it until the share was revoked and created again. It now reserves a new
  Consumer Source Alias and makes the pair ready again; the old alias stays
  quarantined. Run the schema 170 operator step after the migration; until
  then the worker keeps the previous behaviour.
- Core schema 169 and meshd: Device names resolve again. Every live Device
  has a DNS name, `<label>.<Workspace code>.<Network code>.<suffix>`, where
  the label is derived from the hostname and unique in the Network (numbered
  variants such as `laptop-1` when two hostnames give the same label; existing
  Devices are labeled in registration order by the migration). Maps carry an
  address record for the node itself and its same-Network peers, the suffix
  as a route the node answers itself and the Network's zone as search domain;
  `meshd` answers reverse (PTR) queries for those names. Renaming a Device to
  a hostname whose label another Device holds is refused like a taken
  hostname. Labels that hosts look up on their own (`wpad`, `isatap`,
  `localhost`, `www`, ...) are prefixed with `device-`. A Device without a
  label, or names that collide, never fail a map: they are left out and
  counted in `meshtransit_mtcp_map_names_degraded_total`. The Console Device
  inventory returns `dns_name`.
- Core: **share names change** from `….shared.mesh` to `….shared.<suffix>`
  (`….shared.mesh.internal` by default) in maps and in the management API.
  Applications that reach shared Devices by name must use the new name; a
  name sent back on accept may use either form. Names a consumer typed before
  share names were derived are unchanged.
- Core: peers of another Network no longer carry their hostname, in the map's
  name or display name: a consumer knows a shared Device only by its share
  name, a provider its consumers only by a placeholder that does not resolve.
- Core: `MESHTRANSIT_DNS_SUFFIX` (default `mesh.internal`) sets the suffix of
  Device and share names; set it on every role. It needs two labels and may
  not be a special-use zone such as `local` or `arpa`. Configuration schema 26.
- meshd: a map may carry 50,000 DNS records (was 32,768), as MTCP v1 allows.
  A locally answered route for the root or a single label from Core is
  ignored and logged.
- Core schema 168: the Private Endpoint route worker no longer applies and
  withdraws a route for an endpoint created by a MeshCore whose clock runs
  ahead of the database host. Such an endpoint waits until the database clock
  reaches its creation time; before, the readiness confirmation failed with a
  serialization error, the worker withdrew the route it had just applied and
  retried after its backoff. No operator step is needed.
- Core schema 167: guardrail saves and share changes no longer race. A
  share accepted or enabled while its Workspace's guardrails are being saved
  fails as a retryable conflict; a guardrail save that a concurrent share
  changed under is redone by Core up to three times, then fails with
  `version_conflict`, instead of missing it. Saving a guardrail no longer
  deadlocks with a share offer of another Workspace. Switching an enforced
  guardrail to audit mode or deleting it reads no share list: it wakes the
  Networks of the shares of the Networks it named, at most 1,024 at once,
  the rest at the next map reconcile interval, so it works at any size. Only
  previews and saves in enforce mode read shares, at most 20,000 (above that,
  even a loosening save in enforce mode is refused).
  `guardrail.weaken` may preview, and the map reads guardrails through
  indexes. Existing shares that enforced guardrails block leave maps within
  one reconcile interval of the new binary; no operator step is needed, but
  do not change enforce-mode guardrails while binaries from before and after
  schema 167 run together.
- Core: members can be added to and removed from an existing Network. Before,
  a Network created after people joined the Workspace held only its creator,
  so nobody else could enroll a Device into it. The new
  `network.member.manage` permission (owner, `admin`, `it_admin`; a
  Network-scope `it_admin` for its Network only) lists a Network's members,
  adds up to 150 active Workspace members at once, and removes one, handling
  their Devices in that Network with the same plan as a Workspace removal
  (move to the Workspace, hand over to another Network member, or revoke).
  Console routes: `GET /api/v1/workspaces/{workspace}/networks/{network}/members`,
  `POST .../members/actions/add` and `POST .../members/{member}/actions/remove`.
  Additions and removals are recorded on the Network's audit stream as
  `network.member.added` and `network.member.removed` (schema 166).
- Core: a policy holding a rule to a Resource, a Resource Group member or an
  Imported Resource whose Device was suspended, expired or revoked no longer
  fails every publication with a stale revision (412). Such rules publish
  like Device rules: suspended and expired Devices are accepted, a revoked
  Device only in a rule the active policy already holds unchanged, and a new
  or changed rule for a revoked Device is refused with 409
  `device_unavailable`. A kept rule now counts as unchanged only when both
  sides, the protocol, the ports and the destination match, for Device and
  group rules too (migration 165).
- Core schema 164: an enforce-mode guardrail cuts the existing shares it
  blocks. Before, guardrails were checked only when a share was made or rules
  were published, so tightening one later left existing shares open. Maps now
  leave out every share an enforced guardrail of either Workspace blocks and
  put it back once the guardrail is switched to audit mode, loosened or
  deleted; the share itself is unchanged. Saving a guardrail in enforce mode
  needs the `impact_hash` of a preview
  (`POST /api/v1/workspaces/{workspace}/guardrails/actions/preview`), which
  lists the shares the save would cut; a stale or missing hash gets
  `guardrail_impact_changed` (409). A save that cuts or restores shares wakes
  the maps of both sides, with evidence on each Network's audit stream. A
  share accepted or a rule published while the provider's guardrails are
  being saved now fails as a retryable conflict instead of waiting.
- Core: a test now refuses an operator ownership step that takes a previous
  function version away from `mesh_runtime` or `mesh_worker` (steps after
  migration 93 already keep them for rollback), and the `…_role.sql` steps
  create their role only if it is missing, so they can run again.
- Clients: a failure to apply host DNS now sets the DNS state to `failed`
  and turns the mesh names off on the host; the control session and data
  plane stay up and the next map retries. Before, the node left the mesh and reconnected to Core every few
  seconds, receiving the same map. All shared names are routed by one
  locally authoritative `shared.mesh` route instead of one route per name, so
  importing more than 256 shares no longer exceeds the host's route limit,
  and unknown names under `shared.mesh` are answered `NXDOMAIN` instead of
  going to the host's resolvers.
- Windows: `meshd` seals its identity key with DPAPI plus a fixed MeshTransit
  entropy, so a generic DPAPI unseal no longer opens it (code running as
  LocalSystem still can). A key sealed by an older `meshd` opens, is resealed
  and atomically replaced on the first start; an older `meshd` cannot open
  the resealed key, so restore the pre-upgrade key file before downgrading.
- Clients: `meshd` creates only the last folder of its state, key, socket and
  log paths and requires the parent to exist; an existing folder must be a
  real folder (not a link, junction or other reparse point) owned by the
  service (its user on Unix; SYSTEM or Administrators on Windows), or `meshd`
  refuses to start. On Windows, new folders get the restricted access list
  when they are created, `C:\ProgramData\MeshTransit` and its `logs` folder
  are restricted on every start, and a service log that is a link, has other
  hard links or grants anyone else access is replaced. Before, a junction
  planted at `C:\ProgramData\MeshTransit\logs` made the service write its
  log through it.
- Windows: `meshd` authorizes local API callers from the named-pipe
  connection's own access token, read by impersonating the client, instead
  of the token of whatever process has the client's process ID, which a
  reused ID or a handed-over pipe handle could make the wrong one.
  Anonymous clients are refused. `meshctl` now opens the pipe at the
  identification level (it used to connect anonymously), so a new `meshd`
  needs the matching `meshctl`.
- Core: a node must take each whole MTCP message within 30 s plus its size at
  64 KiB/s (at most 10 minutes), besides 10 s per record; otherwise Core
  closes the session (counted as `send_deadline` in
  `meshtransit_mtcp_session_limits_total`) and the node reconnects. A node
  reading one record every few seconds could hold a 32 MiB map in Core's
  memory for over an hour. The protocol limits table described a 16 MiB
  outbound buffer that never existed; it now states the real bounds.
- Core: policy simulation evaluates guardrails. `guardrail_findings` lists,
  for each proposed path to an Imported Resource, the guardrails publication
  would apply: the publishing Workspace's by name, and the provider's only
  where they block and without detail, with `blocks` where publication would
  refuse. `guardrail_evaluation` is no longer listed as unsupported. The
  impact hash includes the findings, so an approval request made before the
  upgrade (which lives at most 10 minutes) must be made again.
- Core schema 163: a share between Workspaces also answers to the provider's
  guardrails when the consumer accepts the offer, activates the Trust
  Contract or publishes new rules to the Imported Resource. Before, only the
  consumer's guardrails were checked, so a provider could not stop a share it
  had already offered. The consumer gets `counterpart_guardrail_violation`
  (409) without the provider's guardrail details.
- Core schema 162: Console sessions can be ended beyond one at a time. A
  person signs out everywhere (`POST /auth/v1/session/logout-all`), which ends
  every session of their Account. An administrator with `member.manage` ends
  the sessions a member signed in to their Workspace
  (`…/members/{member}/actions/revoke-sessions`). The operator ends every
  session of an Account, quarantines it (no sign-in until released) or
  releases it with `meshcore account revoke-sessions|quarantine|release`.
  Before, the Account's session generation was checked but nothing advanced
  it. Devices are not affected; each change writes an audit event.
- Core schema 161 and meshd: a revoked Device is told `REVOKED`, no longer
  `EXPIRED`. Core says so only for the exact machine and node keys it revoked
  (any other key without authority still gets `EXPIRED`, a failed lookup
  `RECONNECT`). meshd then replaces the profile's keys, if they are still the
  ones the revoked session used, and shows the profile as not registered;
  `meshctl login` registers a new Device without a `meshctl logout` first.
- Core schema 160: a Workspace invitation is accepted only by a sign-in whose
  identity provider verified the invited address (equal ignoring ASCII letter
  case; non-ASCII addresses are refused). Before, the link alone let anyone who
  completed sign-in join with the invited role. A refused sign-in creates
  nothing and leaves the invitation pending. Login profiles must request the
  `email` scope; the acceptance evidence carries a digest of the address.
- Dex broker artifact re-qualified at Go 1.26.9: `v2.45.1+compat.9`
  adds patch 0009 (`golang.org/x/net` v0.60.0 and its modules, removing the
  reachable `x/net/http2` findings GO-2026-6603, -6610, -6611, -6612 and -6617
  from the Dex dependency graph), a new source tree and binary digest, and
  regenerated SBOM, license, vulnerability, qualification and upgrade/restore
  evidence. The qualification binary is a standalone build and no longer
  depends on MeshCore's `go.mod`. The upgrade/restore script ran only from the
  old flat layout; it now uses `core/tools/qualification/dexstorage`.
- Go 1.26.9 toolchain baseline and `golang.org/x/net` v0.60.0 (with the
  `x/crypto`, `x/text`, `x/sync`, `x/mod` and `x/tools` releases it requires).
  Go 1.26.8 and `x/net` v0.58.0 carried reachable vulnerabilities, among them
  an HTTP/2 server crash, HTTP/2 memory exhaustion and HTTP/1 connection
  desynchronization (GO-2026-6599 to GO-2026-6617). Core, relay, the
  identity broker image and the clients are built with the new release. The
  Dex workspace verifier accepts a later patch release of the qualified Go
  minor line.
- Core refuses to start, and stops being ready, on a schema older than its
  binary; run the migration before rolling out a new release. A newer schema
  is still accepted, so a rollback is still a binary rollback.
- Core opens its PostgreSQL connections with join_collapse_limit and
  from_collapse_limit 4 (default 8). Searching the join orders of the
  authority functions cost 40-210 MB of planner memory on a backend's first
  call, kept until the connection closed; the largest growth one statement
  now causes is ~24 MB, and no measured statement plans worse. The platform
  integration run fails when one statement grows a backend by more than
  `PLATFORM_PG_MEMORY_GATE_MB` (64; core/tools/pgmemgate).
- Core schema 150: publishing a policy with shared Devices no longer takes
  ~210 MB of PostgreSQL planner memory per backend (it took a POC database
  at its memory limit down); the attach statement keeps its written join
  order. Publishing 3,000 shared rules takes under a second and ~30 MB.
- Core schema 151: a Device is shared into a Network at most once. A second
  live share gave the Device a second alias there and made the maps of both
  Devices invalid once rules used it; accepting one now fails with MT013
  (409 `device_already_shared`).
- MTRP MTT2 tickets (share scale step 5): a relay ticket commits to up to
  16,384 zones by digest and carries the first 32 inline; the node sends the
  rest in ZONES frames, and the relay puts the ticket in force once the list
  matches. Relays bound zones per session and relay-wide, and recheck a route
  by the zone that opened it. Core issues MTT2 to nodes in more than 31 Trust
  Contracts that negotiated `relay.zones2`, once
  `MESHTRANSIT_RELAY_TICKET_ZONES_V2` is on, so every share (up to 10,000)
  can use relays instead of the oldest 31. meshd declares `relay.zones2`.
- Core schema 149 (share scale step 4): the share map readers choose shares
  from the Device's own targets and rules (alias v6, dependencies v4) instead
  of scanning every endpoint or contract, so a providing Device's map no
  longer grows with the deployment's shares and a receiving Device's cost is
  linear. `MESHTRANSIT_CONTROL_MAP_SHARE_STATEMENT_TIMEOUT` (10 s) bounds the
  share readers of a map: a Device receiving 10,000 shares reads them in
  about 5 s. Opt-in load test: `PLATFORM_SHARE_SCALE=N`.
- meshctl down and logout (TD-CLI-04): down keeps the machine off the network
  across restarts until up; logout revokes the Device through MTCP Logout and
  gives the profile new keys, so up enrolls it again. Local API: POST /v1/down,
  /v1/up and /v1/logout.
- Core schema 143 (TD-CORE-14): a revoked Device's addresses go through a
  24-hour quarantine, then registration reuses them.
- meshnetd keeps a handed-over utun descriptor until meshd has received it,
  which fixes utuns that reached meshd unable to deliver packets on macOS.
- Merged Core, meshd and meshctl into one repository with per-directory
  licensing (core/ AGPL-3.0, client/ Apache-2.0).
- Protocol specifications for disco v2, MTRP v1, keys, NAT classification and
  the network threat model (docs/protocol).
- shared/key, shared/disco and shared/mtrp: key types, disco v2 and MTRP v1
  codecs with cross-checked test vectors and fuzz tests.
- shared/stun (RFC 8489/5780 codec) and shared/netcheck (NAT classification).
- test/natlab: in-memory NAT simulator, RFC 5780 STUN server, reference
  traversal agent and a generated traversal matrix.
- MTCP v1 specification (the MeshTransit control protocol) and its
  protobuf schema in api/mtcp/v1.
- Client enforcement evidence (R1-69): policy digest v1 (shared/policydigest,
  docs/protocol/policy-digest-v1.md); meshd reports the digest of the rules
  its packet filter enforces; Core compares it with the delivered filter and
  reports enforced, applying, mismatch or not_reported per Device.
- shared/mtcp (P4a): MTCP v1 records, Noise IK handshake between machine and
  control keys, encrypted session, fragmentation with bounded zstd, proofs of
  possession and control key fingerprints; Go types generated from
  api/mtcp/v1 without protoc (hack/protogen, `make proto`); test vectors
  cross-checked by an independent Python implementation.
- Enforcement evidence ledger (R1-69, schema 136): the enforcement-ledger
  worker records per-Device enforcement intervals, seals
  device.enforcement_mismatch and device.enforcement_restored on the Network
  audit stream, and GET …/devices/enforcement-history?at=T answers what each
  Device enforced at an instant.
- Core MTCP v1 endpoint (P4b, schema 137): with
  MESHTRANSIT_CONTROL_MTCP_ENABLED the control listener serves /mtcp/v1
  (HTTP upgrade), /mtcp/v1/ws (WebSocket fallback) and /mtcp/v1/key beside
  the legacy protocol, with the same control key. Admission before Noise, durable
  ClientHello timestamps per bound machine key, one session per machine
  key, map snapshots and deltas with an acknowledgement window, KeyUpdate,
  Lifecycle, relay tickets, endpoint and enforcement reports. Registration
  over MTCP follows in P4c.
- Registration over MTCP (P4c, schema 138): enrollment keys and browser
  approvals with resume handles, node key rotation, and Logout, which
  revokes the Device and records device.logged_out.
- meshd speaks MTCP v1 (P4d): mtcpclient registers, rotates node keys and
  streams maps over MTCP with a WebSocket fallback; `--control-protocol
  auto|mtcp|legacy` (default auto: MTCP where the control server offers
  it). Profiles keep their keys across protocols; `meshctl up
  --fingerprint` also accepts the `ck=` value of enrollment links.
- Turned off the legacy control protocol on the POC control server (P4e):
  meshd speaks MTCP only.
- Path reports (P4f): meshd reports per peer whether traffic goes direct or
  through which relay, why (`relay_reason`) and byte counters; Core keeps
  the latest report per Device and the Console Devices page shows it in a
  Connection column. The MTCP key document gains each key's `ck=`
  fingerprint, used by the Console install command.
- Port mapping (P5a): meshd asks the local gateway to forward its WireGuard
  port with PCP, NAT-PMP or UPnP IGD (`--port-mapping=auto|off`, default
  auto), renews and verifies the mapping, removes it on exit, and publishes
  it as a `port_mapping` candidate when its external address is public.
  `meshctl status` and `meshctl netcheck` show it. The NAT lab supports
  explicit mappings; symmetric/symmetric pairs go direct when one side maps.
- Cloud public addresses (P5b): on AWS (IMDSv2), GCP, Azure and DigitalOcean,
  recognised from DMI data, meshd reads the instance's public addresses from
  the metadata service and offers them as static candidates with the
  WireGuard port (`--cloud-metadata=auto|off`). `meshctl status` and
  `meshctl netcheck` show them.
- IPv6 hardening (P5c): IPv6 host candidates follow the kernel's address
  state (no tentative, duplicate or deprecated addresses; privacy addresses
  only without a stable one; at most four); CALL_ME_MAYBE sets the port
  mapped and global IPv6 flags; a peer pinging from a known address while no
  path is proven gets an immediate probe, so stateful IPv6 firewalls open
  together. meshrelay gains `--public-ipv6` for RFC 5780 attributes to IPv6
  clients. The NAT lab has IPv6 STUN and firewalled IPv6 nodes; two IPv6
  hosts behind address-and-port-dependent firewalls go direct, also when
  Core publishes no endpoints and only CALL_ME_MAYBE carries them.
- Connectivity on the Console (P5d): meshd reports its NAT classification,
  IPv6 reachability and gateway port mapping state in `EndpointReport`
  (`nat.report1`, new `port_mapping` and `nat_observed_ms` fields); Core
  stores the latest per Device and session when it changes, and the device
  distribution API returns it as `connectivity`.
- Private Interchange (P5e): a Workspace registers its own relays
  (`meshrelay --private-interchange`) and grants each to some of its
  Networks (schema 139, `interchange.read`/`interchange.manage`, management
  API under `/api/v1/workspaces/{id}/interchanges`, audit events
  `interchange.created|updated|deleted` and Network wake events). Core signs
  a relay map per Network with the granted regions marked preferred,
  accepts them as home relays, renews node grants when a Network's relays
  change, and serves each relay its grant sealed to its key at
  `/relay/v1/grant`.
- meshd prefers Private Interchange regions as its home relay (P5f): it
  leaves a preferred region only when that region fails and returns when it
  recovers.

- Relay revocation within seconds (P7): Core checks revocations every
  second and signs a new relay state at once when they change; relays hold
  a long poll (`GET /relay/v1/state?wait=N`, N ≤ 25 s) and apply it as soon
  as it is signed, falling back to 10-second polls against a Core that does
  not hold polls (mtrp-v1 §9).
- Fuzz targets for the MTCP handshake, session records, message records and
  packet filter digest, meshd's map state and cloud metadata parsing, and
  `hack/fuzz-long.sh` to run every fuzz target for a set time.

- Relay failover within seconds (P7): a meshd relay session that hears
  nothing for 1.2 s probes its relay every 0.8 s and declares it dead after
  three unanswered probes; the failure re-chooses the home relay at once,
  and a failed home relay connection is replaced on the first observation
  instead of after two missed refreshes (was up to about a minute).
  A home relay change now moves on the live relay pool instead of
  recreating the WireGuard device and TUN, so connected regions, WireGuard
  sessions and direct paths survive it. A peer endpoint change reloads only
  connectivity in Core (one query instead of a full map snapshot per
  stream). POC drill: silent home relay loss to a working new home in
  4.7 s, double loss to the next region in 5.9 s.
- The relay accepts its key as a systemd credential (`LoadCredential=`,
  mode 0440 inside `$CREDENTIALS_DIRECTORY`); elsewhere the key file must
  still be 0600.
- Core scale-out, step S1 (schema 140): each control replica reads a
  Network's live Devices once per revision into a shared, immutable,
  hash-indexed inventory (singleflight per Network) and builds every
  stream's map from it instead of one peer-candidate query per Device.
  `MESHTRANSIT_CONTROL_MAP_SHARED_INVENTORY` (default true) and
  `MESHTRANSIT_CONTROL_MAP_INVENTORY_STATEMENT_TIMEOUT` (30 s) control it.
  Metrics: `meshtransit_map_snapshots_total{source}`,
  `meshtransit_map_inventory_reads_total`,
  `meshtransit_map_inventory_policy_mismatches_total`. Snapshot build for
  10,000 peers: 312 ms to 96 µs.
- Core scale-out, step S2 (schemas 141, 142): the inventory carries the
  Network's packet policy at selector level (Device, Device Group, Identity
  Group, tag) and expands it per Device in O(rules + output) without
  pairing group members. A revision wakeup refreshes a running stream
  entirely from the shared view (no per-Device transaction); Devices with
  direct shares or that left the view still take the full read. Integration
  tests require the shared and derived maps to equal the direct read.
  Coalesced stream wakeups keep the highest announced revision so a refresh
  never settles for an older view. Scale test at 2000 Devices: revision
  fan-out p95 1.6 s to 404 ms, Postgres pool wait down 11x, stream opens
  59/s to 95/s. Metric `meshtransit_map_snapshots_total{source="derived"}`.
- Less memory per control session: the MTCP record reader starts with a
  1 KiB buffer and grows only for a large record (it held 64 KiB per
  session), the browser-approval watcher starts only when an approval is
  pending (it was a goroutine and a ticker per session), and a stream of
  one Network reads its wakeup sources directly instead of through a
  forwarding goroutine. 2000 sessions: heap 212 MB to 104 MB, RSS 934 MB to
  563 MB, goroutines 10,016 to 6,016. `MESHTRANSIT_PROFILE_ADDRESS` serves
  pprof on loopback for operators.
- Cheap reconcile (scale-out S6): a reread of a Network's shared view that
  finds exactly the same Devices, policy and header keeps the previous
  objects, and a stream's periodic refresh first asks whether its snapshot
  still comes from that latest view (same objects, revision, policy
  revision, header and relay directory, no deadline near). If so it only
  moves to the latest connectivity, in O(1), instead of rebuilding the map;
  the Network is still read once per reconcile interval per replica, so
  changes that do not advance the revision are caught as before. Metric
  `meshtransit_map_snapshots_total{source="unchanged"}`.
- Peer limit (scale-out S6): a map carries at most
  `MESHTRANSIT_CONTROL_MAP_PEER_LIMIT` peers (default 10,000). A Device
  authorized for more receives explicit Device shares first, then peers
  online now, then a stable order; a change of the chosen peers at the same
  revision is sent as an authority delta. The delivery record keeps
  `peer_limit` (sent of authorized), the Devices page shows "Peers limited",
  and the policy preview (also when too large to preview Device by Device)
  returns `peer_estimate`: the largest number of peers one Device would see
  and how many Devices pass 5,000 and the limit, counted per rule side
  without expanding group rules. Connectivity reads for a map are batched,
  so a Device authorized for more than 10,000 peers no longer fails.
- Core scale-out, step S5 (scale-out): control replicas publish their
  MTCP session counts to a Redis registry (`meshtransit:v1:control:replicas`,
  expiry by Redis time); a replica above its fair share sheds a bounded
  number of sessions per step with Lifecycle RECONNECT and a jittered
  retry, so new replicas fill up and the load evens out. Shutdown tells
  every session to reconnect within `MESHTRANSIT_CONTROL_DRAIN_WINDOW`
  instead of all at once. `GET /scale/v1/sessions` on the health port
  answers the cluster total for KEDA's metrics-api scaler; the chart's
  `autoscaling.provider: keda` renders a ScaledObject (CPU, plus sessions
  for control) and leaves the replica count to the autoscaler. The session
  cap may go to 16384. The Redis ACL needs the registry key and `HGETALL`,
  `HDEL`. Scale test: 1000 sessions on one replica settle at 545/455 on
  two in 13 s with exactly 455 reconnects.
- Core scale-out, step S3: each control replica keeps one connectivity
  table per Network with streams, a persistent hash array mapped trie of
  Node to endpoints, home relay and presence, versioned with a bounded
  change log. One worker per Network reads a burst of wakeups from Redis in
  one call and wakes each stream once; a stream moves to the new version
  and builds its delta from the logged Nodes alone. A connectivity change
  costs one Redis read per replica and about 3 µs per stream regardless of
  the Network's size (was a full peer reread and map rebuild per stream,
  6 ms at 5000 peers before Redis). Tables are reread every reconcile
  interval and after a mailbox overflow to repair lost wakeups.
  `MESHTRANSIT_CONTROL_MAP_SHARED_CONNECTIVITY` (default true); metrics
  `meshtransit_map_connectivity_*`. Scale test at 2000 Devices, switch off
  vs on: connectivity fan-out p95 190 ms to 41 ms, Redis connectivity
  reads 266,870 to 5,180, stream opens 95/s to 540/s, process CPU 56 s to
  38 s, and no coalesced (possibly lost) wakeups.
- Core scale-out, step S4: a hostname family may hold 200,000 names (was
  1024); the outbox worker coalesces deliveries per Network and drains
  full batches back to back (batch 32, poll 200 ms); the Postgres pool
  waits for released connections on shutdown. Scale test at 2000 Devices
  in one Network: 26 registrations/s, revision p95 1.6 s.

### Fixed

- A Device registering into a Network with no free address was told to
  retry every two seconds, forever; it is now rejected (NOT_PERMITTED,
  "the Network has no free address") and meshd reports it.
- Rebalancing no longer moves sessions younger than 30 seconds: it could
  end a session in the middle of a registration, and move a node that had
  just arrived.

- meshd reported `control_session: synchronized` while Core was
  unreachable: the MTCP stream reconnects internally and kept the last map
  without telling the daemon. The stream now reports losing and regaining
  its control connection, and the status reads `reconnecting` meanwhile
  (the last map and the tunnels stay up; the daemon stays online).

- Core scale test findings (opt-in `TestRoleControlProcessScalesMapStreams`,
  `MESHTRANSIT_SCALE_SESSIONS=N`): address allocation scanned only the first
  256 addresses of a prefix (the candidate limit), so a Network stopped
  registering Devices at about 253 per prefix with a retryable "registration
  unavailable". Postgres now finds the lowest free address under the
  allocator lock and the search starts there. MTCP map stream ends are
  counted in `meshtransit_mtcp_map_stream_ends_total{reason}` and logged
  when control ended them (they were silent). Per-source MTCP handshake
  admission is configurable (`MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE`,
  `_BURST`; defaults 10/s, 50) for sites where many Devices share one NAT.
- Relay authority hardening (security review): Core rate limits relay
  endpoints per IPv4 address or IPv6 /64 and evicts the least recently seen
  source when its table is full, instead of refusing every new source for
  a minute (one host could lock relays out of revocations); a source holds
  at most four long polls; a data race on the signing window of Network
  maps and grants is gone; a connectivity-only map refresh never issues a
  new relay grant (the full refresh checks the Device first). The relay
  reads no session before its first relay state (bounded wait of 20 s),
  retries a failed poll after about a second instead of 20 s, and backs off
  on persistent UDP read errors.
- Relay failover review: a relay health snapshot naming a region the home
  selector had not been given yet stopped the whole meshd session; only the
  home region's loss triggers a discovery round; the failure hook is in
  place before the home region is dialled.
- A peer endpoint change no longer drops the node's relay grant: the
  connectivity-only reload rebuilt the snapshot without the grant, and the
  node then lost every relay until its next full refresh.
- Every response of the browser auth and management servers carries
  `Cache-Control: no-transform` (plus `no-store` when the handler set none),
  so a proxy in front never compresses responses holding secrets (BREACH).
  Inventory, distribution and session scope responses had no Cache-Control
  and were compressed by Cloudflare.
- Outbox events without a Network scope (identity, session, deployment and
  Workspace events) have no consumer and stayed pending forever, so the
  outbox backlog only grew. The worker role's new outbox-unrouted-retirer
  closes them every minute as `terminal` with error class `no_consumer`,
  keeping the rows; Network revision events are untouched.
- Control key expiry is observable: the control role exports
  `meshtransit_mtcp_control_key_not_after_timestamp_seconds` (latest key) and
  warns in its log 60 days ahead instead of 30.
- Control key rotation without re-enrolling Devices (mtcp-v1 §11). Core
  takes a next key (`MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE`,
  `MESHTRANSIT_CONTROL_MTCP_NEXT_KEY_NOT_AFTER`), lists it in `/mtcp/v1/key`
  and in every KeyUpdate, and answers handshakes made with it. meshd stores
  the announced next key in its encrypted identity record and switches to
  it when Core stops offering the current key, during a session or, after
  being offline, at its next connection. Records with a staged next key
  cannot be read by older meshd builds.

### Removed

- The legacy control protocol and the third-party protocol library it used
  (P6). Core's control listener (`core/internal/adapter/controllistener`)
  serves only MTCP v1 and the relay authority; other paths answer 404.
  MTCP is always on and needs `MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER`;
  `MESHTRANSIT_CONTROL_MTCP_ENABLED` may only be `true`, and
  `MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION`, `_PING_TIMEOUT` and
  `_WRITE_TIMEOUT` are refused. meshd speaks only MTCP:
  `--control-protocol` accepts `auto` or `mtcp`, and `legacy` is refused.
  STUN probes use `shared/stun` without a SOFTWARE attribute.
  `make check-boundaries` fails when go.mod requires a module missing from
  the reviewed allowlist `hack/allowed-modules.txt`.

## meshd (before the merge)

### Unreleased

### Added

- v0.1 release contract, platform priority, native validation matrix, and
  operating-system adapter boundaries.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Digest-bound CycloneDX SBOMs and symbol-aware Grype reports for Linux
  packages, with checksum-pinned tooling and a High/Critical CI gate.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder with hardened split-privilege
  systemd services and package lifecycle scripts.
- Debian service-state preservation across upgrade, removal, and reinstall,
  alternate-root-safe purge behavior, and disposable package lifecycle tests.
- Bounded Linux restart qualification for service, TUN, MeshTransit DNS, and dual-stack
  traffic recovery, with redacted machine-readable reports and parser fixtures.
- Bounded two-node Linux reboot qualification for service, route, identity,
  MeshTransit DNS, and dual-stack traffic recovery with explicit target confirmation.
- Linux route/link/address monitoring with bounded netlink event coalescing,
  polling fallback, immediate endpoint refresh, redacted status counters, and a
  reversible network-change qualification harness.
- Bounded Linux direct-path loss qualification with UDP-only peer isolation,
  measured relay fallback, dual-stack relay traffic proof, direct recovery, and
  automatic nftables cleanup.
- Linux host-policy qualification now records bounded `meshd` memory evidence
  and fails a phase if the service restarts on either node.
- WireGuard peer sessions now survive control-map endpoint-authority refreshes;
  stale direct selections return to the relay path without replacing the peer.
- Separate owner-writable runtime directories for the operator API and
  privileged-helper sockets.
- Initial daemon composition root.
- Atomic profile store with one-active-profile enforcement.
- Versioned local Unix-socket API for health, status, profile creation, listing, and selection.
- Initial architecture and security model.
- Pinned capability-142 adapter for bounded HTTPS control-key and authenticated Noise-handshake probes.
- BSD 3-Clause attribution for the compatibility dependency.
- Fail-closed Linux local API authorization based on kernel `SO_PEERCRED` credentials.
- Optional Linux socket-group authorization for kernel-verified local callers,
  plus service-account resolution for the privileged helper.
- Per-profile persistent machine/node identities with confined, atomic `0600` storage.
- Explicit control-key fingerprint pinning with Noise possession verification and no implicit rotation.
- Pinned Noise HTTP/2 registration, transient auth-key login, and persisted same-origin browser follow-up.
- Local API status fields and endpoints for control trust and registration.
- Pinned capability-142 network-map streaming with frame bounds, watchdog deadlines, and bounded jittered reconnect.
- Upstream-independent validated network snapshots with atomic delta updates and deny-by-default policy state.
- Control-session, netmap-revision, and peer-count status fields.
- Process-local aggregate runtime-recovery status for native fault qualification.
- Bounded, reversible Linux helper-socket fault qualification that requires
  in-process TUN and DNS recovery without a service restart.
- Fail-fast repeated Linux local-runtime recovery qualification with per-sample
  resource invariants, bounded kernel-resource convergence, and redacted
  nearest-rank p95 recovery timings; explicit peer routes and global self
  addresses are checked independently from address-derived kernel routes, and
  aggregate peer-count changes are classified as topology changes.
- Traffic-bearing Linux local-runtime recovery qualification with continuous
  IPv4, IPv6, and uncached MeshTransit DNS probes, mandatory outage observation,
  stable-recovery timing, and nested per-sample runtime/resource validation.

### Changed

- Authenticated direct paths now keep only their remaining proof lease across
  otherwise identical control-map revisions. Routine endpoint publications no
  longer force a relay fallback and immediate re-promotion, while lease expiry,
  socket changes, and peer or endpoint-authority changes still fail closed to
  the signed base path.
- Signed peer home-relay changes now replace the retained fallback metadata
  without overwriting a compatible authenticated direct endpoint. The existing
  proof deadline is unchanged, and expiry restores the newest signed relay
  base while identity, route, authority, socket, and topology changes retain
  fail-closed behavior.
- A temporary local map-application failure now tears down TUN, routes, DNS,
  path probes, and session secrets before the daemon retries from a fresh full
  snapshot. Recovery uses interruptible jittered exponential backoff capped at
  thirty seconds; a profile or registration change bypasses the wait, while
  permanent control trust and protocol failures remain blocked. An ambiguous
  cleanup exits the supervisor instead of reusing uncertain local state.
- Control-map reconnect backoff now resets only after a validated stream stays
  established for thirty seconds, preventing rapid map-then-disconnect loops
  from holding retries at the minimum delay. The watchdog and reconnect policy
  now have deterministic transport-fault coverage.
- Browser-login completion treats bounded transport timeouts, truncated
  exchanges, HTTP 408/425/429, and HTTP 5xx as temporary. Pending state is
  retained, both pending responses and temporary failures consume the
  three-second completion window to throttle retries, and caller cancellation
  still wins immediately. A verified response that races the poll deadline is
  persisted under the caller context instead of being discarded, temporary
  key copies are cleared after registration, and trust or protocol failures
  remain terminal.
- Control supervision now enforces one active runner per daemon service, and
  browser/auth-key registration transitions are serialized with cancellable
  waiting so concurrent local clients cannot create duplicate control sessions
  or reuse the same pending authorization concurrently.
- Linux host-credential provisioning and staged key rotation now tolerate an
  ambiguous return after directory synchronization: retries verify and accept
  the completed state without generating another key or deleting recovery
  material early.
- Top-level online status now reflects a synchronized control session even for
  a peerless Network; data-plane and DNS readiness remain separate fields.
- Compatible peer and policy changes now replace WireGuard peers, relay peer
  authority, and helper-confined host routes without recreating the TUN or UDP
  transport. The privileged route operation is bound to an interface opened by
  the same helper generation, requires unchanged self addresses, and rolls
  completed netlink changes back on failure. Live peer updates omit the private
  key and listen port so the userspace engine cannot rebind its socket.
- Peerless reduced maps now install an empty peer and route configuration while
  retaining the encrypted UDP presence transport. Socket-generation changes
  replace endpoint advertisements only after current-socket discovery, and
  periodic discovery pauses while no peers are visible. This prevents
  transient endpoint withdrawal from driving control-map and tunnel churn.
- Successful network-triggered endpoint refreshes are counted before their
  resulting endpoint update becomes observable.
- Semantically unchanged control-map deltas are revalidated without publishing
  a new local generation, avoiding unnecessary probe, data-plane, and DNS
  reconfiguration while preserving expiry enforcement and reconnect isolation.

## meshctl (before the merge)

### Unreleased

### Added

- `meshctl up`: one idempotent command that finds or creates the profile,
  activates it, pins the control key (built-in for MeshTransit Cloud) and
  registers, waiting for browser approval.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder and package inspection gate.
- Initial `status`, `version`, and profile commands.
- Versioned Unix-socket client with bounded JSON responses.
- Human-readable and JSON output modes.
- Stable usage and runtime exit-code separation.
- `doctor control` command for capability and control-key fingerprint checks.
- Explicit control-key trust with an operator-supplied SHA-256 fingerprint.
- Browser and standard-input auth-key login workflows.
- Bounded browser-login waiting with automatic completion, cancellation, and
  resumable timeout behavior.
- Control-trust, registration, and pinned-key status fields.
- Control-session, validated netmap-revision, and peer-count status output.
- Aggregate direct/relay path counts and redacted relay-region health.
- Aggregate host-network-change and completed endpoint-refresh status counters.
- Aggregate daemon runtime health in human-readable and JSON status output.
- Process-local runtime failure, completed recovery, and pending status with
  backward-compatible handling of older v1 daemons.
