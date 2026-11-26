# Exit Pools

An **Exit Pool** is a group of exit nodes: Devices that carry other Devices'
Internet traffic out through their own connection. A rule grants a source
the Internet through one pool. A Device then sends its Internet traffic into
the mesh only once its machine chooses the pool (root, or the machine's
operators group where root allows it), or lets the administrator choose it.

## The parts

- **Exit Pool.** A name and its exit nodes, in one Network
  (`…/networks/{network}/exit-pools`), with optional DNS upstreams for the
  pool's DNS forwarder.
- **Exit node.** A Linux Device of the Network's Workspace that root allowed
  to forward Internet traffic. In a **failover** pool Core elects one
  primary and moves every consumer when it fails; in a **spread** pool each
  consumer is given its own exit node among the healthy ones, so a pool
  carries more traffic as it grows.
- **Rule to an Exit Pool.** A source (a Device, Device Group, Identity Group
  or Device Tag) may use the pool, for a protocol and ports. Explain and the
  access graph show it as an `exit_pool` edge.

## Setting one up

1. **On each exit node**, as root, allow forwarding (Linux only): add
   `--enable-exit-node` to `MESHD_FLAGS`, restart `meshd`
   (`sudo systemctl restart meshd`), then:

   ```bash
   meshctl exit serve on
   ```

   The exit node forwards only to the Internet, never to private, link-local
   or other special ranges, the mesh or its own networks, whatever Core
   sends, and translates every source to its own address.
2. **In the Console**, create the Exit Pool in the Network, add the exit
   nodes, and choose failover or spread.
3. **Write a rule** from the people or Devices who should use it to the pool,
   and publish the policy.
4. **On each consumer**, choose the pool. On Linux:

   ```bash
   meshctl exit use POOL     # or: meshctl exit use auto
   meshctl exit status
   ```

   macOS, Windows and Android choose it in the app. On Linux,
   `meshctl routes exit-allow-managed on` lets the administrator choose the
   pool instead.

## What keeps it safe

- **Fail closed.** While a pool is chosen, the machine's Internet traffic
  goes into the mesh or nowhere, also while no exit node answers. What still
  leaves directly differs by platform (`meshd`'s own connections, DHCP,
  neighbour discovery, and attached LANs with `exit-allow-lan`); see the
  [Linux](../clients/linux.md#use-an-exit-node),
  [macOS](../clients/macos.md), [Windows](../clients/windows.md) and
  [Android](../clients/android.md) pages. On Android this holds while the app
  is off only with Android's Always-on VPN and Block connections without VPN.
- **DNS through the exit node.** The exit node's forwarder answers names;
  it never returns addresses of the exit node's own networks, refuses names
  no public resolver serves and logs no names.
- **Pinned exit nodes.** The exit nodes a pool has when a machine first uses
  it are pinned. One added later carries that machine's traffic only after
  its user approves it (`meshctl exit approve`), unless the machine follows
  managed pools.
- **Checked every 5 seconds.** On Linux, the helper compares its routes and
  kill switch with what it installed and puts them back if another program
  changed them.

The full behaviour is in [exit nodes on a consumer](../architecture/client.md#exit-nodes-on-a-consumer)
and in the [Linux client](../clients/linux.md#exit-node).

## Turning it on

Self-hosted deployments accept rules to Exit Pools only with
`MESHTRANSIT_EXIT_NODES_ENABLED`, and spread pools only with
`MESHTRANSIT_EXIT_SPREAD_ENABLED` ([configuration](../operations/configuration.md));
both are off by default.
