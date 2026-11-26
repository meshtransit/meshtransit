# Sites

A **Site** is an address space behind the mesh, such as an office LAN or a
cloud VPC, that Devices reach through one or more **routers**. The hosts in a
Site run no client: a router Device forwards the traffic it is allowed to
forward, and a rule decides who may send it.

## The parts

- **Site.** A name and its IPv4 and IPv6 prefixes, in one Network. It is
  managed with the `route.approve` and `route.withdraw` permissions
  (`…/networks/{network}/sites`).
- **Router.** A Linux Device of the Network's Workspace that offers all the
  Site's prefixes. A Site has up to 32 routers, each with a priority; Core
  elects one of them the **primary**, and every node sends the Site's traffic
  through it.
- **Rule to a Site.** A source (a Device, Device Group, Identity Group or
  Device Tag) may reach the Site's prefixes, or only some of them, on a
  protocol and ports. Nothing reaches a Site without such a rule.

## Setting one up

1. **On the router**, as root, let `meshd` forward and offer the subnet
   (Linux only): add `--enable-subnet-router` to `MESHD_FLAGS`, restart
   `meshd` (`sudo systemctl restart meshd`), then:

   ```bash
   sudo /usr/libexec/meshtransit/meshnetd routes router-mode on
   sudo /usr/libexec/meshtransit/meshnetd routes advertise 10.20.0.0/16
   ```

   Offering grants nothing. Core can never turn a host into a router: the
   host forwards only into what root offered and Core serves.
2. **In the Console**, create the Site in the Network with its prefixes,
   and add the router Device. For failover, add a second router with a higher
   priority number (Sites with masquerade only).
3. **Write a rule** from the people or Devices who need the Site to the Site,
   and publish the policy.
4. **On each consumer**, accept subnet routes once (Linux, macOS and
   Windows); nothing is installed until then:

   ```bash
   meshctl routes accept on
   ```

   On Linux and macOS it takes root or the machine's operators group, on
   Windows an administrator; see the [Linux](../clients/linux.md#subnet-routes),
   [macOS](../clients/macos.md) and [Windows](../clients/windows.md) pages.

## Failover

Core checks every router about every 10 seconds and at once when a router
reports a Site failed. A router that fails its probes, stops reporting,
is draining or can no longer serve is replaced by the next usable router in
priority order; stopping `meshd` on a router moves its Sites within a second
or two. A node that stops hearing from the primary while another router
still answers moves on its own until Core elects again. Each change is kept
in the Site's history of primary changes.

The full behaviour, with every limit and error, is in
[rules to Sites](policy.md#rules-to-sites) and
[routers and failover](policy.md#routers-and-failover).

## What keeps it safe

- The router's own settings live in a file only root writes, and it forwards
  only into prefixes that root offered and Core serves.
- Hosts in a Site can answer connections that Devices open, but can never
  open a connection into the mesh.
- With masquerade (the default) the Site's hosts see the router's own
  address; allow that address, not the whole Internet, in any firewall in
  front of them.
- A consumer never lets a Site take over its own network or a mesh address,
  and `meshd`'s own sockets never enter the mesh they carry.

How a client installs and checks the routes is in
[subnet routes](../architecture/client.md#subnet-routes) and
[subnet routers](../architecture/client.md#subnet-routers).

## Turning it on

Self-hosted deployments enable Sites with `MESHTRANSIT_SUBNET_ROUTES_ENABLED`
([configuration](../operations/configuration.md)); it is off by default.
