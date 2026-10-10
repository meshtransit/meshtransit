# Cloud public addresses

On AWS, GCP and Azure an instance's public IPv4 address is a 1:1 NAT in front
of its private address. The operating system never sees it, so it is not a
host candidate, and STUN finds it only while outbound UDP to a relay works.
The provider's instance metadata service knows it directly. meshd reads it
there and offers `publicIP:port` as a static candidate (`STATIC` in MTCP and
disco), with the WireGuard port: a 1:1 NAT keeps the port.

The implementation lives in `client/internal/cloudaddr`.

## Platforms

The platform is recognised once at start from the machine's DMI (SMBIOS)
fields under `/sys/class/dmi/id`. The metadata service is contacted only on a
recognised platform, never otherwise.

| Platform | Recognised by | Request |
|---|---|---|
| AWS | `sys_vendor` or `bios_vendor` "Amazon EC2", or "amazon" in `bios_version` (Xen) | IMDSv2: `PUT /latest/api/token` (60 s TTL), then `public-ipv4` and `ipv6` with the token |
| GCP | `sys_vendor` "Google" and `product_name` "Google Compute Engine" | `computeMetadata/v1/instance/network-interfaces/?recursive=true` with `Metadata-Flavor: Google`; the reply must carry the same header |
| Azure | `sys_vendor` "Microsoft Corporation" and Azure's chassis asset tag | `metadata/instance/network?api-version=2021-02-01` with `Metadata: true` |
| DigitalOcean | `sys_vendor` "DigitalOcean" | `metadata/v1/interfaces/public/0/ipv4/address` and `.../ipv6/address` |

Oracle Cloud does not publish an instance's public address in its metadata,
so it is not supported. A Hyper-V or VMware machine that is not on Azure has
no asset tag match and is never treated as Azure.

## Behaviour

- Lookups run when a control session starts, hourly, after network changes
  (at most once a minute), and after a failure (one minute, doubling up to
  ten).
- Every request goes to `169.254.169.254` over plain HTTP with a two-second
  timeout, no proxy, no redirects and a 64 KiB response limit. A 404 means the
  instance has no such address.
- Only public addresses are kept: global unicast, not private, shared
  (100.64.0.0/10) or link-local; at most eight.
- `--cloud-metadata=auto` (default) looks addresses up when the data plane runs
  on a recognised platform; `--cloud-metadata=off` never contacts the metadata
  service.
- `meshctl status` shows `Cloud:` with the platform and the number of public
  addresses; `meshctl netcheck` also lists them. `/v1/status` never includes
  the addresses, and logs carry only the platform, the count and error codes.

Unlike a port mapping, a metadata answer is not checked against STUN: the
service is reachable only from the instance and served by the provider's
hypervisor.

## Tests

Platform recognition from DMI fields; a fake metadata service per provider
that checks the IMDSv2 token flow and the GCP and Azure headers; 404 for an
instance without a public address; replies without `Metadata-Flavor`,
redirects and oversized bodies are rejected; address filtering; the watcher's
retry and network-change lookups; and the daemon publishing the addresses as
static candidates.
