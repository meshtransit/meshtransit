# Subnet router end to end

`client/internal/e2e/subnetrouter` routes real traffic through a subnet
router on a real Linux kernel, without Core:

- A hub network namespace bridges an underlay (a consumer and two routers)
  and a Site's LAN (both routers and a LAN host, `10.50.0.0/24`). The consumer
  has no route into the LAN but the mesh.
- Each node is the test binary run again in its own namespace. It starts the
  real helper (the netadmin server meshnetd runs) and the real WireGuard data
  plane, and applies the network map Core would send it: the consumer's Site
  route with its primary, the routers' served Site with masquerade and the
  routed rule that admits the consumer.
- The LAN host answers with the address that reached it, so the test sees
  which router (its masquerade address) the traffic went through.

`TestSubnetRouterE2E` checks that:

1. the consumer reaches the LAN host through the primary router;
2. after that router is killed and the map names the other one, traffic goes
   through the other router;
3. a Site no router serves is refused at once (ICMP unreachable), not left to
   time out or to leak out by another route.

`TestSubnetRouterBenchmark` sends to the LAN host for 5 seconds and times
500 one-byte round trips through a router. It fails only below 5 Mbit/s or
above a 100 ms p99, which only a broken path misses, and writes the
measurement as JSON to the file `MESHTRANSIT_E2E_BENCH` names.

Run both in a privileged container (Docker on Linux or a desktop VM):

```bash
make e2e-subnet-router
```

The measurement lands in `dist/subnet-router-bench.json`. CI runs the same
target and keeps the measurement as the `subnet-router-bench` artifact.

Not covered here: a consumer's own choice of another router (it needs path
probes between the nodes) and Core's election, which have their own unit and
integration tests.
