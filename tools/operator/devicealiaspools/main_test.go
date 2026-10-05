package main

import "testing"

const (
	testDeployment = "01995d00-0000-7000-8000-000000000001"
	testActor      = "01995d00-0000-7000-8000-000000000011"
)

func TestParseOptionsAcceptsReferencePools(t *testing.T) {
	t.Parallel()
	opts, err := parseOptions(testDeployment, testActor,
		"198.18.0.0/16", "198.19.0.0/16", "fd02:48de:ec1b:1::/96", "fd02:48de:ec1b:2::/96")
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.pools) != 4 || opts.pools[0].purpose != purposeResource || opts.pools[1].purpose != purposeConsumer {
		t.Fatalf("pools = %+v", opts.pools)
	}
}

func TestParseOptionsRejectsUnsafePools(t *testing.T) {
	t.Parallel()
	valid := []string{"198.18.0.0/16", "198.19.0.0/16", "fd02:48de:ec1b:1::/96", "fd02:48de:ec1b:2::/96"}
	for _, test := range []struct {
		name  string
		index int
		value string
	}{
		{"non-canonical", 0, "198.18.0.1/16"},
		{"IPv4 too wide", 0, "10.0.0.0/7"},
		{"IPv4 too narrow", 1, "198.19.0.0/31"},
		{"IPv6 too wide", 2, "fd02:48de:ec1b::/48"},
		{"IPv6 in IPv4 slot", 0, "fd02:48de:ec1b:1::/96"},
		{"loopback", 0, "127.0.0.0/16"},
		{"multicast", 1, "224.1.0.0/16"},
		{"link-local IPv6", 2, "fe80::/96"},
		{"overlapping roles", 1, "198.18.128.0/17"},
		{"empty", 3, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := append([]string(nil), valid...)
			values[test.index] = test.value
			if _, err := parseOptions(testDeployment, testActor, values[0], values[1], values[2], values[3]); err == nil {
				t.Fatal("unsafe alias pool accepted")
			}
		})
	}
	if _, err := parseOptions("not-an-id", testActor, valid[0], valid[1], valid[2], valid[3]); err == nil {
		t.Fatal("invalid Deployment accepted")
	}
}

func TestConfigurationMatchesExactPools(t *testing.T) {
	t.Parallel()
	opts, err := parseOptions(testDeployment, testActor,
		"198.18.0.0/16", "198.19.0.0/16", "fd02:48de:ec1b:1::/96", "fd02:48de:ec1b:2::/96")
	if err != nil {
		t.Fatal(err)
	}
	existing := configuration{realm: true, pools: map[string]string{}}
	for _, pool := range opts.pools {
		existing.pools[pool.purpose+" "+pool.prefix.String()] = "active"
	}
	if !existing.matches(opts.pools) {
		t.Fatal("identical configuration not recognized")
	}
	delete(existing.pools, purposeConsumer+" 198.19.0.0/16")
	existing.pools[purposeConsumer+" 198.19.0.0/17"] = "active"
	if existing.matches(opts.pools) {
		t.Fatal("different configuration treated as identical")
	}
}
