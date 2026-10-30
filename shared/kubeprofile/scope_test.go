package kubeprofile

import "testing"

// developer is the design's example (K2 §5.1): workloads and logs in the
// rule's namespaces, reading namespaces and nodes cluster-wide.
func developer() Profile {
	return Profile{
		Name: "developer",
		Namespaced: []Rule{{
			APIGroups: []string{"", "apps", "batch"},
			Resources: []string{"pods", "pods/log", "deployments", "replicasets", "jobs", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		}},
		Cluster: []Rule{
			{APIGroups: []string{""}, Resources: []string{"namespaces", "nodes"}, Verbs: []string{"get", "list", "watch"}},
			{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
		},
	}
}

func scoped(t *testing.T, profile Profile, namespaces []string, clusterPart bool) Scope {
	t.Helper()
	scope, err := NewScope(profile, namespaces, clusterPart)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func inNamespace(verb, group, resource, subresource, namespace string) Attributes {
	return Attributes{ResourceRequest: true, Verb: verb, APIGroup: group, Resource: resource,
		Subresource: subresource, Namespace: namespace, Scope: ScopeNamespaced}
}

func clusterWide(verb, group, resource, subresource string) Attributes {
	return Attributes{ResourceRequest: true, Verb: verb, APIGroup: group, Resource: resource,
		Subresource: subresource, Scope: ScopeCluster}
}

// The namespaced part answers only in the rule's namespaces; the cluster
// part only for cluster-scoped resources and paths, and only when the rule
// turns it on (K2 §4, §5.3, Q197).
func TestScopeParts(t *testing.T) {
	t.Parallel()
	teamA := scoped(t, developer(), []string{"team-a", "team-a-stg"}, false)
	withCluster := scoped(t, developer(), []string{"team-a"}, true)
	everywhere := scoped(t, developer(), []string{"*"}, false)
	for name, test := range map[string]struct {
		scope      Scope
		attributes Attributes
		want       bool
	}{
		"in a namespace":              {teamA, inNamespace("delete", "apps", "deployments", "", "team-a"), true},
		"in the other namespace":      {teamA, inNamespace("get", "", "pods", "log", "team-a-stg"), true},
		"outside the namespaces":      {teamA, inNamespace("get", "", "pods", "", "team-b"), false},
		"not in the profile":          {teamA, inNamespace("get", "", "secrets", "", "team-a"), false},
		"every namespace":             {everywhere, inNamespace("get", "", "pods", "", "kube-system"), true},
		"cluster part off":            {teamA, clusterWide("list", "", "nodes", ""), false},
		"cluster part on":             {withCluster, clusterWide("list", "", "nodes", ""), true},
		"cluster part reads only":     {withCluster, clusterWide("delete", "", "nodes", ""), false},
		"a path, cluster part off":    {teamA, Attributes{Verb: "get", Path: "/metrics"}, false},
		"a path, cluster part on":     {withCluster, Attributes{Verb: "get", Path: "/metrics"}, true},
		"another path":                {withCluster, Attributes{Verb: "get", Path: "/logs/"}, false},
		"all namespaces, named":       {teamA, Attributes{ResourceRequest: true, Verb: "list", Resource: "pods", Scope: ScopeNamespaced}, false},
		"all namespaces, every":       {everywhere, Attributes{ResourceRequest: true, Verb: "list", Resource: "pods", Scope: ScopeNamespaced}, true},
		"all namespaces, watch":       {everywhere, Attributes{ResourceRequest: true, Verb: "watch", Resource: "pods", Scope: ScopeNamespaced}, true},
		"no namespace, not a list":    {everywhere, Attributes{ResourceRequest: true, Verb: "create", Resource: "pods", Scope: ScopeNamespaced}, false},
		"unknown scope, namespace":    {everywhere, Attributes{ResourceRequest: true, Verb: "get", Resource: "pods", Namespace: "team-a"}, false},
		"unknown scope, no namespace": {withCluster, Attributes{ResourceRequest: true, Verb: "list", Resource: "nodes"}, false},
		// A cluster-scoped resource never answers through the namespaced
		// part, even under a namespace path.
		"cluster resource in a namespace path": {teamA, Attributes{ResourceRequest: true, Verb: "get",
			Resource: "nodes", Namespace: "team-a", Scope: ScopeCluster}, false},
	} {
		if got := test.scope.Allows(test.attributes); got != test.want {
			t.Errorf("%s: Allows = %v, want %v", name, got, test.want)
		}
	}
}

// S1: exec, attach and port-forward need create whatever verb the request
// carries; S2: they, proxy and upgrades need their exact resource.
func TestScopeInteractive(t *testing.T) {
	t.Parallel()
	exact := Profile{Name: "oncall", Namespaced: []Rule{{APIGroups: []string{""},
		Resources: []string{"pods/exec", "pods/portforward", "services/proxy"}, Verbs: []string{"create", "get"}}}}
	getOnly := Profile{Name: "get-exec", Namespaced: []Rule{{APIGroups: []string{""},
		Resources: []string{"pods/exec"}, Verbs: []string{"get"}}}}
	wildcard := Profile{Name: "wild", Namespaced: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"},
		Verbs: []string{"*"}}}, Cluster: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	starGroup := Profile{Name: "star-group", Namespaced: []Rule{{APIGroups: []string{"*"},
		Resources: []string{"pods/exec"}, Verbs: []string{"create"}}}}
	starSlash := Profile{Name: "star-slash", Namespaced: []Rule{{APIGroups: []string{""},
		Resources: []string{"*/exec"}, Verbs: []string{"create"}}}}
	pods := Profile{Name: "pods", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"},
		Verbs: []string{"*"}}}}
	console := Profile{Name: "console", Namespaced: []Rule{{APIGroups: []string{"subresources.kubevirt.io"},
		Resources: []string{"virtualmachineinstances/console"}, Verbs: []string{"get"}}}}
	upgraded := func(attributes Attributes) Attributes {
		attributes.Upgrade = true
		return attributes
	}
	for name, test := range map[string]struct {
		profile    Profile
		attributes Attributes
		want       bool
	}{
		"exec by post":                  {exact, inNamespace("create", "", "pods", "exec", "team-a"), true},
		"exec by websocket get":         {exact, upgraded(inNamespace("get", "", "pods", "exec", "team-a")), true},
		"exec needs create":             {getOnly, upgraded(inNamespace("get", "", "pods", "exec", "team-a")), false},
		"port-forward":                  {exact, upgraded(inNamespace("get", "", "pods", "portforward", "team-a")), true},
		"attach not named":              {exact, inNamespace("create", "", "pods", "attach", "team-a"), false},
		"wildcard opens no exec":        {wildcard, inNamespace("create", "", "pods", "exec", "team-a"), false},
		"wildcard opens no proxy":       {wildcard, inNamespace("get", "", "services", "proxy", "team-a"), false},
		"wildcard opens no upgrade":     {wildcard, upgraded(inNamespace("get", "x.io", "things", "shell", "team-a")), false},
		"star group opens no exec":      {starGroup, inNamespace("create", "", "pods", "exec", "team-a"), false},
		"star slash opens no exec":      {starSlash, inNamespace("create", "", "pods", "exec", "team-a"), false},
		"pods open no exec":             {pods, inNamespace("create", "", "pods", "exec", "team-a"), false},
		"named proxy":                   {exact, inNamespace("get", "", "services", "proxy", "team-a"), true},
		"pods open no proxy verb":       {pods, inNamespace("proxy", "", "pods", "", "team-a"), false},
		"wildcard still reads pods":     {wildcard, inNamespace("get", "", "pods", "log", "team-a"), true},
		"named upgrade subresource":     {console, upgraded(inNamespace("get", "subresources.kubevirt.io", "virtualmachineinstances", "console", "team-a")), true},
		"wildcard opens no node proxy":  {wildcard, clusterWide("get", "", "nodes", "proxy"), false},
		"pods upgrade on main resource": {pods, upgraded(inNamespace("watch", "", "pods", "", "team-a")), true},
	} {
		scope := scoped(t, test.profile, []string{"team-a"}, true)
		if got := scope.Allows(test.attributes); got != test.want {
			t.Errorf("%s: Allows = %v, want %v", name, got, test.want)
		}
	}
}

// S3: a PUT to a main resource or an apply patch may create the object, so
// it needs create as well.
func TestScopeCreateThroughWrite(t *testing.T) {
	t.Parallel()
	updates := Profile{Name: "updates", Namespaced: []Rule{{APIGroups: []string{"apps"},
		Resources: []string{"deployments", "deployments/scale"}, Verbs: []string{"update", "patch"}}}}
	creates := Profile{Name: "creates", Namespaced: []Rule{{APIGroups: []string{"apps"},
		Resources: []string{"deployments"}, Verbs: []string{"update", "patch", "create"}}}}
	mayCreate := func(attributes Attributes) Attributes {
		attributes.MayCreate = true
		return attributes
	}
	for name, test := range map[string]struct {
		profile    Profile
		attributes Attributes
		want       bool
	}{
		"plain patch":            {updates, inNamespace("patch", "apps", "deployments", "", "team-a"), true},
		"apply without create":   {updates, mayCreate(inNamespace("patch", "apps", "deployments", "", "team-a")), false},
		"put without create":     {updates, mayCreate(inNamespace("update", "apps", "deployments", "", "team-a")), false},
		"apply with create":      {creates, mayCreate(inNamespace("patch", "apps", "deployments", "", "team-a")), true},
		"put to a subresource":   {updates, inNamespace("update", "apps", "deployments", "scale", "team-a"), true},
		"subresource never adds": {updates, mayCreate(inNamespace("update", "apps", "deployments", "scale", "team-a")), true},
	} {
		scope := scoped(t, test.profile, []string{"team-a"}, false)
		if got := scope.Allows(test.attributes); got != test.want {
			t.Errorf("%s: Allows = %v, want %v", name, got, test.want)
		}
	}
}

// S4: in the namespaced part a wildcard never reaches the namespace object;
// S6: in the cluster part a wildcard never writes what takes the cluster.
func TestScopeProtectedResources(t *testing.T) {
	t.Parallel()
	wildcard := Profile{Name: "wild", Namespaced: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"},
		Verbs: []string{"*"}}}, Cluster: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	named := Profile{Name: "named",
		Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "patch"}}},
		Cluster: []Rule{
			{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"create"}},
		}}
	own := func(verb, subresource string) Attributes {
		return Attributes{ResourceRequest: true, Verb: verb, Resource: "namespaces", Subresource: subresource,
			Namespace: "team-a", Name: "team-a", Scope: ScopeCluster}
	}
	for name, test := range map[string]struct {
		profile     Profile
		clusterPart bool
		attributes  Attributes
		want        bool
	}{
		// S4, the namespaced part alone.
		"wildcard reads no namespace":   {wildcard, false, own("get", ""), false},
		"named reads its namespace":     {named, false, own("get", ""), true},
		"named patches its namespace":   {named, false, own("patch", ""), true},
		"named does not finalize":       {named, false, own("update", "finalize"), false},
		"wildcard does not finalize":    {wildcard, false, own("update", "finalize"), false},
		"wildcard deletes no namespace": {wildcard, false, own("delete", ""), false},
		"wildcard still reads its pods": {wildcard, false, inNamespace("get", "", "pods", "", "team-a"), true},
		// The cluster part reads every namespace object, as a
		// ClusterRoleBinding would, but S6 keeps writes to named rules.
		"cluster part reads namespaces":     {wildcard, true, own("get", ""), true},
		"cluster part patches no namespace": {wildcard, true, own("patch", ""), false},
		"cluster part finalizes nothing":    {wildcard, true, own("update", "finalize"), false},
		"wildcard creates no namespace":     {wildcard, true, clusterWide("create", "", "namespaces", ""), false},
		"wildcard reads cluster roles":      {wildcard, true, clusterWide("list", "rbac.authorization.k8s.io", "clusterroles", ""), true},
		"wildcard writes no cluster role":   {wildcard, true, clusterWide("create", "rbac.authorization.k8s.io", "clusterroles", ""), false},
		"wildcard escalates no role":        {wildcard, true, clusterWide("escalate", "rbac.authorization.k8s.io", "clusterroles", ""), false},
		"wildcard writes no binding":        {wildcard, true, clusterWide("create", "rbac.authorization.k8s.io", "clusterrolebindings", ""), false},
		"wildcard writes no webhook":        {wildcard, true, clusterWide("create", "admissionregistration.k8s.io", "validatingwebhookconfigurations", ""), false},
		"wildcard writes no CRD":            {wildcard, true, clusterWide("delete", "apiextensions.k8s.io", "customresourcedefinitions", ""), false},
		"wildcard approves no CSR":          {wildcard, true, clusterWide("update", "certificates.k8s.io", "certificatesigningrequests", "approval"), false},
		"wildcard still writes nodes":       {wildcard, true, clusterWide("patch", "", "nodes", ""), true},
		"named creates a cluster role":      {named, true, clusterWide("create", "rbac.authorization.k8s.io", "clusterroles", ""), true},
		"named creates a namespace":         {named, true, clusterWide("create", "", "namespaces", ""), true},
	} {
		scope := scoped(t, test.profile, []string{"team-a"}, test.clusterPart)
		if got := scope.Allows(test.attributes); got != test.want {
			t.Errorf("%s: Allows = %v, want %v", name, got, test.want)
		}
	}
	// The namespace object answers the namespaced part only in a rule's own
	// namespace.
	other := scoped(t, named, []string{"team-b"}, false)
	if other.Allows(own("get", "")) {
		t.Error("team-b's rule read namespace team-a")
	}
}

// A grant without a profile is the whole group; grants of a group join (K2-I3).
func TestAllowsAny(t *testing.T) {
	t.Parallel()
	teamA := scoped(t, developer(), []string{"team-a"}, false)
	teamB := scoped(t, developer(), []string{"team-b"}, false)
	secret := inNamespace("get", "", "secrets", "", "team-a")
	for name, test := range map[string]struct {
		grants []Grant
		want   bool
	}{
		"none":                {nil, false},
		"full":                {[]Grant{{Full: true}}, true},
		"scoped refuses":      {[]Grant{{Scope: teamA}}, false},
		"scoped and full":     {[]Grant{{Scope: teamA}, {Full: true}}, true},
		"other team":          {[]Grant{{Scope: teamB}}, false},
		"empty scope refuses": {[]Grant{{}}, false},
	} {
		if got := AllowsAny(test.grants, secret); got != test.want {
			t.Errorf("%s: AllowsAny = %v, want %v", name, got, test.want)
		}
	}
	pod := inNamespace("get", "", "pods", "", "team-b")
	if !AllowsAny([]Grant{{Scope: teamA}, {Scope: teamB}}, pod) {
		t.Error("two teams' grants did not join")
	}
}

// A request the parser could not name, and the corners review K2a found.
func TestScopeCorners(t *testing.T) {
	t.Parallel()
	wildcard := Profile{Name: "wild", Namespaced: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"},
		Verbs: []string{"*"}}}, Cluster: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}}}}
	oncall := Profile{Name: "oncall",
		Namespaced: []Rule{
			{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"*"}, ResourceNames: []string{"web-0"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"proxy"}},
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"delete"}},
		},
		Cluster: []Rule{
			{APIGroups: []string{""}, Resources: []string{"persistentvolumes"}, Verbs: []string{"update", "patch"}},
			{NonResourceURLs: []string{"/stream"}, Verbs: []string{"get"}},
		}}
	upgraded := func(attributes Attributes) Attributes {
		attributes.Upgrade = true
		return attributes
	}
	mayCreate := func(attributes Attributes) Attributes {
		attributes.MayCreate = true
		return attributes
	}
	for name, test := range map[string]struct {
		profile    Profile
		namespaces []string
		attributes Attributes
		want       bool
	}{
		"empty verb":              {wildcard, []string{"*"}, inNamespace("", "", "pods", "", "team-a"), false},
		"empty resource":          {wildcard, []string{"*"}, inNamespace("get", "", "", "", "team-a"), false},
		"zero attributes":         {wildcard, []string{"*"}, Attributes{}, false},
		"empty path":              {wildcard, []string{"*"}, Attributes{Verb: "get"}, false},
		"scope out of range":      {wildcard, []string{"*"}, Attributes{ResourceRequest: true, Verb: "get", Resource: "pods", Namespace: "a", Scope: 3}, false},
		"star verb opens exec":    {oncall, []string{"team-a"}, named(inNamespace("create", "", "pods", "exec", "team-a"), "web-0"), true},
		"exec on another pod":     {oncall, []string{"team-a"}, named(inNamespace("create", "", "pods", "exec", "team-a"), "db-0"), false},
		"proxy verb named":        {oncall, []string{"team-a"}, inNamespace("proxy", "", "pods", "", "team-a"), true},
		"proxy verb as exec":      {oncall, []string{"team-a"}, inNamespace("proxy", "", "pods", "exec", "team-a"), false},
		"upgrade on a wild path":  {wildcard, []string{"*"}, upgraded(Attributes{Verb: "get", Path: "/stream"}), false},
		"upgrade on a named path": {oncall, []string{"*"}, upgraded(Attributes{Verb: "get", Path: "/stream"}), true},
		"wildcard writes no PV":   {wildcard, []string{"*"}, clusterWide("create", "", "persistentvolumes", ""), false},
		"named PV update":         {oncall, []string{"*"}, clusterWide("patch", "", "persistentvolumes", ""), true},
		"PV apply needs create":   {oncall, []string{"*"}, mayCreate(clusterWide("patch", "", "persistentvolumes", "")), false},
		"wildcard writes no apiservice": {wildcard, []string{"*"},
			clusterWide("create", "apiregistration.k8s.io", "apiservices", ""), false},
		"delete own namespace": {oncall, []string{"team-a"},
			Attributes{ResourceRequest: true, Verb: "delete", Resource: "namespaces", Namespace: "team-a", Name: "team-a", Scope: ScopeCluster}, true},
		"delete another through own": {oncall, []string{"team-a"},
			Attributes{ResourceRequest: true, Verb: "delete", Resource: "namespaces", Namespace: "team-a", Name: "kube-system", Scope: ScopeCluster}, false},
		"every namespace deletes kube-system": {oncall, []string{"*"},
			Attributes{ResourceRequest: true, Verb: "delete", Resource: "namespaces", Namespace: "kube-system", Name: "kube-system", Scope: ScopeCluster}, true},
	} {
		scope := scoped(t, test.profile, test.namespaces, true)
		if got := scope.Allows(test.attributes); got != test.want {
			t.Errorf("%s: Allows = %v, want %v", name, got, test.want)
		}
	}
}
