package installsecrets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/shared/key"
)

func TestItemsFollowFeatures(t *testing.T) {
	t.Parallel()
	base, err := Items(ProfileCloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	all, err := Items(ProfileCloud, []Feature{FeatureIdentity, FeatureConnectionLogs, FeatureKubernetesCA,
		FeatureEntitlement})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(catalog) || len(base) != len(catalog)-5 {
		t.Fatalf("items: base %d, all %d, catalog %d", len(base), len(all), len(catalog))
	}
	if all[0].Login != "mesh_migrator" {
		t.Fatal("the migrator's login comes first")
	}
	if _, err := Items("compose", nil); !errors.Is(err, ErrPlan) {
		t.Fatalf("unknown profile: %v", err)
	}
	if _, err := Items(ProfileCloud, []Feature{"relay"}); !errors.Is(err, ErrPlan) {
		t.Fatalf("unknown feature: %v", err)
	}
}

// Every item has a valid ID, its default Secret name is a valid object
// name for the longest fullname, and the retained keys are exactly the
// keys whose loss breaks clients, relays, stored digests, wrapped data or
// an entitlement.
func TestCatalogNames(t *testing.T) {
	t.Parallel()
	longest := strings.Repeat("a", 63)
	retained := []string{}
	for _, item := range catalog {
		if !ValidID(item.ID) || !secretKey.MatchString(item.Key) {
			t.Fatalf("item %+v", item)
		}
		name := SecretName(longest, item)
		if len(name) > 253 || !secretName.MatchString(name) {
			t.Fatalf("Secret name %q", name)
		}
		if item.Retained {
			retained = append(retained, item.Key)
		}
		if item.Public != PublicNone && item.Kind != KindKey {
			t.Fatalf("%s: a public half needs a seed", item.ID)
		}
	}
	if strings.Join(retained, ",") != "noise.key,enrollment-digest.key,relay-signing.key,subject-active.key,wrap-key,installation.seed" {
		t.Fatalf("retained = %v", retained)
	}
}

func TestGenerateMatchesNormalize(t *testing.T) {
	t.Parallel()
	for _, kind := range []Kind{KindLoginPassword, KindRedisPassword, KindKey, KindWrapKey, KindClientSecret, KindControlKey, KindBrowserKey} {
		value, err := Generate(kind, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := Normalize(kind, append(bytes.Clone(value), '\n'))
		if err != nil || !bytes.Equal(normalized, value) {
			t.Fatalf("kind %d: %q, %v", kind, normalized, err)
		}
	}
	if _, err := Generate(Kind(99), rand.Reader); !errors.Is(err, ErrPlan) {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestNormalizeRefuses(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{7}, 32)
	for name, test := range map[string]struct {
		kind  Kind
		value string
	}{
		"empty":               {KindLoginPassword, ""},
		"short password":      {KindLoginPassword, "abc"},
		"quote in password":   {KindLoginPassword, strings.Repeat("a'", 20)},
		"space in password":   {KindRedisPassword, strings.Repeat("a ", 20)},
		"padded key":          {KindKey, base64.URLEncoding.EncodeToString(seed)},
		"standard key":        {KindKey, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))},
		"short key":           {KindKey, base64.RawURLEncoding.EncodeToString(seed[:16])},
		"client secret short": {KindClientSecret, strings.Repeat("A", 31)},
		"client secret lines": {KindClientSecret, strings.Repeat("A", 32) + "\nB"},
		"two newlines":        {KindKey, base64.RawURLEncoding.EncodeToString(seed) + "\n\n"},
		"zero key":            {KindKey, base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		"zero wrap key":       {KindWrapKey, base64.StdEncoding.EncodeToString(make([]byte, 32))},
		"zero browser key":    {KindBrowserKey, base64.StdEncoding.EncodeToString(make([]byte, 32))},
		"zero control key":    {KindControlKey, "privkey:" + strings.Repeat("0", 64)},
		"client secret space": {KindClientSecret, strings.Repeat("a", 31) + " b"},
		"client secret utf8":  {KindClientSecret, strings.Repeat("a", 31) + "é"},
		"browser key newline": {KindBrowserKey, base64.StdEncoding.EncodeToString(seed)[:20] + "\n" +
			base64.StdEncoding.EncodeToString(seed)[20:]},
		"control key prefix": {KindControlKey, "nodekey:" + strings.Repeat("0", 64)},
		"browser key short":  {KindBrowserKey, base64.StdEncoding.EncodeToString(seed[:16])},
		"wrap key short":     {KindWrapKey, base64.StdEncoding.EncodeToString(seed[:31])},
	} {
		if _, err := Normalize(test.kind, []byte(test.value)); !errors.Is(err, ErrValue) {
			t.Errorf("%s: Normalize() = %v", name, err)
		}
	}
	// What Core's readers accept from a hand-made Secret passes.
	for name, test := range map[string]struct {
		kind  Kind
		value string
	}{
		"openssl wrap key":          {KindWrapKey, base64.StdEncoding.EncodeToString(seed) + "\n"},
		"login password with \"":    {KindLoginPassword, strings.Repeat("a\"", 20)},
		"redis password with quote": {KindRedisPassword, strings.Repeat(`a'\`, 12)},
		"alphanumeric client":       {KindClientSecret, strings.Repeat("Ab9", 15)},
		"windows line ending":       {KindKey, base64.RawURLEncoding.EncodeToString(seed) + "\r\n"},
		"LF then CRLF":              {KindKey, base64.RawURLEncoding.EncodeToString(seed) + "\n\r\n"},
	} {
		if _, err := Normalize(test.kind, []byte(test.value)); err != nil {
			t.Errorf("%s: Normalize() = %v", name, err)
		}
	}
}

func TestPublicHalves(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{9}, 32)
	value := []byte(base64.RawURLEncoding.EncodeToString(seed))
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	signing, err := key.SigningPrivateFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		public Public
		want   string
	}{
		{PublicRelaySigning, signing.Public().String()},
		{PublicFlowLogSigning, base64.RawURLEncoding.EncodeToString(public)},
		{PublicInstallation, base64.StdEncoding.EncodeToString(public)},
	} {
		got, err := PublicHalf(Item{ID: "x", Kind: KindKey, Public: test.public}, value)
		if err != nil || got != test.want {
			t.Fatalf("%s: %q, %v", test.public, got, err)
		}
	}
	if _, err := PublicHalf(Item{ID: "x", Kind: KindKey}, value); !errors.Is(err, ErrPlan) {
		t.Fatalf("no public half: %v", err)
	}
}

func TestParsePlan(t *testing.T) {
	t.Parallel()
	plan, err := ParsePlan([]byte(`{"profile":"cloud","release":"meshtransit-core","fullname":"meshtransit-core","features":["identity"],"allowNewRetainedKeys":["control-noise"],
		"secrets":{"control-noise":{"existingSecret":"meshtransit-control-identity","key":"noise.key"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePlan([]byte(`{"profile":"cloud","release":"r","fullname":"a",
		"login":{"issuer":"https://id.example.test/oauth2","oidcClientID":"meshcore-bff"}}`)); err != nil {
		t.Fatalf("login plan: %v", err)
	}
	resolved, err := plan.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range resolved {
		switch entry.ID {
		case "control-noise":
			if !entry.BYO || entry.SecretName != "meshtransit-control-identity" || entry.SecretKey != "noise.key" {
				t.Fatalf("override: %+v", entry)
			}
		case "login-mesh-runtime":
			if entry.BYO || entry.SecretName != "meshtransit-core-login-mesh-runtime" || entry.SecretKey != "password" {
				t.Fatalf("default: %+v", entry)
			}
		}
	}
	for name, text := range map[string]string{ //nolint:gosec // G101 false positive: plan JSON, no secret.
		"unknown field":      `{"profile":"cloud","release":"r","fullname":"a","extra":1}`,
		"bad fullname":       `{"profile":"cloud","fullname":"A_b"}`,
		"unknown item":       `{"profile":"cloud","release":"r","fullname":"a","secrets":{"nope":{"existingSecret":"s","key":"k"}}}`,
		"feature off":        `{"profile":"cloud","release":"r","fullname":"a","secrets":{"kube-ca-wrap-key":{"existingSecret":"s","key":"k"}}}`,
		"bad secret name":    `{"profile":"cloud","release":"r","fullname":"a","secrets":{"capture":{"existingSecret":"S","key":"k"}}}`,
		"bad key":            `{"profile":"cloud","release":"r","fullname":"a","secrets":{"capture":{"existingSecret":"s","key":"a/b"}}}`,
		"trailing":           `{"profile":"cloud","release":"r","fullname":"a"} {}`,
		"shared place":       `{"profile":"cloud","release":"r","fullname":"a","secrets":{"capture":{"existingSecret":"s","key":"k"},"initiation":{"existingSecret":"s","key":"k"}}}`,
		"unknown profile":    `{"profile":"compose","release":"r","fullname":"a"}`,
		"login http issuer":  `{"profile":"cloud","release":"r","fullname":"a","login":{"issuer":"http://id.example.test","oidcClientID":"c"}}`,
		"login client space": `{"profile":"cloud","release":"r","fullname":"a","login":{"issuer":"https://id.example.test","oidcClientID":"a b"}}`,
		"no release":         `{"profile":"cloud","fullname":"a"}`,
		"allow unretained":   `{"profile":"cloud","release":"r","fullname":"a","allowNewRetainedKeys":["capture"]}`,
		"allow feature off":  `{"profile":"cloud","release":"r","fullname":"a","allowNewRetainedKeys":["kube-ca-wrap-key"]}`,
		"unknown redis mode": `{"profile":"cloud","release":"r","fullname":"a","redisMode":"cluster"}`,
		"provider users made by the bootstrap": `{"profile":"cloud","release":"r","fullname":"a","redisMode":"providerUsers",
			"secrets":{"redis-api":{"existingSecret":"r","key":"api"},"redis-control":{"existingSecret":"r","key":"control"}}}`,
		"single with a role password": `{"profile":"cloud","release":"r","fullname":"a","redisMode":"single",
			"secrets":{"redis-api":{"existingSecret":"r","key":"api"}}}`,
	} {
		if _, err := ParsePlan([]byte(text)); !errors.Is(err, ErrPlan) {
			t.Errorf("%s: ParsePlan() = %v", name, err)
		}
	}
}

func TestRedisModes(t *testing.T) {
	t.Parallel()
	redisItems := func(text string) map[string]bool {
		t.Helper()
		plan, err := ParsePlan([]byte(text))
		if err != nil {
			t.Fatalf("ParsePlan(%s) = %v", text, err)
		}
		resolved, err := plan.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, entry := range resolved {
			if entry.Kind == KindRedisPassword {
				found[entry.ID] = entry.BYO
			}
		}
		return found
	}
	// The default makes every role's password.
	for _, text := range []string{
		`{"profile":"cloud","release":"r","fullname":"a"}`,
		`{"profile":"cloud","release":"r","fullname":"a","redisMode":"aclPerRole"}`,
	} {
		if got := redisItems(text); len(got) != 3 || got["redis-api"] || got["redis-control"] || got["redis-worker"] {
			t.Errorf("%s: redis items %v, want three made by the bootstrap", text, got)
		}
	}
	// Provider users: the installer's three Secrets, never made.
	got := redisItems(`{"profile":"cloud","release":"r","fullname":"a","redisMode":"providerUsers","secrets":{
		"redis-api":{"existingSecret":"r","key":"api"},"redis-control":{"existingSecret":"r","key":"control"},
		"redis-worker":{"existingSecret":"r","key":"worker"}}}`)
	if len(got) != 3 || !got["redis-api"] || !got["redis-control"] || !got["redis-worker"] {
		t.Errorf("providerUsers: redis items %v, want three of the installer's", got)
	}
	// Single: no role passwords; the one user's password is the installer's
	// Secret, checked like any BYO item.
	if got := redisItems(`{"profile":"cloud","release":"r","fullname":"a","redisMode":"single",
		"secrets":{"redis-single":{"existingSecret":"auth","key":"password"}}}`); len(got) != 1 || !got["redis-single"] {
		t.Errorf("single: redis items %v, want only the installer's redis-single", got)
	}
	for name, text := range map[string]string{ //nolint:gosec // plan documents naming Secrets, no secret value
		"single without its Secret": `{"profile":"cloud","release":"r","fullname":"a","redisMode":"single"}`,
		"single sharing a place": `{"profile":"cloud","release":"r","fullname":"a","redisMode":"single","secrets":{
			"redis-single":{"existingSecret":"s","key":"k"},"login-mesh-runtime":{"existingSecret":"s","key":"k"}}}`,
		"redis-single in another mode": `{"profile":"cloud","release":"r","fullname":"a",
			"secrets":{"redis-single":{"existingSecret":"s","key":"k"}}}`,
	} {
		if _, err := ParsePlan([]byte(text)); !errors.Is(err, ErrPlan) {
			t.Errorf("%s: ParsePlan() = %v", name, err)
		}
	}
}
