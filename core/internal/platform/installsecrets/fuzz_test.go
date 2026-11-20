package installsecrets

import (
	"bytes"
	"testing"
)

// A plan that parses resolves, and every resolved place is a valid Secret
// name and key.
func FuzzParsePlan(f *testing.F) {
	f.Add([]byte(`{"profile":"cloud","release":"r","fullname":"mt","features":["identity"],
		"secrets":{"control-noise":{"existingSecret":"mine","key":"noise.key"}},"allowNewRetainedKeys":["control-noise"]}`))
	f.Add([]byte(`{"profile":"selfhost","release":"r","fullname":"a"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		plan, err := ParsePlan(data)
		if err != nil {
			return
		}
		resolved, err := plan.Resolve()
		if err != nil {
			t.Fatalf("a parsed plan does not resolve: %v", err)
		}
		for _, entry := range resolved {
			if !secretName.MatchString(entry.SecretName) || len(entry.SecretName) > 253 ||
				!secretKey.MatchString(entry.SecretKey) {
				t.Fatalf("place %s/%s", entry.SecretName, entry.SecretKey)
			}
		}
	})
}

// Normalize never panics, never grows a value, and a normalized value
// stays valid.
func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{"privkey:" + string(bytes.Repeat([]byte("1"), 64)), "AAAA\n", "x\r\n"} {
		f.Add(uint8(KindControlKey), []byte(seed))
	}
	f.Fuzz(func(t *testing.T, kind uint8, value []byte) {
		normalized, err := Normalize(Kind(kind), value)
		if err != nil {
			return
		}
		if len(normalized) > len(value) {
			t.Fatal("normalize grew the value")
		}
		again, err := Normalize(Kind(kind), normalized)
		if err != nil && Kind(kind) != KindWrapKey {
			t.Fatalf("not stable: %v", err)
		}
		if err == nil && len(again) > len(normalized) {
			t.Fatal("normalize grew a normalized value")
		}
	})
}
