package selfhost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// RFC 7677 §3's exchange (user "user", password "pencil"): a verifier is
// right when its ServerKey signs the exchange as the server did and its
// StoredKey checks the client's proof.
func TestSCRAMVerifierMatchesRFC7677(t *testing.T) {
	t.Parallel()
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	verifier, err := scramVerifierWithSalt([]byte("pencil"), salt)
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.SplitN(strings.SplitN(verifier, "$", 3)[2], ":", 2)
	storedKey, _ := base64.StdEncoding.DecodeString(keys[0])
	serverKey, _ := base64.StdEncoding.DecodeString(keys[1])
	const nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	authMessage := "n=user,r=rOprNGfwEbeRWgbNEkqO," + "r=" + nonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=" + nonce
	mac := func(key []byte) []byte {
		hash := hmac.New(sha256.New, key)
		hash.Write([]byte(authMessage))
		return hash.Sum(nil)
	}
	if got := base64.StdEncoding.EncodeToString(mac(serverKey)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("server signature = %s", got)
	}
	proof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	signature := mac(storedKey)
	clientKey := make([]byte, len(proof))
	for index := range proof {
		clientKey[index] = proof[index] ^ signature[index]
	}
	if digest := sha256.Sum256(clientKey); !hmac.Equal(digest[:], storedKey) {
		t.Fatal("the client's proof does not check against StoredKey")
	}
}

func TestDatastoreFilesHoldNoPassword(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	init := string(readFile(t, dir, "postgres-init.sql"))
	acl := string(readFile(t, dir, "redis-users.acl"))
	for _, name := range []string{"postgres-migrator-password", "postgres-runtime-password", "postgres-worker-password",
		"identity-migrator-password", "identity-runtime-password", "redis-password"} {
		password := string(readFile(t, dir, name))
		if strings.Contains(init, password) || strings.Contains(acl, password) {
			t.Fatalf("%s appears in a datastore file", name)
		}
	}
	if strings.Count(init, "PASSWORD 'SCRAM-SHA-256$4096:") != 5 ||
		!strings.Contains(init, "CREATE DATABASE meshtransit OWNER mesh_migrator;") ||
		!strings.Contains(init, "CREATE EXTENSION btree_gist;") {
		t.Fatalf("init SQL = %s", init)
	}
	if !strings.HasPrefix(acl, "user default off\nuser meshtransit on #") || !strings.Contains(acl, "-@all +ping") {
		t.Fatalf("ACL = %s", acl)
	}
}
