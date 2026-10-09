package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

func privateIdentityLoginServiceTestOptions(t *testing.T) privateIdentityLoginServiceOptions {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"console.example.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	t.Cleanup(func() { clear(keyPEM) })
	return privateIdentityLoginServiceOptions{Address: "127.0.0.1:0", MaxConnections: 2,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), PrivateKeyPEM: keyPEM}
}

func TestComposePrivateIdentityLoginServiceUsesConcreteFactoryGraph(t *testing.T) {
	t.Parallel()
	fixture, factoryOptions, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, factoryOptions, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(factory.Close)
	options := privateIdentityLoginServiceTestOptions(t)
	service, err := composePrivateIdentityLoginService(factory, options)
	if err != nil || service == nil || service.Done() != nil {
		t.Fatal("concrete graph did not compose a dormant service")
	}
	if fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("serving composition substituted ports or performed effects")
	}
	for _, value := range []any{options, service} {
		if fmt.Sprint(value) != "[REDACTED]" {
			t.Fatal("serving composition disclosed resident profile")
		}
		text := fmt.Sprintf("%#v", value)
		if strings.Contains(text, options.Address) || strings.Contains(text, "PRIVATE KEY") {
			t.Fatal("detailed profile disclosed")
		}
		if body, err := json.Marshal(value); body != nil || err == nil {
			t.Fatal("serving composition serialized")
		}
		valuer, ok := value.(slog.LogValuer)
		if !ok || valuer.LogValue().String() != "[REDACTED]" {
			t.Fatal("structured composition disclosed")
		}
	}
}

func TestComposePrivateIdentityLoginServiceRejectsPartialFactory(t *testing.T) {
	t.Parallel()
	for _, factory := range []*privateIdentityFactory{nil, {}, {identity: &privateIdentity{}}} {
		if service, err := composePrivateIdentityLoginService(factory, privateIdentityLoginServiceTestOptions(t)); service != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
			t.Fatal("partial factory released serving ownership")
		}
	}
	fixture, factoryOptions, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, factoryOptions, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(factory.Close)
	options := privateIdentityLoginServiceTestOptions(t)
	options.Address = "224.0.0.1:443"
	if service, err := composePrivateIdentityLoginService(factory, options); service != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) || err.Error() != errInvalidPrivateIdentityComposition.Error() {
		t.Fatal("serving error reflected topology or released unsafe ownership")
	}
}
