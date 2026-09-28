package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

const qualificationConnectTimeout = 5 * time.Second

func openAdminDatabase(ctx context.Context, database databaseSettings) (*pgx.Conn, error) {
	if ctx == nil || database.address == "" || database.database == "" || database.user == "" {
		return nil, errInvalidInput
	}
	password, err := database.passwordFile.Read()
	if err != nil {
		return nil, errors.New("read postgres admin password")
	}
	caPEM, err := database.trustFile.Read()
	if err != nil {
		return nil, errors.New("read postgres trust bundle")
	}
	host, portValue, err := net.SplitHostPort(database.address)
	if err != nil || host == "" {
		return nil, errInvalidInput
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return nil, errInvalidInput
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, errInvalidInput
	}
	configuration, err := pgx.ParseConfig(
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable",
	)
	if err != nil {
		return nil, fmt.Errorf("parse safe postgres configuration: %w", err)
	}
	configuration.Host = host
	configuration.Port = uint16(port)
	configuration.Database = database.database
	configuration.User = database.user
	configuration.Password = password
	configuration.ConnectTimeout = qualificationConnectTimeout
	configuration.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: host,
	}
	configuration.Fallbacks = nil
	configuration.RequireAuth = "scram-sha-256"
	configuration.RuntimeParams["application_name"] =
		"meshtransit-qualification-providertransition"
	connection, err := pgx.ConnectConfig(ctx, configuration)
	if err != nil {
		return nil, fmt.Errorf("open qualification postgres connection: %w", err)
	}
	return connection, nil
}
