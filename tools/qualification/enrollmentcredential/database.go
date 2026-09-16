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

func openAdminDatabase(
	ctx context.Context,
	database databaseSettings,
) (*pgx.Conn, error) {
	if ctx == nil || database.database == "" || database.user == "" ||
		(database.address == "") == (database.unixSocket == "") {
		return nil, errInvalidInput
	}
	config, err := pgx.ParseConfig(
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable",
	)
	if err != nil {
		return nil, fmt.Errorf("parse safe postgres configuration: %w", err)
	}
	config.Database = database.database
	config.User = database.user
	config.ConnectTimeout = qualificationConnectTimeout
	if database.unixSocket != "" {
		config.Host = database.unixSocket
		config.TLSConfig = nil
	} else {
		password, readErr := database.passwordFile.Read()
		if readErr != nil {
			return nil, errors.New("read postgres admin password")
		}
		caPEM, readErr := database.trustFile.Read()
		if readErr != nil {
			return nil, errors.New("read postgres trust bundle")
		}
		host, portValue, splitErr := net.SplitHostPort(database.address)
		if splitErr != nil || host == "" {
			return nil, errInvalidInput
		}
		port, parseErr := strconv.ParseUint(portValue, 10, 16)
		if parseErr != nil || port == 0 {
			return nil, errInvalidInput
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caPEM) {
			return nil, errInvalidInput
		}
		config.Host = host
		config.Port = uint16(port)
		config.Password = password
		config.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			ServerName: host,
		}
	}
	config.RuntimeParams["application_name"] = "meshtransit-qualification-enrollmentcredential"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open qualification postgres connection: %w", err)
	}
	return connection, nil
}
