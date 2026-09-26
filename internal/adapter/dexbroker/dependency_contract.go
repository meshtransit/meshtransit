//go:build dexbroker

package dexbroker

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dexidp/dex/connector"
	dexoidc "github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage"
	dexsql "github.com/dexidp/dex/storage/sql"
)

var _ http.Handler = (*server.Server)(nil)
var _ func(context.Context, server.Config) (*server.Server, error) = server.NewServer
var _ interface{ Done() <-chan struct{} } = (*server.Server)(nil)
var _ interface {
	Start(context.Context) <-chan struct{}
} = (signer.Signer)(nil)
var _ func(context.Context, *slog.Logger) (dexsql.PreparedPostgresStorage, error) = (&dexsql.Postgres{}).OpenWithPreparedSchema
var _ func(string, *slog.Logger, *http.Client) (connector.Connector, error) = (&dexoidc.Config{}).OpenWithHTTPClient
var _ = server.Config{
	Issuer:               "https://issuer.invalid/dex",
	Storage:              nil,
	Signer:               nil,
	ConnectorHTTPClients: map[string]*http.Client{},
}
var _ = storage.Claims{UserID: "dependency-contract", AuthTime: 1}
