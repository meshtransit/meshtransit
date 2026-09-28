# check=error=true

ARG VERSION=dev
ARG REVISION=unknown

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION

RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build \
    -buildvcs=false \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -X github.com/meshtransit/meshtransit/internal/buildinfo.version=$VERSION -X github.com/meshtransit/meshtransit/internal/buildinfo.revision=$REVISION" \
    -o /out/meshcore \
    ./cmd/meshcore

FROM scratch

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="MeshTransit Core" \
      org.opencontainers.image.description="MeshTransit control-plane runtime" \
      org.opencontainers.image.source="https://github.com/meshtransit/meshtransit" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=build --chown=65532:65532 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/meshcore /meshcore
COPY --chown=65532:65532 LICENSE /licenses/LICENSE
COPY --chown=65532:65532 COMMERCIAL-LICENSING.md /licenses/COMMERCIAL-LICENSING.md
COPY --chown=65532:65532 THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER 65532:65532
EXPOSE 8081/tcp 8443/tcp

ENTRYPOINT ["/meshcore"]
