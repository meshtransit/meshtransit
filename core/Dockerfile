# check=error=true

ARG VERSION=dev
ARG REVISION=unknown

FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api ./api
COPY shared ./shared
COPY core/cmd ./core/cmd
COPY core/internal ./core/internal
COPY core/migrations ./core/migrations

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION

RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build \
    -buildvcs=false \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -X meshtransit.net/core/internal/platform/buildinfo.version=$VERSION -X meshtransit.net/core/internal/platform/buildinfo.revision=$REVISION" \
    -o /out/meshcore \
    ./core/cmd/meshcore

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
COPY --chown=65532:65532 core/LICENSE /licenses/LICENSE
COPY --chown=65532:65532 COMMERCIAL-LICENSING.md /licenses/COMMERCIAL-LICENSING.md
COPY --chown=65532:65532 core/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER 65532:65532
EXPOSE 8081/tcp 8443/tcp

ENTRYPOINT ["/meshcore"]
