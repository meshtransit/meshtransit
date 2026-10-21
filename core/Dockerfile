# check=error=true

ARG VERSION=dev
ARG REVISION=unknown

FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build

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

# The DB-IP "IP to Country Lite" table (CC BY 4.0, IP Geolocation by DB-IP)
# that places Devices' public addresses in countries
# (MESHTRANSIT_GEOIP_COUNTRY_FILE). Pinned by digest; a new month's table is a
# new URL and digest.
FROM scratch AS geoip
ADD --checksum=sha256:097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80 \
    https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz /dbip-country-lite.csv.gz

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
COPY --from=geoip --chown=65532:65532 /dbip-country-lite.csv.gz /usr/share/meshtransit/dbip-country-lite.csv.gz

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER 65532:65532
EXPOSE 8081/tcp 8443/tcp

ENTRYPOINT ["/meshcore"]
