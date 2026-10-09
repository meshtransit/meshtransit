# check=error=true

ARG VERSION=dev
ARG REVISION=unknown

FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY shared ./shared
COPY relay/cmd ./relay/cmd
COPY relay/internal ./relay/internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION

RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build \
    -buildvcs=false \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION -X main.commit=$REVISION" \
    -o /out/meshrelay \
    ./relay/cmd/meshrelay

# Let the non-root relay bind 443 without running as root: the file
# capability survives into the scratch image and needs no other privilege.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libcap2-bin >/dev/null \
    && setcap cap_net_bind_service=+ep /out/meshrelay \
    && getcap /out/meshrelay

FROM scratch

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="MeshTransit Interchange" \
      org.opencontainers.image.description="MeshTransit relay (meshrelay)" \
      org.opencontainers.image.source="https://github.com/meshtransit/meshtransit" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=build --chown=65532:65532 /out/meshrelay /meshrelay
COPY --chown=65532:65532 relay/LICENSE /licenses/LICENSE
COPY --chown=65532:65532 COMMERCIAL-LICENSING.md /licenses/COMMERCIAL-LICENSING.md
COPY --chown=65532:65532 relay/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md

USER 65532:65532
# MTRP UDP, STUN, STUN alternate port and TLS/WebSocket (with --tls); admin
# (metrics) stays on localhost unless --admin says otherwise.
EXPOSE 3479/udp 3478/udp 3480/udp 443/tcp

ENTRYPOINT ["/meshrelay"]
CMD ["serve"]
