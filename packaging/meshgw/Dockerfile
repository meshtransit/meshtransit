# check=error=true

# The MeshTransit Kubernetes gateway (k8s-gateway-plan §4.2 W7). Build from
# the meshcore root:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f packaging/meshgw/Dockerfile -t <registry>/meshgw:<tag> .

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY shared ./shared
COPY api ./api
COPY client/cmd/meshgw ./client/cmd/meshgw
COPY client/internal ./client/internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION
ARG BUILD_DATE

RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build \
    -buildvcs=false \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -X meshtransit.net/client/internal/version.Version=$VERSION -X meshtransit.net/client/internal/version.Commit=$REVISION -X meshtransit.net/client/internal/version.Date=$BUILD_DATE" \
    -o /out/meshgw \
    ./client/cmd/meshgw

# Every state directory lives under this, an emptyDir in the pod; the image
# carries it owned by the gateway's user for runs without one.
RUN mkdir -p /out/var/lib/meshgw && chown -R 65532:65532 /out/var/lib/meshgw

FROM scratch

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="MeshTransit Kubernetes gateway" \
      org.opencontainers.image.description="MeshTransit userspace mesh gateway for Kubernetes (meshgw)" \
      org.opencontainers.image.source="https://github.com/meshtransit/meshtransit" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

# CA roots: Core and the relays are reached over HTTPS.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/meshgw /meshgw
COPY --from=build --chown=65532:65532 /out/var/lib/meshgw /var/lib/meshgw
COPY client/LICENSE /licenses/LICENSE
COPY client/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
COPY client/third_party/licenses /licenses/third_party

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# The encrypted path's UDP port and the probes; kubectl's port is inside
# the userspace stack, not the pod's.
USER 65532:65532
EXPOSE 41641/udp 9090/tcp

ENTRYPOINT ["/meshgw"]
