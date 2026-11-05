# Fortik container image (Phase 6). Multi-stage: build with the Go toolchain
# (cgo: the SQL classifier links libpg_query), run from distroless base
# (glibc, no shell, no package manager) as a non-root user. The console is embedded in
# the binary (internal/console/dist); the policy bundle ships in the image.
#
#   docker build -t fortik:dev .
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY migrations migrations
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/fortik ./cmd/fortik

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/fortik /usr/local/bin/fortik
COPY policies /etc/fortik/policies
# 65532 = nonroot in distroless; the root filesystem can be read-only (state
# lives in Postgres, secrets in the mounted secret store, the fail spool in
# /var/lib/fortik/spool).
USER 65532:65532
EXPOSE 8443 8090 6432 9091
ENTRYPOINT ["/usr/local/bin/fortik"]
CMD ["serve", "-config", "/etc/fortik/fortik.yaml"]
