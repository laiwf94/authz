# syntax=docker/dockerfile:1
# toolgate is part of the root module and runs as `authz mcp`; build from the
# repository root:
#   docker build -f toolgate/Dockerfile .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/authz \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
# One binary: the gateway is `authz mcp`, the fake upstream `authz mcpfake`.
COPY --from=build /out/authz /authz
# Audit log and tool pins live here; owned by nonroot so a fresh volume is writable.
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot:nonroot
ENV TOOLGATE_ADDR=0.0.0.0:8080
EXPOSE 8080 8081
ENTRYPOINT ["/authz", "mcp"]
