# syntax=docker/dockerfile:1
# toolgate is part of the root module and runs as `authz mcp`; build from the
# repository root:
#   docker build -f toolgate/Dockerfile .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# /out/root becomes the image root. toolgate and mcpfake are links to the
# one binary, which runs as `authz mcp` and `authz mcpfake` under those
# names, so `--entrypoint /toolgate` and `--entrypoint /mcpfake` from the
# old image keep working.
RUN mkdir -p /out/root /out/data \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/root/authz ./cmd/authz \
 && ln -s authz /out/root/toolgate \
 && ln -s authz /out/root/mcpfake

FROM gcr.io/distroless/static-debian12:nonroot
# One binary: the gateway is `authz mcp`, the fake upstream `authz mcpfake`.
# Copying the directory keeps /toolgate and /mcpfake symlinks rather than
# second copies of the binary.
COPY --from=build /out/root/ /
# Audit log and tool pins live here; owned by nonroot so a fresh volume is writable.
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot:nonroot
ENV TOOLGATE_ADDR=0.0.0.0:8080
EXPOSE 8080 8081
ENTRYPOINT ["/authz", "mcp"]
