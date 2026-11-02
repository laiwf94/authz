# syntax=docker/dockerfile:1
# Build from the repository root: docker build -f wicket/Dockerfile .
# The image runs "authz gateway". /wicket is a symlink to /authz, and a binary
# started as "wicket" is "authz gateway", so an entrypoint of /wicket, as in
# deployments written for the old image, starts the same gateway.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/authz \
 && ln -s authz /out/wicket

FROM gcr.io/distroless/static-debian12:nonroot
# Copying the directory keeps /wicket a symlink rather than a second binary.
COPY --from=build /out/ /
USER nonroot:nonroot
EXPOSE 4180
ENTRYPOINT ["/authz", "gateway"]
