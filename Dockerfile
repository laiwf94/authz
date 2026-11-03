# syntax=docker/dockerfile:1
# The authz image: one static binary on distroless, run as nonroot.
#
#   docker build -t authz .
#   docker build --build-arg VERSION=v0.1.0 -t authz:v0.1.0 .
#
# Both base images are pinned by digest so the image, and its size, change
# only when this file does. The size is measured by scripts/image-size.go and
# held under the limit in bench/image-baseline.json by the "Image size" step
# in ci.yml; the baseline recorded there is the starting point for the week 5
# benchmark gate.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
# Modules first, so a source change does not download them again.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is what "authz version" prints; without it the binary reports
# (devel). The build stage has no git, so the source revision is not stamped.
ARG VERSION=
# /out/root becomes the image root. /wicket is a symlink to /authz: a binary
# started as "wicket" is "authz gateway", so images and scripts written for
# wicket keep working. /out/data becomes /data, owned by nonroot, so
# GRANTD_DATA_DIR=/data works on a fresh volume.
RUN mkdir -p /out/root /out/data \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/root/authz ./cmd/authz \
 && ln -s authz /out/root/wicket

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# Copying the directory keeps /wicket a symlink rather than a second binary.
COPY --from=build /out/root/ /
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/authz"]
CMD ["serve"]
