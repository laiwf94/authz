# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# /wicket is a symlink to /authz: a binary started as "wicket" is
# "authz gateway", so images and scripts written for wicket keep working.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/authz \
 && ln -s authz /out/wicket

FROM gcr.io/distroless/static-debian12:nonroot
# Copying the directory keeps /wicket a symlink rather than a second binary.
COPY --from=build /out/ /
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/authz"]
CMD ["serve"]
