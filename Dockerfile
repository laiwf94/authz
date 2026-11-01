# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/authz

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/authz /authz
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/authz"]
CMD ["serve"]
