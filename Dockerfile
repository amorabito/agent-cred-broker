# Multi-stage: static Go binary into a distroless nonroot base — no shell, no
# package manager, minimal attack surface for a credential chokepoint (ADR-0001).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/broker ./cmd/broker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/broker /broker
# 8443 = TLS API listener (agents); 8081 = health/metrics (scrapers only).
EXPOSE 8443 8081
USER nonroot:nonroot
ENTRYPOINT ["/broker"]
