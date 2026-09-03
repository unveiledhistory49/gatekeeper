# Build: docker build -t gatekeeper .
# Run:   docker run -p 8080:8080 -e GATEKEEPER_DATABASE_URL=sqlite://./data/gatekeeper.db gatekeeper
#
# No HEALTHCHECK here: the CLI has no `health` subcommand
# (subcommands: provision-org, create-user, serve, migrate, verify-audit),
# and debian:bookworm-slim ships neither curl nor wget. Probe /healthz
# from the orchestrator instead (see docker-compose.yml).

FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/gatekeeper ./cmd/gatekeeper

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 -d /app gatekeeper
WORKDIR /app
COPY --from=build /app/gatekeeper /app/gatekeeper
USER gatekeeper
EXPOSE 8080
ENTRYPOINT ["/app/gatekeeper"]
CMD ["serve"]
