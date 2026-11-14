FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/buildtrace ./cmd/buildtrace

FROM alpine:3.23
# Manifest capture shells out to git; verification itself stays offline and
# needs only the static binary. Keep the runtime unprivileged in both cases.
RUN apk add --no-cache git ca-certificates
COPY --from=build /out/buildtrace /usr/local/bin/buildtrace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/buildtrace"]
CMD ["version"]
