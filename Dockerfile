FROM golang:1.23-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/buildtrace ./cmd/buildtrace

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/buildtrace /usr/local/bin/buildtrace
ENTRYPOINT ["/usr/local/bin/buildtrace"]
CMD ["version"]
