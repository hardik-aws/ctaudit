# Build a static ctaudit binary, then copy it into a distroless image that
# runs as a non-root user and already carries a CA bundle.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /ctaudit ./cmd/ctaudit

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ctaudit /ctaudit
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ctaudit"]
