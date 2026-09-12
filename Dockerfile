FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/xdauth-broker ./cmd/xdauth-broker
RUN CGO_ENABLED=0 go build -o /out/xdauth-pam ./cmd/xdauth-pam

FROM gcr.io/distroless/static-debian12:nonroot AS broker
COPY --from=build /out/xdauth-broker /xdauth-broker
ENTRYPOINT ["/xdauth-broker"]
