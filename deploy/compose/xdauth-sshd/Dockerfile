FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/xdauth-sshd ./cmd/xdauth-sshd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/xdauth-sshd /usr/local/bin/xdauth-sshd
EXPOSE 2323
ENTRYPOINT ["/usr/local/bin/xdauth-sshd"]
