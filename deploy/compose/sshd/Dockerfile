FROM golang:1.26-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpam0g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/xdauth-pam ./cmd/xdauth-pam
RUN CGO_ENABLED=1 go build -buildmode=c-shared -o /out/xdauth_pam.so ./cmd/xdauth-pam-native
# xdauth_pam.so is experimental and not used by default; see docs/native-pam-status.md and pam-sshd-native.

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server libpam-runtime && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd && useradd -m -s /bin/bash testuser

COPY --from=build /out/xdauth-pam /usr/local/bin/xdauth-pam
COPY --from=build /out/xdauth_pam.so /usr/local/lib/security/xdauth_pam.so
COPY deploy/compose/sshd/sshd_config /etc/ssh/sshd_config
COPY deploy/compose/sshd/pam-sshd /etc/pam.d/sshd
COPY deploy/compose/sshd/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
