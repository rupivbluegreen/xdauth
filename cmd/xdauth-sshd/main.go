// Command xdauth-sshd is a minimal example SSH server that authenticates every connection through xdauth via keyboard-interactive.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/xdauth/pkg/client"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	os.Exit(run())
}

func run() int {
	listenAddr := flag.String("listen", envOr("XDAUTH_SSHD_LISTEN_ADDR", ":2323"), "address to listen on (env XDAUTH_SSHD_LISTEN_ADDR)")
	brokerURL := flag.String("broker-url", os.Getenv("XDAUTH_BROKER_URL"), "xdauth broker base URL (env XDAUTH_BROKER_URL)")
	hostKeyFile := flag.String("host-key-file", os.Getenv("XDAUTH_SSHD_HOST_KEY_FILE"), "path to an SSH host private key; an ephemeral ed25519 key is generated if unset (env XDAUTH_SSHD_HOST_KEY_FILE)")
	shellMessage := flag.String("shell-message", envOr("XDAUTH_SSHD_SHELL_MESSAGE", "xdauth-sshd: this is a demo shell, authenticated via keyboard-interactive."), "message printed in the demo session (env XDAUTH_SSHD_SHELL_MESSAGE)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if *brokerURL == "" {
		fmt.Fprintln(os.Stderr, "xdauth-sshd: --broker-url is required")
		return 2
	}

	hostKey, err := loadOrGenerateHostKey(*hostKeyFile)
	if err != nil {
		logger.Error("host key", "error", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	config := newServerConfig(ctx, *brokerURL, logger)
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Error("listen", "error", err)
		return 1
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	logger.Info("xdauth-sshd starting", "addr", *listenAddr, "broker_url", *brokerURL)
	serve(ctx, listener, config, *shellMessage, logger)
	return 0
}

// loadOrGenerateHostKey reads a host key from disk, or generates a fresh in-memory ed25519 key for the life of this process.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read host key file: %w", err)
		}
		return ssh.ParsePrivateKey(keyBytes)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("wrap ephemeral host key: %w", err)
	}
	return signer, nil
}

// newServerConfig wires keyboard-interactive as the only accepted auth method, mirroring the PAM demo's no-password posture.
func newServerConfig(ctx context.Context, brokerURL string, logger *slog.Logger) *ssh.ServerConfig {
	return &ssh.ServerConfig{
		KeyboardInteractiveCallback: keyboardInteractiveAuth(ctx, brokerURL, logger),
	}
}

// keyboardInteractiveAuth runs the xdauth flow inline: the challenge() call below IS the wire write, sent before Poll ever blocks.
func keyboardInteractiveAuth(ctx context.Context, brokerURL string, logger *slog.Logger) func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		loginHint := conn.User()
		clientHost := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(clientHost); err == nil {
			clientHost = host
		}

		sess, err := client.Start(ctx, client.StartRequest{
			BrokerURL:  brokerURL,
			LoginHint:  loginHint,
			ClientKind: "ssh",
			ClientHost: clientHost,
		})
		if err != nil {
			logger.Error("start sign-in", "user", loginHint, "error", err)
			return nil, fmt.Errorf("xdauth-sshd: could not start sign-in: %w", err)
		}

		instruction := fmt.Sprintf("xdauth: to finish signing in, visit:\n\n  %s\n\nand enter the code: %s\n\nwaiting for approval...\n", sess.VerificationURI, sess.UserCode)
		// this call sends the prompt over the SSH connection right now: no exec'd helper, no stdout pipe, no relay to buffer or delay it.
		if _, err := challenge("", instruction, nil, nil); err != nil {
			return nil, fmt.Errorf("xdauth-sshd: keyboard-interactive challenge: %w", err)
		}

		result, err := client.Poll(ctx, sess)
		if err != nil {
			logger.Error("poll for approval", "user", loginHint, "error", err)
			return nil, fmt.Errorf("xdauth-sshd: could not poll for approval: %w", err)
		}

		if result.Status != "approved" {
			logger.Warn("sign-in not approved", "user", loginHint, "status", result.Status)
			return nil, fmt.Errorf("xdauth-sshd: sign-in %s", result.Status)
		}

		logger.Info("sign-in approved", "user", loginHint, "identity", result.Artifact.Identity)
		return &ssh.Permissions{Extensions: map[string]string{"xdauth-identity": result.Artifact.Identity}}, nil
	}
}

// serve accepts connections until ctx is done; each connection is handled on its own goroutine.
func serve(ctx context.Context, listener net.Listener, config *ssh.ServerConfig, shellMessage string, logger *slog.Logger) {
	for {
		nConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Error("accept", "error", err)
				return
			}
		}
		go handleConn(nConn, config, shellMessage, logger)
	}
}

// handleConn runs the SSH handshake (which drives the keyboard-interactive auth above) and then serves session channels.
func handleConn(nConn net.Conn, config *ssh.ServerConfig, shellMessage string, logger *slog.Logger) {
	defer nConn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		logger.Warn("handshake failed", "remote", nConn.RemoteAddr().String(), "error", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported in this demo")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Warn("accept channel", "error", err)
			continue
		}
		go serveSession(channel, requests, shellMessage, sshConn.Permissions)
	}
}

// serveSession is a trivial demo shell: it prints a message identifying the approved user and exits.
func serveSession(channel ssh.Channel, requests <-chan *ssh.Request, shellMessage string, perms *ssh.Permissions) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "shell", "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			identity := ""
			if perms != nil {
				identity = perms.Extensions["xdauth-identity"]
			}
			fmt.Fprintf(channel, "%s\nlogged in as: %s\n", shellMessage, identity)
			return
		case "pty-req":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}
