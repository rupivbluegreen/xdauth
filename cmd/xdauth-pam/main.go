// Command xdauth-pam is a pam_exec helper: it runs the xdauth flow for PAM_USER and fails closed on any error.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rupivbluegreen/xdauth/pkg/client"
)

func main() {
	os.Exit(run())
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "xdauth-pam: "+format+"\n", args...)
	return 1
}

// run reads the broker URL from argv[1] first: sshd strips its own daemon environment before
// invoking PAM, so XDAUTH_BROKER_URL is rarely visible here even when set on the sshd process.
func run() int {
	brokerURL := os.Getenv("XDAUTH_BROKER_URL")
	if len(os.Args) > 1 {
		brokerURL = os.Args[1]
	}
	loginHint := os.Getenv("PAM_USER")
	clientHost := os.Getenv("PAM_RHOST")
	if clientHost == "" {
		clientHost, _ = os.Hostname()
	}

	if brokerURL == "" {
		return fail("broker URL not set: pass it as argv[1] in pam.d (recommended) or set XDAUTH_BROKER_URL")
	}
	if loginHint == "" {
		return fail("PAM_USER is not set; this must be run from pam_exec")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sess, err := client.Start(ctx, client.StartRequest{
		BrokerURL:  brokerURL,
		LoginHint:  loginHint,
		ClientKind: "ssh",
		ClientHost: clientHost,
	})
	if err != nil {
		return fail("could not start sign-in: %v", err)
	}

	fmt.Printf("xdauth: to finish signing in, visit:\n\n  %s\n\nand enter the code: %s\n\n", sess.VerificationURI, sess.UserCode)
	fmt.Println("xdauth: waiting for approval...")

	result, err := client.Poll(ctx, sess)
	if err != nil {
		return fail("could not poll for approval: %v", err)
	}

	switch result.Status {
	case "approved":
		fmt.Println("xdauth: approved.")
		return 0
	case "denied":
		return fail("sign-in denied")
	case "expired":
		return fail("sign-in expired before approval")
	default:
		return fail("unexpected status %q", result.Status)
	}
}
