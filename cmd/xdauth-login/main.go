// Command xdauth-login is a minimal reference CLI built on pkg/client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rupivbluegreen/xdauth/pkg/client"
)

func main() {
	os.Exit(run())
}

func run() int {
	brokerURL := flag.String("broker-url", os.Getenv("XDAUTH_BROKER_URL"), "xdauth broker base URL (or set XDAUTH_BROKER_URL)")
	loginHint := flag.String("login-hint", "", "the identity you expect to authenticate as")
	clientHost, _ := os.Hostname()
	host := flag.String("client-host", clientHost, "hostname reported to the approval page")
	flag.Parse()

	if *brokerURL == "" || *loginHint == "" {
		fmt.Fprintln(os.Stderr, "usage: xdauth-login --broker-url URL --login-hint USER")
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sess, err := client.Start(ctx, client.StartRequest{
		BrokerURL:  *brokerURL,
		LoginHint:  *loginHint,
		ClientKind: "cli",
		ClientHost: *host,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdauth-login: start failed:", err)
		return 1
	}

	fmt.Printf("To sign in, visit:\n\n  %s\n\nand enter the code: %s\n\n", sess.VerificationURI, sess.UserCode)
	fmt.Printf("Waiting for approval (expires in %s)...\n", sess.ExpiresIn)

	result, err := client.Poll(ctx, sess)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdauth-login: poll failed:", err)
		return 1
	}

	switch result.Status {
	case "approved":
		out, _ := json.MarshalIndent(result.Artifact, "", "  ")
		fmt.Println(string(out))
		return 0
	case "denied":
		fmt.Fprintln(os.Stderr, "xdauth-login: sign-in denied")
		return 1
	case "expired":
		fmt.Fprintln(os.Stderr, "xdauth-login: sign-in expired before approval")
		return 1
	}
	return 0
}
