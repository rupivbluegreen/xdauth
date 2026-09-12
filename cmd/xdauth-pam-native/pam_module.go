// Package main is a native PAM module: it calls the PAM conversation function in-process, unlike pam_exec, so messages are never delayed by a relay.
package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdlib.h>

// declared here, not via pam_modules.h, since that header's pam_sm_* prototypes clash with cgo's own export prototypes below.
extern int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);

// sends one PAM_TEXT_INFO message and discards the reply, avoiding cgo marshaling of C function pointers and struct arrays.
static int send_info_message(const struct pam_conv *conv, const char *text) {
	struct pam_message msg;
	msg.msg_style = PAM_TEXT_INFO;
	msg.msg = text;
	const struct pam_message *msgp = &msg;
	struct pam_response *resp = NULL;
	int ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
	if (resp != NULL) {
		if (resp[0].resp != NULL) {
			free(resp[0].resp);
		}
		free(resp);
	}
	return ret;
}
*/
import "C"

import (
	"context"
	"time"
	"unsafe"

	"github.com/rupivbluegreen/xdauth/pkg/client"
)

// sessionTimeout bounds how long a login blocks waiting for approval; must not exceed sshd's own LoginGraceTime.
const sessionTimeout = 3 * time.Minute

// KNOWN ISSUE: outbound HTTP from this function has hung indefinitely in one containerized OpenSSH test environment even to a bare TCP dial with no DNS involved; not yet root-caused, unconfirmed whether it reproduces outside Docker. See docs/gossh-server.md for the alternative, fully verified approach.
//
//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	brokerURL := moduleArg(argc, argv, 0)
	if brokerURL == "" {
		return C.PAM_AUTH_ERR
	}

	var cUser *C.char
	if C.pam_get_user(pamh, &cUser, nil) != C.PAM_SUCCESS || cUser == nil {
		return C.PAM_AUTH_ERR
	}
	loginHint := C.GoString(cUser)

	var convPtr unsafe.Pointer
	if C.pam_get_item(pamh, C.PAM_CONV, &convPtr) != C.PAM_SUCCESS || convPtr == nil {
		return C.PAM_AUTH_ERR
	}
	conv := (*C.struct_pam_conv)(convPtr)

	clientHost := envItem(pamh, C.PAM_RHOST)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	sess, err := client.Start(ctx, client.StartRequest{
		BrokerURL:  brokerURL,
		LoginHint:  loginHint,
		ClientKind: "ssh",
		ClientHost: clientHost,
	})
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	msg := "xdauth: to finish signing in, visit " + sess.VerificationURI + " and enter the code: " + sess.UserCode
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	if C.send_info_message(conv, cMsg) != C.PAM_SUCCESS {
		return C.PAM_AUTH_ERR
	}

	result, err := client.Poll(ctx, sess)
	if err != nil || result.Status != "approved" {
		return C.PAM_AUTH_ERR
	}
	return C.PAM_SUCCESS
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

// moduleArg returns the i-th pam.d module argument, or "" if argc/argv don't cover it.
func moduleArg(argc C.int, argv **C.char, i int) string {
	if i >= int(argc) {
		return ""
	}
	entries := unsafe.Slice(argv, int(argc))
	return C.GoString(entries[i])
}

// envItem reads a PAM item (e.g. PAM_RHOST) as a Go string, "" if unset.
func envItem(pamh *C.pam_handle_t, item C.int) string {
	var p unsafe.Pointer
	if C.pam_get_item(pamh, item, &p) != C.PAM_SUCCESS || p == nil {
		return ""
	}
	return C.GoString((*C.char)(p))
}

func main() {}
