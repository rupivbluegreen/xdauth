package broker

import (
	"html/template"

	"github.com/rupivbluegreen/xdauth/web"
)

// templates is parsed once so tests can render pages without constructing a Broker.
var templates *template.Template

func init() {
	var err error
	templates, err = template.ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		panic("xdauth/internal/broker: parse embedded templates: " + err.Error())
	}
}

// approvePage is the data approve.html renders; see templates_test.go for check 3 (context always shown).
type approvePage struct {
	Identity       string
	ClientHost     string
	ClientKind     string
	ClientIP       string
	VerifiedClient string // non-empty iff ClientAuthenticator verified the caller
	StartedAt      string
	CSRFToken      string
	ApproveAction  string
}

type resultPage struct {
	Title   string
	Message string
}
