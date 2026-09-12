module github.com/rupivbluegreen/xdauth

go 1.24.0

require (
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/crewjam/saml v0.5.1 // internal/saml: SAML 2.0 service-provider support alongside OIDC, no maintained stdlib-only alternative
	github.com/go-chi/chi/v5 v5.1.0 // router named allowed by the MVP spec
	github.com/golang-jwt/jwt/v5 v5.2.1 // test-only: signs ID tokens for the fake OIDC provider in integration_test.go
	github.com/stretchr/testify v1.10.0 // test assertion library named allowed by the MVP spec
	golang.org/x/oauth2 v0.23.0
	golang.org/x/time v0.6.0 // token-bucket rate limiter for /auth/start (x/time/rate), avoids hand-rolling one
)

require (
	github.com/beevik/etree v1.6.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
