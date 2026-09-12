package saml

import (
	"context"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

func TestNew_RequiresBaseURL(t *testing.T) {
	_, err := New(context.Background(), Config{IDPMetadataXML: []byte("<x/>")})
	require.Error(t, err)
}

func TestNew_RequiresExactlyOneMetadataSource(t *testing.T) {
	_, err := New(context.Background(), Config{BaseURL: "https://broker.example"})
	require.Error(t, err, "neither IDPMetadataURL nor IDPMetadataXML set")

	_, err = New(context.Background(), Config{
		BaseURL:        "https://broker.example",
		IDPMetadataURL: "https://idp.example/metadata",
		IDPMetadataXML: []byte("<x/>"),
	})
	require.Error(t, err, "both set")
}

func minimalIDPMetadata() []byte {
	return []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)
}

func TestBeginLogin_SetsCorrelationAndReturnsRedirect(t *testing.T) {
	p, err := New(context.Background(), Config{
		BaseURL:        "https://broker.example",
		IDPMetadataXML: minimalIDPMetadata(),
	})
	require.NoError(t, err)

	sess := &store.Session{ID: "sess-123"}
	redirectURL, err := p.BeginLogin(sess)
	require.NoError(t, err)

	assert.NotEmpty(t, sess.SAMLRequestID)
	assert.Equal(t, "saml", sess.Protocol)
	assert.True(t, strings.HasPrefix(redirectURL, "https://idp.example/sso?"), "redirect must target the IdP's SSO endpoint: %s", redirectURL)
	assert.Contains(t, redirectURL, "SAMLRequest=")
	assert.Contains(t, redirectURL, "RelayState=sess-123")
}

func TestIdentityFromAssertion_DefaultsToNameID(t *testing.T) {
	assertion := &crewjamsaml.Assertion{
		ID:      "assertion-1",
		Subject: &crewjamsaml.Subject{NameID: &crewjamsaml.NameID{Value: "alice"}},
	}
	ident, err := identityFromAssertion(assertion, "")
	require.NoError(t, err)
	assert.Equal(t, "alice", ident.Value)
	assert.Equal(t, "alice", ident.Subject)
}

func TestIdentityFromAssertion_NoNameIDFailsClosed(t *testing.T) {
	_, err := identityFromAssertion(&crewjamsaml.Assertion{ID: "assertion-1"}, "")
	require.Error(t, err)
}

func TestIdentityFromAssertion_NamedAttribute(t *testing.T) {
	assertion := &crewjamsaml.Assertion{
		ID:      "assertion-1",
		Subject: &crewjamsaml.Subject{NameID: &crewjamsaml.NameID{Value: "alice@example.com"}},
		AttributeStatements: []crewjamsaml.AttributeStatement{{
			Attributes: []crewjamsaml.Attribute{
				{FriendlyName: "sAMAccountName", Values: []crewjamsaml.AttributeValue{{Value: "alice"}}},
				{Name: "groups", Values: []crewjamsaml.AttributeValue{{Value: "eng"}, {Value: "sre"}}},
			},
		}},
	}

	ident, err := identityFromAssertion(assertion, "sAMAccountName")
	require.NoError(t, err)
	assert.Equal(t, "alice", ident.Value, "should use the attribute, not the NameID, once configured")
	assert.Equal(t, "alice@example.com", ident.Subject, "Subject still reports the NameID regardless of IdentityAttribute")
	assert.Equal(t, "alice", ident.Claims["sAMAccountName"])
	assert.Equal(t, []string{"eng", "sre"}, ident.Claims["groups"], "multi-value attributes stay a slice")
}

func TestIdentityFromAssertion_MissingConfiguredAttributeFailsClosed(t *testing.T) {
	assertion := &crewjamsaml.Assertion{
		ID:      "assertion-1",
		Subject: &crewjamsaml.Subject{NameID: &crewjamsaml.NameID{Value: "alice"}},
	}
	_, err := identityFromAssertion(assertion, "sAMAccountName")
	require.Error(t, err, "a configured but absent attribute must fail closed, not silently fall back to NameID")
}
