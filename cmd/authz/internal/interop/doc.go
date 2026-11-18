// Package interop holds the tests that run "authz gateway" against real
// identity providers instead of the fake one. They are built only with
// -tags interop and need the provider running: scripts/interop-keycloak.sh
// starts Keycloak with throwaway TLS certificates and runs them, and
// .github/workflows/interop.yml runs that script.
//
// keycloak_test.go provisions a realm through the Keycloak admin API with
// an OpenID Connect client that has a back-channel logout URL and a SAML
// client with a signing certificate and a single logout service, signs
// browsers in through Keycloak's own login pages, ends sessions at Keycloak
// and requires each matching gateway session to end within two seconds
// while the others stay signed in.
package interop
