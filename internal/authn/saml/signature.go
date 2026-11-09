package saml

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Algorithms accepted in signatures. SHA-1 based methods and inclusive or
// "WithComments" canonicalization are refused.
var (
	allowedSignatureMethods = map[string]bool{
		dsig.RSASHA256SignatureMethod:   true,
		dsig.RSASHA384SignatureMethod:   true,
		dsig.RSASHA512SignatureMethod:   true,
		dsig.ECDSASHA256SignatureMethod: true,
		dsig.ECDSASHA384SignatureMethod: true,
		dsig.ECDSASHA512SignatureMethod: true,
	}
	allowedDigests = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
	excC14N   = string(dsig.CanonicalXML10ExclusiveAlgorithmId)
	enveloped = string(dsig.EnvelopedSignatureAltorithmId)
)

var errNoSignature = errors.New("not signed")

// wrappingError marks a structural signature problem: the shape signature
// wrapping attacks produce (extra signatures, duplicate IDs, a Reference to
// some other element).
type wrappingError struct{ msg string }

func (e *wrappingError) Error() string { return e.msg }

// verifySigned checks the enveloped signature that is a direct child of el
// and returns the element rebuilt from exactly the bytes the signature
// covers. Callers must use only the returned element: it is the defense
// against signature wrapping, where a verifier checks one element and the
// application reads another (Somorovsky et al., "On Breaking SAML: Be
// Whoever You Want to Be").
//
// Before handing the element to goxmldsig, the signature is held to a strict
// shape: one Reference, pointing at el's own ID, that ID unique in the whole
// document, only enveloped-signature and exclusive canonicalization
// transforms, and SHA-2 algorithms.
func verifySigned(root, el *etree.Element, certs []*x509.Certificate, now time.Time) (*etree.Element, error) {
	sigs := children(el, NSDSig, "Signature")
	if len(sigs) == 0 {
		return nil, errNoSignature
	}
	if len(sigs) > 1 {
		return nil, &wrappingError{"more than one signature on the element"}
	}
	id := attr(el, "ID")
	if !idRe.MatchString(id) {
		return nil, errors.New("signed element has no valid ID")
	}
	if n := countID(root, id); n != 1 {
		return nil, &wrappingError{fmt.Sprintf("ID %q appears %d times", id, n)}
	}
	if err := checkSignedInfo(sigs[0], id); err != nil {
		return nil, err
	}
	// Copy the element together with the namespace declarations it
	// inherits, so canonicalization sees the same context the signer did.
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	// Certificate lifetimes are checked at the assertion's now, the same
	// instant every other validity check uses.
	vc.Clock = dsig.NewFakeClockAt(now)
	verified, err := vc.Validate(detached)
	if err != nil {
		return nil, fmt.Errorf("signature invalid: %v", err)
	}
	if verified.Tag != el.Tag || verified.NamespaceURI() != el.NamespaceURI() || attr(verified, "ID") != id {
		return nil, &wrappingError{"signed content is not the expected element"}
	}
	return verified, nil
}

func checkSignedInfo(sig *etree.Element, id string) error {
	si, err := child(sig, NSDSig, "SignedInfo")
	if err != nil || si == nil {
		return errors.New("signature needs exactly one SignedInfo")
	}
	cm, err := child(si, NSDSig, "CanonicalizationMethod")
	if err != nil || cm == nil || attr(cm, "Algorithm") != excC14N {
		return errors.New("signature must use exclusive canonicalization without comments")
	}
	sm, err := child(si, NSDSig, "SignatureMethod")
	if err != nil || sm == nil || !allowedSignatureMethods[attr(sm, "Algorithm")] {
		return errors.New("signature method not allowed")
	}
	refs := children(si, NSDSig, "Reference")
	if len(refs) != 1 {
		return &wrappingError{fmt.Sprintf("signature must have exactly one Reference, has %d", len(refs))}
	}
	if attr(refs[0], "URI") != "#"+id {
		return &wrappingError{"signature Reference does not point at the signed element"}
	}
	hasEnveloped := false
	if ts, err := child(refs[0], NSDSig, "Transforms"); err != nil {
		return err
	} else if ts != nil {
		list := children(ts, NSDSig, "Transform")
		if len(list) != len(ts.ChildElements()) || len(list) > 2 {
			return errors.New("unexpected signature transforms")
		}
		for _, t := range list {
			switch attr(t, "Algorithm") {
			case enveloped:
				hasEnveloped = true
			case excC14N:
			default:
				return errors.New("signature transform not allowed")
			}
		}
	}
	if !hasEnveloped {
		return errors.New("signature must be enveloped")
	}
	dm, err := child(refs[0], NSDSig, "DigestMethod")
	if err != nil || dm == nil || !allowedDigests[attr(dm, "Algorithm")] {
		return errors.New("digest method not allowed")
	}
	return nil
}
