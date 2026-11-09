// Package mtc encodes Merkle Tree Certificates, as specified by
// draft-ietf-plants-merkle-tree-certs-07, following the profile in
// doc/profile.md.
package mtc

import (
	"crypto/mldsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// backdate is how much notBefore precedes the issuance time.
	backdate = time.Hour

	// beforeAfterDelta is notAfter - notBefore.
	// The Validity Period counts both ends, so it is exactly 160 hours.
	beforeAfterDelta = 160*time.Hour - time.Second
)

// A Template is the input to [TBSCertificate].
type Template struct {
	// CAID is the CA ID, used as the issuer and authority key identifier.
	CAID TrustAnchorID

	// IssuedAt is the issuance time, from which the validity is computed.
	IssuedAt time.Time

	// PublicKey is the subject public key.
	PublicKey *mldsa.PublicKey

	// DNSNames and IPAddresses are the subject alternative names, encoded
	// in this order.
	DNSNames    []string
	IPAddresses []netip.Addr
}

// TBSCertificate returns the DER encoding of the TBSCertificate for t,
// according to the profile in doc/profile.md, with index 0.
//
// The serial number doesn't affect the [LogEntry], so the result can be linted
// and logged before the index is known, and then passed to [SetSerial].
func TBSCertificate(t *Template) ([]byte, error) {
	if t.CAID == (TrustAnchorID{}) {
		return nil, errors.New("missing CA ID")
	}
	if t.IssuedAt.IsZero() {
		return nil, errors.New("missing issuance time")
	}
	spkiAlg, err := mldsaAlgorithmIdentifier(t.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(t.DNSNames) == 0 && len(t.IPAddresses) == 0 {
		return nil, errors.New("no subject alternative names")
	}
	for _, name := range t.DNSNames {
		if name == "" || strings.ContainsFunc(name, isNotIA5) {
			return nil, fmt.Errorf("invalid DNS name %q", name)
		}
	}
	for _, ip := range t.IPAddresses {
		if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() {
			return nil, fmt.Errorf("invalid IP address %v", ip)
		}
	}

	notBefore, notAfter := Validity(t.IssuedAt)

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(2) // v3
		})
		b.AddASN1Uint64(logNumber << 48) // serialNumber for index 0
		b.AddBytes(mtcProofAlgorithmIdentifier)
		addCAIDName(b, t.CAID) // issuer
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1UTCTime(notBefore)
			b.AddASN1UTCTime(notAfter)
		})
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {}) // empty subject
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(spkiAlg)
			b.AddASN1BitString(t.PublicKey.Bytes())
		})
		b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addExtensions(b, t)
			})
		})
	})
	return b.Bytes()
}

// Validity returns the notBefore and notAfter of a certificate issued at
// issuedAt, in UTC.
func Validity(issuedAt time.Time) (notBefore, notAfter time.Time) {
	// RFC 5280, Section 4.1.2.5.1 requires UTCTime to be expressed in UTC,
	// with seconds, and cryptobyte's encoding depends on the time.Location.
	notBefore = issuedAt.UTC().Add(-backdate).Truncate(time.Second)
	return notBefore, notBefore.Add(beforeAfterDelta)
}

var (
	oidTrustAnchorIDAttribute = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

	oidExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtKeyUsageServerAuth        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidPolicyDomainValidated        = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
)

// mtcProofAlgorithmIdentifier is the AlgorithmIdentifier for id-alg-mtcProof
// (1.3.6.1.5.5.7.6.67), with parameters absent.
var mtcProofAlgorithmIdentifier = []byte{
	0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43}

// mldsaAlgorithmIdentifier returns the SubjectPublicKeyInfo AlgorithmIdentifier
// for pk, byte-for-byte as required by the Chrome Quantum-resistant Root
// Program Policy, Section 2.4.3.2.
func mldsaAlgorithmIdentifier(pk *mldsa.PublicKey) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("missing public key")
	}
	var last byte
	switch pk.Parameters() {
	case mldsa.MLDSA44():
		last = 0x11
	case mldsa.MLDSA65():
		last = 0x12
	case mldsa.MLDSA87():
		last = 0x13
	default:
		return nil, fmt.Errorf("unsupported ML-DSA parameters %v", pk.Parameters())
	}
	return []byte{0x30, 0x0b, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last}, nil
}

// addCAIDName adds the CA ID as a PKIX distinguished name, with a single
// id-rdna-trustAnchorID attribute whose value is a RELATIVE-OID, per
// draft-ietf-plants-merkle-tree-certs-07, Section 5.1.
func addCAIDName(b *cryptobyte.Builder, id TrustAnchorID) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidTrustAnchorIDAttribute)
				b.AddASN1(cryptobyte_asn1.Tag(13), func(b *cryptobyte.Builder) { // RELATIVE-OID
					b.AddBytes(id.Bytes())
				})
			})
		})
	})
}

// addExtensions adds the extensions in the order listed in doc/profile.md.
func addExtensions(b *cryptobyte.Builder, t *Template) {
	addExtension(b, oidExtensionKeyUsage, true, func(b *cryptobyte.Builder) {
		// digitalSignature (bit 0) only. DER requires removing trailing zero
		// bits from a named bit list (X.690, Section 11.2.2), so there are 7
		// unused bits, which AddASN1BitString can't express.
		b.AddASN1(cryptobyte_asn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(7)
			b.AddUint8(0x80)
		})
	})
	addExtension(b, oidExtensionExtendedKeyUsage, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidExtKeyUsageServerAuth)
		})
	})
	addExtension(b, oidExtensionAuthorityKeyID, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { // keyIdentifier
				b.AddBytes(t.CAID.Bytes())
			})
		})
	})
	// Critical because the subject is empty, per RFC 5280, Section 4.2.1.6.
	addExtension(b, oidExtensionSubjectAltName, true, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, name := range t.DNSNames {
				b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) { // dNSName
					b.AddBytes([]byte(name))
				})
			}
			for _, ip := range t.IPAddresses {
				b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) { // iPAddress
					b.AddBytes(ip.AsSlice())
				})
			}
		})
	})
	addExtension(b, oidExtensionCertificatePolicies, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // PolicyInformation
				b.AddASN1ObjectIdentifier(oidPolicyDomainValidated)
			})
		})
	})
}

func addExtension(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, critical bool, value cryptobyte.BuilderContinuation) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		// critical is omitted if false, since it's DEFAULT FALSE.
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1(cryptobyte_asn1.OCTET_STRING, value)
	})
}

func isNotIA5(r rune) bool { return r >= 0x80 }
