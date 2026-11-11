package mtc

import (
	"crypto/mldsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// caValidity is the time between the notBefore and notAfter of an unsigned
// CA certificate.
//
// It is the longest a CA cosigner key can be trusted for after it's generated,
// per the Chrome Quantum-resistant Root Program Policy: keys are at most 4
// years (1461 days) old when submitted (Section 2.6.3), are included up to a
// quarter (~90 days) later, and are then trusted for at most 2280 days (Section
// 2.6.2).
const caValidity = (1461 + 2280 + 90) * 24 * time.Hour

// A CATemplate is the input to [CACertificate].
type CATemplate struct {
	// CAID is the CA ID, used as the subject, the issuer, the serial number,
	// and the subject key identifier.
	CAID TrustAnchorID

	// NotBefore is the day the CA cosigner key was generated. The time of day
	// is discarded, and both notBefore and notAfter are at midnight UTC.
	NotBefore time.Time

	// PublicKey is the ML-DSA-44 public key of the CA cosigner.
	PublicKey *mldsa.PublicKey

	// PrefixURLs are the c2sp.org/mtc-tlog CA prefix URLs.
	PrefixURLs []string
}

// CACertificate returns the DER encoding of the certificate that represents a
// CA, as specified in draft-ietf-plants-merkle-tree-certs-07, Section 5.5, and
// c2sp.org/mtc-tlog@v0.1.0, according to the profile in doc/profile.md.
//
// It is an unsigned certificate, as specified in RFC 9925.
func CACertificate(t *CATemplate) ([]byte, error) {
	if t.CAID == (TrustAnchorID{}) {
		return nil, errors.New("missing CA ID")
	}
	// The serial number is the binary representation of the CA ID, which
	// RFC 5280, Section 4.1.2.2 limits to a positive integer of 20 octets.
	serial := new(big.Int).SetBytes(t.CAID.Bytes())
	if serial.Sign() <= 0 || len(t.CAID.Bytes()) > 19 {
		return nil, fmt.Errorf("CA ID %v can't be a serial number", t.CAID)
	}
	if t.NotBefore.IsZero() {
		return nil, errors.New("missing notBefore")
	}
	if t.PublicKey == nil || t.PublicKey.Parameters() != mldsa.MLDSA44() {
		return nil, errors.New("CA cosigner key is not ML-DSA-44")
	}
	spkiAlg, err := mldsaAlgorithmIdentifier(t.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(t.PrefixURLs) == 0 {
		return nil, errors.New("no CA prefix URLs")
	}
	for _, u := range t.PrefixURLs {
		if u == "" || strings.ContainsFunc(u, isNotIA5) {
			return nil, fmt.Errorf("invalid CA prefix URL %q", u)
		}
	}

	year, month, day := t.NotBefore.UTC().Date()
	notBefore := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(caValidity)

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // tbsCertificate
			b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1Int64(2) // v3
			})
			b.AddASN1BigInt(serial)
			b.AddBytes(unsignedAlgorithmIdentifier)
			// The issuer is a placeholder, set like in a self-signed
			// certificate, as allowed by RFC 9925, Section 3.2.
			addCAIDName(b, t.CAID) // issuer
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addTime(b, notBefore)
				addTime(b, notAfter)
			})
			addCAIDName(b, t.CAID) // subject
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(spkiAlg)
				b.AddASN1BitString(t.PublicKey.Bytes())
			})
			b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					addCAExtensions(b, t, spkiAlg)
				})
			})
		})
		b.AddBytes(unsignedAlgorithmIdentifier) // signatureAlgorithm
		b.AddASN1BitString(nil)                 // signatureValue
	})
	return b.Bytes()
}

var (
	oidExtensionBasicConstraints          = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionSubjectKeyID              = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionMTCCertificationAuthority = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}
	oidExtensionMTCTlogPrefixURLs         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 2}
)

// unsignedAlgorithmIdentifier is the AlgorithmIdentifier for id-alg-unsigned
// (1.3.6.1.5.5.7.6.36), with parameters absent, from RFC 9925, Section 3.1.
var unsignedAlgorithmIdentifier = []byte{
	0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24}

// addCAExtensions adds the extensions in the order listed in doc/profile.md.
func addCAExtensions(b *cryptobyte.Builder, t *CATemplate, sigAlg []byte) {
	addExtension(b, oidExtensionKeyUsage, true, func(b *cryptobyte.Builder) {
		// keyCertSign (bit 5) and cRLSign (bit 6), with one unused bit.
		b.AddASN1(cryptobyte_asn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(1)
			b.AddUint8(0x06)
		})
	})
	addExtension(b, oidExtensionBasicConstraints, true, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Boolean(true) // cA
		})
	})
	addExtension(b, oidExtensionSubjectKeyID, false, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(t.CAID.Bytes())
	})
	addExtension(b, oidExtensionMTCCertificationAuthority, true, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// The ML-DSA signature AlgorithmIdentifier is the same as the
			// SubjectPublicKeyInfo one, per RFC 9881, Section 2.
			b.AddBytes(sigAlg)
			// The widest range the syntax allows, mtcMinSerial to mtcMaxSerial.
			b.AddASN1Uint64(1 << 48)        // minSerial
			b.AddASN1Uint64(math.MaxUint64) // maxSerial
		})
	})
	addExtension(b, oidExtensionMTCTlogPrefixURLs, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, u := range t.PrefixURLs {
				b.AddASN1(cryptobyte_asn1.IA5String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(u))
				})
			}
		})
	})
}

// addTime adds a Time as UTCTime through 2049, and as GeneralizedTime from
// 2050, per RFC 5280, Section 4.1.2.5. t must be in UTC.
func addTime(b *cryptobyte.Builder, t time.Time) {
	if t.Year() < 2050 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}
