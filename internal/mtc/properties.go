package mtc

import (
	"golang.org/x/crypto/cryptobyte"
)

// CertificatePropertyType values, from draft-ietf-tls-trust-anchor-ids-06,
// Section 7.
const (
	propertyTrustAnchorID          = 0
	propertyTrustAnchorGroups      = 1
	propertyTrustAnchorNegotiation = 2
)

// StandaloneProperties returns the CertificatePropertyList of the standalone
// certificates of a CA, as recommended by
// draft-ietf-plants-merkle-tree-certs-07, Section 9.2.
//
// Their trust anchor ID is the CA ID, and they are in every landmark group of
// the CA, caID.2.{0-}.{0-}. They are not gated on trust anchor negotiation.
func StandaloneProperties(caID TrustAnchorID) ([]byte, error) {
	groups, err := exactPattern(caID)
	if err != nil {
		return nil, err
	}
	groups = append(groups, 2, 2)    // landmarkGroups(2)
	groups = append(groups, 0, 0x80) // {0-}, any log number
	groups = append(groups, 0, 0x80) // {0-}, any landmark
	return propertyList(caID.Bytes(), [][]byte{groups}, false)
}

// exactPattern returns the trust anchor ID pattern that only matches the
// components of id, to be extended with more components.
func exactPattern(id TrustAnchorID) ([]byte, error) {
	components, err := components(id.b)
	if err != nil {
		return nil, err
	}
	var pattern []byte
	for _, c := range components {
		// To get an exact match, use the component for both minimum and
		// maximum, per draft-ietf-tls-trust-anchor-ids-06, Section 5.3.1.
		pattern = appendComponent(pattern, c)
		pattern = appendComponent(pattern, c)
	}
	return pattern, nil
}

// propertyList encodes a CertificatePropertyList with a trust_anchor_id, a
// trust_anchor_groups, and optionally a trust_anchor_negotiation property.
func propertyList(id []byte, patterns [][]byte, negotiation bool) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(propertyTrustAnchorID)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(id)
		})
		b.AddUint16(propertyTrustAnchorGroups)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // TrustAnchorIDPatternList
				for _, p := range patterns {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(p)
					})
				}
			})
		})
		if negotiation {
			b.AddUint16(propertyTrustAnchorNegotiation)
			b.AddUint16(0) // data
		}
	})
	return b.Bytes()
}
