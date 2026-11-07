package mtc

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// A Proof is the contents of an MTCProof with no extensions.
type Proof struct {
	// Start and End are the bounds of the subtree [Start, End).
	Start, End int64

	// InclusionProof is the subtree inclusion proof for the entry.
	InclusionProof torchwood.RecordInSubtreeProof

	// Cosignatures are the subtree cosignatures, ordered by cosigner ID as
	// required by draft-ietf-plants-merkle-tree-certs-07, Section 6.2.
	// It is empty for landmark-relative certificates.
	Cosignatures []Cosignature
}

type Cosignature struct {
	CosignerID TrustAnchorID
	Signature  []byte
}

// PlaceholderProof returns a proof for index 0 in the subtree [0, 1), with no
// inclusion proof or cosignatures, to build a certificate for pre-issuance
// linting from the output of [TBSCertificate].
func PlaceholderProof() *Proof {
	return &Proof{Start: 0, End: 1}
}

// Certificate returns the DER encoding of the Certificate made of a
// DER-encoded TBSCertificate and an MTCProof built from p.
func Certificate(tbs []byte, p *Proof) ([]byte, error) {
	parts, err := splitTBS(tbs)
	if err != nil {
		return nil, err
	}
	serial := cryptobyte.String(parts.serial)
	var serialNumber uint64
	if !serial.ReadASN1Integer(&serialNumber) || serialNumber>>48 != logNumber {
		return nil, errors.New("TBSCertificate serialNumber is not in issuance log 1")
	}
	index := int64(serialNumber & (1<<48 - 1))

	// ValidSubtree rejects negative and reversed bounds, and the index check
	// below rejects empty subtrees.
	if p.End >= 1<<48 || !torchwood.ValidSubtree(p.Start, p.End) {
		return nil, fmt.Errorf("invalid subtree [%d, %d)", p.Start, p.End)
	}
	if index < p.Start || index >= p.End {
		return nil, fmt.Errorf("index %d is not in subtree [%d, %d)", index, p.Start, p.End)
	}
	if !slices.IsSortedFunc(p.Cosignatures, func(a, b Cosignature) int {
		return compareCosignerIDs(a.CosignerID, b.CosignerID)
	}) {
		return nil, errors.New("cosignatures are not ordered by cosigner ID")
	}
	for i, c := range p.Cosignatures {
		if c.CosignerID == (TrustAnchorID{}) {
			return nil, errors.New("missing cosigner ID")
		}
		// Since they are sorted, duplicates are adjacent.
		if i > 0 && c.CosignerID == p.Cosignatures[i-1].CosignerID {
			return nil, fmt.Errorf("duplicate cosigner ID %v", c.CosignerID)
		}
	}

	proof := cryptobyte.NewBuilder(nil)
	proof.AddUint16(0) // extensions
	proof.AddUint48(uint64(p.Start))
	proof.AddUint48(uint64(p.End))
	proof.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, h := range p.InclusionProof {
			b.AddBytes(h[:])
		}
	})
	proof.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range p.Cosignatures {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.CosignerID.Bytes())
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.Signature)
			})
		}
	})
	proofBytes, err := proof.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding MTCProof: %w", err)
	}

	b := cryptobyte.NewBuilder(make([]byte, 0, len(tbs)+len(proofBytes)+32))
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(mtcProofAlgorithmIdentifier) // signatureAlgorithm
		b.AddASN1BitString(proofBytes)          // signatureValue
	})
	return b.Bytes()
}

// compareCosignerIDs orders cosigner IDs as required by
// draft-ietf-plants-merkle-tree-certs-07, Section 6.2: shorter byte strings
// first, and byte strings of the same length lexicographically.
func compareCosignerIDs(a, b TrustAnchorID) int {
	if c := cmp.Compare(len(a.b), len(b.b)); c != 0 {
		return c
	}
	return strings.Compare(a.b, b.b)
}
