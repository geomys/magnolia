package mtc

import (
	"bytes"
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

// PlaceholderProof returns the encoding of an MTCProof for index 0 in the
// subtree [0, 1), with no inclusion proof or cosignatures, to build a
// certificate for pre-issuance linting from the output of [TBSCertificate].
func PlaceholderProof() []byte {
	b, err := (&Proof{Start: 0, End: 1}).Bytes()
	if err != nil {
		panic("mtc: " + err.Error())
	}
	return b
}

// Bytes returns the encoding of the MTCProof.
func (p *Proof) Bytes() ([]byte, error) {
	b, err := p.BytesWithoutSignatures()
	if err != nil {
		return nil, err
	}
	signatures, err := SignaturesBytes(p.Cosignatures)
	if err != nil {
		return nil, err
	}
	return append(b, signatures...), nil
}

// SignaturesBytes returns the encoding of the signatures field of an MTCProof
// with the given cosignatures, which must be ordered by cosigner ID.
func SignaturesBytes(cosignatures []Cosignature) ([]byte, error) {
	if !slices.IsSortedFunc(cosignatures, func(a, b Cosignature) int {
		return CompareCosignerIDs(a.CosignerID, b.CosignerID)
	}) {
		return nil, errors.New("cosignatures are not ordered by cosigner ID")
	}
	for i, c := range cosignatures {
		if c.CosignerID == (TrustAnchorID{}) {
			return nil, errors.New("missing cosigner ID")
		}
		// Since they are sorted, duplicates are adjacent.
		if i > 0 && c.CosignerID == cosignatures[i-1].CosignerID {
			return nil, fmt.Errorf("duplicate cosigner ID %v", c.CosignerID)
		}
	}
	signatures := cryptobyte.NewBuilder(nil)
	signatures.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range cosignatures {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.CosignerID.Bytes())
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.Signature)
			})
		}
	})
	b, err := signatures.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding MTCProof signatures: %w", err)
	}
	return b, nil
}

// BytesWithoutSignatures returns the encoding of the MTCProof up to the
// signatures field, ignoring the cosignatures. Followed by the output of
// [SignaturesBytes], it is the encoding of an MTCProof.
func (p *Proof) BytesWithoutSignatures() ([]byte, error) {
	// ValidSubtree accepts empty subtrees.
	if p.End >= 1<<48 || p.Start >= p.End || !torchwood.ValidSubtree(p.Start, p.End) {
		return nil, fmt.Errorf("invalid subtree [%d, %d)", p.Start, p.End)
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
	b, err := proof.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding MTCProof: %w", err)
	}
	return b, nil
}

// Certificate returns the DER encoding of the Certificate made of a
// DER-encoded TBSCertificate and an encoded MTCProof, such as the output of
// [Proof.Bytes].
func Certificate(tbs, proof []byte) ([]byte, error) {
	// Check the signature algorithm of the TBSCertificate, and extract the index.
	parts, err := splitTBS(tbs)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(parts.signatureAlg, mtcProofAlgorithmIdentifier) {
		return nil, errors.New("TBSCertificate signature is not id-alg-mtcProof")
	}
	serial := cryptobyte.String(parts.serial)
	var serialNumber uint64
	if !serial.ReadASN1Integer(&serialNumber) || serialNumber>>48 != logNumber {
		return nil, errors.New("TBSCertificate serialNumber is not in issuance log 1")
	}
	index := serialNumber & (1<<48 - 1)

	// Check the proof covers the index.
	p := cryptobyte.String(proof)
	var extensions cryptobyte.String
	var start, end uint64
	if !p.ReadUint16LengthPrefixed(&extensions) || !p.ReadUint48(&start) || !p.ReadUint48(&end) {
		return nil, errors.New("malformed MTCProof")
	}
	if index < start || index >= end {
		return nil, fmt.Errorf("index %d is not in subtree [%d, %d)", index, start, end)
	}

	b := cryptobyte.NewBuilder(make([]byte, 0, len(tbs)+len(proof)+32))
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(mtcProofAlgorithmIdentifier) // signatureAlgorithm
		b.AddASN1BitString(proof)               // signatureValue
	})
	return b.Bytes()
}

// CompareCosignerIDs orders cosigner IDs as required by
// draft-ietf-plants-merkle-tree-certs-07, Section 6.2: shorter byte strings
// first, and byte strings of the same length lexicographically.
func CompareCosignerIDs(a, b TrustAnchorID) int {
	if c := cmp.Compare(len(a.b), len(b.b)); c != 0 {
		return c
	}
	return strings.Compare(a.b, b.b)
}
