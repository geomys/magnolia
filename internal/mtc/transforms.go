package mtc

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// tbsParts holds the parts of a DER-encoded TBSCertificate that [LogEntry] and
// [SetSerial] need. They alias the input of [splitTBS].
type tbsParts struct {
	// outer SEQUENCE identifier and length octets: skipped
	version []byte
	serial  []byte
	// signature: skipped
	issuerToSubject []byte
	spkiAlg         []byte
	spki            []byte
	afterSPKI       []byte
}

// splitTBS splits a DER-encoded TBSCertificate into its [tbsParts].
func splitTBS(tbs []byte) (*tbsParts, error) {
	input := cryptobyte.String(tbs)
	var contents cryptobyte.String
	if !input.ReadASN1(&contents, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("malformed TBSCertificate")
	}

	var version, serial cryptobyte.String
	if !contents.ReadASN1Element(&version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("malformed TBSCertificate version")
	}
	if !contents.ReadASN1Element(&serial, cryptobyte_asn1.INTEGER) {
		return nil, errors.New("malformed TBSCertificate serialNumber")
	}
	if !contents.SkipASN1( /* signature */ cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate signature")
	}

	issuerToSubject := contents
	if !contents.SkipASN1(cryptobyte_asn1.SEQUENCE) ||
		!contents.SkipASN1(cryptobyte_asn1.SEQUENCE) ||
		!contents.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate issuer, validity, or subject")
	}
	issuerToSubject = issuerToSubject[:len(issuerToSubject)-len(contents)]

	var spki, spkiContents, spkiAlg cryptobyte.String
	if !contents.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate subjectPublicKeyInfo")
	}
	if s := spki; !s.ReadASN1(&spkiContents, cryptobyte_asn1.SEQUENCE) ||
		!spkiContents.ReadASN1Element(&spkiAlg, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate subjectPublicKeyInfo algorithm")
	}

	return &tbsParts{
		version:         version,
		serial:          serial,
		issuerToSubject: issuerToSubject,
		spkiAlg:         spkiAlg,
		spki:            spki,
		afterSPKI:       contents,
	}, nil
}

const (
	// logNumber is the issuance log number used in serial numbers.
	// Only log 1 is ever used in Magnolia's profile.
	logNumber = 1

	// tbsCertEntry is the MTCLogEntryType of a TBSCertificateLogEntry.
	tbsCertEntry = 1

	// maxLogEntrySize is the maximum size of an MTCLogEntry.
	maxLogEntrySize = 65535
)

// LogEntry returns the MTCLogEntry for a DER-encoded TBSCertificate, with no
// extensions and type tbs_cert_entry, constructed as described in
// draft-ietf-plants-merkle-tree-certs-07, Section 5.2.1.
func LogEntry(tbs []byte) ([]byte, error) {
	p, err := splitTBS(tbs)
	if err != nil {
		return nil, err
	}
	spkiHash := sha256.Sum256(p.spki)

	b := cryptobyte.NewBuilder(make([]byte, 0, len(tbs)))
	b.AddUint16(0) // extensions
	b.AddUint16(tbsCertEntry)
	// tbs_cert_entry_data, the contents octets of a TBSCertificateLogEntry.
	b.AddBytes(p.version)
	b.AddBytes(p.issuerToSubject)
	b.AddBytes(p.spkiAlg)
	b.AddASN1OctetString(spkiHash[:])
	b.AddBytes(p.afterSPKI)
	entry, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if len(entry) > maxLogEntrySize {
		return nil, fmt.Errorf("MTCLogEntry is %d bytes, exceeding the maximum of %d", len(entry), maxLogEntrySize)
	}
	return entry, nil
}

// SetSerial sets the serialNumber of a DER-encoded TBSCertificate, modifying
// tbs in place. If it returns an error, tbs is unchanged.
func SetSerial(tbs []byte, index int64) error {
	if index < 0 || index >= 1<<48 {
		return fmt.Errorf("index %d out of range", index)
	}
	var b cryptobyte.Builder
	b.AddASN1Uint64(logNumber<<48 | uint64(index))
	serial, err := b.Bytes()
	if err != nil {
		return err
	}
	f, err := splitTBS(tbs)
	if err != nil {
		return err
	}
	if len(f.serial) != len(serial) {
		return fmt.Errorf("serialNumber is %d bytes, expected %d", len(f.serial), len(serial))
	}
	copy(f.serial, serial)
	return nil
}
