# Subscriber certificate profile

There is one profile. Every certificate is a domain-validated TLS server
certificate, built from an entry in issuance log 1 and served as a standalone or
landmark-relative Merkle Tree Certificate.

The profile follows the BRs' Subscriber (Server) Certificate Profile (§7.1.2.7),
as modified by the Chrome Quantum-resistant Root Program Policy (CQRP, §2.4.3.2)
and draft-ietf-plants-merkle-tree-certs-07. Where they disagree, CQRP wins.

## Fields

| Field | Value |
| --- | --- |
| `version` | v3 |
| `serialNumber` | `(1 << 48) \| index`, where `index` is the entry's position in log 1 |
| `signature` | `id-alg-mtcProof`, parameters absent |
| `issuer` | The CA ID as a single `id-rdna-trustAnchorID` attribute |
| `notBefore` | Issuance time minus one hour, truncated to the second, as UTCTime |
| `notAfter` | `notBefore` + 160h − 1s, as UTCTime |
| `subject` | Empty |
| `subjectPublicKeyInfo` | ML-DSA-44, ML-DSA-65, or ML-DSA-87 |
| `issuerUniqueID`, `subjectUniqueID` | Absent |
| `signatureAlgorithm` | Same as `signature` |
| `signatureValue` | The MTCProof |

For example, for CA ID `66252.1` the issuer has one attribute, of type
`id-rdna-trustAnchorID` (1.3.6.1.5.5.7.25.3), whose value is the RELATIVE-OID
`66252.1`, encoded as `0d 04 84 85 4c 01`. The same four bytes `84 85 4c 01`, the
CA ID's binary representation, are the authority key identifier.

The ML-DSA AlgorithmIdentifier is exactly `300b06096086480165030403` followed by
`11`, `12`, or `13`. There are no parameters, and HashML-DSA is not accepted.
Other key types may be added later.

## Extensions

In this order:

| Extension | Critical | Value |
| --- | --- | --- |
| `keyUsage` | Yes | `digitalSignature` |
| `extKeyUsage` | No | `id-kp-serverAuth` |
| `authorityKeyIdentifier` | No | `keyIdentifier` only, set to the CA ID's binary representation |
| `subjectAltName` | Yes | `dNSName`s, then `iPAddress`es |
| `certificatePolicies` | No | One `PolicyInformation`, `2.23.140.1.2.1`, no qualifiers |

Nothing else is included. In particular:

- **authorityInformationAccess.** A SHOULD since SC-104. There is no OCSP
  responder, and relying parties find the CA by trust anchor ID, not by
  fetching its certificate.
- **crlDistributionPoints.** Optional for Short-lived Subscriber Certificates.
- **Signed Certificate Timestamp List.** Forbidden by CQRP.
- **subjectKeyIdentifier.** NOT RECOMMENDED by the BRs.
- **basicConstraints.** Optional.
- **issuerAltName.** Optional and purely cosmetic.

## Notes

**Lifetime.** The Validity Period counts both ends, so it is exactly 160 hours.
That is under the 7 days that make a certificate Short-lived (BRs §1.6.1), under
the 7-day maximum of a CQRP Active CA Cosigner #1 key (§2.6.2), and under
Apple's announced 7-day cap. Short-lived certificates need neither revocation
(BRs §4.9.1.1) nor a CRL distribution point. Because of the backdate,
a certificate is usable for about 159 hours after issuance.

**Serial number.** The BRs require serial numbers to be non-sequential and to
contain 64 bits of CSPRNG output. CQRP overrides this by requiring
`serialNumber` to follow the MTC draft (§2.4.3.2). Only log 1 is ever used.

**Authority key identifier.** The BRs require it, and CQRP doesn't say
otherwise. ARI also needs it, since RFC 9773 identifies certificates by their
authority key identifier and serial number. It must match the subject key
identifier of the issuing CA's certificate, which the MTC draft says SHOULD be
the CA ID. We publish the CA certificate as an RFC 9925 unsigned certificate
with that subject key identifier. Boulder ends up with the same value.

**Subject and SAN.** CQRP requires an empty subject for DV certificates, so
there is no common name and the SAN extension is critical (RFC 5280
§4.2.1.6). The profile allows IP addresses, even though the ACME server only
accepts `dns` identifiers for now.

**Key usage.** RFC 9881 allows `digitalSignature` for ML-DSA keys. The BRs only
define key usage tables for RSA and ECDSA, but recommend the extension.

**Size.** An MTCLogEntry can't exceed 65535 bytes, which bounds the number and
length of names.

## Linting

Every certificate will be linted with zlint twice: before its entry is added to the
log, with a placeholder proof, and after issuance, with the real one. These
lints are ignored because they don't apply to MTCs or to this profile:

- `e_signature_algorithm_not_supported`: `id-alg-mtcProof` is not a BRs
  signature algorithm, but CQRP allows it.
- `e_algorithm_identifier_improper_encoding`: the BRs only list RSA and ECDSA
  key encodings, but CQRP allows ML-DSA.
- `e_sub_cert_aia_missing`: AIA is a SHOULD since SC-104.
- `w_sub_cert_aia_does_not_contain_issuing_ca_url`: same.
- `w_ext_subject_key_identifier_missing_sub_cert`: the BRs don't recommend it.
- `n_ct_sct_policy_count_unsatisfied`: MTCs have no SCTs.

The EV Guidelines and ETSI lint sources are excluded entirely, since the profile
is not EV and has no qcStatements.

## CA certificate

The CA is represented by an unsigned certificate (RFC 9925), following
draft-ietf-plants-merkle-tree-certs-07, Section 5.5, mtc-tlog, and CQRP
§2.4.3.1. It is generated from the configuration and served by the read path at
`ca.pem`.

| Field | Value |
| --- | --- |
| `version` | v3 |
| `serialNumber` | The CA ID's binary representation, as an integer |
| `signature` | `id-alg-unsigned`, parameters absent |
| `issuer` | Same as `subject` |
| `notBefore` | The day the CA cosigner key was generated, at midnight UTC |
| `notAfter` | `notBefore` + 3831 days |
| `subject` | The CA ID as a single `id-rdna-trustAnchorID` attribute |
| `subjectPublicKeyInfo` | The ML-DSA-44 CA cosigner key |
| `signatureAlgorithm` | Same as `signature` |
| `signatureValue` | Empty |

Extensions, in this order:

| Extension | Critical | Value |
| --- | --- | --- |
| `keyUsage` | Yes | `keyCertSign`, `cRLSign` |
| `basicConstraints` | Yes | `cA` TRUE, no `pathLenConstraint` |
| `subjectKeyIdentifier` | No | The CA ID's binary representation |
| `id-pe-mtcCertificationAuthority-SHA256` | Yes | `sigAlg` ML-DSA-44, `minSerial` 2^48, `maxSerial` 2^64 − 1 |
| `id-mtcTlogPrefixURLs` | No | `ReadPrefix + "/issuance"` |

**Validity.** No policy sets the validity of an MTC CA certificate, and the
BRs' Root CA profile doesn't apply to it. `notAfter` is the latest a CA cosigner
key can be trusted until after it's generated under CQRP: keys are at
most 4 years (1461 days) old when submitted (§2.6.3), are included up to a
quarter (90 days) later, and are then trusted for at most 2280 days (§2.6.2).

**Serial range.** `minSerial` and `maxSerial` are the widest range the
extension allows. They exist for relying parties to revoke ranges of entries
and to limit log numbers (MTC draft §7.5), and a relying party's copy of the
certificate can narrow them. Certificates are only issued from log 1.
