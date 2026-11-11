# Magnolia URLs

This document describes the URLs of a Magnolia CA, using CA ID `66252.1` as an
example.

| Prefix        | Example                                     | Description |
| ---           | ---                                         | ---         |
| `WritePrefix` | `https://acme.example.com`                  | ACME server, shared by all issuers |
| `ReadPrefix`  | `https://read.example.com/66252.1`          | read path of an issuer |
| CA prefix URL | `https://read.example.com/66252.1/issuance` | `ReadPrefix + "/issuance"`, the [mtc-tlog] CA prefix URL |

## Write path

| URL                                                              | Description         |
| ---                                                              | ---                 |
| `https://acme.example.com/directory`                             | ACME directory      |
| `https://acme.example.com/nonce`                                 | `newNonce`          |
| `https://acme.example.com/new-account`                           | `newAccount`        |
| `https://acme.example.com/account/<id>`                          | account             |
| `https://acme.example.com/key-change`                            | `keyChange`         |
| `https://acme.example.com/new-order`                             | `newOrder`          |
| `https://acme.example.com/order/<id>`                            | order               |
| `https://acme.example.com/order/<id>/finalize`                   | finalize            |
| `https://acme.example.com/order/<id>/authz/<i>`                  | authorization       |
| `https://acme.example.com/order/<id>/authz/<i>/challenge/<type>` | challenge           |
| `https://acme.example.com/health`                                | health check        |
| `https://acme.example.com/metrics`                               | Prometheus metrics  |

## Read path

The `1` path component is the log number. `<date>` is the certificate's
`notAfter` UTC date as `YYYY-MM-DD`. `<start>` is split into groups of three
digits, like `<N>`.

| URL                                                                              | Description |
| ---                                                                              | ---         |
| `https://read.example.com/66252.1/ca.pem`                                        | CA certificate ([RFC 9925] unsigned) |
| `https://read.example.com/66252.1/issuance/1/checkpoint`                         | issuance log checkpoint |
| `https://read.example.com/66252.1/issuance/1/tile/<L>/<N>[.p/<W>]`               | issuance log tiles |
| `https://read.example.com/66252.1/issuance/1/tile/entries/<N>[.p/<W>]`           | issuance log entry bundles |
| `https://read.example.com/66252.1/issuance/1/landmarks`                          | active landmarks |
| `https://read.example.com/66252.1/issuance/1/subtrees/<start>-<end>`             | subtree cosignatures ([C2SP/C2SP#397]) |
| `https://read.example.com/66252.1/certificate/1/<date>/<index>-<token>`          | standalone certificate, the ACME certificate URL |
| `https://read.example.com/66252.1/certificate/1/<date>/<index>-<token>/landmark` | landmark-relative certificate |
| `https://read.example.com/66252.1/evidence/1/checkpoint`                         | evidence log checkpoint |
| `https://read.example.com/66252.1/evidence/1/tile/<L>/<N>[.p/<W>]`               | evidence log tiles |
| `https://read.example.com/66252.1/evidence/1/tile/entries/<N>[.p/<W>]`           | evidence log entry bundles |
| `https://read.example.com/health`                                                | health check |
| `https://read.example.com/metrics`                                               | Prometheus metrics |

## Read path files

The read path serves the files in the issuer's `LocalDirectory`. Paths are
relative to `ReadPrefix`. In file names, but not in URLs, `<index>` is also
split into groups of three digits.

| Path                                            | Files |
| ---                                             | ---   |
| `ca.pem`                                        | none, generated from the configuration |
| `issuance/1/checkpoint`                         | `issuance/checkpoint` |
| `issuance/1/tile/...`                           | `issuance/tile/...` |
| `issuance/1/landmarks`                          | `landmarks` |
| `issuance/1/subtrees/<start>-<end>`             | `subtrees/<start>-<end>` |
| `certificate/1/<date>/<index>-<token>`          | `certs/<date>/tbs/<index>-<token>`<br>`certs/<date>/standalone/<index>-<token>`<br>`subtrees/<start>-<end>` |
| `certificate/1/<date>/<index>-<token>/landmark` | `certs/<date>/tbs/<index>-<token>`<br>`certs/<date>/landmark/<index>-<token>` |
| `evidence/1/checkpoint`                         | `evidence/checkpoint` |
| `evidence/1/tile/...`                           | `evidence/tile/...` |

[mtc-tlog]: https://c2sp.org/mtc-tlog@v0.1.0
[RFC 9925]: https://www.rfc-editor.org/info/rfc9925
[C2SP/C2SP#397]: https://github.com/C2SP/C2SP/issues/397
