# Magnolia divergences from ACME

Magnolia diverges from the [RFC 8555] ACME spec in the following ways:

## [Section 6.2](https://www.rfc-editor.org/info/rfc8555#section-6.2)

Magnolia does not support the `ES256` JWS signature algorithm.
Instead, it only implements the ML-DSA algorithms specified in [RFC 9964].

## [Section 7.1.2](https://www.rfc-editor.org/info/rfc8555#section-7.1.2)

Account objects do not have the `orders` field.

## [Section 7.5.2](https://www.rfc-editor.org/info/rfc8555#section-7.5.2)

Authorizations can't be deactivated. They belong to a single order and expire
with it.

[RFC 8555]: https://www.rfc-editor.org/info/rfc8555
[RFC 9964]: https://www.rfc-editor.org/info/rfc9964
