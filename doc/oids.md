# The Geomys PEN OID arc

This document describes the allocated OIDs under the Geomys PEN arc 1.3.6.1.4.1.66252.

| OID                         | Description           |
| ---                         | ---                   |
| 66252.0                     | mirroring cosigner    |
| 66252.{1..99}               | CA cosigners / CA IDs |
| 66252.{1..99}.0.1           | issuance logs         |
| 66252.{1..99}.1.1.{0..}     | landmarks             |
| 66252.{1..99}.2.1.{0..}     | landmark groups       |
| 66252.128                   | staging arc           |
| 66252.128.0                 | [staging mirroring cosigner][] |
| 66252.128.{1..99}           | staging CA cosigners / CA IDs  |
| 66252.128.{1..99}.{0,1,2}.1 | staging issuance logs, landmarks, and landmark groups |
| 66252.99999                 | INSECURE testing arc           |
| 66252.99999.1               | INSECURE testing CA ID         |
| 66252.99999.1.0.1           | INSECURE testing issuance logs |

[staging mirroring cosigner]: https://groups.google.com/a/chromium.org/g/mtcs/c/pn-h-vY9JhE
