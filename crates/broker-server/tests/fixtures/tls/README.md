# Test certificates

Certificates and keys for the TLS tests of the LLM proxy (upstream
providers reached over TLS with a private CA and a client certificate).
They exist only for these tests: never trust them anywhere else.

| File | What | Valid until (UTC) |
|---|---|---|
| `ca.pem` | test CA | 2126-01-01 |
| `server.pem`, `server.key` | server certificate for `localhost` and `127.0.0.1`, issued by `ca.pem` | 2126-01-01 |
| `client-a.pem`, `client-a.key` | client certificate `broker-a`, issued by `ca.pem` | 2125-06-01 |
| `client-b.pem`, `client-b.key` | client certificate `broker-b`, issued by `ca.pem` | 2125-09-01 |
| `other-ca.pem` | a second, unrelated CA | 2126-01-01 |
| `other-server.pem`, `other-server.key` | server certificate for `localhost` and `127.0.0.1`, issued by `other-ca.pem` | 2126-01-01 |

All keys are ECDSA P-256 in PKCS#8 PEM; every certificate is valid from
2026-01-01. The fixed dates let tests assert expiry timestamps.

They were generated once with `./generate.sh` (OpenSSL 3.4 or newer).
Running it again replaces every file with new keys and certificates of the
same shape; the CA keys are deleted after signing.
