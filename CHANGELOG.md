# Changelog

All notable changes to `komma-softhouse/asice-engine` are documented here. The format follows Keep a Changelog and the project follows SemVer.

## [1.0.0] - 2026-09-17

### Added

- ASiC-E containers: stored mimetype first, OpenDocument manifest, data files, one signature document per signer.
- XAdES signatures in two halves: the digest of the canonical SignedInfo goes out, the value comes back; the value is verified before it is stored.
- Signed properties with signing time, certificate digest, production place and claimed roles; unsigned properties with the RFC 3161 time-stamp and the OCSP answer, plus the certificates they reference.
- OCSP client (DER request with nonce, answer parsed for status and responder certificate) and time-stamp client, both degrading to a note when unreachable.
- Certificate reader: signer name, Estonian personal code, serial and issuer hashes for the OCSP CertID, AIA URLs, RSA and ECDSA key types.
- Validation: file digests against their References, signature value against the signer's key, long-term status, errors per signature.
- Pending signatures serialize and restore intact, for queues, sessions and database rows.
