# Certificate fixtures

These are public root certificates, not private keys, extracted from
https://github.com/certifi/python-certifi/blob/2025.01.31/certifi/cacert.pem
on 2026-10-25. The ECC G3 DER SHA-256 matches the fingerprint in that source
and `data/trust_audit_emudhra.json`. G1 is an unaffected negative control,
ensuring that an emSign subject name alone does not trigger an incident match.

The incident scope and package fixes were checked against the official sources
listed in the evidence JSON. G3 presence is a review candidate, not proof of
runtime acceptance. The test suite builds metadata/environment fixtures in
temporary directories; it never runs their code.
