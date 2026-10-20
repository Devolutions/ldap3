# Doing a release

Make sure you've done all the tests and clippying and things.

## LDAP-WASM 0.3.5 (unreleased)

- Updated SSPI to 0.20.0 for standard SPNEGO initiation and final-response handling rather than an unsolicited Kerberos U2U request rejected by Windows LDAP.
- Kept KDC-configured sessions Kerberos-only and no-KDC sessions on NTLM.
- Preserved Kerberos credential domains and qualified usernames without changing NTLM challenge-domain behavior.
- Processed the final SASL server token before accepting bind success or enabling protected LDAP traffic.
- Propagated KDC proxy transport and HTTP failures without including the token-bearing URL.
- Updated SSPI-managed message sequencing and browser randomness configuration; Rust 1.89 or later is required.

## Checks

Fix (what you can) for outdated packages:

```shell
cargo audit
```

## Release order

```shell
cargo publish -p "ldap3_proto"
cargo publish -p "ldap3_client"
cargo publish -p "ldap3_cli"
```
