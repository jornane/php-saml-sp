# TODO
 
## 1.0

### Features

- ability to add `mdui` to generated metadata
- ability to expose requested attributes through metadata

### Open Issues

- ability to enforce encryption for all IdPs, or per IdP? Seems unwise to allow
  IdP overrides...
- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Validate schema of outgoing SAML messages (`AuthnRequest`)?
- Validate schema of generated Metadata?
- Validate `RelayState` on return from IdP?
- check xenc:EncryptedKey @Recipient?

## 1.1

- support `<shibm:Scope>` from IdP metadata to restrict scopes for:
  - `eduPersonPrincipalName`
  - `urn:oasis:names:tc:SAML:attribute:subject-id`
  - `urn:oasis:names:tc:SAML:attribute:pairwise-id`
- Provide `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?

# 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
  - remove libsodium (no longer needed as PHP >= 7.1 supports AES-256-GCM as 
    well
- support auto update of IdP metadata? This may be something best left to 
  php-saml-ds?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- Implement unsolicited `Response`, "IdP initiated"
- Receive unsolicited `LogoutRequest` from IdPs
- Sign SAML metadata
