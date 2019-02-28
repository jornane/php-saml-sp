# TODO
 
## 1.0

- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Add `mdui` to generated metadata
- Validate schema of outgoing SAML messages (`AuthnRequest`)?
- Validate schema of generated Metadata?
- Validate `RelayState` on return from IdP?
- Verify extracted symmetric key size before feeding it to decryption function
- make it possible to enforce assertion encryption (per IdP)

## 1.1

- support `<shibm:Scope>` to restrict scopes for e.d. `eduPersonPrincipalName`
- Provide `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?

# 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- support auto update of IdP metadata? This may be something best left to 
  php-saml-ds?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- Implement unsolicited `Response`, "IdP initiated"
- Receive unsolicited `LogoutRequest` from IdPs
- Sign SAML metadata
