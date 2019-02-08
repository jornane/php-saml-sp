# TODO
 
## 1.0

- can we somehow make `SameSite` cookie parameter work for the application 
  while having it disabled for the ACS endpoint? A form POST comes from a 
  remote location...

- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Add `mdui` to generated metadata
- Validate schema of outgoing SAML messages (`AuthnRequest`, metadata)
- Validate `RelayState` on return from IdP?
- be a bit more lenient with the dateTime matching

## 1.1

- support `<shibm:Scope>` to restrict scopes for e.d. `eduPersonPrincipalName`
- verify the `NameQualifier` and `SPNameQualifier` in the NameID (ePTID) match
  the IdP entityID and SP entityID, now the verified IdP entityID and SP 
  entityID from the assertion are taken.
- Provide `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?

# 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- support auto update of IdP metadata? This may be something best left to 
  php-saml-ds?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- Implement unsolicited `Response`, "IdP initiated"
- Implement SLO
  - Send `LogoutRequest`
  - Receive `LogoutResponse`
  - Receive unsolicited `LogoutRequest` from IdPs
- Support receiving encrypted Assertions (saml2int)
  - rsa-oaep-mgf1p
  - aes-256-gcm
- Sign SAML metadata
