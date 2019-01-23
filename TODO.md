# TODO
 
## 1.0

- Wrap keys in `PublicKey` and `PrivateKey` objects and make sure they are of
  type RSA and have sufficient length
- Verify `NotBefore` in `Response`? 
- Add `mdui` to generated metadata
- Validate schema of outgoing SAML messages (`AuthnRequest`, metadata)
- Validate `RelayState` on return from IdP?
- Provide `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`
- support eduPersonTargetedId in "string" format as documented here: https://wiki.geant.org/display/eduGAIN/IDP+Attribute+Profile+and+Recommended+Attributes

## 1.1

- support `<shibm:Scope>` to restrict scopes for e.d. `eduPersonPrincipalName`

# 2.0

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
