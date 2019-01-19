# TODO
 
## 1.0

- Verify `NotBefore` in `Response`? 
- Add `mdui` to generated metadata
- API function to extract SP entity ID from SP object?
- Use `XmlDocument` also for `XmlIdpInfoSource`
- Validate schema of outgoing SAML messages (`AuthnRequest`, metadata)
- Validate schema when reading SAML metadata (`XmlIdpInfoSource`)
- Validate `RelayState` on return?

# 2.0

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
