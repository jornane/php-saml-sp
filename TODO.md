# TODO
 
## 1.0

- add mdui/etc to generated metadata
- make sure `RelayState` returned is the exact value we sent through session 
  (?)
- ability to get SP entityID from SP object (?)
- figure out if we need to verify "NotBefore" in SAML assertions
- make sure we get a fresh session (`AuthnInstant`) when using `ForceAuthn`
- fix issue with NameID when LoA upgrade fails, this is actually at the IdP?
- deal with receiving NameID without prefix, we have to 'normalize' this 
  somehow?
- switch XML idp info reader to use the XmlDocument class, should work fine
  with DOMXpath now :)
- introduce validate method allowing user to validate the scheme
- also verify XML documents we sent out, to make sure they contain no invalid
  data
- normalize the document, set remove whitespace and do not format when 
  outputting the XML before calling `DOMDocument::saveXML()`

# 2.0

- implement SLO
  - LogoutRequest
  - LogoutResponse
- SLO (respond to unsolicited LogoutRequest from IdPs)
- support encrypted Assertions (saml2int)
  - rsa-oaep-mgf1p
  - aes-256-gcm
- Sign SAML metadata
