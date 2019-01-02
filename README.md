# Introduction

This library allows web applications to allow users to authenticate with SAML 
IdPs.

# Why

- simpleSAMLphp is the "swiss army knife", we want only SAML 2.0, and only SP 
  functionality and no extensive list of dependencies;
- we want to have certain functionality configurable from the application at 
  "runtime" which is not possible with e.g. mod_auth_mellon or simpleSAMLphp 
  without hacks;
- mod_auth_mellon depends on Apache
- small code base, no dependencies, easy to audit

# Features

- Only SAML SP functionality
- HTTP-Redirect binding for sending `AuthnRequest` to IdP
- HTTP-POST binding for receiving `Assertion` from IdP
- Only supports `transient` NameID
- Only supports RSA with SHA256
- No (assertion, NameID) encryption
- Tested with IdPs:
  - simpleSAMLphp
  - OpenConext
  - FrkoIdP
- Less than 1000 NCLOC

# TODO 

- Metadata Generator
- Metadata Importer
- Scales for eduGAIN (large number of IdPs)
- Allows application to _dynamically_ specify `AuthnContext` in the 
  `AuthnRequest` for e.g. MFA
- Allows applications to scope the IdP list in combination with IdP Discovery
- Supports [Identity Provider Discovery Service Protocol and Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf)
- Supports `eduPersonTargetedId` (also formatted as a NameID)
- Supports `<shib:Scope>` (which scopes can be claimed by which IdP)
- Supports figuring out IdP when using SAML Proxies supporting ... (special Proxy? thingy)

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
