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
- Only HTTP-Redirect binding for sending `AuthnRequest` to IdP
- Only HTTP-POST binding for receiving `Assertion` from IdP
- Only supports RSA with SHA256 for signatures
- No encryption support
- Tested with IdPs:
  - simpleSAMLphp
  - OpenConext
  - FrkoIdP
- Less than 1000 NCLOC

# TODO 

- Metadata Generator
- Metadata Importer
- Scales for eduGAIN (large number of IdPs)
- Allows application to at runtime specify `AuthnContext` in the `AuthnRequest` 
  e.g. for MFA
- Allows applications to scope the IdP list in combination with IdP Discovery
- Supports [Identity Provider Discovery Service Protocol and Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf)
- Supports `eduPersonTargetedId` (also formatted as a NameID)
- Supports `<shib:Scope>` (which scopes can be claimed by which IdP)
- Supports figuring out IdP when using SAML Proxies supporting ... (special Proxy? thingy)

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
