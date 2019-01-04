# Introduction

This library allows web applications to allow users to authenticate with SAML 
IdPs.

# Why

- simpleSAMLphp is the "swiss army knife", we want only SAML 2.0, and only SP 
  functionality and no extensive list of features/dependencies;
- we want to support "at runtime" `AuthnContext` switches, i.e. upgrade to a
  higher LoA with MFA;
- mod_auth_mellon depends on Apache;
- small code base, no dependencies, easy to audit;

# Features

- Only SAML SP functionality
- Only HTTP-Redirect binding for sending `AuthnRequest` to IdP
- Only HTTP-POST binding for receiving `Assertion` from IdP
- Only supports RSA with SHA256 for signatures
- Supports signed `samlp:Response` and/or signed `saml:Assertion`
- Validates XML schema(s)
- **NO** encryption support
- Tested with IdPs:
  - simpleSAMLphp
  - OpenConext
  - FrkoIdP
- Currently ~500 NCLOC

# TODO 

- handle `NameID` eduPersonTargetedId properly (?)
- verify response status code
- Metadata Generator
- Allow to specify `AuthnContext` on authentication for MFA support;
- [Identity Provider Discovery Service Protocol and Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf)
- Logout
- (Maybe) SLO

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
