# Introduction

This library allows adding SAML Service Provider (SP) support to your PHP web
application and interface with SAML Identity Providers (IdPs).

**NOTE**: this library did NOT receive a security audit. Do **NOT** use it in
production until there is a 1.0 release!

# Why

We want to have a minimal implementation of a SAML SP library. Exiting (PHP) 
software either has a much larger scope, or tries to conform fully to the SAML 
specification. This library only tries to implement the minimum amount to work 
in [SAML2int](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html) 
scenarios and be secure at the same time. It will never implement unsafe 
algorithms like SHA1.

# Features

- Only SAML SP functionality
- Only HTTP-Redirect binding for sending `AuthnRequest` to IdP
- Only HTTP-POST binding for receiving `Assertion` from IdP
- Only supports RSA with SHA256 for signing/verifying signatures
- Always signs `AuthnRequest` and `LogoutRequest`
- Supports signed `samlp:Response` and/or signed `saml:Assertion`
- Requires `LogoutResponse` to be signed
- Allow specifying `AuthnContextClassRef` and `ForceAuthn` as part of the
  Authentication Request
- No dependency on `robrichards/xmlseclibs`
- Validates XML schema(s) when processing messages
- Tested with IdPs:
  - simpleSAMLphp
  - OpenConext
  - FrkoIdP
- Currently ~1000 NCLOC

# X.509

Use the following command to create a self-signed certificate for use with the
SP library.

    $ openssl req \
        -nodes \
        -subj "/CN=SAML SP" \
        -x509 \
        -sha256 \
        -newkey rsa:3072 \
        -keyout "sp.key" \
        -out "sp.crt" \
        -days 3600

# Testing

Modify `example/index.php` and point it to your (test) IdP.

    $ php -S localhost:8081 -t example

With your browser you can then go to 
[http://localhost:8081/](http://localhost:8081/) and trigger the login. The 
SP metadata can be found here: 
[http://localhost:8081/metadata](http://localhost:8081/metadata).

# simpleSAMLphp as IdP

In your simpleSAMLphp's `metadata/saml20-sp-remote.php`, configure this for 
this SP library:

    'validate.authnrequest' => true,
    'saml20.sign.assertion' => true,
    'sign.logout' => true,
    'validate.logout' => true,

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
