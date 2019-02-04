# Introduction

This library allows adding SAML Service Provider (SP) support to your PHP web
application and interface with SAML Identity Providers (IdPs).

**NOTE**: this library did NOT receive a security audit. Do **NOT** use it in
production until there is a 1.0 release!

# Why

We want to have a minimal implementation of a SAML SP library. Exiting (PHP) 
software either has a much larger scope, or tries to conform fully to the SAML 
specification. This library only tries to implement the minimum amount to work
with deployed IdPs and be secure at all times. It will never support insecure
algorithms like (RSA)-SHA1.

# Features

- Only SAML SP functionality
- Only HTTP-Redirect binding for sending `AuthnRequest` to IdP
- Only HTTP-POST binding for receiving `Assertion` from IdP
- Only supports RSA with SHA256 for signing/verifying signatures
- Always signs `AuthnRequest`
- Supports signed `samlp:Response` and/or signed `saml:Assertion`
- Allow specifying `AuthnContextClassRef` as part of the `AuthnRequest`
- No dependency on `robrichards/xmlseclibs`
- Serializes `eduPersonTargetedId` as `idpEntityId!spEntityId!persistentId`
- Validates XML schema(s) when processing XML messages
- Tested with IdPs:
  - [simpleSAMLphp](https://simplesamlphp.org/)
  - [OpenConext](https://openconext.org/)
  - [FrkoIdP](https://github.com/fkooman/php-saml-idp/)
  - [AD FS](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)
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
        -days 3650

# Example

Two examples are provided in the `example/` directory. In order test them:

    $ composer install
    $ php -S localhost:8081 -t example

The example performs authentication and shows the attributes received from the 
IdP. It does not support logout at the IdP, but instead performs a "local" 
logout (and then redirects again to the IdP).

With your browser you can go to 
[http://localhost:8081/](http://localhost:8081/). The example will redirect 
immediately to the IdP. The metadata of the SP can be found at this URL: 
`http://localhost:8081/metadata`

# IdP Configuration

Make sure the IdP signs the `saml:Assertion` and/or `samlp:Response` it sends 
back the the SP.

Optionally the IdP can verify the `samlp:AuthnRequest` as sent by the IdP.

Encryption is **NOT** currently supported.

# Tests

In order to run the tests:

    $ composer install
    $ vendor/bin/phpunit

# XML Schema Validation

Source of XSD files in `src/schema`:

    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/cs01/xsd/sstc-saml-metadata-ui-v1.0.xsd

All occurrences of `schemaLocation` in the XSD files were modified to point to
the local files instead of the remote resources.

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
