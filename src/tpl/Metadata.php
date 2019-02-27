<md:EntityDescriptor validUntil="<?=$validUntil; ?>" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="<?=$entityID; ?>">
  <md:Extensions>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="2048" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate><?=$X509Certificate; ?></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </md:KeyDescriptor>
<?php if (null !== $SingleLogoutService): ?>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="<?=$SingleLogoutService; ?>"/>
<?php endif; ?>
    <md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<?=$AssertionConsumerService; ?>"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
