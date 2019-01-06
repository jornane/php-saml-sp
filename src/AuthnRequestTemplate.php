<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$authnRequestId; ?>" Version="2.0" IssueInstant="<?=$issueInstant; ?>" Destination="<?=$destination; ?>" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="<?=$forceAuthn ? 'true' : 'false'; ?>" IsPassive="false" AssertionConsumerServiceURL="<?=$assertionConsumerServiceURL; ?>">
  <saml:Issuer><?=$issuer; ?></saml:Issuer>
<?php if (null !== $authnContextClassRef): ?>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef><?=$authnContextClassRef; ?></saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
<?php endif; ?>
</samlp:AuthnRequest>
