<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$authnRequestId; ?>" Version="2.0" IssueInstant="<?=$issueInstant; ?>" Destination="<?=$destination; ?>" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="<?=$forceAuthn ? 'true' : 'false'; ?>" IsPassive="false" AssertionConsumerServiceURL="<?=$assertionConsumerServiceURL; ?>">
  <saml:Issuer><?=$issuer; ?></saml:Issuer>
<?php if (0 !== \count($authnContextClassRefList)): ?>
  <samlp:RequestedAuthnContext Comparison="exact">
<?php foreach ($authnContextClassRefList as $authnContextClassRef): ?>
    <saml:AuthnContextClassRef><?=$authnContextClassRef; ?></saml:AuthnContextClassRef>
<?php endforeach; ?>
  </samlp:RequestedAuthnContext>
<?php endif; ?>
</samlp:AuthnRequest>
