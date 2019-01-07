<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$ID; ?>" Version="2.0" IssueInstant="<?=$IssueInstant; ?>" Destination="<?=$Destination; ?>" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="<?=$ForceAuthn ? 'true' : 'false'; ?>" IsPassive="false" AssertionConsumerServiceURL="<?=$AssertionConsumerServiceURL; ?>">
  <saml:Issuer><?=$Issuer; ?></saml:Issuer>
<?php if (0 !== \count($AuthnContextClassRef)): ?>
  <samlp:RequestedAuthnContext Comparison="exact">
<?php foreach ($AuthnContextClassRef as $v): ?>
    <saml:AuthnContextClassRef><?=$v; ?></saml:AuthnContextClassRef>
<?php endforeach; ?>
  </samlp:RequestedAuthnContext>
<?php endif; ?>
</samlp:AuthnRequest>
