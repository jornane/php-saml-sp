<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$ID; ?>" Version="2.0" IssueInstant="<?=$IssueInstant; ?>" Destination="<?=$Destination; ?>">
  <saml:Issuer><?=$Issuer; ?></saml:Issuer>
  <?=$NameID->toXML(); ?>
</samlp:LogoutRequest>
