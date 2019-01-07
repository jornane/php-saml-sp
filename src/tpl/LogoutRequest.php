<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$logoutRequestId; ?>" Version="2.0" IssueInstant="<?=$issueInstant; ?>" Destination="<?=$destination; ?>">
  <saml:Issuer><?=$issuer; ?></saml:Issuer>
  <?=$nameId; ?>
</samlp:LogoutRequest>
