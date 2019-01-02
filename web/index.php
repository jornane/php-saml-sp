<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

\session_name('SID');
\session_start();

if (\array_key_exists('auth', $_SESSION)) {
    echo '<html><head><title>Auth</title></head><body><table>';
    foreach ($_SESSION['auth'] as $k => $v) {
        $x = '';
        foreach ($v as $w) {
            $x .= '<li>'.$w.'</li>';
        }
        echo \sprintf('<tr><td>%s</td><td><ul>%s</ul></td></tr>', $k, $x);
    }
    echo '</table></body></html>';
    unset($_SESSION['auth']);
} else {
    // we want to verify the ID on the ACS (InResponseTo)
    $id = '_'.\bin2hex(\random_bytes(32));
    $_SESSION['ID'] = $id;

    $idpSso = 'http://localhost:8080/sso.php';
    $spEntityId = 'http://localhost:8081/metadata.php';
    $acsUrl = 'http://localhost:8081/acs.php';

    // not yet authenticated
    $authnRequest = \sprintf('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="%s"
                    Version="2.0"
                    IssueInstant="2019-01-02T12:50:24Z"
                    Destination="%s"
                    Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit"
                    ForceAuthn="false"
                    IsPassive="false"
                    AssertionConsumerServiceURL="%s"
                    >
    <saml:Issuer>%s</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                        AllowCreate="true"
                        />
</samlp:AuthnRequest>', $id, $idpSso, $acsUrl, $spEntityId);

    $samlRequest = \base64_encode(\gzdeflate($authnRequest));

    $q = \http_build_query(
        [
            'SAMLRequest' => $samlRequest,
        ]
    );

    \http_response_code(302);
    \header(\sprintf('Location: %s?%s', $idpSso, $q));
}
