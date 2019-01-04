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

namespace fkooman\SAML\SP;

use DateTime;

class SP
{
    /** @var string */
    private $entityId;

    /** @var string */
    private $acsUrl;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param string $entityId
     * @param string $acsUrl
     */
    public function __construct($entityId, $acsUrl)
    {
        $this->entityId = $entityId;
        $this->acsUrl = $acsUrl;
        $this->dateTime = new DateTime();
    }

    /**
     * @param IdPInfo $idpInfo
     * @param string  $relayState
     *
     * @return string
     */
    public function login(IdPInfo $idpInfo, $relayState)
    {
        // XXX delete all existing session stuff!

        $requestId = \sprintf('_%s', \bin2hex(\random_bytes(16)));
        $_SESSION['_saml_auth_id'] = $requestId;
        // XXX why do we store idpInfo?!
        $_SESSION['_saml_auth_idp'] = $idpInfo;

        $authnRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{ID}}" Version="2.0" IssueInstant="{{IssueInstant}}" Destination="{{Destination}}" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="{{AssertionConsumerServiceURL}}">
  <saml:Issuer>{{Issuer}}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
</samlp:AuthnRequest>
EOF;

        $authnRequest = \str_replace(
            [
                '{{ID}}',
                '{{IssueInstant}}',
                '{{Destination}}',
                '{{AssertionConsumerServiceURL}}',
                '{{Issuer}}',
            ],
            [
                $requestId,
                $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                $idpInfo->getSsoUrl(),
                $this->acsUrl,
                $this->entityId,
            ],
            $authnRequest
        );

        $samlRequest = \base64_encode(\gzdeflate($authnRequest));

        // set the session stuff
        // create a SSO SAMLRequest URL, return it
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
            ]
        );

        // XXX make sure the SSO URL does not yet contain a '?'
        return \sprintf('%s?%s', $idpInfo->getSsoUrl(), $httpQuery);
    }

    /**
     * @return false|Assertion
     */
    public function getAssertion()
    {
        if (!\array_key_exists('_saml_auth_assertion', $_SESSION)) {
            return false;
        }

        return $_SESSION['_saml_auth_assertion'];
    }

    /**
     * @param IdPInfo $idpInfo
     * @param string  $samlResponse
     * @param string  $relayState
     *
     * @return void
     */
    public function handleResponse(IdPInfo $idpInfo, $samlResponse)
    {
        $r = new Response(\dirname(__DIR__).'/schema');
        $samlAssertion = $r->verify(\base64_decode($samlResponse, true), $_SESSION['_saml_auth_id'], $this->acsUrl, $idpInfo);

        $_SESSION['_saml_auth_assertion'] = $samlAssertion;
    }
}
