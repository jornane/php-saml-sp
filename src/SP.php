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
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;
use RuntimeException;

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

        if (PHP_SESSION_ACTIVE !== \session_status()) {
            // we MUST have an active session
            throw new RuntimeException('no session');
        }
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param IdPInfo $idpInfo
     * @param string  $relayState
     *
     * @return string
     */
    public function login(IdPInfo $idpInfo, $relayState)
    {
        // unset the existing session variables
        unset($_SESSION['_saml_auth_id']);
        unset($_SESSION['_saml_auth_assertion']);

        $requestId = \sprintf('_%s', Hex::encode(\random_bytes(16)));
        $_SESSION['_saml_auth_id'] = $requestId;

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

        $samlRequest = Base64::encode(\gzdeflate($authnRequest));

        // create a SSO SAMLRequest URL
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
            ]
        );
        $ssoUrl = $idpInfo->getSsoUrl();
        if (false === \strpos($ssoUrl, '?')) {
            return \sprintf('%s?%s', $ssoUrl, $httpQuery);
        }

        return \sprintf('%s&%s', $ssoUrl, $httpQuery);
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
        $responseStr = new Response(
            \dirname(__DIR__).'/schema',
            $this->dateTime
        );
        $samlAssertion = $responseStr->verify(
            Base64::decode($samlResponse),
            $_SESSION['_saml_auth_id'],
            $this->acsUrl,
            $idpInfo
        );
        $_SESSION['_saml_auth_assertion'] = $samlAssertion;
    }
}
