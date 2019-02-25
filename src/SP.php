<?php

/*
 * Copyright (c) 2019 François Kooman <fkooman@tuxed.net>
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

use DateInterval;
use DateTime;
use fkooman\SAML\SP\Exception\SpException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;

class SP
{
    /** @var SpInfo */
    private $spInfo;

    /** @var IdpInfoSourceInterface */
    private $idpInfoSource;

    /** @var \DateTime */
    private $dateTime;

    /** @var SessionInterface */
    private $session;

    /** @var RandomInterface */
    private $random;

    /** @var Template */
    private $tpl;

    /**
     * @param SpInfo                 $spInfo
     * @param IdpInfoSourceInterface $idpInfoSource
     */
    public function __construct(SpInfo $spInfo, IdpInfoSourceInterface $idpInfoSource)
    {
        $this->spInfo = $spInfo;
        $this->idpInfoSource = $idpInfoSource;
        $this->dateTime = new DateTime();
        $this->session = new Session();
        $this->random = new Random();
        $this->tpl = new Template(__DIR__.'/tpl');
    }

    /**
     * @return SpInfo
     */
    public function getSpInfo()
    {
        return $this->spInfo;
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
     * @param SessionInterface $session
     *
     * @return void
     */
    public function setSession(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @param RandomInterface $random
     *
     * @return void
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * @param string        $idpEntityId
     * @param string        $relayState
     * @param array<string> $authnContextClassRef
     *
     * @return string
     */
    public function login($idpEntityId, $relayState, array $authnContextClassRef = [])
    {
        $requestId = \sprintf('_%s', Hex::encode($this->random->requestId()));
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }
        $ssoUrl = $idpInfo->getSsoUrl();

        $authnRequest = $this->tpl->render(
            'AuthnRequest',
            [
                'ID' => $requestId,
                'IssueInstant' => $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                'Destination' => $ssoUrl,
                'AssertionConsumerServiceURL' => $this->spInfo->getAcsUrl(),
                'Issuer' => $this->spInfo->getEntityId(),
                'AuthnContextClassRef' => $authnContextClassRef,
            ]
        );

        $this->session->set('_fkooman_saml_sp_auth_id', $requestId);
        $this->session->set('_fkooman_saml_sp_auth_idp', $idpEntityId);
        $this->session->set('_fkooman_saml_sp_auth_acr', $authnContextClassRef);

        return self::prepareRequestUrl($ssoUrl, $authnRequest, $relayState, $this->spInfo->getPrivateKey());
    }

    /**
     * @param string $samlResponse
     *
     * @return void
     */
    public function handleResponse($samlResponse)
    {
        $idpEntityId = $this->session->get('_fkooman_saml_sp_auth_idp');
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }

        /** @var array<string> */
        $authnContextClassRef = $this->session->get('_fkooman_saml_sp_auth_acr');

        $response = new Response($this->dateTime);
        $samlAssertion = $response->verify(
            Base64::decode($samlResponse),
            $this->spInfo->getEntityId(),
            $this->session->get('_fkooman_saml_sp_auth_id'),
            $this->spInfo->getAcsUrl(),
            $authnContextClassRef,
            $idpInfo
        );

        $this->session->delete('_fkooman_saml_sp_auth_id');
        $this->session->delete('_fkooman_saml_sp_auth_idp');
        $this->session->delete('_fkooman_saml_sp_auth_acr');
        $this->session->set('_fkooman_saml_sp_auth_assertion', $samlAssertion);
    }

    /**
     * @param string $relayState
     *
     * @return string
     */
    public function logout($relayState)
    {
        if (false === $samlAssertion = $this->getAssertion()) {
            // no session available
            return $relayState;
        }

        $idpEntityId = $samlAssertion->getIssuer();
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }
        // delete the assertion, so we are no longer authenticated
        $this->session->delete('_fkooman_saml_sp_auth_assertion');

        $idpSloUrl = $idpInfo->getSloUrl();
        if (null === $idpSloUrl) {
            // IdP does not support SLO, nothing we can do about it
            return $relayState;
        }
        if (null === $spSloUrl = $this->spInfo->getSloUrl()) {
            // SP does not support SLO, do not redirect to IdP
            return $relayState;
        }

        $requestId = \sprintf('_%s', Hex::encode($this->random->requestId()));
        $logoutRequest = $this->tpl->render(
            'LogoutRequest',
            [
                'ID' => $requestId,
                'IssueInstant' => $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                'Destination' => $idpSloUrl,
                'Issuer' => $this->spInfo->getEntityId(),
                // we need the _exact_ (XML) NameID we got during
                // authentication for the LogoutRequest
                // XXX but it MUST be in the correct namespace, so we pretty much
                // have to rewrite it to match LogoutRequest document namespace
                'NameID' => $samlAssertion->getNameId(),
            ]
        );
        $this->session->set('_fkooman_saml_sp_auth_logout_id', $requestId);
        $this->session->set('_fkooman_saml_sp_auth_logout_idp', $idpEntityId);

        return self::prepareRequestUrl($idpSloUrl, $logoutRequest, $relayState, $this->spInfo->getPrivateKey());
    }

    /**
     * @param string $queryString
     *
     * @return void
     */
    public function handleLogoutResponse($queryString)
    {
        if (null === $spSloUrl = $this->spInfo->getSloUrl()) {
            // SP does not support SLO, nothing we can do here...
            return;
        }

        $idpEntityId = $this->session->get('_fkooman_saml_sp_auth_logout_idp');
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }

        $logoutResponse = new LogoutResponse();
        $logoutResponse->verify(
            new QueryParameters($queryString),
            $this->session->get('_fkooman_saml_sp_auth_logout_id'),
            $spSloUrl,
            $idpInfo
        );

        $this->session->delete('_fkooman_saml_sp_auth_logout_id');
        $this->session->delete('_fkooman_saml_sp_auth_logout_idp');
    }

    /**
     * @return false|Assertion
     */
    public function getAssertion()
    {
        if (!$this->session->has('_fkooman_saml_sp_auth_assertion')) {
            return false;
        }

        return $this->session->get('_fkooman_saml_sp_auth_assertion');
    }

    /**
     * @return string
     */
    public function metadata()
    {
        $validUntil = \date_add(clone $this->dateTime, new DateInterval('PT36H'));

//    <md:AttributeConsumingService index="0">
//      <md:ServiceName xml:lang="en">Academic Journals R US</ServiceName>
//      <md:RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" isRequired="true"/>
//      <md:RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" isRequired="false"/>
//    </md:AttributeConsumingService>

        return $this->tpl->render(
            'Metadata',
            [
                'validUntil' => $validUntil->format('Y-m-d\TH:i:s\Z'),
                'entityID' => $this->spInfo->getEntityId(),
                'X509Certificate' => $this->spInfo->getPublicKey()->toEncodedString(),
                'AssertionConsumerService' => $this->spInfo->getAcsUrl(),
                'SingleLogoutService' => $this->spInfo->getSloUrl(),
            ]
        );
    }

    /**
     * @param string     $requestUrl
     * @param string     $requestXml
     * @param string     $relayState
     * @param PrivateKey $privateKey
     *
     * @return string
     */
    private static function prepareRequestUrl($requestUrl, $requestXml, $relayState, PrivateKey $privateKey)
    {
        $httpQueryParameters = [
            'SAMLRequest' => Base64::encode(\gzdeflate($requestXml)),
            'RelayState' => $relayState,
            'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        ];

        // add the Signature key/value to the HTTP query
        $httpQueryParameters['Signature'] = Signer::signRedirect(
            \http_build_query($httpQueryParameters),
            $privateKey
        );

        return \sprintf(
            '%s%s%s',
            $requestUrl,
            false === \strpos($requestUrl, '?') ? '?' : '&',
            \http_build_query($httpQueryParameters)
        );
    }
}
