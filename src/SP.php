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

        $this->session->set('_saml_auth_id', $requestId);
        $this->session->set('_saml_auth_idp', $idpEntityId);
        $this->session->set('_saml_auth_authn_context_class_ref', $authnContextClassRef);

        return self::prepareRequestUrl($ssoUrl, $authnRequest, $relayState, $this->spInfo->getPrivateKey());
    }

    /**
     * @param string $samlResponse
     *
     * @return void
     */
    public function handleResponse($samlResponse)
    {
        $idpEntityId = $this->session->get('_saml_auth_idp');
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }

        /** @var array<string> */
        $authnContextClassRef = $this->session->get('_saml_auth_authn_context_class_ref');

        $response = new Response($this->dateTime);
        $samlAssertion = $response->verify(
            Base64::decode($samlResponse),
            $this->session->get('_saml_auth_id'),
            $this->spInfo->getAcsUrl(),
            $authnContextClassRef,
            $idpInfo
        );

        $this->session->delete('_saml_auth_id');
        $this->session->delete('_saml_auth_idp');
        $this->session->delete('_saml_auth_authn_context_class_ref');
        $this->session->set('_saml_auth_assertion', $samlAssertion);
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

        // delete the assertion, so we are no longer authenticated
        $this->session->delete('_saml_auth_assertion');

        return $relayState;
    }

    /**
     * @return false|Assertion
     */
    public function getAssertion()
    {
        if (!$this->session->has('_saml_auth_assertion')) {
            return false;
        }

        return $this->session->get('_saml_auth_assertion');
    }

    /**
     * @return string
     */
    public function metadata()
    {
        $validUntil = \date_add(clone $this->dateTime, new DateInterval('PT36H'));

        return $this->tpl->render(
            'Metadata',
            [
                'validUntil' => $validUntil->format('Y-m-d\TH:i:s\Z'),
                'entityID' => $this->spInfo->getEntityId(),
                'X509Certificate' => $this->spInfo->getPublicKeyEncoded(),
                'AssertionConsumerService' => $this->spInfo->getAcsUrl(),
            ]
        );
    }

    /**
     * @param string $requestUrl
     * @param string $requestXml
     * @param string $relayState
     * @param string $privateKey
     *
     * @return string
     */
    private static function prepareRequestUrl($requestUrl, $requestXml, $relayState, $privateKey)
    {
        $samlRequest = Base64::encode(\gzdeflate($requestXml));
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(
            [
                'Signature' => Signer::signRedirect($httpQuery, $privateKey),
            ]
        );

        return \sprintf(
            '%s%s%s&%s',
            $requestUrl,
            false === \strpos($requestUrl, '?') ? '?' : '&',
            $httpQuery,
            $signatureQuery
        );
    }
}
