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

use DateTime;
use fkooman\SAML\SP\Exception\SpException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;

class SP
{
    /** @var string */
    private $spEntityId;

    /** @var string */
    private $spAcsUrl;

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
     * @param string $spEntityId
     * @param string $spAcsUrl
     */
    public function __construct($spEntityId, $spAcsUrl, IdpInfoSourceInterface $idpInfoSource)
    {
        $this->spEntityId = $spEntityId;
        $this->spAcsUrl = $spAcsUrl;
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
     * @param string $idpEntityId
     * @param string $relayState
     * @param array  $authOptions
     *
     * @return string
     */
    public function login($idpEntityId, $relayState, array $authOptions = [])
    {
        $requestId = \sprintf('_%s', Hex::encode($this->random->get(16)));
        $authnContextClassRef = \array_key_exists('AuthnContextClassRef', $authOptions) ? $authOptions['AuthnContextClassRef'] : [];
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
                'ForceAuthn' => \array_key_exists('ForceAuthn', $authOptions) && $authOptions['ForceAuthn'],
                'AssertionConsumerServiceURL' => $this->spAcsUrl,
                'Issuer' => $this->spEntityId,
                'AuthnContextClassRef' => $authnContextClassRef,
            ]
        );

        $this->session->set('_saml_auth_id', $requestId);
        $this->session->set('_saml_auth_idp', $idpEntityId);
        $this->session->set('_saml_auth_authn_context_class_ref', $authnContextClassRef);

        return self::prepareRequestUrl($ssoUrl, $authnRequest, $relayState);
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

        $idpEntityId = $this->session->get('_saml_auth_idp');
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }
        $sloUrl = $idpInfo->getSloUrl();

        // delete the assertion, so we are no longer authenticated
        $this->session->delete('_saml_auth_assertion');

        if (null === $sloUrl) {
            // IdP does not support SLO, nothing we can do about it
            return $relayState;
        }

        $requestId = \sprintf('_%s', Hex::encode($this->random->get(16)));
        $logoutRequest = $this->tpl->render(
            'LogoutRequest',
            [
                'ID' => $requestId,
                'IssueInstant' => $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                'Destination' => $sloUrl,
                'Issuer' => $this->spEntityId,
                // we need the _exact_ (XML) NameID we got during
                // authentication for the LogoutRequest
                'NameID' => $samlAssertion->getNameId(),
            ]
        );

        $this->session->set('_saml_auth_logout_id', $requestId);
        $this->session->set('_saml_auth_logout_idp', $idpEntityId);

        return self::prepareRequestUrl($sloUrl, $logoutRequest, $relayState);
    }

    /**
     * @return false|Assertion
     */
    public function getAssertion()
    {
        if (!$this->session->has('_saml_auth_assertion')) {
            return false;
        }

        /* @var Assertion */
        return $this->session->get('_saml_auth_assertion');
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

        $responseStr = new Response($this->dateTime);
        $samlAssertion = $responseStr->verify(
            Base64::decode($samlResponse),
            $this->session->get('_saml_auth_id'),
            $this->spAcsUrl,
            $idpInfo
        );

        // make sure we get any of the requested AuthnContextClassRef
        // XXX move this to Response?!
        if (0 !== \count($this->session->get('_saml_auth_authn_context_class_ref'))) {
            if (!\in_array($samlAssertion->getAuthnContextClassRef(), $this->session->get('_saml_auth_authn_context_class_ref'), true)) {
                throw new \Exception(\sprintf('we wanted any of "%s"', \implode(', ', $this->session->get('_saml_auth_authn_context_class_ref'))));
            }
        }

        $this->session->delete('_saml_auth_id');
        $this->session->delete('_saml_auth_authn_context_class_ref');
        $this->session->set('_saml_auth_assertion', $samlAssertion);
    }

    /**
     * @param string $samlResponse
     *
     * @return void
     */
    public function handleLogoutResponse($samlResponse)
    {
    }

    /**
     * @param string $requestUrl
     * @param string $requestXml
     * @param string $relayState
     *
     * @return string
     */
    private function prepareRequestUrl($requestUrl, $requestXml, $relayState)
    {
        // XXX check  return value gzdeflate?
        $samlRequest = Base64::encode(\gzdeflate($requestXml));
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
            ]
        );

        if (false === \strpos($requestUrl, '?')) {
            return \sprintf('%s?%s', $requestUrl, $httpQuery);
        }

        return \sprintf('%s&%s', $requestUrl, $httpQuery);
    }
}
