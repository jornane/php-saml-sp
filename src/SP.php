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
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;

class SP
{
    /** @var string */
    private $entityId;

    /** @var string */
    private $acsUrl;

    /** @var \DateTime */
    private $dateTime;

    /** @var SessionInterface */
    private $session;

    /** @var RandomInterface */
    private $random;

    /**
     * @param string $entityId
     * @param string $acsUrl
     */
    public function __construct($entityId, $acsUrl)
    {
        $this->entityId = $entityId;
        $this->acsUrl = $acsUrl;
        $this->dateTime = new DateTime();
        $this->session = new Session();
        $this->random = new Random();
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
     * @param IdPInfo $idpInfo
     * @param string  $relayState
     * @param array   $authOptions
     *
     * @return string
     */
    public function login(IdPInfo $idpInfo, $relayState, $authOptions = [])
    {
        $this->clearSessionVariables();

        $authnRequestId = \sprintf('_%s', Hex::encode($this->random->get(16)));
        $issueInstant = $this->dateTime->format('Y-m-d\TH:i:s\Z');
        $destination = $idpInfo->getSsoUrl();
        $forceAuthn = \array_key_exists('forceAuthn', $authOptions) && $authOptions['forceAuthn'];
        $assertionConsumerServiceURL = $this->acsUrl;
        $issuer = $this->entityId;

        $authnContextClassRefList = \array_key_exists('authnContextClassRefList', $authOptions) ? $authOptions['authnContextClassRefList'] : [];

        // XXX there must be a better way...
        \ob_start();
        include __DIR__.'/tpl/AuthnRequest.php';
        $authnRequest = \trim(\ob_get_clean());

        $this->session->set('_saml_auth_id', $authnRequestId);
        $this->session->set('_saml_auth_idp', $idpInfo);
        $this->session->set('_salm_auth_authn_context_class_ref_list', $authnContextClassRefList);

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
     * @param string $relayState
     *
     * @return false|string
     */
    public function logout($relayState)
    {
        if (false === $samlAssertion = $this->getAssertion()) {
            // user not authenticated, we don't need to do anything
            return false;
        }

        $nameId = $samlAssertion->getNameId();
        /** @var IdPInfo */
        $idpInfo = $this->session->get('_saml_auth_idp');

        // unset the existing session variables
        $this->clearSessionVariables();

        if (null === $sloUrl = $idpInfo->getSloUrl()) {
            // IdP does not support SLO, nothing we can do about it
            return false;
        }

        $logoutRequestId = \sprintf('_%s', Hex::encode($this->random->get(16)));
        $issueInstant = $this->dateTime->format('Y-m-d\TH:i:s\Z');
        $destination = $idpInfo->getSloUrl();
        $issuer = $this->entityId;

        // XXX there must be a better way...
        \ob_start();
        include __DIR__.'/tpl/LogoutRequest.php';
        $logoutRequest = \trim(\ob_get_clean());
        $samlRequest = Base64::encode(\gzdeflate($logoutRequest));

        // create a SSO SAMLRequest URL
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
            ]
        );

        if (false === \strpos($sloUrl, '?')) {
            return \sprintf('%s?%s', $sloUrl, $httpQuery);
        }

        return \sprintf('%s&%s', $sloUrl, $httpQuery);
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
        $idpInfo = $this->session->get('_saml_auth_idp');
        $responseStr = new Response(
            $this->dateTime
        );
        $samlAssertion = $responseStr->verify(
            Base64::decode($samlResponse),
            $this->session->get('_saml_auth_id'),
            $this->acsUrl,
            $idpInfo
        );

        // make sure we get any of the requested AuthnContextClassRef
        if (0 !== \count($this->session->get('_salm_auth_authn_context_class_ref_list'))) {
            if (!\in_array($samlAssertion->getAuthnContextClassRef(), $this->session->get('_salm_auth_authn_context_class_ref_list'), true)) {
                throw new \Exception(\sprintf('we wanted any of "%s"', \implode(', ', $this->session->get('_salm_auth_authn_context_class_ref_list'))));
            }
        }

        $this->session->delete('_saml_auth_id');
        $this->session->delete('_salm_auth_authn_context_class_ref_list');
        $this->session->set('_saml_auth_assertion', $samlAssertion);
    }

    /**
     * @return void
     */
    private function clearSessionVariables()
    {
        $this->session->delete('_saml_auth_id');
        $this->session->delete('_saml_auth_idp');
        $this->session->delete('_saml_auth_assertion');
        $this->session->delete('_salm_auth_authn_context_class_ref_list');
    }
}
