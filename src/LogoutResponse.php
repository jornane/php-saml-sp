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
use Exception;
use ParagonIE\ConstantTime\Base64;

class LogoutResponse
{
    /** @var \DateTime */
    private $dateTime;

    /**
     * @param \DateTime $dateTime
     */
    public function __construct(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param string  $samlResponse
     * @param string  $relayState
     * @param string  $signature
     * @param string  $expectedInResponseTo
     * @param string  $expectedSloUrl
     * @param IdpInfo $idpInfo
     *
     * @return void
     */
    public function verify($samlResponse, $relayState, $signature, $expectedInResponseTo, $expectedSloUrl, IdpInfo $idpInfo)
    {
        Signer::verifyRedirect($samlResponse, $relayState, $signature, $idpInfo->getPublicKey());

        $logoutResponseDocument = XmlDocument::fromString(\gzinflate(Base64::decode($samlResponse)));
        $logoutResponseElement = $logoutResponseDocument->getElement('/samlp:LogoutResponse');
        $inResponseTo = $logoutResponseElement->getAttribute('InResponseTo');

        // the LogoutResponse Issuer MUST be IdP entityId
        $issuerElement = $logoutResponseDocument->getElement('/samlp:LogoutResponse/saml:Issuer');
        if ($idpInfo->getEntityId() !== $issuerElement->textContent) {
            throw new Exception('unexpected Issuer');
        }

        // XXX do not accept old logout responses

        if ($inResponseTo !== $expectedInResponseTo) {
            throw new Exception('unexpected InResponseTo');
        }

        $destination = $logoutResponseElement->getAttribute('Destination');
        if ($destination !== $expectedSloUrl) {
            throw new Exception('unexpected Destination');
        }
    }
}