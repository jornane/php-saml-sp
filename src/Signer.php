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

use fkooman\SAML\SP\Exception\SignerException;
use ParagonIE\ConstantTime\Base64;

class Signer
{
    /**
     * @param XmlDocument $xmlDocument
     * @param string      $signatureRoot
     * @param string      $publicKey
     *
     * @return void
     */
    public static function verifyPost(XmlDocument $xmlDocument, $signatureRoot, $publicKey)
    {
        $rootElement = $xmlDocument->getElement($signatureRoot);
        $rootElementId = $rootElement->getAttribute('ID');
        $referenceUri = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference')->getAttribute('URI');
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new SignerException('reference URI does not point to document ID');
        }

        $signatureValue = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignatureValue')->textContent;
        $digestValue = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->textContent;

        $canonicalSignedInfo = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo')->C14N(true, false);
        $signatureElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature');
        $rootElement->removeChild($signatureElement);

        $rootElementDigest = Base64::encode(
            \hash(
                'sha256',
                $rootElement->C14N(true, false),
                true
            )
        );

        // compare the digest from the XML with the actual digest
        if (!\hash_equals($rootElementDigest, $digestValue)) {
            throw new SignerException('unexpected digest');
        }

        self::verifySignature($canonicalSignedInfo, Base64::decode($signatureValue), $publicKey);
    }

    /**
     * @param string $samlResponse
     * @param string $relayState
     * @param string $signature
     * @param string $publicKey
     *
     * @return void
     */
    public static function verifyRedirect($samlResponse, $relayState, $signature, $publicKey)
    {
        $httpQuery = \http_build_query(
            [
                'SAMLResponse' => $samlResponse,
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );

        self::verifySignature($httpQuery, Base64::decode($signature), $publicKey);
    }

    /**
     * @param string $httpQuery
     * @param string $privateKey
     *
     * @return string
     */
    public static function signRedirect($httpQuery, $privateKey)
    {
        if (false === \openssl_sign($httpQuery, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new SignerException('unable to sign');
        }

        return Base64::encode($signature);
    }

    /**
     * @param string $data
     * @param string $signature
     * @param string $publicKey
     *
     * @return void
     */
    private static function verifySignature($data, $signature, $publicKey)
    {
        if (1 !== \openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256)) {
            throw new SignerException('invalid signature');
        }
    }
}
