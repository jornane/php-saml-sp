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
    const SIGNER_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGNER_XML_SIG_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGNER_XML_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGNER_HASH_ALGO = 'sha256';

    /**
     * @param XmlDocument   $xmlDocument
     * @param string        $signatureRoot
     * @param array<string> $publicKeys
     *
     * @return void
     */
    public static function verifyPost(XmlDocument $xmlDocument, $signatureRoot, array $publicKeys)
    {
        $rootElement = $xmlDocument->getElement($signatureRoot);
        $rootElementId = $rootElement->getAttribute('ID');
        $referenceUri = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference')->getAttribute('URI');
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new SignerException('reference URI does not point to document ID');
        }

        $digestMethod = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod')->getAttribute('Algorithm');
        if (self::SIGNER_XML_DIGEST_ALGO !== $digestMethod) {
            throw new SignerException(\sprintf('digest method "%s" not supported', $digestMethod));
        }
        $signatureMethod = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:SignatureMethod')->getAttribute('Algorithm');
        if (self::SIGNER_XML_SIG_ALGO !== $signatureMethod) {
            throw new SignerException(\sprintf('signature method "%s" not supported', $signatureMethod));
        }

        $signatureValue = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignatureValue')->textContent;
        $digestValue = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->textContent;

        $canonicalSignedInfo = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo')->C14N(true, false);
        $signatureElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature');
        $rootElement->removeChild($signatureElement);

        $rootElementDigest = Base64::encode(
            \hash(
                self::SIGNER_HASH_ALGO,
                $rootElement->C14N(true, false),
                true
            )
        );

        // compare the digest from the XML with the actual digest
        if (!\hash_equals($rootElementDigest, $digestValue)) {
            throw new SignerException('unexpected digest');
        }

        self::verifySignature($canonicalSignedInfo, Base64::decode($signatureValue), $publicKeys);
    }

    /**
     * @param string        $samlResponse
     * @param string        $relayState
     * @param string        $signature
     * @param array<string> $publicKeys
     *
     * @return void
     */
    public static function verifyRedirect($samlResponse, $relayState, $signature, array $publicKeys)
    {
        $httpQuery = \http_build_query(
            [
                'SAMLResponse' => $samlResponse,
                'RelayState' => $relayState,
                'SigAlg' => self::SIGNER_XML_SIG_ALGO,
            ]
        );

        self::verifySignature($httpQuery, Base64::decode($signature), $publicKeys);
    }

    /**
     * @param string $httpQuery
     * @param string $privateKey
     *
     * @return string
     */
    public static function signRedirect($httpQuery, $privateKey)
    {
        if (false === $privateKeyResource = \openssl_pkey_get_private($privateKey)) {
            throw new SignerException('invalid private key');
        }
        if (false === \openssl_sign($httpQuery, $signature, $privateKeyResource, self::SIGNER_OPENSSL_ALGO)) {
            throw new SignerException('unable to sign');
        }

        return Base64::encode($signature);
    }

    /**
     * @param string        $data
     * @param string        $signature
     * @param array<string> $publicKeys
     *
     * @return void
     */
    private static function verifySignature($data, $signature, array $publicKeys)
    {
        foreach ($publicKeys as $publicKey) {
            if (false === $publicKeyResource = \openssl_pkey_get_public($publicKey)) {
                throw new SignerException('invalid public key');
            }
            if (1 === \openssl_verify($data, $signature, $publicKeyResource, self::SIGNER_OPENSSL_ALGO)) {
                return;
            }
        }

        throw new SignerException('invalid signature');
    }
}
