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
    /** @var string */
    private $publicKey;

    /**
     * @param string $publicKey
     */
    public function __construct($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @param XmlDocument $xmlDocument
     * @param string      $signatureRoot
     *
     * @return void
     */
    public function verifyPost(XmlDocument $xmlDocument, $signatureRoot)
    {
        $rootElement = $xmlDocument->getElement($signatureRoot);
        $rootElementId = $rootElement->getAttribute('ID');
        $referenceUri = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference')->getAttribute('URI');
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new SignerException('reference URI does not point to Response document ID');
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
            throw new SignerException('digest does not match');
        }

        // verify the signature
        $verifyResult = \openssl_verify(
            $canonicalSignedInfo,
            Base64::decode($signatureValue),
            $this->publicKey,
            OPENSSL_ALGO_SHA256
        );
        if (1 !== $verifyResult) {
            throw new SignerException('invalid signature over SignedInfo');
        }
    }
}
