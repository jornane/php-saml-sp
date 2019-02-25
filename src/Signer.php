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

use DOMElement;
use DOMNode;
use fkooman\SAML\SP\Exception\SignerException;
use ParagonIE\ConstantTime\Base64;

class Signer
{
    const SIGNER_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGNER_XML_SIG_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGNER_XML_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGNER_HASH_ALGO = 'sha256';

    /**
     * @param XmlDocument      $xmlDocument
     * @param \DOMElement      $domElement
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verifyPost(XmlDocument $xmlDocument, DOMElement $domElement, array $publicKeys)
    {
        $rootElementId = $xmlDocument->domXPath->evaluate('string(self::node()/@ID)', $domElement);
        $referenceUri = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/@URI)', $domElement);
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new SignerException('reference URI does not point to document ID');
        }

        $digestMethod = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm)', $domElement);
        if (self::SIGNER_XML_DIGEST_ALGO !== $digestMethod) {
            throw new SignerException(\sprintf('digest method "%s" not supported', $digestMethod));
        }

        $signatureMethod = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $domElement);
        if (self::SIGNER_XML_SIG_ALGO !== $signatureMethod) {
            throw new SignerException(\sprintf('signature method "%s" not supported', $signatureMethod));
        }

        $signatureValue = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignatureValue)', $domElement);
        $digestValue = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue)', $domElement);

        $signedInfoElement = self::getOneElement($xmlDocument, 'ds:Signature/ds:SignedInfo', $domElement);
        $canonicalSignedInfo = $signedInfoElement->C14N(true, false);
        $signatureElement = self::getOneElement($xmlDocument, 'ds:Signature', $domElement);
        $domElement->removeChild($signatureElement);

        $rootElementDigest = Base64::encode(
            \hash(
                self::SIGNER_HASH_ALGO,
                $domElement->C14N(true, false),
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
     * @param string     $httpQuery
     * @param PrivateKey $privateKey
     *
     * @return string
     */
    public static function signRedirect($httpQuery, PrivateKey $privateKey)
    {
        if (false === \openssl_sign($httpQuery, $signature, $privateKey->raw(), self::SIGNER_OPENSSL_ALGO)) {
            throw new SignerException('unable to sign');
        }

        return Base64::encode($signature);
    }

    /**
     * @param QueryParameters  $queryParameters
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verifyRedirect(QueryParameters $queryParameters, array $publicKeys)
    {
        $samlResponse = $queryParameters->requireQueryParameter('SAMLResponse', true);
        $relayState = $queryParameters->requireQueryParameter('RelayState', true);
        $sigAlg = $queryParameters->requireQueryParameter('SigAlg', true);
        // XXX RelayState is actually optional...
        $httpQuery = \sprintf('SAMLResponse=%s&RelayState=%s&SigAlg=%s', $samlResponse, $relayState, $sigAlg);

        self::verifySignature($httpQuery, Base64::decode($queryParameters->requireQueryParameter('Signature')), $publicKeys);
    }

    /**
     * @param string           $data
     * @param string           $signature
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    private static function verifySignature($data, $signature, array $publicKeys)
    {
        foreach ($publicKeys as $publicKey) {
            if (1 === \openssl_verify($data, $signature, $publicKey->raw(), self::SIGNER_OPENSSL_ALGO)) {
                return;
            }
        }

        throw new SignerException('invalid signature');
    }

    /**
     * @param XmlDocument $xmlDocument
     * @param string      $xPathQuery
     * @param \DOMNode    $contextNode
     *
     * @return \DOMElement
     */
    private static function getOneElement(XmlDocument $xmlDocument, $xPathQuery, DOMNode $contextNode)
    {
        $domNodeList = $xmlDocument->domXPath->query($xPathQuery, $contextNode);
        if (0 === $domNodeList->length) {
            throw new SignerException(\sprintf('element "%s" not found', $xPathQuery));
        }
        if (1 !== $domNodeList->length) {
            throw new SignerException(\sprintf('element "%s" found more than once', $xPathQuery));
        }
        $domElement = $domNodeList->item(0);
        if (!($domElement instanceof DOMElement)) {
            throw new SignerException(\sprintf('element "%s" is not an element', $xPathQuery));
        }

        return $domElement;
    }
}
