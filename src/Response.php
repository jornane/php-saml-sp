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

class Response
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
     * @param string  $expectedInResponseTo
     * @param string  $expectedAcsUrl
     * @param IdPInfo $idpInfo
     *
     * @return Assertion
     */
    public function verify($samlResponse, $expectedInResponseTo, $expectedAcsUrl, IdPInfo $idpInfo)
    {
        $responseDocument = XmlDocument::fromString($samlResponse);
        $signatureCount = 0;
        if ($responseDocument->hasElement('/samlp:Response/ds:Signature')) {
            // samlp:Response is signed
            self::verifySignature($responseDocument, '/samlp:Response', $idpInfo->getPublicKey());
            ++$signatureCount;
        }

        // make sure we have exactly 1 assertion
        // XXX introduce count method?!
        $assertionElement = $responseDocument->getElement('/samlp:Response/saml:Assertion');

        if ($responseDocument->hasElement('/samlp:Response/saml:Assertion/ds:Signature')) {
            // saml:Assertion is signed
            self::verifySignature($responseDocument, '/samlp:Response/saml:Assertion', $idpInfo->getPublicKey());
            ++$signatureCount;
        }

        if (0 === $signatureCount) {
            throw new Exception('neither the response, nor the assertion was signed');
        }

        // the Assertion Issuer MUST be IdP entityId
        $issuerElement = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:Issuer');
        if ($idpInfo->getEntityId() !== $issuerElement->textContent) {
            throw new Exception('unexpected Issuer');
        }

        $subjectConfirmationDataElement = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData');
        $notOnOrAfter = new DateTime($subjectConfirmationDataElement->getAttribute('NotOnOrAfter'));
        if ($this->dateTime >= $notOnOrAfter) {
            throw new Exception('notOnOrAfter expired');
        }
        if ($expectedAcsUrl !== $subjectConfirmationDataElement->getAttribute('Recipient')) {
            throw new Exception('unexpected Recipient');
        }
        if ($expectedInResponseTo !== $subjectConfirmationDataElement->getAttribute('InResponseTo')) {
            throw new Exception('unexpected InResponseTo');
        }

        $attributeList = self::extractAttributes($responseDocument);

        return new Assertion($idpInfo->getEntityId(), $attributeList);
    }

    /**
     * @param XmlDocument $xmlDocument
     * @param string      $signatureRoot
     * @param resource    $publicKey
     *
     * @return void
     */
    private static function verifySignature(XmlDocument $xmlDocument, $signatureRoot, $publicKey)
    {
        $rootElement = $xmlDocument->getElement($signatureRoot);
        $rootElementId = $rootElement->getAttribute('ID');
        $referenceUri = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference')->getAttribute('URI');
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new Exception('reference URI does not point to Response document ID');
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
            throw new Exception('digest does not match');
        }

        // verify the signature
        $verifyResult = \openssl_verify(
            $canonicalSignedInfo,
            Base64::decode($signatureValue),
            $publicKey,
            OPENSSL_ALGO_SHA256
        );
        if (1 !== $verifyResult) {
            throw new Exception('invalid signature over SignedInfo');
        }
    }

    /**
     * @param XmlDocument $xmlDocument
     *
     * @return array<string,array<string>>
     */
    private static function extractAttributes(XmlDocument $xmlDocument)
    {
        $attributeValueElements = $xmlDocument->getElements(
            '/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue'
        );
        $attributeList = [];
        foreach ($attributeValueElements as $attributeValueElement) {
            $attributeName = $attributeValueElement->parentNode->getAttribute('Name');
            if (!\array_key_exists($attributeName, $attributeList)) {
                $attributeList[$attributeName] = [];
            }
            $attributeList[$attributeName][] = $attributeValueElement->textContent;
        }

        return $attributeList;
    }
}
