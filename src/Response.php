<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
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

        // XXX verify status code in response

        $sigCount = 0;
        if ($responseDocument->hasElement('/samlp:Response/ds:Signature')) {
            // samlp:Response is signed
            self::verifySignature($responseDocument, '/samlp:Response', $idpInfo->getPublicKey());
            ++$sigCount;
        }

        // make sure we have exactly 1 assertion
        // XXX introduce count method?!
        $assertionElement = $responseDocument->getElement('/samlp:Response/saml:Assertion');

        if ($responseDocument->hasElement('/samlp:Response/saml:Assertion/ds:Signature')) {
            // saml:Assertion is signed
            self::verifySignature($responseDocument, '/samlp:Response/saml:Assertion', $idpInfo->getPublicKey());
            ++$sigCount;
        }

        if (0 === $sigCount) {
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
        $signedElement = $xmlDocument->getElement($signatureRoot);
        $signedElementId = $signedElement->getAttribute('ID');

        $signatureElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature');

        // 5. make sure the Reference points to Response
        $referenceElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference');
        $referenceUri = $referenceElement->getAttribute('URI');

        if ('#'.$signedElementId !== $referenceUri) {
            throw new Exception('reference URI does not point to Response document ID');
        }

        // 3. get the SignatureValue from XML (from Response OR from Assertion)
        $signatureValueElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignatureValue');
        $signatureValueStr = $signatureValueElement->textContent;

        // 4. get the DigestValue from XML
        $digestValueElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue');
        $digestValueStr = $digestValueElement->textContent;

        $signedInfoElement = $xmlDocument->getElement($signatureRoot.'/ds:Signature/ds:SignedInfo');
        $signedInfoElementCanonical = $signedInfoElement->C14N(true, false);

        // 6. remove the Signature from the XML
        $signedElement->removeChild($signatureElement);

        // calculate the digest over the Response element without the Signature
        // element
        $signedElementDigest = Base64::encode(
            \hash(
                'sha256',
                $signedElement->C14N(true, false),
                true
            )
        );

        // compare the SignedInfo digest with the actual digest
        if (!\hash_equals($signedElementDigest, $digestValueStr)) {
            throw new Exception('digest does not match');
        }

        // verify the signature over the SignedInfo element
        if (1 !== \openssl_verify($signedInfoElementCanonical, Base64::decode($signatureValueStr), $publicKey, OPENSSL_ALGO_SHA256)) {
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
        $queryResponse = $xmlDocument->getElements('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute');
        // find all attribute names
        $attributeList = [];
        foreach ($queryResponse as $qR) {
            $attributeList[$qR->getAttribute('Name')] = [];
        }

        // find the attribute values
        foreach (\array_keys($attributeList) as $attrName) {
            $queryResponse = $xmlDocument->getElements(\sprintf('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue', $attrName));
            foreach ($queryResponse as $qR) {
                // XXX this does NOT always work, only when there is actually textContent...
                $attributeList[$attrName][] = $qR->textContent;
            }
        }

        return $attributeList;
    }
}
