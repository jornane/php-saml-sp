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
use fkooman\SAML\SP\Exception\ResponseException;

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
     * @param string        $samlResponse
     * @param string        $expectedInResponseTo
     * @param string        $expectedAcsUrl
     * @param array<string> $authnContext
     * @param IdpInfo       $idpInfo
     *
     * @return Assertion
     */
    public function verify($samlResponse, $expectedInResponseTo, $expectedAcsUrl, array $authnContext, IdpInfo $idpInfo)
    {
        $responseDocument = XmlDocument::fromString($samlResponse);
        $signerCount = 0;
        if ($responseDocument->hasElement('/samlp:Response/ds:Signature')) {
            // samlp:Response is signed
            Signer::verifyPost($responseDocument, '/samlp:Response', $idpInfo->getPublicKeys());
            ++$signerCount;
        }

        // check the status code
        $statusCode = $responseDocument->getElement('/samlp:Response/samlp:Status/samlp:StatusCode')->getAttribute('Value');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            throw new ResponseException(\sprintf('status error code: %s', $statusCode));
        }

        // make sure we have exactly 1 assertion
        // XXX introduce count method?!
        $responseDocument->getElement('/samlp:Response/saml:Assertion');

        if ($responseDocument->hasElement('/samlp:Response/saml:Assertion/ds:Signature')) {
            // saml:Assertion is signed
            Signer::verifyPost($responseDocument, '/samlp:Response/saml:Assertion', $idpInfo->getPublicKeys());
            ++$signerCount;
        }

        if (0 === $signerCount) {
            throw new ResponseException('neither the response, nor the assertion was signed');
        }

        // the Assertion Issuer MUST be IdP entityId
        $issuerElement = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:Issuer');
        if ($idpInfo->getEntityId() !== $issuerElement->textContent) {
            throw new ResponseException('unexpected Issuer');
        }

        $subjectConfirmationDataElement = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData');
        $notOnOrAfter = new DateTime($subjectConfirmationDataElement->getAttribute('NotOnOrAfter'));
        if ($this->dateTime >= $notOnOrAfter) {
            throw new ResponseException('notOnOrAfter expired');
        }
        if ($expectedAcsUrl !== $subjectConfirmationDataElement->getAttribute('Recipient')) {
            throw new ResponseException('unexpected Recipient');
        }
        if ($expectedInResponseTo !== $subjectConfirmationDataElement->getAttribute('InResponseTo')) {
            throw new ResponseException('unexpected InResponseTo');
        }

        $attributeList = self::extractAttributes($responseDocument);
        $authnContextClassRef = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef')->textContent;

        if (0 !== \count($authnContext)) {
            // we requested a particular authnContext, make sure we got it
            if (!\in_array($authnContextClassRef, $authnContext, true)) {
                throw new ResponseException(\sprintf('we wanted any of "%s"', \implode(', ', $authnContext)));
            }
        }

        $nameId = $responseDocument->getElementString('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID');
        $authnInstant = $responseDocument->getElement('/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext')->getAttribute('AuthnInstant');

        return new Assertion($idpInfo->getEntityId(), $nameId, new DateTime($authnInstant), $authnContextClassRef, $attributeList);
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
