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
use DOMElement;
use DOMXpath;
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
        $responseDocument = XmlDocument::fromProtocolMessage($samlResponse);
        $responseElement = $this->getOneElement($responseDocument, '/samlp:Response');

        // check the status code
        $statusCode = $responseDocument->domXPath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            $statusCodes = [$statusCode];
            // check if we have an additional status code
            $statusCodes[] = $responseDocument->domXPath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value)');

            throw new ResponseException(\sprintf('status error code: %s', \implode(',', $statusCodes)));
        }

        $responseSigned = false;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/ds:Signature');
        if (1 === $domNodeList->length) {
            // samlp:Response is signed
            Signer::verifyPost($responseDocument, $responseElement, $idpInfo->getPublicKeys());
            $responseSigned = true;
        }

        $assertionElement = $this->getOneElement($responseDocument, '/samlp:Response/saml:Assertion');
        $assertionSigned = false;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/saml:Assertion/ds:Signature');
        if (1 === $domNodeList->length) {
            // saml:Assertion is signed
            Signer::verifyPost($responseDocument, $assertionElement, $idpInfo->getPublicKeys());
            $assertionSigned = true;
        }

        if (!$responseSigned && !$assertionSigned) {
            throw new ResponseException('samlp:Response and/or saml:Assertion MUST be signed');
        }

        // the saml:Assertion Issuer MUST be IdP entityId
        $issuerElement = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Issuer)');
        if ($idpInfo->getEntityId() !== $issuerElement) {
            throw new ResponseException('unexpected Issuer');
        }

        $notOnOrAfter = new DateTime($responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)'));
        if ($this->dateTime >= $notOnOrAfter) {
            throw new ResponseException('notOnOrAfter expired');
        }
        $recipient = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient)');
        if ($expectedAcsUrl !== $recipient) {
            throw new ResponseException('unexpected Recipient');
        }
        $inResponseTo = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo)');
        if ($expectedInResponseTo !== $inResponseTo) {
            throw new ResponseException('unexpected InResponseTo');
        }

        $authnInstant = new DateTime($responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/@AuthnInstant)'));

        $authnContextClassRef = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef)');
        if (0 !== \count($authnContext)) {
            // we requested a particular AuthnContext, make sure we got it
            if (!\in_array($authnContextClassRef, $authnContext, true)) {
                throw new ResponseException(\sprintf('we wanted any of "%s"', \implode(', ', $authnContext)));
            }
        }

        $nameId = null;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID');
        if (null !== $nameIdElement = $domNodeList->item(0)) {
            // we got a NameID
            // set the "prefix" to "saml" as that is what we use in LogoutRequests
            // XXX what a mess...
            $nameIdElement->prefix = 'saml';
            $nameId = $responseDocument->domDocument->saveXML($nameIdElement);
        }

        $attributeList = self::extractAttributes($responseDocument->domXPath);

        return new Assertion($idpInfo->getEntityId(), $nameId, $authnInstant, $authnContextClassRef, $attributeList);
    }

    /**
     * @param \DOMXPath $domXPath
     *
     * @return array<string,array<string>>
     */
    private static function extractAttributes(DOMXPath $domXPath)
    {
        $attributeValueElements = $domXPath->query(
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

    /**
     * @param string $xPathQuery
     *
     * @return \DOMElement
     */
    private static function getOneElement(XmlDocument $xmlDocument, $xPathQuery)
    {
        $domNodeList = $xmlDocument->domXPath->query($xPathQuery);
        if (0 === $domNodeList->length) {
            throw new ResponseException(\sprintf('element "%s" not found', $xPathQuery));
        }
        if (1 !== $domNodeList->length) {
            throw new ResponseException(\sprintf('element "%s" found more than once', $xPathQuery));
        }
        $domElement = $domNodeList->item(0);
        if (!($domElement instanceof DOMElement)) {
            throw new ResponseException(\sprintf('element "%s" is not an element', $xPathQuery));
        }

        return $domElement;
    }
}
