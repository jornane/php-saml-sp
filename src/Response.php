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
     * @param SpInfo        $spInfo
     * @param IdpInfo       $idpInfo
     * @param string        $samlResponse
     * @param string        $expectedInResponseTo
     * @param array<string> $authnContext
     *
     * @return Assertion
     */
    public function verify(SpInfo $spInfo, IdpInfo $idpInfo, $samlResponse, $expectedInResponseTo, array $authnContext)
    {
        $responseSigned = false;
        $assertionEncrypted = false;
        $assertionSigned = false;

        $responseDocument = XmlDocument::fromProtocolMessage($samlResponse);
        $responseElement = XmlDocument::requireDomElement($responseDocument->domXPath->query('/samlp:Response')->item(0));

        $domNodeList = $responseDocument->domXPath->query('ds:Signature', $responseElement);
        if (1 === $domNodeList->length) {
            // samlp:Response is signed
            Crypto::verifyXml($responseDocument, $responseElement, $idpInfo->getPublicKeys());
            $responseSigned = true;
        }

        // handle samlp:Status
        $statusCodeElement = XmlDocument::requireDomElement($responseDocument->domXPath->query('samlp:Status/samlp:StatusCode', $responseElement)->item(0));
        $statusCode = $statusCodeElement->getAttribute('Value');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            // check if there is a second-level status code
            $secondLevelStatusCode = null;
            $domNodeList = $responseDocument->domXPath->query('samlp:StatusCode', $statusCodeElement);
            if (1 === $domNodeList->length) {
                $secondLevelStatusCode = XmlDocument::requireDomElement($domNodeList->item(0))->getAttribute('Value');
            }
            $exceptionMsg = null === $secondLevelStatusCode ? $statusCode : \sprintf('%s (%s)', $statusCode, $secondLevelStatusCode);

            throw new ResponseException($exceptionMsg);
        }

        $domNodeList = $responseDocument->domXPath->query('saml:EncryptedAssertion', $responseElement);
        if (1 === $domNodeList->length) {
            // saml:EncryptedAssertion
            $encryptedAssertionElement = XmlDocument::requireDomElement($domNodeList->item(0));
            $decryptedAssertion = Crypto::decryptXml($responseDocument, $encryptedAssertionElement, $spInfo->getPrivateKey());

            // create and validate new document for Assertion
            $assertionDocument = XmlDocument::fromAssertion($decryptedAssertion);
            $assertionElement = XmlDocument::requireDomElement($assertionDocument->domXPath->query('/saml:Assertion')->item(0));

            // we replace saml:EncryptedAssertion with saml:Assertion in the original document
            $responseElement->replaceChild(
                $responseDocument->domDocument->importNode($assertionElement, true),
                $encryptedAssertionElement
            );
            $assertionEncrypted = true;
        }

        if ($spInfo->getRequireEncryptedAssertion() && !$assertionEncrypted) {
            throw new ResponseException('assertion was not encrypted, but encryption is enforced');
        }

        // now we MUST have a saml:Assertion
        $assertionElement = XmlDocument::requireDomElement($responseDocument->domXPath->query('saml:Assertion', $responseElement)->item(0));

        $domNodeList = $responseDocument->domXPath->query('ds:Signature', $assertionElement);
        if (1 === $domNodeList->length) {
            // saml:Assertion is signed
            Crypto::verifyXml($responseDocument, $assertionElement, $idpInfo->getPublicKeys());
            $assertionSigned = true;
        }

        if (!$responseSigned && !$assertionSigned) {
            throw new ResponseException('samlp:Response and/or saml:Assertion MUST be signed');
        }

        // the saml:Assertion Issuer MUST be IdP entityId
        $issuerElement = $responseDocument->domXPath->evaluate('string(saml:Issuer)', $assertionElement);
        if ($issuerElement !== $idpInfo->getEntityId()) {
            throw new ResponseException(\sprintf('expected saml:Issuer "%s", got "%s"', $idpInfo->getEntityId(), $issuerElement));
        }

        // the saml:Conditions/saml:AudienceRestriction MUST be us
        $audienceElement = $responseDocument->domXPath->evaluate('string(saml:Conditions/saml:AudienceRestriction/saml:Audience)', $assertionElement);
        if ($audienceElement !== $spInfo->getEntityId()) {
            throw new ResponseException(\sprintf('expected saml:Audience "%s", got "%s"', $spInfo->getEntityId(), $audienceElement));
        }

        $notOnOrAfter = new DateTime($responseDocument->domXPath->evaluate('string(saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)', $assertionElement));
        if (DateTimeValidator::isOnOrAfter($this->dateTime, $notOnOrAfter)) {
            throw new ResponseException('saml:Assertion no longer valid (/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)');
        }

        $recipient = $responseDocument->domXPath->evaluate('string(saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient)', $assertionElement);
        if ($recipient !== $spInfo->getAcsUrl()) {
            throw new ResponseException(\sprintf('expected Recipient "%s", got "%s"', $spInfo->getAcsUrl(), $recipient));
        }

        $inResponseTo = $responseDocument->domXPath->evaluate('string(saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo)', $assertionElement);
        if ($inResponseTo !== $expectedInResponseTo) {
            throw new ResponseException(\sprintf('expected InResponseTo "%s", got "%s"', $expectedInResponseTo, $inResponseTo));
        }

        // notBefore
        $notBefore = new DateTime($responseDocument->domXPath->evaluate('string(saml:Conditions/@NotBefore)', $assertionElement));
        if (DateTimeValidator::isBefore($this->dateTime, $notBefore)) {
            throw new ResponseException('saml:Assertion not yet valid (/samlp:Response/saml:Assertion/saml:Conditions/@NotBefore)');
        }

        $authnInstant = new DateTime($responseDocument->domXPath->evaluate('string(saml:AuthnStatement/saml:AuthnContext/@AuthnInstant)', $assertionElement));

        $authnContextClassRef = $responseDocument->domXPath->evaluate('string(saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef)', $assertionElement);
        if (0 !== \count($authnContext)) {
            // we requested a particular AuthnContext, make sure we got it
            if (!\in_array($authnContextClassRef, $authnContext, true)) {
                throw new ResponseException(\sprintf('expected AuthnContext containing any of [%s], got "%s"', \implode(',', $authnContext), $authnContextClassRef));
            }
        }

        $attributeList = self::extractAttributes($idpInfo->getEntityId(), $spInfo->getEntityId(), $responseDocument);
        $samlAssertion = new Assertion($idpInfo->getEntityId(), $authnInstant, $authnContextClassRef, $attributeList);

        // NameID
        $domNodeList = $responseDocument->domXPath->query('saml:Subject/saml:NameID', $assertionElement);
        if (null !== $nameIdNode = $domNodeList->item(0)) {
            $nameId = new NameId($idpInfo->getEntityId(), $spInfo->getEntityId(), XmlDocument::requireDomElement($nameIdNode));
            $samlAssertion->setNameId($nameId);
        }

        return $samlAssertion;
    }

    /**
     * @param string      $idpEntityId
     * @param string      $spEntityId
     * @param XmlDocument $domXPath
     *
     * @return array<string,array<string>>
     */
    private static function extractAttributes($idpEntityId, $spEntityId, XmlDocument $xmlDocument)
    {
        $attributeList = [];
        $attributeDomNodeList = $xmlDocument->domXPath->query('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute');
        foreach ($attributeDomNodeList as $attributeDomNode) {
            $attributeElement = XmlDocument::requireDomElement($attributeDomNode);
            $attributeName = $attributeElement->getAttribute('Name');
            $attributeList[$attributeName] = [];
            if ('urn:oid:1.3.6.1.4.1.5923.1.1.1.10' === $attributeName) {
                // ePTID (eduPersonTargetedId) is a special case as it wraps an
                // saml:NameID construct and not "simple" string values...
                $nameIdElement = XmlDocument::requireDomElement($xmlDocument->domXPath->query('saml:AttributeValue/saml:NameID', $attributeElement)->item(0));
                $nameId = new NameId($idpEntityId, $spEntityId, $nameIdElement);
                $attributeList['urn:oid:1.3.6.1.4.1.5923.1.1.1.10'][] = $nameId->toUserId();
                continue;
            }
            // XXX verify ePPN and subject-id/pairwise-id for IdPInfo->getScopeList()
            $attributeValueDomNodeList = $xmlDocument->domXPath->query('saml:AttributeValue', $attributeElement);
            // loop over AttributeValue
            foreach ($attributeValueDomNodeList as $attributeValueDomNode) {
                $attributeValueElement = XmlDocument::requireDomElement($attributeValueDomNode);
                $attributeList[$attributeName][] = $attributeValueElement->textContent;
            }
        }

        return $attributeList;
    }
}
