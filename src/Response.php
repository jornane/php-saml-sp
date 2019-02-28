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
        $responseDocument = XmlDocument::fromProtocolMessage($samlResponse);
        $responseElement = XmlDocument::requireDomElement($responseDocument->domXPath->query('/samlp:Response')->item(0));

        // check the status code
        $statusCode = $responseDocument->domXPath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            $statusCodes = [$statusCode];
            // check if we have an additional status code
            $statusCodes[] = $responseDocument->domXPath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value)');
            // XXX better error, this is useless...
            throw new ResponseException(\sprintf('status error code: %s', \implode(',', $statusCodes)));
        }

        $responseSigned = false;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/ds:Signature');
        if (1 === $domNodeList->length) {
            // samlp:Response is signed
            Crypto::verifyPost($responseDocument, $responseElement, $idpInfo->getPublicKeys());
            $responseSigned = true;
        }

        $assertionEncrypted = false;

        // we used XML schema hardening to force that there is exactly 1 saml:Assertion / saml:EncryptedAssertion (saml2int)
        // did we get an EncryptedAssertion?
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/saml:EncryptedAssertion');
        if (1 === $domNodeList->length) {
            // EncryptedAssertion
            $encryptedAssertionElement = XmlDocument::requireDomElement($domNodeList->item(0));
            $assertionElement = Crypto::decryptAssertion($responseDocument, $encryptedAssertionElement, $spInfo->getPrivateKey());

            // we replace saml:EncryptedAssertion with saml:Assertion in the original document
            $responseElement->replaceChild(
                $responseDocument->domDocument->importNode($assertionElement, true),
                $encryptedAssertionElement
            );
            $assertionEncrypted = true;
        }

        if ($spInfo->getRequireEncryptedAssertion() && !$assertionEncrypted) {
            throw new ResponseException('assertion not encrypted, but encryption required');
        }

        // now we MUST have a saml:Assertion
        $assertionElement = XmlDocument::requireDomElement($responseDocument->domXPath->query('/samlp:Response/saml:Assertion')->item(0));

        $assertionSigned = false;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/saml:Assertion/ds:Signature');
        if (1 === $domNodeList->length) {
            // saml:Assertion is signed
            Crypto::verifyPost($responseDocument, $assertionElement, $idpInfo->getPublicKeys());
            $assertionSigned = true;
        }

        if (!$responseSigned && !$assertionSigned) {
            throw new ResponseException('samlp:Response and/or saml:Assertion MUST be signed');
        }

        // the saml:Assertion Issuer MUST be IdP entityId
        $issuerElement = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Issuer)');
        if ($idpInfo->getEntityId() !== $issuerElement) {
            throw new ResponseException(\sprintf('expected saml:Issuer "%s", got "%s"', $idpInfo->getEntityId(), $issuerElement));
        }

        // the saml:Conditions/saml:AudienceRestriction MUST be us
        $audienceElement = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience)');
        if ($audienceElement !== $spInfo->getEntityId()) {
            throw new ResponseException(\sprintf('expected saml:Audience "%s", got "%s"', $spInfo->getEntityId(), $audienceElement));
        }

        $notOnOrAfter = new DateTime($responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)'));
        if (DateTimeValidator::isOnOrAfter($this->dateTime, $notOnOrAfter)) {
            throw new ResponseException('saml:Assertion no longer valid (/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)');
        }

        $recipient = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient)');
        if ($spInfo->getAcsUrl() !== $recipient) {
            throw new ResponseException(\sprintf('expected Recipient "%s", got "%s"', $spInfo->getAcsUrl(), $recipient));
        }

        $inResponseTo = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo)');
        if ($expectedInResponseTo !== $inResponseTo) {
            throw new ResponseException(\sprintf('expected InResponseTo "%s", got "%s"', $expectedInResponseTo, $inResponseTo));
        }

        // notBefore
        $notBefore = new DateTime($responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:Conditions/@NotBefore)'));
        if (DateTimeValidator::isBefore($this->dateTime, $notBefore)) {
            throw new ResponseException('saml:Assertion not yet valid (/samlp:Response/saml:Assertion/saml:Conditions/@NotBefore)');
        }

        $authnInstant = new DateTime($responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/@AuthnInstant)'));

        $authnContextClassRef = $responseDocument->domXPath->evaluate('string(/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef)');
        if (0 !== \count($authnContext)) {
            // we requested a particular AuthnContext, make sure we got it
            if (!\in_array($authnContextClassRef, $authnContext, true)) {
                throw new ResponseException(\sprintf('expected AuthnContext containing any of [%s], got "%s"', \implode(',', $authnContext), $authnContextClassRef));
            }
        }

        $attributeList = self::extractAttributes($idpInfo->getEntityId(), $spInfo->getEntityId(), $responseDocument->domXPath);
        $samlAssertion = new Assertion($idpInfo->getEntityId(), $authnInstant, $authnContextClassRef, $attributeList);

        $nameId = null;
        $domNodeList = $responseDocument->domXPath->query('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID');
        if (null !== $nameIdNode = $domNodeList->item(0)) {
            $nameId = new NameId($idpInfo->getEntityId(), $spInfo->getEntityId(), XmlDocument::requireDomElement($nameIdNode));
        }

        if (null !== $nameId) {
            $samlAssertion->setNameId($nameId);
        }

        return $samlAssertion;
    }

    /**
     * @param string    $idpEntityId
     * @param string    $spEntityId
     * @param \DOMXPath $domXPath
     *
     * @return array<string,array<string>>
     */
    private static function extractAttributes($idpEntityId, $spEntityId, DOMXPath $domXPath)
    {
        $attributeValueElements = $domXPath->query(
            '/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue'
        );
        $attributeList = [];
        foreach ($attributeValueElements as $attributeValueElement) {
            $parentElement = XmlDocument::requireDomElement($attributeValueElement->parentNode);
            $attributeName = $parentElement->getAttribute('Name');
            if (!\array_key_exists($attributeName, $attributeList)) {
                $attributeList[$attributeName] = [];
            }
            if ('urn:oid:1.3.6.1.4.1.5923.1.1.1.10' === $attributeName) {
                // eduPersonTargetedId, serialize this accordingly
                $nameId = new NameId($idpEntityId, $spEntityId, XmlDocument::requireDomElement($attributeValueElement));
                $attributeValue = $nameId->serialize();
            } else {
                $attributeValue = \trim($attributeValueElement->textContent);
            }

            $attributeList[$attributeName][] = $attributeValue;
        }

        return $attributeList;
    }
}
