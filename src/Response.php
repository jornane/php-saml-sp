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
use DOMDocument;
use DOMXPath;
use Exception;

class Response
{
    /** @var string */
    private $schemaDir;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param string $schemaDir
     */
    public function __construct($schemaDir)
    {
        $this->schemaDir = $schemaDir;
        $this->dateTime = new DateTime();
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
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
        $x = $this->getDomDocument($samlResponse);

        // 4.1.4.3 <Response> Message Processing Rules
        // * Verify any signatures present on the assertion(s) or the response
        // * Verify that the Recipient attribute in any bearer <SubjectConfirmationData> matches the assertion consumer service URL to which the <Response> or artifact was delivered
        // * Verify that the NotOnOrAfter attribute in any bearer <SubjectConfirmationData> has not passed, subject to allowable clock skew between the providers
        // * Verify that the InResponseTo attribute in the bearer <SubjectConfirmationData> equals the ID of its original <AuthnRequest> message, unless the response is unsolicited (see Section 4.1.5), in which case the attribute MUST NOT be present
        // * Verify that any assertions relied upon are valid in other respects
        // * If any bearer <SubjectConfirmationData> includes an Address attribute, the service provider MAY check the user agent's client address against it.
        // * Any assertion which is not valid, or whose subject confirmation requirements cannot be met SHOULD be discarded and SHOULD NOT be used to establish a security context for the principal.
        // * If an <AuthnStatement> used to establish a security context for the principal contains a SessionNotOnOrAfter attribute, the security context SHOULD be discarded once this time isreached, unless the service provider reestablishes the principal's identity by repeating the use of this profile.

        // * The service provider MUST ensure that bearer assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid based on the NotOnOrAfter attribute in the <SubjectConfirmationData>.

        // XXX verify status code in response, maybe

        $sigCount = 0;
        if (self::hasElement($x, '/samlp:Response/ds:Signature')) {
            $this->verifySignature($x, '/samlp:Response', $idpInfo);
            ++$sigCount;
        }

        if (self::hasElement($x, '/samlp:Response/saml:Assertion/ds:Signature')) {
            $this->verifySignature($x, '/samlp:Response/saml:Assertion', $idpInfo);
            ++$sigCount;
        }
        if (0 === $sigCount) {
            throw new Exception('neither the response, nor the assertion was signed');
        }

        $subjectConfirmationDataElement = self::getOneElement($x, '/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData');
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
        $attributeList = self::extractAttributes($x);

        return new Assertion($attributeList);
    }

    /**
     * @param \DOMXPath $d
     * @param mixed     $sigPrefix
     *
     * @return void
     */
    private function verifySignature(DOMXPath $x, $sigPrefix, IdPInfo $idpInfo)
    {
        $signedElement = self::getOneElement($x, $sigPrefix);
        $signedElementId = $signedElement->getAttribute('ID');

        // the response Issuer MUST be IdP entityId
        $issuerElement = self::getOneElement($x, $sigPrefix.'/saml:Issuer');
        if ($idpInfo->getEntityId() !== $issuerElement->textContent) {
            throw new Exception('unexpected Issuer');
        }

        // 4. TODO check whether the *response* is signed, or the *assertion*, for now we
        //    expect the Response to be signed
        $signatureElement = self::getOneElement($x, $sigPrefix.'/ds:Signature');

        // 5. make sure the Reference points to Response
        $referenceElement = self::getOneElement($x, $sigPrefix.'/ds:Signature/ds:SignedInfo/ds:Reference');
        $referenceUri = $referenceElement->getAttribute('URI');

        if ('#'.$signedElementId !== $referenceUri) {
            throw new Exception('reference URI does not point to Response document ID');
        }

        // 3. get the SignatureValue from XML (from Response OR from Assertion)
        $signatureValueElement = self::getOneElement($x, $sigPrefix.'/ds:Signature/ds:SignatureValue');
        $signatureValueStr = $signatureValueElement->textContent;

        // 4. get the DigestValue from XML
        $digestValueElement = self::getOneElement($x, $sigPrefix.'/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue');
        $digestValueStr = $digestValueElement->textContent;

        $signedInfoElement = self::getOneElement($x, $sigPrefix.'/ds:Signature/ds:SignedInfo');
        $signedInfoElementCanonical = $signedInfoElement->C14N(true, false);

        // 6. remove the Signature from the XML
        $signedElement->removeChild($signatureElement);

        // calculate the digest over the Response element without the Signature
        // element
        $signedElementDigest = \base64_encode(
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
        if (1 !== \openssl_verify($signedInfoElementCanonical, \base64_decode($signatureValueStr, true), $idpInfo->getPublicKey(), OPENSSL_ALGO_SHA256)) {
            throw new Exception('invalid signature over SignedInfo');
        }
    }

    /**
     * @param \DOMXPath $d
     * @param string    $xQuery
     *
     * @return bool
     */
    private static function hasElement(DOMXPath $d, $xQuery)
    {
        $queryResponse = $d->query($xQuery);

        return 0 !== $queryResponse->count();
    }

    /**
     * @param \DOMXPath $d
     * @param string    $xQuery
     *
     * @return \DOMElement
     */
    private static function getOneElement(DOMXPath $d, $xQuery)
    {
        $queryResponse = $d->query($xQuery);
        if (1 !== $queryResponse->count()) {
            throw new Exception(\sprintf('expected exactly 1 element for "%s"', $xQuery));
        }

        $e = $queryResponse->item(0);
        if (!($e instanceof \DOMElement)) {
            throw new Exception('expected DOMElement');
        }

        return $e;
    }

    /**
     * @return array<string,array<string>>
     */
    private static function extractAttributes(DOMXPath $d)
    {
        $queryResponse = $d->query('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute');
        // find all attribute names
        $attributeList = [];
        foreach ($queryResponse as $qR) {
            $attributeList[$qR->getAttribute('Name')] = [];
        }

        // find the attribute values
        foreach (\array_keys($attributeList) as $attrName) {
            $queryResponse = $d->query(\sprintf('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue', $attrName));
            foreach ($queryResponse as $qR) {
                // XXX this does NOT always work, only when there is actually textContent...
                $attributeList[$attrName][] = $qR->textContent;
            }
        }

        return $attributeList;
    }

    /**
     * @param string $xmlStr
     *
     * @return \DOMXPath
     */
    private function getDomDocument($xmlStr)
    {
        $domDocument = new DOMDocument();
        $domDocument->loadXML($xmlStr, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT);
        $schemaFile = \sprintf('%s/saml-schema-protocol-2.0.xsd', $this->schemaDir);
        if (false === $domDocument->schemaValidate($schemaFile)) {
            throw new Exception('schema validation failed');
        }
        // XXX do we still need to disable entity loader?! then schema validation does NOT work
        //     temporary enable it after loading the doc?!
        // XXX do we still need to protect against XXE?
        // @see https://phpsecurity.readthedocs.io/en/latest/Injection-Attacks.html#xml-injection
        $domXPath = new DOMXPath($domDocument);
        $domXPath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $domXPath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $domXPath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        return $domXPath;
    }
}
