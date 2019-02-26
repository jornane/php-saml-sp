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
use fkooman\SAML\SP\Exception\XmlIdpInfoSourceException;
use RuntimeException;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var XmlDocument */
    private $xmlDocument;

    /**
     * @param string $metadataFile
     */
    public function __construct($metadataFile)
    {
        if (false === $xmlData = \file_get_contents($metadataFile)) {
            throw new RuntimeException(\sprintf('unable to read file "%s"', $metadataFile));
        }

        $this->xmlDocument = XmlDocument::fromMetadata(
            $xmlData,
            // XXX we have to be a bit smarter here! potential trouble!
            // do NOT validate the schema, we assume the XML is validated and
            // trusted...
            false
        );
    }

    /**
     * @param string $entityId
     *
     * @return false|IdpInfo
     */
    public function get($entityId)
    {
        $xPathQuery = \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId);
        $domNodeList = $this->xmlDocument->domXPath->query($xPathQuery);
        if (0 === $domNodeList->length) {
            // IdP not found
            return false;
        }
        if (1 !== $domNodeList->length) {
            // IdP found more than once?
            throw new XmlIdpInfoSourceException(\sprintf('IdP "%s" found more than once', $entityId));
        }
        $domElement = XmlDocument::requireDomElement($domNodeList->item(0));

        return new IdpInfo(
            $entityId,
            $this->getSingleSignOnService($domElement),
            $this->getSingleLogoutService($domElement),
            $this->getPublicKeys($domElement)
        );
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return string
     */
    private function getSingleSignOnService(DOMElement $domElement)
    {
        $domNodeList = $this->xmlDocument->domXPath->query('md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            throw new XmlIdpInfoSourceException('no "md:SingleSignOnService" available');
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return string|null
     */
    private function getSingleLogoutService(DOMElement $domElement)
    {
        $domNodeList = $this->xmlDocument->domXPath->query('md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            return null;
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return array<PublicKey>
     */
    private function getPublicKeys(DOMElement $domElement)
    {
        $publicKeys = [];
        $domNodeList = $this->xmlDocument->domXPath->query('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $domElement);
        if (0 === $domNodeList->length) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one X509Certificate');
        }
        for ($i = 0; $i < $domNodeList->length; ++$i) {
            $certificateNode = $domNodeList->item($i);
            if (null !== $certificateNode) {
                $publicKeys[] = PublicKey::fromEncodedString($certificateNode->textContent);
            }
        }

        return $publicKeys;
    }
}
