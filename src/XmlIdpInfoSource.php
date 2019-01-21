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

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var XmlDocument */
    private $xmlDocument;

    /**
     * @param string $metadataFile
     */
    public function __construct($metadataFile)
    {
        // XXX make sure we can read the file
        $this->xmlDocument = XmlDocument::fromMetadata(
            \file_get_contents($metadataFile),
            // do not validate the schema
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
        $domNodeList = $this->xmlDocument->domXPath->query(\sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId));
        if (0 !== $domNodeList->length) {
            // we simply return the first entity with this "entityID"
            return new IdpInfo(
                $entityId,
                $this->getSingleSignOnService($domNodeList->item(0)),
                $this->getPublicKey($domNodeList->item(0))
            );
        }

        return false;
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return string
     */
    private function getSingleSignOnService(DOMElement $domElement)
    {
        // XXX what if there is more than one result?!
        return $this->xmlDocument->domXPath->evaluate('string(md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location)', $domElement);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return array<string>
     */
    private function getPublicKey(DOMElement $domElement)
    {
        $publicKeys = [];
        $domNodeList = $this->xmlDocument->domXPath->query('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $domElement);
        if (0 === $domNodeList->length) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one X509Certificate');
        }
        for ($i = 0; $i < $domNodeList->length; ++$i) {
            $publicKeys[] = \str_replace([' ', "\t", "\n", "\r", "\0", "\x0B"], '', $domNodeList->item($i)->textContent);
        }

        return \array_unique($publicKeys);
    }
}
