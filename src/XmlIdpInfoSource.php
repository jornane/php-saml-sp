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

use fkooman\SAML\SP\Exception\XmlIdpInfoSourceException;
use RuntimeException;
use SimpleXMLElement;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var \SimpleXMLElement */
    private $simpleXml;

    /**
     * @param string $metadataFile
     */
    public function __construct($metadataFile)
    {
        $entityLoader = \libxml_disable_entity_loader(false);
        if (false === $this->simpleXml = \simplexml_load_file($metadataFile, 'SimpleXMLElement', LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT)) {
            throw new RuntimeException(\sprintf('unable to read "%s"', $metadataFile));
        }
        $this->simpleXml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        \libxml_disable_entity_loader($entityLoader);
    }

    /**
     * @param string $entityId
     *
     * @return false|IdpInfo
     */
    public function get($entityId)
    {
        $this->simpleXml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $entityInfoResult = $this->simpleXml->xpath(\sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId));
        if (0 !== \count($entityInfoResult)) {
            // we simply return the first entity with this "entityID"
            return new IdpInfo(
                $entityId,
                self::getSingleSignOnService($entityInfoResult[0]),
                self::getPublicKey($entityInfoResult[0])
            );
        }

        return false;
    }

    /**
     * @return array<IdpInfo>
     */
    public function getAll()
    {
        $idpInfoList = [];
        $entityInfoResult = $this->simpleXml->xpath('//md:EntityDescriptor/md:IDPSSODescriptor');
        foreach ($entityInfoResult as $entityInfo) {
            $entityId = (string) $entityInfo->xpath('..')[0]['entityID']; // <<< horribly XXX ugly!
            $idpInfoList[] = new IdpInfo(
                $entityId,
                self::getSingleSignOnService($entityInfoResult[0]),
                self::getPublicKey($entityInfoResult[0])
            );
        }

        return $idpInfoList;
    }

    /**
     * @param \SimpleXMLElement $idpSsoDescriptor
     *
     * @return string
     */
    private static function getSingleSignOnService(SimpleXMLElement $idpSsoDescriptor)
    {
        $idpSsoDescriptor->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $queryResult = $idpSsoDescriptor->xpath('md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location');
        if (0 === \count($queryResult)) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one SingleSignOnService');
        }

        return (string) $queryResult[0]['Location'];
    }

    /**
     * @param \SimpleXMLElement $idpSsoDescriptor
     *
     * @return array<string>
     */
    private static function getPublicKey(SimpleXMLElement $idpSsoDescriptor)
    {
        $publicKeys = [];
        $idpSsoDescriptor->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $queryResult = $idpSsoDescriptor->xpath('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate');
        if (0 === \count($queryResult)) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one X509Certificate');
        }
        foreach ($queryResult as $publicKey) {
            $publicKeys[] = \str_replace([' ', "\t", "\n", "\r", "\0", "\x0B"], '', (string) $publicKey);
        }

        return \array_unique($publicKeys);
    }
}
