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

use DOMDocument;
use DOMXPath;
use Exception;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var array<string> */
    private $xmlFileList;

    public function __construct(array $xmlFileList)
    {
        $this->xmlFileList = $xmlFileList;
    }

    /**
     * @param string $entityId
     *
     * @return false|IdpInfo
     */
    public function get($entityId)
    {
        foreach ($this->xmlFileList as $xmlFile) {
            // before we directly used DOMDocument::load to load a file, but
            // that didn't work reliably, sometimes it failed to load the XML,
            // not sure what is going on there!
            // now we load the XML in memory which is a BAD idea when using
            // big XML files, e.g. eduGAIN
            if (false === $xmlData = \file_get_contents($xmlFile)) {
                throw new Exception(\sprintf('unable to read "%s"', $xmlFile));
            }
            $domDocument = new DOMDocument();
            if (false === $domDocument->loadXML($xmlData, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT)) {
                throw new Exception(\sprintf('unable to load data from "%s"', $xmlFile));
            }
            $domXPath = new DOMXPath($domDocument);
            $domXPath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $domXPath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

            // check if the IdP is listed in the file
            $queryResult = $domXPath->query(
                \sprintf(
                    '//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor',
                    $entityId
                )
            );

            if (1 !== $queryResult->length) {
                // try next file
                continue;
            }

            // extract *REQUIRED* HTTP-Redirect SingleSignOnService
            $queryResult = $domXPath->query(
                \sprintf(
                    '//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
                    $entityId
                )
            );
            if (1 !== $queryResult->length) {
                throw new Exception('no SingleSignOnService found with HTTP-Redirect binding');
            }
            $singleSignOnServiceLocation = $queryResult->item(0)->getAttribute('Location');

            // extract *OPTIONAL* HTTP-Redirect SingleLogoutService
            $singleLogoutServiceLocation = null;
            $queryResult = $domXPath->query(
                \sprintf(
                    '//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
                    $entityId
                )
            );
            if (1 === $queryResult->length) {
                $singleLogoutServiceLocation = $queryResult->item(0)->getAttribute('Location');
            }

            // extract *REQUIRED* X.509 "signing" certificate
            $queryResult = $domXPath->query(
                \sprintf(
                    '//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                    $entityId
                )
            );
            if (1 !== $queryResult->length) {
                // try without "use"
                $queryResult = $domXPath->query(
                    \sprintf(
                        '//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                        $entityId
                    )
                );
            }
            if (1 !== $queryResult->length) {
                throw new Exception('no X509Certificate found');
            }
            $signingCertificate = self::removeWhitespaces($queryResult->item(0)->textContent);

            return new IdpInfo($entityId, $singleSignOnServiceLocation, $singleLogoutServiceLocation, $signingCertificate);
        }

        return false;
    }

    /**
     * @param string $str
     *
     * @return string
     */
    private static function removeWhitespaces($str)
    {
        return \str_replace([' ', "\t", "\n", "\r", "\0", "\x0b"], '', $str);
    }
}
