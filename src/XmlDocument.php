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
use fkooman\SAML\SP\Exception\XmlDocumentException;

class XmlDocument
{
    /** @var \DOMDocument */
    private $domDocument;

    /** @var \DOMXPath */
    private $domXPath;

    private function __construct(DOMDocument $domDocument)
    {
        $this->domDocument = $domDocument;
        $this->domXPath = new DOMXPath($domDocument);
        $this->domXPath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $this->domXPath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $this->domXPath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    }

    /**
     * @param string $xmlStr
     *
     * @return self
     */
    public static function fromString($xmlStr)
    {
        $domDocument = new DOMDocument();
        $entityLoader = \libxml_disable_entity_loader(true);
        $loadResult = $domDocument->loadXML($xmlStr, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT);
        \libxml_disable_entity_loader($entityLoader);
        if (false === $loadResult) {
            throw new XmlDocumentException('unable to load XML document');
        }

        // validate the document against the SAML schema
        $schemaFile = __DIR__.'/schema/saml-schema-protocol-2.0.xsd';
        $entityLoader = \libxml_disable_entity_loader(false);
        $validateResult = $domDocument->schemaValidate($schemaFile);
        \libxml_disable_entity_loader($entityLoader);
        if (false === $validateResult) {
            throw new XmlDocumentException(\sprintf('schema validation against "%s" failed', $schemaFile));
        }

        return new self($domDocument);
    }

    /**
     * @param string $xPathQuery
     *
     * @return bool
     */
    public function hasElement($xPathQuery)
    {
        $queryResult = $this->domXPath->query($xPathQuery);

        return 1 === $queryResult->length;
    }

    /**
     * @param string $xPathQuery
     *
     * @return \DOMElement
     */
    public function getElement($xPathQuery)
    {
        $queryResult = $this->domXPath->query($xPathQuery);
        if (1 !== $queryResult->length) {
            throw new XmlDocumentException(\sprintf('expected 1 element for query "%s", got %d elements', $xPathQuery, $queryResult->length));
        }

        $resultElement = $queryResult->item(0);
        if (!($resultElement instanceof \DOMElement)) {
            throw new XmlDocumentException('expected DOMElement');
        }

        return $resultElement;
    }

    /**
     * Extract a portion of an XML document as string.
     *
     * @param string $xPathQuery
     *
     * @return string
     */
    public function getElementString($xPathQuery)
    {
        return $this->domDocument->saveXML($this->getElement($xPathQuery));
    }

    /**
     * @param string $xPathQuery
     *
     * @return \DOMNodeList
     */
    public function getElements($xPathQuery)
    {
        return $this->domXPath->query($xPathQuery);
    }
}
