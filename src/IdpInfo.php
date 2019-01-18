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

class IdpInfo
{
    /** @var string */
    private $entityId;

    /** @var string */
    private $ssoUrl;

    /** @var array<string> */
    private $publicKeys = [];

    /**
     * @param string        $entityId
     * @param string        $ssoUrl
     * @param array<string> $publicKeys
     */
    public function __construct($entityId, $ssoUrl, array $publicKeys)
    {
        $this->entityId = $entityId;
        $this->ssoUrl = $ssoUrl;
        foreach ($publicKeys as $publicKey) {
            $this->publicKeys[] = "-----BEGIN CERTIFICATE-----\n".\chunk_split($publicKey, 64, "\n").'-----END CERTIFICATE-----';
        }
    }

    /**
     * @return string
     */
    public function getEntityId()
    {
        return $this->entityId;
    }

    /**
     * @return string
     */
    public function getSsoUrl()
    {
        return $this->ssoUrl;
    }

    /**
     * @return array<string>
     */
    public function getPublicKeys()
    {
        return $this->publicKeys;
    }
}
