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

class SpInfo
{
    /** @var string */
    private $entityId;

    /** @var PrivateKey */
    private $privateKey;

    /** @var PublicKey */
    private $publicKey;

    /** @var string */
    private $acsUrl;

    /** @var string|null */
    private $sloUrl = null;

    /** @var bool */
    private $requireEncryptedAssertion = false;

    /**
     * @param string     $entityId
     * @param PrivateKey $privateKey
     * @param PublicKey  $publicKey
     * @param string     $acsUrl
     */
    public function __construct($entityId, PrivateKey $privateKey, PublicKey $publicKey, $acsUrl)
    {
        $this->entityId = $entityId;
        $this->acsUrl = $acsUrl;
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * @return string
     */
    public function getEntityId()
    {
        return $this->entityId;
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function getAcsUrl()
    {
        return $this->acsUrl;
    }

    /**
     * @param string $sloUrl
     *
     * @return void
     */
    public function setSloUrl($sloUrl)
    {
        $this->sloUrl = $sloUrl;
    }

    /**
     * @return string|null
     */
    public function getSloUrl()
    {
        return $this->sloUrl;
    }

    /**
     * @param bool $requireEncryptedAssertion
     *
     * @return void
     */
    public function setRequireEncryptedAssertion($requireEncryptedAssertion)
    {
        $this->requireEncryptedAssertion = $requireEncryptedAssertion;
    }

    /**
     * @return bool
     */
    public function getRequireEncryptedAssertion()
    {
        return $this->requireEncryptedAssertion;
    }
}
