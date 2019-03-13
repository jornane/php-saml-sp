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
use fkooman\SAML\SP\Exception\CryptoException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Binary;

class Crypto
{
    const SIGN_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGN_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGN_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGN_HASH_ALGO = 'sha256';

    const ENCRYPT_OPENSSL_ALGO = 'aes-256-gcm';
    const ENCRYPT_ALGO = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
    const ENCRYPT_KEY_DIGEST_ALGO = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const ENCRYPT_KEY_ALGO_LIST = [
        'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
        'http://www.w3.org/2001/04/xmlenc#rsa-oaep',
    ];
    const ENCRYPT_KEY_LEN = 32;
    const ENCRYPT_TAG_LEN = 16; // GCM authentication tag is always 128 bits

    /**
     * @param XmlDocument      $xmlDocument
     * @param \DOMElement      $domElement
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verifyXml(XmlDocument $xmlDocument, DOMElement $domElement, array $publicKeys)
    {
        $rootElementId = $xmlDocument->domXPath->evaluate('string(self::node()/@ID)', $domElement);
        $referenceUri = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/@URI)', $domElement);
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new CryptoException('reference URI does not point to document ID');
        }

        $digestMethod = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm)', $domElement);
        if (self::SIGN_DIGEST_ALGO !== $digestMethod) {
            throw new CryptoException(\sprintf('digest method "%s" not supported', $digestMethod));
        }

        $signatureMethod = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $domElement);
        if (self::SIGN_ALGO !== $signatureMethod) {
            throw new CryptoException(\sprintf('signature method "%s" not supported', $signatureMethod));
        }

        $signatureValue = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignatureValue)', $domElement);
        $digestValue = $xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue)', $domElement);

        $signedInfoElement = XmlDocument::requireDomElement($xmlDocument->domXPath->query('ds:Signature/ds:SignedInfo', $domElement)->item(0));
        $canonicalSignedInfo = $signedInfoElement->C14N(true, false);
        $signatureElement = XmlDocument::requireDomElement($xmlDocument->domXPath->query('ds:Signature', $domElement)->item(0));
        $domElement->removeChild($signatureElement);

        $rootElementDigest = Base64::encode(
            \hash(
                self::SIGN_HASH_ALGO,
                $domElement->C14N(true, false),
                true
            )
        );

        // compare the digest from the XML with the actual digest
        if (!\hash_equals($rootElementDigest, $digestValue)) {
            throw new CryptoException('unexpected digest');
        }

        self::verify($canonicalSignedInfo, Base64::decode($signatureValue), $publicKeys);
    }

    /**
     * @param string           $inStr
     * @param string           $inSig
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verify($inStr, $inSig, array $publicKeys)
    {
        foreach ($publicKeys as $publicKey) {
            if (1 === \openssl_verify($inStr, $inSig, $publicKey->raw(), self::SIGN_OPENSSL_ALGO)) {
                // signature verified
                return;
            }
        }

        throw new CryptoException('unable to verify signature');
    }

    /**
     * @param string     $inStr
     * @param PrivateKey $privateKey
     *
     * @return string
     */
    public static function sign($inStr, PrivateKey $privateKey)
    {
        if (false === \openssl_sign($inStr, $outSig, $privateKey->raw(), self::SIGN_OPENSSL_ALGO)) {
            throw new CryptoException('unable to create signature');
        }

        return $outSig;
    }

    /**
     * @param XmlDocument $xmlDocument
     * @param \DOMElement $domElement
     * @param PrivateKey  $privateKey
     *
     * @return string
     */
    public static function decryptXml(XmlDocument $xmlDocument, DOMElement $domElement, PrivateKey $privateKey)
    {
        // make sure we support the encryption algorithm
        $encryptionMethod = $xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)', $domElement);
        if (self::ENCRYPT_ALGO !== $encryptionMethod) {
            throw new CryptoException(\sprintf('encryption method "%s" not supported', $encryptionMethod));
        }

        // make sure we support the key transport encryption algorithm
        $keyEncryptionMethod = $xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)', $domElement);
        if (!\in_array($keyEncryptionMethod, self::ENCRYPT_KEY_ALGO_LIST, true)) {
            throw new CryptoException(\sprintf('key encryption algorithm "%s" not supported', $keyEncryptionMethod));
        }

        // make sure we support the key transport encryption digest algorithm
        $keyEncryptionDigestMethod = $xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm)', $domElement);
        if (self::ENCRYPT_KEY_DIGEST_ALGO !== $keyEncryptionDigestMethod) {
            throw new CryptoException(\sprintf('key encryption digest "%s" not supported', $keyEncryptionDigestMethod));
        }

        // extract the session key
        $keyCipherValue = $xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue)', $domElement);

        // decrypt the session key
        if (false === \openssl_private_decrypt(Base64::decode($keyCipherValue), $symmetricEncryptionKey, $privateKey->raw(), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('unable to extract session key');
        }

        // make sure the obtained key is the exact length we expect
        if (self::ENCRYPT_KEY_LEN !== Binary::safeStrLen($symmetricEncryptionKey)) {
            throw new CryptoException('extracted session key has unexpected length');
        }

        // extract the encrypted Assertion
        $assertionCipherValue = Base64::decode($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/xenc:CipherData/xenc:CipherValue)', $domElement));

        // extract the nonce (IV), cipher text and authentication tag
        $ivLength = \openssl_cipher_iv_length(self::ENCRYPT_OPENSSL_ALGO);
        $cipherNonce = Binary::safeSubstr($assertionCipherValue, 0, $ivLength);
        $cipherText = Binary::safeSubstr($assertionCipherValue, $ivLength, -self::ENCRYPT_TAG_LEN);
        $authTag = Binary::safeSubstr($assertionCipherValue, -self::ENCRYPT_TAG_LEN);

        // decrypt the Assertion
        if (false === $decryptedAssertion = \openssl_decrypt($cipherText, self::ENCRYPT_OPENSSL_ALGO, $symmetricEncryptionKey, OPENSSL_RAW_DATA, $cipherNonce, $authTag)) {
            throw new CryptoException('unable to decrypt data');
        }

        return $decryptedAssertion;
    }
}
