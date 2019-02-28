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
use RuntimeException;

class Crypto
{
    const SIGN_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGN_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGN_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGN_HASH_ALGO = 'sha256';

    const ENCRYPT_ALGO = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
    const ENCRYPT_KEY_ALGO = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /**
     * @param XmlDocument      $xmlDocument
     * @param \DOMElement      $domElement
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verifyPost(XmlDocument $xmlDocument, DOMElement $domElement, array $publicKeys)
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

        self::verifySignature($canonicalSignedInfo, Base64::decode($signatureValue), $publicKeys);
    }

    /**
     * @param string     $httpQuery
     * @param PrivateKey $privateKey
     *
     * @return string
     */
    public static function signRedirect($httpQuery, PrivateKey $privateKey)
    {
        if (false === \openssl_sign($httpQuery, $signature, $privateKey->raw(), self::SIGN_OPENSSL_ALGO)) {
            throw new CryptoException('unable to sign');
        }

        return Base64::encode($signature);
    }

    /**
     * @param QueryParameters  $queryParameters
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    public static function verifyRedirect(QueryParameters $queryParameters, array $publicKeys)
    {
        $samlResponse = $queryParameters->requireQueryParameter('SAMLResponse', true);
        $relayState = $queryParameters->requireQueryParameter('RelayState', true);
        $sigAlg = $queryParameters->requireQueryParameter('SigAlg', true);
        // XXX RelayState is actually optional...
        $httpQuery = \sprintf('SAMLResponse=%s&RelayState=%s&SigAlg=%s', $samlResponse, $relayState, $sigAlg);

        self::verifySignature($httpQuery, Base64::decode($queryParameters->requireQueryParameter('Signature')), $publicKeys);
    }

    /**
     * @param XmlDocument $xmlDocument
     * @param \DOMElement $domElement
     * @param PrivateKey  $privateKey
     *
     * @return \DOMElement
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
        if (self::ENCRYPT_KEY_ALGO !== $keyEncryptionMethod) {
            throw new CryptoException(\sprintf('key encryption method "%s" not supported', $keyEncryptionMethod));
        }

        // make sure this system supports aes-256-gcm from libsodium
        if (false === \sodium_crypto_aead_aes256gcm_is_available()) {
            throw new RuntimeException('AES decryption not supported on this hardware');
        }

        // extract the session key
        $keyCipherValue = $xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue)', $domElement);

        // decrypt the session key
        if (false === \openssl_private_decrypt(Base64::decode($keyCipherValue), $symmetricEncryptionKey, $privateKey->raw(), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('unable to extract decryption key');
        }

        // extract the encrypted Assertion
        $assertionCipherValue = Base64::decode($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/xenc:CipherData/xenc:CipherValue)', $domElement));

        // split the nonce and data
        $cipherNonce = Binary::safeSubstr($assertionCipherValue, 0, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $cipherText = Binary::safeSubstr($assertionCipherValue, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);

        // decrypt the Assertion
        if (false === $decryptedAssertion = \sodium_crypto_aead_aes256gcm_decrypt($cipherText, '', $cipherNonce, $symmetricEncryptionKey)) {
            throw new CryptoException('unable to decrypt data');
        }

        // create and validate new document for Assertion
        $assertionDocument = XmlDocument::fromAssertion($decryptedAssertion);

        return XmlDocument::requireDomElement($assertionDocument->domXPath->query('/saml:Assertion')->item(0));
    }

    /**
     * @param string           $data
     * @param string           $signature
     * @param array<PublicKey> $publicKeys
     *
     * @return void
     */
    private static function verifySignature($data, $signature, array $publicKeys)
    {
        foreach ($publicKeys as $publicKey) {
            if (1 === \openssl_verify($data, $signature, $publicKey->raw(), self::SIGN_OPENSSL_ALGO)) {
                return;
            }
        }

        throw new CryptoException('invalid signature');
    }
}
