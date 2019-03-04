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

use ParagonIE\ConstantTime\Binary;

class Oaep
{
    const ENCRYPT_OAEP_MGF1_DIGEST = 'sha1';
    const ENCRYPT_OAEP_MGF1_DIGEST_LEN = 20; // php -r "echo strlen(hash('sha1', '', true));"
    const ENCRYPT_OAEP_DIGEST = 'sha1';
    const ENCRYPT_OAEP_DIGEST_LEN = 20;      // php -r "echo strlen(hash('sha1', '', true));"

//    const ENCRYPT_OAEP_DIGEST = 'sha256';
//    const ENCRYPT_OAEP_DIGEST_LEN = 32;      // php -r "echo strlen(hash('sha256', '', true));"

    /**
     * OpenSSL in PHP only supports "OAEP" with MFG1 where SHA-1 is used for
     * both MGF1 and the digest. This method implements just the OAEP padding
     * removal after decryption.
     *
     * @param string $encodedMessage
     * @param int    $modLen
     *
     * @return false|string
     */
    public static function decode($encodedMessage, $modLen)
    {
        // padded string MUST be length of n (modulus of RSA key)
        // Length checking
        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.
        if (Binary::safeStrlen($encodedMessage) !== $modLen || $modLen < 2 * self::ENCRYPT_OAEP_DIGEST_LEN + 2) {
            return false;
        }

        // EME-OAEP decoding
        $lHash = \hash(self::ENCRYPT_OAEP_DIGEST, '', true);
        $y = \ord($encodedMessage[0]);
        $maskedSeed = Binary::safeSubstr($encodedMessage, 1, self::ENCRYPT_OAEP_DIGEST_LEN);
        $maskedDB = Binary::safeSubstr($encodedMessage, self::ENCRYPT_OAEP_DIGEST_LEN + 1);
        $seedMask = self::mgf1($maskedDB, self::ENCRYPT_OAEP_DIGEST_LEN);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::mgf1($seed, $modLen - self::ENCRYPT_OAEP_DIGEST_LEN - 1);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = Binary::safeSubstr($db, 0, self::ENCRYPT_OAEP_DIGEST_LEN);
        $m = Binary::safeSubstr($db, self::ENCRYPT_OAEP_DIGEST_LEN);
        // XXX make sure hash_equals has correct order!
        if (!\hash_equals($lHash, $lHash2)) {
            return false;
        }

        $m = \ltrim($m, \chr(0));
        if (1 !== \ord($m[0])) {
            return false;
        }

        return Binary::safeSubstr($m, 1);
    }

    /**
     * @param string $mgfSeed
     * @param int    $maskLen
     *
     * @return string
     */
    private static function mgf1($mgfSeed, $maskLen)
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.
        $t = '';
        $count = \ceil($maskLen / self::ENCRYPT_OAEP_MGF1_DIGEST_LEN);
        for ($i = 0; $i < $count; ++$i) {
            $c = \pack('N', $i);
            $t .= \hash(self::ENCRYPT_OAEP_MGF1_DIGEST, $mgfSeed.$c, true);
        }

        return Binary::safeSubstr($t, 0, $maskLen);
    }
}
