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

/**
 * Userspace implementation of OAEP. Inspired by phpseclib/phpseclib's handling
 * of RSA OAEP. We only implement the decoding and let php-openssl extension
 * take care of the actual decryption (OPENSSL_NO_PADDING).
 *
 * @see https://tools.ietf.org/html/rfc3447
 */
class Oaep
{
    const ENCRYPT_OAEP_MGF1_DIGEST = 'sha1';
    const ENCRYPT_OAEP_MGF1_DIGEST_LEN = 20; // php -r "echo strlen(hash('sha1', '', true));"
    const ENCRYPT_OAEP_DIGEST = 'sha1';
    const ENCRYPT_OAEP_DIGEST_LEN = 20;      // php -r "echo strlen(hash('sha1', '', true));"

    /**
     * @see https://github.com/golang/go/blob/0c7cdb49d89b34baf1f407135b64fd38876823e2/src/crypto/rsa/rsa.go#L569
     * @see https://github.com/openssl/openssl/blob/39c44eee7fd89ce13e805873e1c43bd8e488a93f/crypto/rsa/rsa_oaep.c#L116
     * @see https://github.com/phpseclib/phpseclib/blob/604954cd09345e96c9fe38f77d84dd2e6d843dc0/phpseclib/Crypt/RSA.php#L1212
     * @see https://tools.ietf.org/html/rfc3447#section-7.1.2
     *
     * @param string $EM
     * @param int    $k
     *
     * @return false|string
     */
    public static function decode($EM, $k)
    {
        $hLen = self::ENCRYPT_OAEP_DIGEST_LEN;

        if (Binary::safeStrlen($EM) !== $k) {
            return false;
        }

        // a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen (see the note
        // in Section 7.1.1).
        $l = '';
        $lHash = \hash(self::ENCRYPT_OAEP_DIGEST, '', true);

        // b. Separate the encoded message EM into a single octet Y, an octet
        //    string maskedSeed of length hLen, and an octet string maskedDB
        //    of length k - hLen - 1 as
        //
        //       EM = Y || maskedSeed || maskedDB.
        $Y = \ord($EM[0]);
        $maskedSeed = Binary::safeSubstr($EM, 1, $hLen);
        $maskedDB = Binary::safeSubstr($EM, $hLen + 1);

        // c. Let seedMask = MGF(maskedDB, hLen).
        $seedMask = self::MGF($maskedDB, $hLen);

        // d. Let seed = maskedSeed \xor seedMask.
        $seed = $maskedSeed ^ $seedMask;

        // e. Let dbMask = MGF(seed, k - hLen - 1).
        $dbMask = self::MGF($seed, $k - $hLen - 1);

        // f. Let DB = maskedDB \xor dbMask.
        $DB = $maskedDB ^ $dbMask;

        // g. Separate DB into an octet string lHash' of length hLen, a
        //    (possibly empty) padding string PS consisting of octets with
        //    hexadecimal value 0x00, and a message M as
        //
        //       DB = lHash' || PS || 0x01 || M.
        //
        //    If there is no octet with hexadecimal value 0x01 to separate PS
        //    from M, if lHash does not equal lHash', or if Y is nonzero,
        //    output "decryption error" and stop.  (See the note below.)
        $lHashPrime = Binary::safeSubstr($DB, 0, $hLen);

        $M = Binary::safeSubstr($DB, $hLen);

        $hashesMatch = \hash_equals($lHash, $lHashPrime);
        $leadingZeros = 1;
        $patternMatch = 0;
        $offset = 0;
        for ($i = 0; $i < Binary::safeStrlen($M); ++$i) {
            // XXX the casts are a bit ugly
            $patternMatch |= $leadingZeros & (int) ("\1" === $M[$i]);
            $leadingZeros &= (int) ("\0" === $M[$i]);
            $offset += $patternMatch ? 0 : 1;
        }
        // we do & instead of && to avoid https://en.wikipedia.org/wiki/Short-circuit_evaluation
        // to protect against timing attacks
        if (!$hashesMatch & !$patternMatch) {
            return false;
        }

        // Output the message M
        return Binary::safeSubstr($M, $offset + 1);
    }

    /**
     * @see https://tools.ietf.org/html/rfc3447#appendix-B.2.1
     *
     * @param string $mgfSeed
     * @param int    $maskLen
     *
     * @return string
     */
    private static function MGF($mgfSeed, $maskLen)
    {
        // XXX
        //   1. If maskLen > 2^32 hLen, output "mask too long" and stop.
        $hLen = self::ENCRYPT_OAEP_MGF1_DIGEST_LEN;
        $T = '';
        for ($counter = 0; $counter <= \ceil($maskLen / $hLen) - 1; ++$counter) {
            $C = \pack('N', $counter);
            $T .= \hash(self::ENCRYPT_OAEP_MGF1_DIGEST, $mgfSeed.$C, true);
        }

        return Binary::safeSubstr($T, 0, $maskLen);
    }
}
