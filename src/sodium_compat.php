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

if (!\defined('SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES')) {
    \define('SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES', \Sodium\CRYPTO_AEAD_AES256GCM_NPUBBYTES);
}

if (!\is_callable('sodium_crypto_aead_aes256gcm_is_available')) {
    /**
     * @return bool
     */
    function sodium_crypto_aead_aes256gcm_is_available()
    {
        return \Sodium\crypto_aead_aes256gcm_is_available();
    }
}

if (!\is_callable('sodium_crypto_aead_aes256gcm_decrypt')) {
    /**
     * @param string $message
     * @param string $assocData
     * @param string $nonce
     * @param string $key
     *
     * @return false|string
     */
    function sodium_crypto_aead_aes256gcm_decrypt($message, $assocData, $nonce, $key)
    {
        return \Sodium\crypto_aead_aes256gcm_decrypt($message, $assocData, $nonce, $key);
    }
}
