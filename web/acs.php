<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
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

require_once \dirname(__DIR__).'/vendor/autoload.php';
$baseDir = \dirname(__DIR__);

use fkooman\SAML\SP\IdPInfo;
use fkooman\SAML\SP\SP;

try {
    \session_name('SID');
    \session_start();

    $idpInfo = new IdPInfo(
        'http://localhost:8080/sso.php',
        \file_get_contents($baseDir.'/server.crt')
    );

    $entityId = 'http://localhost:8081/metadata.php';
    $acsUrl = 'http://localhost:8081/acs.php';
    $relayState = 'http://localhost:8081/index.php';

    $sp = new SP($entityId, $acsUrl);

    $samlResponse = $_POST['SAMLResponse'];
    $sp->handleResponse($idpInfo, $samlResponse);
    \http_response_code(302);
    \header(\sprintf('Location: %s', $_POST['RelayState']));
} catch (Exception $e) {
    echo 'Error: '.$e->getMessage().PHP_EOL;
}
