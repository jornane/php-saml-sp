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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\SAML\SP\Exception\SamlException;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use fkooman\SAML\SP\XmlIdpInfoSource;

try {
    \session_name('SID');
    \session_start();

    $idpInfoSource = new XmlIdpInfoSource(__DIR__.'/adfs.xml');
//    $idpEntityId = 'https://x509idp.moonshot.utr.surfcloud.nl/metadata';
    //$idpEntityId = 'http://localhost:8080/metadata.php';

    $idpEntityId = 'http://fs.tuxed.example/adfs/services/trust';

    $relayState = 'http://localhost:8081/simple.php';

    // configure the SP
    $spInfo = new SpInfo(
        'http://localhost:8081/simple.php/metadata',
        'http://localhost:8081/simple.php/acs',
        null, // no SingleLogout
        \file_get_contents('sp.key'), // used to sign AuthnRequest/LogoutRequest
        \file_get_contents('sp.crt')  // used to provide in metadata
    );
    $sp = new SP($spInfo, $idpInfoSource);

    $pathInfo = \array_key_exists('PATH_INFO', $_SERVER) ? $_SERVER['PATH_INFO'] : '/';
    $requestMethod = $_SERVER['REQUEST_METHOD'];

    switch ($pathInfo) {
        case '/':
            if (false === $samlAssertion = $sp->getAssertion()) {
                // not logged in, redirect to IdP
                \http_response_code(302);
                \header(\sprintf('Location: %s', $sp->login($idpEntityId, $relayState)));
            } else {
                echo '<pre>';
                echo 'IdP: '.$samlAssertion->getIssuer().PHP_EOL;
                foreach ($samlAssertion->getAttributes() as $k => $v) {
                    echo $k.': '.\implode(',', $v).PHP_EOL;
                }
                echo '</pre>';
                echo '<a href="simple.php/logout"><button>Local Logout</button></a>';
            }
            break;

        case '/logout':
            \http_response_code(302);
            \header(\sprintf('Location: %s', $sp->logout($relayState)));
            break;

        // callback from IdP containing the SAML "Response"
        case '/acs':
            if ('POST' === $requestMethod) {
                // listen only for POST HTTP request
                $samlResponse = $_POST['SAMLResponse'];
                $sp->handleResponse($samlResponse);
                \http_response_code(302);
                \header(\sprintf('Location: %s', $_POST['RelayState']));
            } else {
                \http_response_code(405);
                echo '[405] only POST allowed on ACS';
            }
            break;

        // exposes the SP metadata
        case '/metadata':
            \header('Content-Type: application/samlmetadata+xml');
            echo $sp->metadata();
            break;
    }
} catch (SamlException $e) {
    echo 'Error: '.$e->getMessage().PHP_EOL;
}
