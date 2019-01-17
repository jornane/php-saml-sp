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

    $idpInfoSource = new XmlIdpInfoSource(__DIR__.'/idp.xml');
    $idpEntityId = 'https://x509idp.moonshot.utr.surfcloud.nl/metadata';
    //$idpEntityId = 'http://localhost:8080/metadata.php';

    $relayState = 'http://localhost:8081/simple.php';

    // the eduPersonEntitlement required for access to the "admin"
    $entitlementAttribute = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
    $adminEntitlement = 'urn:example:admin';
    $adminAuthnContext = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
    //$adminAuthnContext = 'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken';

    // configure the SP
    $spInfo = new SpInfo(
        'http://localhost:8081/full.php/metadata',
        'http://localhost:8081/full.php/acs',
        'http://localhost:8081/full.php/slo',
        \file_get_contents('sp.key'), // used to sign AuthnRequest/LogoutRequest
        \file_get_contents('sp.crt')  // used to provide in metadata
    );
    $sp = new SP($spInfo, $idpInfoSource);

    $pathInfo = \array_key_exists('PATH_INFO', $_SERVER) ? $_SERVER['PATH_INFO'] : '/';
    $requestMethod = $_SERVER['REQUEST_METHOD'];

    switch ($pathInfo) {
        case '/':
            if (false === $samlAssertion = $sp->getAssertion()) {
                // not logged in, show login button
                echo '<a href="full.php/login"><button>Login</button></a>';
            } else {
                echo '<pre>';
                echo 'IdP: '.$samlAssertion->getIssuer().PHP_EOL;
                foreach ($samlAssertion->getAttributes() as $k => $v) {
                    echo $k.': '.\implode(',', $v).PHP_EOL;
                }
                echo '</pre>';
                echo '<a href="full.php/admin"><button>Admin</button></a><a href="full.php/logout"><button>Logout</button></a>';
            }
            break;

        // user triggers "login"
        case '/login':
            \http_response_code(302);
            \header(\sprintf('Location: %s', $sp->login($idpEntityId, $relayState)));
            break;

        // in order to access the admin, the user needs to have a certain
        // "entitlement" *AND* be authenticated using a certain "AuthnContext"
        case '/admin':
            if (false === $samlAssertion = $sp->getAssertion()) {
                // not logged in, show login button
                echo '<a href="login"><button>Login</button></a>';
            } else {
                $samlAttributes = $samlAssertion->getAttributes();
                if (!\array_key_exists($entitlementAttribute, $samlAttributes)) {
                    \http_response_code(403);
                    echo \sprintf('[403] required attribute "%s" not available from IdP', $entitlementAttribute);
                } elseif (!\in_array($adminEntitlement, $samlAttributes[$entitlementAttribute], true)) {
                    \http_response_code(403);
                    echo \sprintf('[403] required attribute value "%s" not available for this user', $adminEntitlement);
                } else {
                    // make sure we have the correct AuthnContext?
                    if ($adminAuthnContext !== $samlAssertion->getAuthnContext()) {
                        \http_response_code(302);
                        \header(
                            \sprintf(
                                'Location: %s',
                                $sp->login(
                                    $idpEntityId,
                                    $relayState,
                                    [$adminAuthnContext]
                                )
                            )
                        );
                    }
                    // all conditions fulfilled!
                    echo 'Welcome Admin!';
                    echo '<a href="logout"><button>Logout</button></a>';
                }
            }
            break;

        // user triggers "logout"
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

        // callback from IdP containing the SAML "LogoutResponse"
        case '/slo':
            $sp->handleLogoutResponse($_GET['SAMLResponse'], $_GET['RelayState'], $_GET['Signature']);
            \http_response_code(302);
            \header(\sprintf('Location: %s', $_GET['RelayState']));
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
