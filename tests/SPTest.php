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

namespace fkooman\SAML\SP\Tests;

use DateTime;
use fkooman\SAML\SP\ArrayIdpInfoSource;
use fkooman\SAML\SP\Assertion;
use fkooman\SAML\SP\SP;
use PHPUnit\Framework\TestCase;

class SPTest extends TestCase
{
    /** @var \fkooman\SAML\SP\SP */
    private $sp;

    public function setUp()
    {
        $this->sp = new SP(
            'http://localhost:8081/metadata.php',
            'http://localhost:8081/acs.php',
            new ArrayIdpInfoSource(
                [
                    'http://localhost:8080/metadata.php' => [
                        'ssoUrl' => 'http://localhost:8080/sso.php',
                        'sloUrl' => 'http://localhost:8080/slo.php',
                        'publicKey' => \file_get_contents(__DIR__.'/data/FrkoIdP.crt'),
                    ],
                ]
            )
        );
        $this->sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
        $this->sp->setSession(new TestSession());
        $this->sp->setRandom(new TestRandom());
    }

    public function testSimple()
    {
        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app'
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs.php">
  <saml:Issuer>http://localhost:8081/metadata.php</saml:Issuer>
</samlp:AuthnRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
            ]
        );

        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s', $httpQuery), $ssoUrl);
    }

    public function testAuthnContextClassRef()
    {
        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app',
            [
                'AuthnContextClassRef' => [
                    'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
                ],
            ]
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs.php">
  <saml:Issuer>http://localhost:8081/metadata.php</saml:Issuer>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
            ]
        );

        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s', $httpQuery), $ssoUrl);
    }

    public function testForceAuthn()
    {
        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app',
            [
                'ForceAuthn' => true,
            ]
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="true" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs.php">
  <saml:Issuer>http://localhost:8081/metadata.php</saml:Issuer>
</samlp:AuthnRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
            ]
        );

        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s', $httpQuery), $ssoUrl);
    }

    public function testLogout()
    {
        $testSession = new TestSession();
        $samlAssertion = new Assertion(
            'http://localhost:8080/metadata.php',
            '<saml:NameID SPNameQualifier="http://localhost:8081/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID>',
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                ],
            ]
        );
        $testSession->set('_saml_auth_assertion', $samlAssertion);
        $testSession->set('_saml_auth_idp', 'http://localhost:8080/metadata.php');
        $this->sp->setSession($testSession);
        $sloUrl = $this->sp->logout(
            'http://localhost:8080/app'
        );

        $logoutRequest = <<< EOF
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/slo.php">
  <saml:Issuer>http://localhost:8081/metadata.php</saml:Issuer>
  <saml:NameID SPNameQualifier="http://localhost:8081/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID></samlp:LogoutRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($logoutRequest)),
                'RelayState' => $relayState,
            ]
        );

        $this->assertSame(\sprintf('http://localhost:8080/slo.php?%s', $httpQuery), $sloUrl);
    }
}
