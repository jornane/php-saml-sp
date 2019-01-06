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
use fkooman\SAML\SP\IdPInfo;
use fkooman\SAML\SP\SP;
use PHPUnit\Framework\TestCase;

class SPTest extends TestCase
{
    public function testSimple()
    {
        $sp = new SP(
            'http://localhost:8081/metadata.php',
            'http://localhost:8081/acs.php'
        );
        $sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
        $sp->setSession(new TestSession());
        $sp->setRandom(new TestRandom());
        $ssoUrl = $sp->login(
            new IdPInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/FrkoIdP.crt')),
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
        $sp = new SP(
            'http://localhost:8081/metadata.php',
            'http://localhost:8081/acs.php'
        );
        $sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
        $sp->setSession(new TestSession());
        $sp->setRandom(new TestRandom());
        $ssoUrl = $sp->login(
            new IdPInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/FrkoIdP.crt')),
            'http://localhost:8080/app',
            ['authnContextClassRefList' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken']]
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
        $sp = new SP(
            'http://localhost:8081/metadata.php',
            'http://localhost:8081/acs.php'
        );
        $sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
        $sp->setSession(new TestSession());
        $sp->setRandom(new TestRandom());
        $ssoUrl = $sp->login(
            new IdPInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/FrkoIdP.crt')),
            'http://localhost:8080/app',
            ['forceAuthn' => true]
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
}
