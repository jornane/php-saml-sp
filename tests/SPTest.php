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
use fkooman\SAML\SP\Signer;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use PHPUnit\Framework\TestCase;

class SPTest extends TestCase
{
    /** @var \fkooman\SAML\SP\SP */
    private $sp;

    public function setUp()
    {
        $this->sp = new SP(
            new SpInfo(
                'http://localhost:8081/metadata.php',
                'http://localhost:8081/acs.php',
                'http://localhost:8081/logout.php',
                \file_get_contents(__DIR__.'/data/sp.key'),
                \file_get_contents(__DIR__.'/data/sp.crt')
            ),
            new ArrayIdpInfoSource(
                [
                    'http://localhost:8080/metadata.php' => [
                        'ssoUrl' => 'http://localhost:8080/sso.php',
                        'sloUrl' => 'http://localhost:8080/slo.php',
                        'publicKeys' => [
                            \file_get_contents(__DIR__.'/data/FrkoIdP.crt'),
                        ],
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
        $session = new TestSession();
        $this->sp->setSession($session);

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
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, \file_get_contents(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
        $this->assertSame('http://localhost:8080/metadata.php', $session->get('_saml_auth_idp'));
        $this->assertSame('_30313233343536373839616263646566', $session->get('_saml_auth_id'));
        $this->assertSame([], $session->get('_saml_auth_authn_context_class_ref'));
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
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, \file_get_contents(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
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
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );

        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, \file_get_contents(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
    }

    public function testLogout()
    {
        $testSession = new TestSession();
        $samlAssertion = new Assertion(
            'http://localhost:8080/metadata.php',
            '<saml:NameID SPNameQualifier="http://localhost:8081/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID>',
            new DateTime('2019-01-02T20:05:33Z'),
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
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );

        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, \file_get_contents(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/slo.php?%s&%s', $httpQuery, $signatureQuery), $sloUrl);
    }

    public function testMetadata()
    {
        $metadataResponse = <<< EOF
<EntityDescriptor validUntil="2018-01-02T20:00:00Z" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="http://localhost:8081/metadata.php">
  <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEBTCCAm2gAwIBAgIUS7YFVomn/lUz/H0CEm8RL1UxNpowDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHU0FNTCBTUDAeFw0xOTAxMDcxODU5MTNaFw0yODExMTUxODU5MTNaMBIxEDAOBgNVBAMMB1NBTUwgU1AwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDydCL4AJfuaOesEcLb+WUiQx0HXs42yyXl/ZIWpg7NaASFFRZC096gnW06sDq2TLIpCdcKt8qd5WBxll4RXN/CoPC1nnHW6AzGPC3zVQne7unJuPSG8Ka1OzXBt9tA+NyQd0h/U5yIVUrtK0svNGtjZ8pOZ76Dm/STIV5mq3HZQ7RfJtMPfagcDY72Eu+FNQaQ72YQFKlg6tm3mqduGdIuMATfVv4my4EHDkux8PV+AbtZcnwq4YlrbgeQ73CnA8LCw0WG8yHblzd8eKwdBuE53tthvu44qEvtx49nrvP0o6KfGG7Qn7tDzaXkmxz23L4GsXdON9jc9yu/BUYYYtUwB7shW42q2RJHWOel5L/GEXGesn4C5DMUG62I4+RDxUIwtoHjz5Fh4BC32uZvPBnIIphXXoDqCqGN9ruzLD1wBlj5UwTr7ves0+aYUwv7lOq1TY5ljA5PkBz3mVQjWMgWaruGdLgJsC3OsRmidUN+/XtXvBHFCeBkvURoOBl95UcCAwEAAaNTMFEwHQYDVR0OBBYEFAdw5e4frADj6CRyrRT1ojo+9ojOMB8GA1UdIwQYMBaAFAdw5e4frADj6CRyrRT1ojo+9ojOMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAHN1ZOlG7gEZYrxjCWTITiP2eCMMb5+bCpi3D69tCtRE1Tz4vEDlHrdepqQo7TVrCYoQiUg1KnGDBMXxY/L/MGKJbgeP+9o8cNpP+1scF5Sac6K/jRAlzso//eSUJkReYynUHjLaIsmhyQ8UOEfUHQmpgAGlSHNcTT9lUpwyphQs4HcIgTYXT1sZVb09/7gEeaKdAfXQ5BEyLU3RYaQUzkyvHYywo1gSKOSjB2UfqCt2+nJzztQzZzmDePDVRWyxfQNHN/Y4PUxIKi/8hxBB3497A5FNsI7gq1j5dBzbPpv+G17sBix7QkoiMy5n2degHhLfSFX1I6+I1lMIEtqR+uI9civOtRo9D90L8uydACoLY4CqslouwCsHuJU39h1HEES8FaXYS7nrthVShNJ8pOk5SPshl637FxlLGWfuFZR1Ot20WtVgXZFwq9ZgRrAnO7PLgbXadocn4skHHbigVWHdwjZIv1rjOVcewY/W/w93mgh5CZikrQQ2PTmUPn6Raw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/acs.php"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/logout.php"/>
  </SPSSODescriptor>
</EntityDescriptor>
EOF;

        $this->assertSame(
            $metadataResponse,
            $this->sp->metadata()
        );
    }

    public function testHandleResponse()
    {
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP.xml');

        $session = new TestSession();
        $session->set('_saml_auth_idp', 'http://localhost:8080/metadata.php');
        $session->set('_saml_auth_id', '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067');
        $session->set('_saml_auth_authn_context_class_ref', []);
        $this->sp->setSession($session);
        $this->sp->handleResponse(\base64_encode($samlResponse));
        $samlAssertion = $session->get('_saml_auth_assertion');
        $this->assertSame('http://localhost:8080/metadata.php', $samlAssertion->getIssuer());
        $this->assertSame('<saml:NameID SPNameQualifier="http://localhost:8081/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID>', $samlAssertion->getNameId());
        $this->assertSame(
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\ResponseException
     * @expectedExceptionMessage we wanted any of "urn:x-example:bar"
     */
    public function testHandleResponseWrongAuthnContext()
    {
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP.xml');

        $session = new TestSession();
        $session->set('_saml_auth_idp', 'http://localhost:8080/metadata.php');
        $session->set('_saml_auth_id', '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067');
        $session->set('_saml_auth_authn_context_class_ref', ['urn:x-example:bar']);
        $this->sp->setSession($session);
        $this->sp->handleResponse(\base64_encode($samlResponse));
    }

    public function testHandleLogoutResponse()
    {
        $samlResponse = <<< EOF
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1e60a9a613e672a64fabef086613452f95676962a7b54bc1e330182ba0c98ae5" Version="2.0" IssueInstant="2019-01-13T21:14:35Z" Destination="http://localhost:8081/logout.php" InResponseTo="_c82bae71c665cb8a1a804bc4b61593f6">
    <saml:Issuer>http://localhost:8080/metadata.php</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>

EOF;
        $session = new TestSession();
        $session->set('_saml_auth_logout_id', '_c82bae71c665cb8a1a804bc4b61593f6');
        $session->set('_saml_auth_logout_idp', 'http://localhost:8080/metadata.php');
        $this->sp->setSession($session);

        $this->sp->handleLogoutResponse(\base64_encode(\gzdeflate($samlResponse)), 'http://localhost:8081/index.php', 'H76WdCmVsHixVXKS3SnqaVJ7lQP7z9o7bp025T1KRcq+RLT3SSVkpzGkeeteSjeY3Yr2yrUHfJHOAL+bG2esKEgLMWW/rqAxzQS6cywHdKLNW4y/hFtxxMKoiGi38mpg6TTwLiF+IFtAHMTogZtSCFN6VKbFnD7yppxpgYaouxl/E8pkc82hK1nXtwYEVDQJ6UIFbxglWRkG53S8IEto1Hshrfshr/Zui5TAKSIyx58LZDZPU4Wj3an2s2NUtyuv9wRjqIH/GaATlkQf/3kf1eC0RR1Fg+ZO+KLhXgbZ9Vuc52yfL0vgEBcfe4QESX0l/zRCRQQr/yCi4BTn7G39swd7a+tQ8eWClDuw2s8cmdpz3DROZsNQZHVbOx35018V+6/t2CHk/84s1IpiFzMjs98KxzVQBW0U+TIgKLTFjuE4GX1KyZVX6nqtpQCUj4L47KCcn/iipUYK4SjCTLdyxlCnkyb81VVh3kyu5Gg2ebXOOwjNBWV+Jrc+u8YMbJNF');

        $this->assertFalse($session->has('_saml_auth_logout_id'));
        $this->assertFalse($session->has('_saml_auth_logout_idp'));
    }
}
