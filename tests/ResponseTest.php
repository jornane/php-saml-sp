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
use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\Response;
use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase
{
    public function testFrkoIdP()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP.xml');
        $samlAssertion = $response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/FrkoIdP.crt')])
        );
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

    public function testSURFconext()
    {
        $response = new Response(new DateTime('2019-01-02T21:58:23Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/SURFconext.xml');
        $samlAssertion = $response->verify(
            $samlResponse,
            '_928BA2C80BB10E7BA8F2C4504E0EB20B',
            'https://labrat.eduvpn.nl/saml/postResponse',
            [],
            new IdpInfo('https://idp.surfnet.nl', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/SURFconext.crt')])
        );
        $this->assertSame(
            [
                'urn:mace:dir:attribute-def:eduPersonEntitlement' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'urn:mace:dir:attribute-def:eduPersonTargetedID' => [
                    'c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' => [
                    'c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    public function testSimpleSamlPhp()
    {
        $response = new Response(new DateTime('2019-01-02T22:19:20Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/simpleSAMLphp.xml');
        $samlAssertion = $response->verify(
            $samlResponse,
            '_b354c4367b3e379f940145868f28987e9520b1fb0b',
            'https://vpn.tuxed.net/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            [],
            new IdpInfo('https://vpn.tuxed.net/simplesaml/saml2/idp/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/simpleSAMLphp.crt')])
        );
        $this->assertSame(
            [
                'uid' => [
                    'test',
                ],
                'eduPersonAffiliation' => [
                    'member',
                    'student',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\SignerException
     * @expectedExceptionMessage unexpected digest
     */
    public function testInvalidDigest()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP_invalid_digest.xml');
        $response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/FrkoIdP.crt')])
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\SignerException
     * @expectedExceptionMessage invalid signature
     */
    public function testWrongCertificate()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP.xml');
        $response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/simpleSAMLphp.crt')])
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\SignerException
     * @expectedExceptionMessage invalid signature
     */
    public function testWrongSignature()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP_invalid_signature.xml');
        $response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/FrkoIdP.crt')])
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\ResponseException
     * @expectedExceptionMessage neither the samlp:Response, nor the saml:Assertion was signed
     */
    public function testNotSigned()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/FrkoIdP_not_signed.xml');
        $response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/FrkoIdP.crt')])
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\ResponseException
     * @expectedExceptionMessage we only support 1 assertion in the samlp:Response
     */
    public function testTwoAssertions()
    {
        $response = new Response(new DateTime('2019-01-02T21:58:23Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/SURFconext_two_assertions.xml');
        $response->verify(
            $samlResponse,
            '_928BA2C80BB10E7BA8F2C4504E0EB20B',
            'https://labrat.eduvpn.nl/saml/postResponse',
            [],
            new IdpInfo('https://idp.surfnet.nl', 'http://localhost:8080/sso.php', null, [\file_get_contents(__DIR__.'/data/SURFconext.crt')])
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\SignerException
     * @expectedExceptionMessage digest method "http://www.w3.org/2000/09/xmldsig#sha1" not supported
     */
    public function testSha1()
    {
        $response = new Response(new DateTime('2019-01-16T23:47:31Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/x509idp.moonshot.utr.surfcloud.nl.xml');
        $response->verify(
            $samlResponse,
            '_3c35f56a7156b0805fbccb717cc15194',
            'http://localhost:8081/acs',
            [],
            new IdpInfo('https://x509idp.moonshot.utr.surfcloud.nl/metadata', 'https://x509idp.moonshot.utr.surfcloud.nl/sso', null, [\file_get_contents(__DIR__.'/data/x509idp.moonshot.utr.surfcloud.nl.crt')])
        );
    }

    public function testAdfs()
    {
        $response = new Response(new DateTime('2019-01-16T23:47:31Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/adfs_idp_response.xml');
        $samlAssertion = $response->verify(
            $samlResponse,
            '_cf4383b97e07821f6b9a07e57b3d4557',
            'https://vpn.tuxed.net/php-saml-sp/example/full.php/acs',
            [],
            new IdpInfo('http://fs.tuxed.example/adfs/services/trust', 'SSO', null, [\file_get_contents(__DIR__.'/data/adfs_idp_response.crt')])
        );
        $this->assertSame(
            [
                'http://schemas.xmlsoap.org/claims/CommonName' => [
                    'François Kooman',
                ],
            ],
            $samlAssertion->getAttributes()
        );
        $this->assertSame('<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">WrlwOmM5zcufWzakxkurPqQnZtvlDoxJt6kwJvf950M=</saml:NameID>', $samlAssertion->getNameId());
    }
}
