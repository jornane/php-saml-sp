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

    /**
     * @expectedException \fkooman\SAML\SP\Exception\ResponseException
     * @expectedExceptionMessage status error code: urn:oasis:names:tc:SAML:2.0:status:Responder,urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext
     */
    public function testErrorResponse()
    {
        $response = new Response(new DateTime('2019-01-16T23:47:31Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/SURFsecureID_error.xml');
        $response->verify(
            $samlResponse,
            '_6a31edbaec0922414f9a96e5fdb5493e',
            'https://kluitje.eduvpn.nl/portal/_saml/acs',
            [],
            new IdpInfo('https://sa-gw.test.surfconext.nl/authentication/metadata', 'SSO', null, [''])
        );
    }

//    public function testLogoutResponseAdfs()
//    {

//SAMLResponse: fVLLbsMgEPwVi7uNX0ls5Fiqkkuk9NJEPfRSEbw0ljAgL0T5/GK7OUSqcmSZ2XlAg3xQlh3Nj/HuA9AajRAd9lvyXUPBhZR5fLmUXVzWso6rTSnidRimaSZkUdQk+oQRe6O3JE9SEh0QPRw0Oq5dGKVZHadZnFXnrGKrgmWbZFWmXyTaA7peczczr85ZZJTerE6cv0OXaHDUXm08mYvRUrjzwSqg0iuVhAuKypBoN3mddPyomeHYI9N8AGROsNPb+5EFS0wsIOY1WhC97KELNvUj6tlMSWVd5aUsZLqWuchWIkt5xS9QrTnwjQiE+6A0srmr13J2NM4Io0jbzF2MC/U1iSPCOHVB2qmLUIXEvyYeyXknkQbUrReA1I0eXUMXhbZZ3vDkuPP4fNqZDqJPrjy8doAzmp28COuRRLRt6PNW+t9HaX8B

//RelayState: https://vpn.tuxed.net/php-saml-sp/example/full.php

//Signature: pI58/1WP+XoSYL02mKehsQJQzD3YFReFtuURm4ppqT8iMUbvjXEe6EK78hRs69ScZAJJAzDznzi4WzTAfKlHXS2i/AUWFKaE7O930viStr0SBb7VHpdmHlnoQNKjNmZTZnCbwXlpU6ccKpspToc1F/02Jxk/oniyoyqX5amViQgI7CwjKGghLlfgJZQV2+cTye1C7ZdBTOIv7k8YfqASLq4pkZrvqGhFJRj9yfNx1Oqd+MCqg/bIIcyM9sMUrsG0gZkwnq0aJaxr1vGhJJo5U8tKGLHhsuDXHGgj9BMs5St7RBjgTPulztw/pRRCFts4eu/q+yWZZ4G3Zz1V8Kd3rA==

//SigAlg: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256

//        'https://vpn.tuxed.net/php-saml-sp/example/full.php/slo?SAMLResponse=fVJNb4MgGP4rhjsCzg8k1mRpLybdZW122GVhiquJAvGFpj9%2fqOuhydIj8Dzv8%2fFSgZxGK47mx3j3rsAaDSpqDjv0VfZJm5VZgTuav%2bC0y76x5KzDnKYyZXlOS9qh6EPNMBi9Q0lMUdQAeNVocFK7cEVZiSnDjJ8ZFykVjMWcZp8oOihwg5ZuZV6csyAIuVodO39TXayVI%2fZi8WIOgyXqJic7KtL7cYzDA4HRoGi%2feF10%2fKyFkTCA0HJSIFwrTq9vRxEsiXYDCa%2fBqnboBxVMN%2foe9WxCUpbKss9KJlnGeV8UvEwL2tMkkV3B81Si6DaNGsTa1XM5OxtnWjOiulq7mDfqc5IEUPPSBaqXLkIVPfw1cU8uux5IQF2HVgFxswdXkU2hrrYdnpx0Hh5Pe9Op6EOOXj13ACtanHwbxgOKSF2Rx6nkv49S%2fwI%3d&RelayState=https%3a%2f%2fvpn.tuxed.net%2fphp-saml-sp%2fexample%2ffull.php&Signature=U%2fhsM3x89%2f%2bFdjzLLgdS43EvtOM%2byblt9fBYvw%2bB3gWWuWpaPTUeZzYGQDC4xbWwG6PpVFaHs5RV3oA5daClC7GJpJSEyMrRIsWJlK8T5W3D%2foYDDAbtsjmzeprb3zn2kZVU1Fgk2SL2lg%2b8xHk%2fi4SjxNuF2DaEPmS%2fHlvNuXMd%2bDREGhgVuUdFEaPgU9%2bTWtFuH4KtgyEQ%2b%2bG02NPXy1EWZWuB7Djso1cdOK3SxjW5y%2fzYPXBSjMksUpxMCQZl4Z9bufavIq50GAoMl2syiN5vW%2fKIxtVzSQ0RKJVg16%2fvs8vgIibZdqQOBNj8RMYBR0cekWD%2fYwz5SxlLVEfKmA%3d%3d&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256'

//    }
}
