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

use fkooman\SAML\SP\XmlIdpInfoSource;
use PHPUnit\Framework\TestCase;

class XmlIdpInfoSourceTest extends TestCase
{
    public function testSimple()
    {
        $pemCert = <<< EOF
-----BEGIN CERTIFICATE-----
MIID+TCCAmGgAwIBAgIJAPVzLlTLsbPrMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFNBTUwgSWRQMB4XDTE4MTIyNzExMTIyNFoXDTI4MTEwNDExMTIyNFowEzER
MA8GA1UEAwwIU0FNTCBJZFAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
gQDGNgKz8zelTUyRKxI90K8bvoYJsyllqPbVzU40EZ63WZjjalZyQuf4++/gGtWo
jaRYDtx2Cbe6koWyrtQV9xhlfgZJFV5eAqaDeQrAP8TtzExoHeXpUEfbXDhx9Wh5
4MO9tdiBUOuOjoME+WSEZm8AJv5x1fffBvpcMzJ2l6aXer3DB8bumMVMkU13U7AK
2MFBuhlPQnAah3bUpEW8xIfEUFp+W2Gr3a2b+Ko6xL3jNfXHhya2hALKKMZOd57c
IY9OVdDkwZN0PQE34Eu622mBxmNkoLGhOlQiKDoR1wZo9aHS2HNaYIk9IW2kyq+T
mhQ/VTXVxI/6XhQ8EyDAswRdGjrc69md/jis1ZIfWcOh1F8zkkTGo+0vIOtylPkl
VIkc0qWxCYnxrKF2F+hcO7i8cMf3a454JZnFCemKXnT3+XC5oI8jiJJsvHnsCExR
OfC1pYAdhjH8b1tAW497QKaerGmHKGVObLirwHJzWusFNx/xR3y10k4sya6oMtVw
Ml0CAwEAAaNQME4wHQYDVR0OBBYEFEKnC3VD3kFPXAmwdD7pWAyKXsQEMB8GA1Ud
IwQYMBaAFEKnC3VD3kFPXAmwdD7pWAyKXsQEMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggGBAGjq0wauMePKl74uVP4JZy2UnV/MX38n83fYptfbLV9U730m
LovKF6SYmtUkA18bCJ7rlf4mp5WFphypodRptIVNZZOITTRG4Rs4o5l3TZn5qa43
ddEwstpy2906Zai1zHTaAgbL8r0Fa4dQSlnCBlJYS7Qnmlkcw/K8LQQHvVrMfUq3
dPhOgov4dAIB3wxauxkR5BHoLIa2+voEOna8H3hTqbiZ/7TMUmnzOUGuKB+k7+JQ
vKrqvljPXvdryCZMCwZHIGaDuRnlm+jJcQUa8nR3jb5Okr6DsmfYVs6Ik3LUp7tT
KY2bEjcdHnGOKQqCJy+I1sC1dI5p/yVibFio7MEfrXQhtakfGuDHPQP18Qfdn8nM
62DoEX4LvzEizg1DC8M6KG1Qw+KHpJKbXYM7WLXWPIe0IiBS+bSwtadPgnN/D6z3
InSEuGYaRKlvMtQKcmt+OU+Ft9g3dc8n2oks803+UQ8U7eOLKtAttsYoIh0OVmda
8eGhfLDBaD7SQ/jVsw==
-----END CERTIFICATE-----
EOF;
        $xmlIdpInfoSource = new XmlIdpInfoSource(__DIR__.'/data/idp.tuxed.net.xml');
        $idpInfo = $xmlIdpInfoSource->get('https://idp.tuxed.net/metadata.php');
        $this->assertSame('https://idp.tuxed.net/metadata.php', $idpInfo->getEntityId());
        $this->assertSame('https://idp.tuxed.net/sso.php', $idpInfo->getSsoUrl());
        $this->assertSame('https://idp.tuxed.net/slo.php', $idpInfo->getSloUrl());
        $this->assertSame($pemCert, $idpInfo->getPublicKeys()[0]);
    }

    public function testNoNsPrefix()
    {
        $xmlIdpInfoSource = new XmlIdpInfoSource(__DIR__.'/data/x509idp.moonshot.utr.surfcloud.nl_metadata.xml');
        $idpInfo = $xmlIdpInfoSource->get('https://x509idp.moonshot.utr.surfcloud.nl/metadata');
        $this->assertSame('https://x509idp.moonshot.utr.surfcloud.nl/metadata', $idpInfo->getEntityId());
        $this->assertSame('https://x509idp.moonshot.utr.surfcloud.nl/sso', $idpInfo->getSsoUrl());
    }
}
