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
MIID+TCCAmGgAwIBAgIJAPVzLlTLsbPrMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCFNBTUwg
SWRQMB4XDTE4MTIyNzExMTIyNFoXDTI4MTEwNDExMTIyNFowEzERMA8GA1UEAwwIU0FNTCBJZFAw
ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDGNgKz8zelTUyRKxI90K8bvoYJsyllqPbV
zU40EZ63WZjjalZyQuf4++/gGtWojaRYDtx2Cbe6koWyrtQV9xhlfgZJFV5eAqaDeQrAP8TtzExo
HeXpUEfbXDhx9Wh54MO9tdiBUOuOjoME+WSEZm8AJv5x1fffBvpcMzJ2l6aXer3DB8bumMVMkU13
U7AK2MFBuhlPQnAah3bUpEW8xIfEUFp+W2Gr3a2b+Ko6xL3jNfXHhya2hALKKMZOd57cIY9OVdDk
wZN0PQE34Eu622mBxmNkoLGhOlQiKDoR1wZo9aHS2HNaYIk9IW2kyq+TmhQ/VTXVxI/6XhQ8EyDA
swRdGjrc69md/jis1ZIfWcOh1F8zkkTGo+0vIOtylPklVIkc0qWxCYnxrKF2F+hcO7i8cMf3a454
JZnFCemKXnT3+XC5oI8jiJJsvHnsCExROfC1pYAdhjH8b1tAW497QKaerGmHKGVObLirwHJzWusF
Nx/xR3y10k4sya6oMtVwMl0CAwEAAaNQME4wHQYDVR0OBBYEFEKnC3VD3kFPXAmwdD7pWAyKXsQE
MB8GA1UdIwQYMBaAFEKnC3VD3kFPXAmwdD7pWAyKXsQEMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcN
AQELBQADggGBAGjq0wauMePKl74uVP4JZy2UnV/MX38n83fYptfbLV9U730mLovKF6SYmtUkA18b
CJ7rlf4mp5WFphypodRptIVNZZOITTRG4Rs4o5l3TZn5qa43ddEwstpy2906Zai1zHTaAgbL8r0F
a4dQSlnCBlJYS7Qnmlkcw/K8LQQHvVrMfUq3dPhOgov4dAIB3wxauxkR5BHoLIa2+voEOna8H3hT
qbiZ/7TMUmnzOUGuKB+k7+JQvKrqvljPXvdryCZMCwZHIGaDuRnlm+jJcQUa8nR3jb5Okr6DsmfY
Vs6Ik3LUp7tTKY2bEjcdHnGOKQqCJy+I1sC1dI5p/yVibFio7MEfrXQhtakfGuDHPQP18Qfdn8nM
62DoEX4LvzEizg1DC8M6KG1Qw+KHpJKbXYM7WLXWPIe0IiBS+bSwtadPgnN/D6z3InSEuGYaRKlv
MtQKcmt+OU+Ft9g3dc8n2oks803+UQ8U7eOLKtAttsYoIh0OVmda8eGhfLDBaD7SQ/jVsw==
-----END CERTIFICATE-----
EOF;
        $xmlIdpInfoSource = new XmlIdpInfoSource([__DIR__.'/data/idp.tuxed.net.xml']);
        $idpInfo = $xmlIdpInfoSource->get('https://idp.tuxed.net/metadata.php');
        $this->assertSame('https://idp.tuxed.net/metadata.php', $idpInfo->getEntityId());
        $this->assertSame('https://idp.tuxed.net/sso.php', $idpInfo->getSsoUrl());
        $this->assertSame('https://idp.tuxed.net/slo.php', $idpInfo->getSloUrl());
        $this->assertSame($pemCert, $idpInfo->getPublicKey());
    }
}
