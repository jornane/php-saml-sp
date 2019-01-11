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
$baseDir = \dirname(__DIR__);

use fkooman\SAML\SP\ArrayIdpInfoSource;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;

try {
    \session_name('SID');
    \session_start();

    $idpInfoSource = new ArrayIdpInfoSource(
        [
            'http://localhost:8080/metadata.php' => [
                'ssoUrl' => 'http://localhost:8080/sso.php',
                'sloUrl' => 'http://localhost:8080/slo.php',
                'publicKeys' => ['MIIEBzCCAm+gAwIBAgIUcIRtCxY3eLWX+LdiAYSN3wfotb0wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIU0FNTCBJZFAwHhcNMTgxMjI2MDkzMzQ2WhcNMjgxMTAzMDkzMzQ2WjATMREwDwYDVQQDDAhTQU1MIElkUDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAMCKe4GcjMlArsLJLz6JoNQtMre/ENnUnzVldTpbg4IN0fdZNzXtru+pn8WNugNgK2Xip8eePf2CFwf4jKqnPdIV46VnuumMQxnXuv5ZgoWrIa2Siz8r8GiLWxOU14BFReaR49kYGTfM5S85bSp+c6aQg0R79uCDzMTo47+W5/UIObpJy9BSDPORgSB0Z/QWTv7G1sk3ETP4LBTu98cfFEL9vIbA8p9ZJI5mP35/vCT57EODoQLpbaOUmEyZP0P9eIX83KFoQd/FH6n3gScTHjTd5KQ4Mx0fAyPuWEHL3THaAPNAhy0ZyhceWFDxDjakXDgbpchDvvlesbHxnAHx57wAYeceyJZrjGj+fzCtbrXXdFYE7lUp4Y2GoBAhUrzXwqcW+zougwBhPTuWy3KBnFUrCYmGwqKMAdqKbXtoMz0e50boxeIn/t9vwRZVHvSLHtW/6VCjWR69vcUcBsjcBDTpj0L6++8Xd+c7AFLFkY0LKTEIdYIa0SuNH1ekjJiKJQIDAQABo1MwUTAdBgNVHQ4EFgQUlLVXzf5MmAQkld7/gbis0isR8skwHwYDVR0jBBgwFoAUlLVXzf5MmAQkld7/gbis0isR8skwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAYEARJIbFgB3XuBoK9k6EzUuce1Q7IvhnorjVrfKUM7rL2plQ6p24Eagqzh2O8S4O2AHaHo5fc/FItQ0XSWAQeOBpYR5fs994ZAknVT0NZV0We20Dn7JcIBf9EgRvCJGKjfxUlQOQfJ6B1EbsouGaF17FOfUKb03UqmB5kyTX2b9HJj96rW/nXzxQ5OsqJ7PlDXLxz6GVf5urpvs66mUIPR67qKTIOXNUz9rgOVZ80MiifdXOB60u2a9QraC1++g8ZSEn+ROm+pGzPMSXAVmnehDoquA7w/1FPz4OachJEuvajGqENjQX+lDjWTkeozkAFOw0C51unjOCNwfaFxzBH9YulLcpMKNEoXawIXc8RZhyMktL2zZ3y0QDKY/qkDhCE+Nf1mLiK5byyUM5dlXw9JVKcu9EGvYfm04ONZVV1g/idAVJ3WxnNtE5ednATZTI4EzomnYzfvZevqViX4SBVast2396LqpxJgWQ8VYCAwYUssqQe/ZWSIhhwzb61QIqg5N'],
            ],

            'https://vpn.tuxed.net/simplesaml/saml2/idp/metadata.php' => [
                'ssoUrl' => 'https://vpn.tuxed.net/simplesaml/saml2/idp/SSOService.php',
                'sloUrl' => 'https://vpn.tuxed.net/simplesaml/saml2/idp/SingleLogoutService.php',
                'publicKeys' => ['MIIDVzCCAj+gAwIBAgIJAJnLmzXGE2RnMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwHhcNMTkwMTAyMjIxMzE4WhcNMjkwMTAxMjIxMzE4WjBCMQswCQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8IVa3PHdZS22uycpiQejtlCV9ZZMALq70MLbrRXZuVPmRIT6+04ZeL3dZeF/jiqz/Lh3V8Kcuxin2ytVX9k+2+n8/PZivF3+jRuQp855oNP9MPTvL9aLIQMfzj7ldGnzRTfhVgSlL/OmwO/okoadbGzppteYgYxGxyF6QVCEmFegKsbznMKDnUwZ22jW572UP0yKBmXLl7WHO2Pz5D17NPDUbO5cVrPzXtaVDvVJ6ZHipq7WI1x6I9Erdys9R+0sEtsGt1+GFdyvnv943HK9IIjykLJaO9ByoJfD3yXoLQysTf6Yb0dfQR58cyHbXv89KPF3bRJGr0tpA2bpCTFIBQIDAQABo1AwTjAdBgNVHQ4EFgQUnmfNpVU35yfya2SMM69IoBqIGs4wHwYDVR0jBBgwFoAUnmfNpVU35yfya2SMM69IoBqIGs4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAyoj4qVhbQQRn3C0aslZJf/GziSVOWrYze4nxGsw2AUtbwDFq38Ohb4dsKWVk7LM7pxsrflfpCgIHr8bNxZ1xQiRsotQLqGHX3CAbFeTWjqZuxbv1wyILYb85/EUUGx76u+DK8NjDwfimaXKJuZwVh0+STygi1TgX9e947I4eHu2/SwXX/clj2fg0z6UZ6NpyTj9ViLe6S9uJtp86eHwPiMUYqb8L6SuiHAmSCSXKpzidSeUTHvyzh8k2rZDxvV2iE5eC20E9yaHwqb2EUD9nkzq2PEg8AZ5GQ6Dv+t2jD/I5xY6IDWgaJdaiGtu/2l3BINxINGqOM7hIbEjyUcdmA=='],
            ],
        ]
    );

    $spInfo = new SpInfo(
        'http://localhost:8081/metadata.php',
        'http://localhost:8081/acs.php',
        'http://localhost:8081/logout.php',
        \file_get_contents('sp.key'),
        \file_get_contents('sp.crt')
    );

    $sp = new SP($spInfo, $idpInfoSource);
    $sp->handleLogoutResponse($_GET['SAMLResponse'], $_GET['RelayState'], $_GET['Signature']);
    \http_response_code(302);
    \header(\sprintf('Location: %s', $_GET['RelayState']));
} catch (Exception $e) {
    echo 'Error: '.$e->getMessage().PHP_EOL;
    echo $e->getTraceAsString();
}
