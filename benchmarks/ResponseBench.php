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

use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\Response;

class ResponseBench
{
    /**
     * @Revs(1000)
     * @Iterations(5)
     *
     * @return void
     */
    public function benchHandleResponse()
    {
        $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(\dirname(__DIR__).'/tests/data/FrkoIdP.xml');
        $samlAssertion = $response->verify(
            $samlResponse,
            'http://localhost:8081/metadata.php',
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            [],
            new IdpInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', [\file_get_contents(\dirname(__DIR__).'/tests/data/FrkoIdP.crt')])
        );
    }
}
