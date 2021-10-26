<?php

namespace Fidelize\JWTAuth\Test;

use Fidelize\JWTAuth\JwtAdapter;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;

class JwtAdapterTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Config::shouldReceive('get')->with('jwt.keys_directory')->andReturn(__DIR__ . '/keys');
        $key = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuOVk35U8Q+xkFSvp9CcI
dzAnbnd/rX1HlXYcr0ihLuh0TzlhJBLCg9rOafxUDaRuPvwDB0MN+c+lIBjEDXYu
zh9LDlrd7vg6fMXeDArLBUyJn3hVU49mthu2Wv4KfAcNzrUTQeWLMxXnHRuyyTw8
JcvqkC9K2hfECgAIXmIWjJ/1J84iLFgT/upk5o7QX9kNAu0+9iUQ6FuyMPdEnUFS
83UpUoE8u1pulHizWeVKiUKUTlp521dO16vmL06WI0oHdLRqojUumnDRraaFKPgq
FowVCddlKdGLDAMAHOqPl+s1cvcYon3KhE5f+2preyrFEp/MLZKINRdNmnJff3QM
Yf1gaQqNl2PUK89e0HxGXHSZLvIGZIxowGCBmH/2N5i1nrutQ3S3cZ7A/Autb4nh
papWRw6xFRueaaV5oAEZ/5Vyv9dH6ALBk+p8sp1ldr0yjia7SMc8rEatrh85jAVI
wSyevn8CyL67qny3M/Yv8xeE1owYqeVCEVW/a65b++Lwj7sTuhrBGG8rrIaT/v5P
p9vGs2EkOaLwi3Jz2oG52uZs+8J3AK67fipKzrXe9Bleh9USIP7ouQPZpg//1MQD
L3HrYctZIrCukKKDZxaOALHGU6KlQ4jMMXMZzBvfCrv32whl9SHvXBxtGREcRX85
BDVsWAUdKuI5vZtAF+B95oECAwEAAQ==
-----END PUBLIC KEY-----
';
        putenv('JWT_PUBLIC_KEY_FOO='.base64_encode($key));
    }

    public function testEncodeWhenThereIsNoPrivateKey()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw',
            $adapter->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereIsAPrivateKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key'
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk',
            $adapter->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereAreMultiplePrivateKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key',
            __DIR__ . '/keys/jwt.another.key',
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->expectException(JWTException::class);
        $adapter->encode($this->getPayload());
    }

    public function testDecodeWithInvalidToken()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->expectException(TokenInvalidException::class);
        $adapter->decode('invalid_token');
    }

    public function testDecodeWithInvalidSignature()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter('INVALID_secret');
        $this->expectException(TokenInvalidException::class);
        $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw');
    }

    public function testDecodeWithValidTokenUsingSecret()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $result = $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw');
        $this->assertEquals($this->getPayload(), $result);
    }

    public function testDecodeWithValidTokenUsingPublicKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key.pub',
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $result = $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk');
        $this->assertEquals($this->getPayload(), $result);
    }

    public function testDecodeWithInvalidIss()
    {
        $adapter = $this->getJwtAdapter();
        $this->expectException(TokenInvalidException::class);
        $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpc3MiOiJmb29hIiwiaWF0IjoxMjM0NTYsImV4cCI6MTI3MDU2LCJqYXQiOiJmb29iYXJiYXoifQ.Em9g8nEf6Obwxq22ZxcKQve9tRIrWVr7v8JzZGQQJ7waLu_pIMgsUAMjm9ieUXILQ04ZXk_ZqC_4XUceHIKFWPirh2ekPbP0AF8a7qdpRkVzlP3WwbGhyBcDi4Ti6t_TzqZyIiCP4_yPK7n9il4Rn5mzW_0V8fVcPqg-yOM4hcOZMAxFUYevBe76VIO-DoVeY9QfoWxx4vw6yNWOnlw4AEjro_Mi9JlHveeTaYaSMOfq4xeKp76jE-YuiRncQM95omJc_CsGU0SJwhsh-J4ZP2k2-ctHY01q03YVwHUb_vfiYtdG9G0TAiZZwLTYJoRQN9jFm97fdJ0KADostIqP1auVzeYEXaqiJpvi6GHD8NR5SaLJxI3OGoEjGx2a7UCxomNmWDjYqI9oxSQi-ikCJTUVyV-FJcDf4v3l8-2gsmpaJT2tgGTz5HPapKFG8ReY8RXbZTHtD45tVDYyclgC6vJFopTWgziG66L1TOi1gY8xmnAanhchJ6BmLoA6KqkFqmx2QqUIX65AgOczpclcwEgA5jSPm2hVaRpMeiRdKI5sna-A9V7juweRKMyMPQy7Q6kxZvBaGcxamysbDIi6vSMObdJSt5FbZic7-YGFpdctPlgydAi_Pxv2abd09BDiUIjTqXF0WgOId4SiG6PiZsg0ulBW-Pa7MMHafsMGiVI');
    }

    public function testDecodeWithValidTokenUsingEnv()
    {
        $adapter = $this->getJwtAdapter();
        $result = $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpc3MiOiJmb28iLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.JFhJ3sCHq1mkn5c5YN25rMLSZ3jFGmSXGO26wPbU6IxKTRBQXxA1KS9kM6dGxxfgT_QMqsvb2BiOpch-cxtQamNl3sEWhUEsmHHpVEQsQfRmWeHfVt5Vy9kGkwH_BLFF7GqNPx3AOoeVynzNqASmv3dyqZDB_3xbvWd6vhXKf_c8nchVcSlIqUwg6GD5jnb39IMWP5qS2XmkYP09KEsA1vpQgsWQZyNMEQYOQf6yMGX0btKF8ZbjqBWlyRiLPKKmVuoBtXmhIXrtDQGKxhOEGMnwC6qREciR26-WuSl4O_iJUCLmG3CHmJdOv6bWVhAC6Fi-SbTZwuGyAYF7W-ySHdZ6CJs-18LYQ--RAX3cSh7mkKUajJJ1alEGdpTbBrGaGThc4TQ7fHgtkundlDicUE2ZtbInJKqKBaC9yRVdMOyIGSfusB_2f51KiOqdRnQLDsp8rrGIP4MA2scJhC9zHf-UQ3LxsK68RX1aXbTd_7Ejs_eLl9yPOE_Gjraff836SteoSPofdb_-gNOmGPAHEDI4TmC7FRwZCScdYq220tQM6xGsk7435fvbcGv4Oy9wSrl9rUofx7R5U1lqNoqxTD0WbnEux0_PdO2PLk8EDiAvKdTA_gt5i3WHgt-QilKwv1d0eXYrgNQN6rRE2a55jmAey1LpKO2Zk-qxT3ohtdo');
        $this->assertEquals($this->getPayloadWithIss(), $result);
    }

    private function getPayload()
    {
        return [
            'sub' => 'fidmaster',
            'iat' => 123456,
            'exp' => 123456 + 3600,
            'jat' => 'foobarbaz',
        ];
    }

    private function getPayloadWithIss()
    {
        return [
            'sub' => 'fidmaster',
            'iss' => 'foo',
            'iat' => 123456,
            'exp' => 123456 + 3600,
            'jat' => 'foobarbaz',
        ];
    }

    private function getJwtAdapter($secret = 'secret')
    {
        $config = Configuration::forSymmetricSigner(new RS256(), InMemory::plainText($secret));
        return new JwtAdapter($config);
    }
}
