<?php
namespace Fidelize\JWTAuth;

use Exception;
use Log;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Keychain;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;
use Tymon\JWTAuth\Contracts\Providers\JWT;

class JwtAdapter extends Lcobucci implements JWT
{
    public function __construct()
    {
        return parent::__construct(
            new Builder(),
            new Parser(),
            Config::get('jwt.secret'),
            Config::get('jwt.algo'),
            []
        );
    }

    /**
     * Create a JSON Web Token.
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        try {
            foreach ($payload as $key => $value) {
                $this->builder->set($key, $value);
            }
            $key = $this->getPrivateKey();
            $signer = is_object($key) ? new RS256() : new HS256();
            $this->builder->sign($signer, $key);
            $token = $this->builder->getToken();
            return $token->__toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            $token = $this->parser->parse((string) $token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage());
        }

        $claims = $token->getClaims();

        if (array_key_exists('iss', $claims)) {
            if ($this->validateIss($token, $claims)) {
                return array_map(
                    function (Claim $claim) {
                        return $claim->getValue();
                    },
                    $claims
                );
            }
        }

        // Test token signature against all available public keys + JWT secret
        $atLeastOnePublicKeyWorked = false;

        foreach ($this->getPublicKeys() as $publicKey) {
            $signer = is_object($publicKey) ? new RS256() : new HS256();
            if ($token->verify($signer, $publicKey)) {
                $atLeastOnePublicKeyWorked = true;
                break;
            }
        }

        if (!$atLeastOnePublicKeyWorked) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        // Convert to plain scalar values instead of an array of Claim objects
        return array_map(
            function (Claim $claim) {
                return $claim->getValue();
            },
            $claims
        );
    }

    private function validateIss($token, $claims) {
        $iss = trim($claims['iss']->getValue());
        $issuer = preg_replace('/[^A-Z0-9]+/', '_', strtoupper($iss));

        if (!$publicKey = $this->getPublicKeysFromEnv($issuer)) {
            Log::warning('Env public key not found', [
                'Iss' => $issuer
            ]);

            return false;
        }

        $signer = new RS256();
        $verifiedKey = $token->verify($signer, $publicKey);
        if ($verifiedKey === true) {
            Log::debug('Token successfully validated with .env', [
                'Iss' => $issuer
            ]);

            return true;
        }

        Log::warning('Token invalid with .env verify', [
            'Iss' => $issuer
        ]);

        return false;
    }

    /**
     * PRIVATE key is used to generate new tokens. In order to be trusted,
     * the system receiving the token must validate it against the PUBLIC key.
     */
    public function getPrivateKey()
    {
        $files = $this->globKeys('jwt.*.key');

        if (count($files) > 1) {
            throw new TokenInvalidException('Multiple private keys found.');
        }

        // If there is no private key, fallback to JWT_SECRET
        if (count($files) == 0) {
            return $this->secret;
        }

        $file = array_pop($files);
        $keychain = new Keychain();
        return $keychain->getPrivateKey("file://{$file}");
    }

    /**
     * PUBLIC keys against which it will try to validate and trust the token.
     * Note that though you can trust and use the token, you are not able
     * to generate tokens using PUBLIC keys, only PRIVATE ones.
     */
    private function getPublicKeys()
    {
        $files = $this->globKeys('jwt.*.key.pub');
        $keychain = new Keychain();
        $keys = [];

        foreach ($files as $file) {
            $keys[] = $keychain->getPublicKey("file://{$file}");
        }

        // If there is no public key, fallback to JWT_SECRET
        $keys[] = $this->secret;

        return $keys;
    }

    private function getPublicKeysFromEnv($iss)
    {
        $env = getenv('JWT_PUBLIC_KEY_' . $iss);

        return base64_decode($env);
    }

    private function globKeys($pattern)
    {
        return File::glob($this->getKeysDirectory() . $pattern);
    }

    private function getKeysDirectory()
    {
        return Config::get('jwt.keys_directory') . DIRECTORY_SEPARATOR;
    }
}
